//! Crash-safe atomic file replacement.
//!
//! Writers create a random same-directory temporary file, write and fsync
//! it, then replace the target: on Unix (and for brand-new files) via
//! `std::fs::rename` — an atomic replace on Unix, `MoveFileEx` with
//! `MOVEFILE_REPLACE_EXISTING` on Windows. On any failure the original
//! file is left untouched and the temporary file is removed. On Unix the
//! parent directory is synced afterwards so the rename survives power
//! loss.
//!
//! On Windows, replacing an **existing** file goes through Win32
//! `ReplaceFile` (via `PowerShell`'s `[System.IO.File]::Replace`, since
//! the workspace forbids unsafe code and std exposes no equivalent):
//! unlike a rename-over, `ReplaceFile` keeps the original file's
//! security descriptor, so an administrator's explicitly tightened ACL
//! survives the write instead of silently widening to the inherited
//! directory ACL. A missing or failing `PowerShell` falls back to the
//! rename-over (write correctness first, ACL preservation second). The
//! invocation needs no privileges a standard user token lacks — the
//! `icacls /save` + `/restore` roundtrip was rejected here because
//! `/restore` demands `SeRestorePrivilege`.

use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

use crate::error::CoreError;

/// Attempts at drawing a non-colliding temporary name before giving up.
/// Collisions are random 48-bit events; more than one retry never happens
/// in practice.
const TMP_ATTEMPTS: usize = 4;

/// Write `bytes` to `target` atomically.
///
/// The temporary file is created owner-readable/writable only on Unix; on
/// Windows an existing target's security descriptor is preserved across
/// the replace (see the module documentation).
///
/// The temporary name starts with a dot and ends in `.tmp-…` so sync
/// tools (e.g. Syncthing `stignore`) can exclude in-flight writes; see
/// docs/sync.md.
///
/// # Errors
///
/// Returns an error if any step fails; the target is never left
/// half-written.
pub fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let Some(dir) = target.parent() else {
        return Err(CoreError::Path(format!(
            "target {} has no parent directory",
            target.display()
        )));
    };
    let name = target
        .file_name()
        .ok_or_else(|| CoreError::Path(format!("invalid target {}", target.display())))?
        .to_os_string();

    let mut last: Option<CoreError> = None;
    for _ in 0..TMP_ATTEMPTS {
        let suffix = match random_suffix() {
            Ok(s) => s,
            Err(e) => {
                last = Some(e);
                break;
            }
        };
        let mut tmp = OsString::from(".");
        tmp.push(&name);
        tmp.push(format!(".tmp-{suffix}").as_str());
        let tmp = dir.join(tmp);
        match write_and_replace(&tmp, target, bytes) {
            Ok(()) => return Ok(()),
            // Another writer won this random suffix; their file must
            // not be deleted — the loop draws a fresh name instead.
            Err(ReplaceError::NameTaken) => {}
            Err(ReplaceError::Other(e)) => {
                // Our own temporary file: safe to clean up.
                let _ = fs::remove_file(&tmp);
                last = Some(e);
                break;
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        CoreError::Secret("atomic write: exhausted temporary name attempts".to_string())
    }))
}

/// Distinguish "the random temp name is taken" (retry with a new name)
/// from every other failure.
enum ReplaceError {
    NameTaken,
    Other(CoreError),
}

fn random_suffix() -> Result<String, CoreError> {
    let mut nonce = [0u8; 6];
    getrandom::fill(&mut nonce)
        .map_err(|e| CoreError::Secret(format!("getrandom temp name: {e}")))?;
    Ok(hex::encode(nonce))
}

fn write_and_replace(tmp: &Path, target: &Path, bytes: &[u8]) -> Result<(), ReplaceError> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(tmp) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ReplaceError::NameTaken);
        }
        Err(e) => return Err(ReplaceError::Other(CoreError::Io(e))),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| ReplaceError::Other(CoreError::Io(e)))?;
    }
    file.write_all(bytes)
        .map_err(|e| ReplaceError::Other(CoreError::Io(e)))?;
    file.sync_all()
        .map_err(|e| ReplaceError::Other(CoreError::Io(e)))?;
    drop(file);

    replace_file(tmp, target).map_err(ReplaceError::Other)?;

    #[cfg(unix)]
    if let Some(dir) = target.parent()
        && let Ok(dir_file) = fs::File::open(dir)
    {
        // Directory sync is advisory: some filesystems/network mounts
        // reject it, which must not fail the write.
        let _ = dir_file.sync_all();
    }
    Ok(())
}

/// Move the synced temporary file over the target.
///
/// On Windows, replacing an existing file must preserve that file's
/// security descriptor (see [`crate::atomic`] module docs); a fresh
/// target has nothing to preserve and takes the plain rename.
fn replace_file(tmp: &Path, target: &Path) -> Result<(), CoreError> {
    #[cfg(windows)]
    if target.exists() {
        return replace_file_preserving_acl(tmp, target);
    }
    fs::rename(tmp, target).map_err(CoreError::Io)
}

/// Replace `target` with `tmp` via Win32 `ReplaceFile`, keeping the
/// target's security descriptor and other metadata.
///
/// The paths travel through environment variables to sidestep quoting,
/// and the fallback keeps writes working where `PowerShell` is
/// unavailable (locked-down hosts) — with the pre-fix behavior of
/// inheriting the directory ACL.
///
/// # Errors
///
/// Returns an error if both the `ReplaceFile` attempt and the
/// rename-over fallback fail.
#[cfg(windows)]
fn replace_file_preserving_acl(tmp: &Path, target: &Path) -> Result<(), CoreError> {
    use std::os::windows::process::CommandExt as _;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const SCRIPT: &str = "try { [System.IO.File]::Replace($env:KYZ_ATOMIC_FROM, $env:KYZ_ATOMIC_TO, [NullString]::Value); exit 0 } catch { $_ | Out-String | Write-Error; exit 1 }";

    let attempted = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env("KYZ_ATOMIC_FROM", tmp)
        .env("KYZ_ATOMIC_TO", target)
        .output();
    match attempted {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            log::warn!(
                "ReplaceFile via PowerShell failed for {} (exit {:?}); falling back to a rename-over that inherits the directory ACL: {}",
                target.display(),
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
            fs::rename(tmp, target).map_err(CoreError::Io)
        }
        Err(e) => {
            log::warn!(
                "PowerShell is unavailable for ReplaceFile ({e}); replacing {} with a rename-over that inherits the directory ACL",
                target.display()
            );
            fs::rename(tmp, target).map_err(CoreError::Io)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_existing_and_cleans_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("vault.json");
        write_atomic(&target, b"first").expect("write 1");
        assert_eq!(fs::read(&target).expect("read"), b"first");
        write_atomic(&target, b"second").expect("write 2");
        assert_eq!(fs::read(&target).expect("read"), b"second");

        // No leftover temporary files.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&target).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn failed_write_leaves_target_untouched_and_cleans_temp() {
        let dir = tempfile::tempdir().expect("tempdir");
        // An occupied target: renaming a file over a directory fails on
        // every supported platform, exercising the error path after the
        // write and fsync but before the target could be replaced.
        let target = dir.path().join("vault.json");
        fs::create_dir(&target).expect("occupied target");
        assert!(write_atomic(&target, b"replacement").is_err());
        assert!(target.is_dir());
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn replacing_a_file_preserves_its_explicit_dacl() {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("vault.json");
        write_atomic(&target, b"first").expect("initial write");

        // Simulate an administrator tightening the file: drop
        // inheritance and grant only the current user.
        let user = std::env::var("USERNAME").expect("USERNAME");
        let tighten = std::process::Command::new("icacls")
            .creation_flags(CREATE_NO_WINDOW)
            .arg(&target)
            .args(["/inheritance:r", "/grant:r", &format!("{user}:(F)")])
            .status()
            .expect("tighten ACL");
        assert!(tighten.success(), "test setup: icacls tighten failed");

        write_atomic(&target, b"second").expect("replace");
        assert_eq!(fs::read(&target).expect("read"), b"second");

        // Without preservation the replaced file re-inherits the
        // directory ACEs, visible as `(I)` markers in icacls output.
        let query = std::process::Command::new("icacls")
            .creation_flags(CREATE_NO_WINDOW)
            .arg(&target)
            .output()
            .expect("query ACL");
        assert!(query.status.success());
        let text = String::from_utf8_lossy(&query.stdout);
        assert!(
            !text.contains("(I)"),
            "explicit DACL was replaced by inherited ACEs: {text}"
        );
    }
}
