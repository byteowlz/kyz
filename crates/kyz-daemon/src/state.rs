//! Daemon state directory layout and secure file helpers.
//!
//! All daemon runtime state lives under `<state_dir>/daemon/`:
//!
//! | File           | Purpose                                        |
//! |----------------|------------------------------------------------|
//! | `daemon.lock`  | OS file lock; the single-instance authority    |
//! | `daemon.pid`   | PID metadata for status/diagnostics only       |
//! | `kyzd.sock`    | Unix management socket (0600)                  |
//! | `ipc.token`    | Management IPC auth token (0600)               |
//! | `proxy.token`  | HTTP proxy bearer token (0600)                 |
//! | `audit.log`    | Structured audit events (JSON Lines)           |
//! | `daemon.log`   | Run/diagnostic log                              |
//!
//! Unix: directory `0700`, files `0600`. Windows: the directory DACL is
//! tightened to the current user only (no inheritance from `Everyone`),
//! files inherit that restriction.

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use crate::DaemonError;
use crate::Result;

/// Subdirectory of the XDG state dir holding all daemon state.
pub const STATE_SUBDIR: &str = "daemon";

/// Unix management socket filename.
pub const SOCK_FILENAME: &str = "kyzd.sock";

/// PID metadata filename (diagnostics only, never authoritative).
pub const PID_FILENAME: &str = "daemon.pid";

/// Single-instance lock filename.
pub const LOCK_FILENAME: &str = "daemon.lock";

/// Structured audit log filename.
pub const AUDIT_LOG_FILENAME: &str = "audit.log";

/// Run log filename.
pub const DAEMON_LOG_FILENAME: &str = "daemon.log";

/// Management IPC auth token filename.
pub const IPC_TOKEN_FILENAME: &str = "ipc.token";

/// HTTP proxy bearer token filename.
pub const PROXY_TOKEN_FILENAME: &str = "proxy.token";

/// Resolved paths of every file the daemon owns.
#[derive(Debug, Clone)]
pub struct DaemonPaths {
    /// The `<state_dir>/daemon` directory itself.
    pub dir: PathBuf,
}

impl DaemonPaths {
    /// Derive the daemon state paths from the app state directory.
    #[must_use]
    pub fn new(app_state_dir: &Path) -> Self {
        Self {
            dir: app_state_dir.join(STATE_SUBDIR),
        }
    }

    /// Unix management socket path.
    #[cfg(unix)]
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.dir.join(SOCK_FILENAME)
    }

    /// Windows named pipe name (`\\.\pipe\kyzd-<user>-<state-dir-hash>`).
    ///
    /// The username is embedded so concurrent Windows sessions get distinct
    /// pipes; access control is enforced by the per-connection IPC token
    /// (named pipe default ACLs cannot be restricted without unsafe Win32
    /// calls, which this workspace forbids).
    #[cfg(windows)]
    #[must_use]
    pub fn pipe_name(&self) -> String {
        let user = std::env::var("USERNAME").unwrap_or_default();
        let safe: String = user
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        // The state-dir hash keeps concurrent daemons on distinct state
        // directories from colliding on `first_pipe_instance`.
        let hash = kyz_core::fnv1a_64(self.dir.to_string_lossy().as_bytes());
        format!(r"\\.\pipe\kyzd-{safe}-{hash:016x}")
    }

    /// PID metadata file path.
    #[must_use]
    pub fn pid_path(&self) -> PathBuf {
        self.dir.join(PID_FILENAME)
    }

    /// Single-instance lock file path.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILENAME)
    }

    /// Audit log path.
    #[must_use]
    pub fn audit_log_path(&self) -> PathBuf {
        self.dir.join(AUDIT_LOG_FILENAME)
    }

    /// Run log path.
    #[must_use]
    pub fn daemon_log_path(&self) -> PathBuf {
        self.dir.join(DAEMON_LOG_FILENAME)
    }

    /// Management IPC token path.
    #[must_use]
    pub fn ipc_token_path(&self) -> PathBuf {
        self.dir.join(IPC_TOKEN_FILENAME)
    }

    /// Proxy bearer token path.
    #[must_use]
    pub fn proxy_token_path(&self) -> PathBuf {
        self.dir.join(PROXY_TOKEN_FILENAME)
    }

    /// Create the state directory with restricted permissions.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or secured.
    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(windows)]
        {
            restrict_dir_acl_to_user(&self.dir)?;
        }
        Ok(())
    }
}

/// Remove a file if it exists; best-effort cleanup of stale runtime files.
/// Failures are non-fatal and surface again on the next bind attempt.
pub(crate) fn remove_if_exists(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Write a file with owner-only permissions (0600 on Unix).
///
/// # Errors
///
/// Returns an error if the write or permission fix fails.
pub fn write_secure_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// On Windows, drop inheritance and grant full control to the current user
/// only, so the daemon state directory carries no `Everyone` ACE.
///
/// Implemented via the built-in `icacls` tool: the workspace forbids unsafe
/// code, and no maintained safe-binding crate covers named pipe/DACL
/// mutation. Failure is fatal — a world-readable daemon state directory is
/// never acceptable.
#[cfg(windows)]
fn restrict_dir_acl_to_user(dir: &Path) -> Result<()> {
    let user = std::env::var("USERNAME").map_err(|e| {
        DaemonError::Internal(format!("cannot determine current user for ACL setup: {e}"))
    })?;
    if user.is_empty() {
        return Err(DaemonError::Internal(
            "cannot determine current user for ACL setup: USERNAME is empty".to_string(),
        ));
    }
    let grant = format!("{user}:(OI)(CI)F");
    let output = std::process::Command::new("icacls")
        .arg(dir)
        .args(["/inheritance:r", "/grant:r"])
        .arg(&grant)
        .output()
        .map_err(|e| DaemonError::Internal(format!("running icacls to secure state dir: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DaemonError::Internal(format!(
            "icacls failed to restrict state dir ACL (exit {:?}): {}",
            output.status.code(),
            stderr.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_nested_under_daemon_subdir() {
        let paths = DaemonPaths::new(Path::new("/tmp/kyz-state"));
        assert_eq!(paths.dir, Path::new("/tmp/kyz-state/daemon"));
        assert_eq!(
            paths.pid_path(),
            Path::new("/tmp/kyz-state/daemon/daemon.pid")
        );
        assert_eq!(
            paths.lock_path(),
            Path::new("/tmp/kyz-state/daemon/daemon.lock")
        );
        assert_eq!(
            paths.audit_log_path(),
            Path::new("/tmp/kyz-state/daemon/audit.log")
        );
    }

    #[test]
    fn ensure_creates_restrictive_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = DaemonPaths::new(tmp.path());
        paths.ensure().expect("ensure state dir");

        let meta = fs::metadata(&paths.dir).expect("stat state dir");
        assert!(meta.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "state dir must be 0700");
        }
    }

    #[cfg(windows)]
    #[test]
    fn ensure_state_dir_acl_excludes_everyone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = DaemonPaths::new(tmp.path());
        paths.ensure().expect("ensure state dir");

        let output = std::process::Command::new("icacls")
            .arg(&paths.dir)
            .output()
            .expect("icacls query");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            !text.to_lowercase().contains("everyone"),
            "state dir ACL must not contain Everyone: {text}"
        );
    }

    #[test]
    fn secure_file_roundtrip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("secret.txt");
        write_secure_file(&target, b"abc").expect("write");
        assert_eq!(fs::read(&target).expect("read"), b"abc");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&target).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "state files must be 0600");
        }
    }
}
