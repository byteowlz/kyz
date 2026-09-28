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
    // The daemon runs detached without a console, so a console app spawned
    // with default flags gets a brand-new (visible) console window; the
    // flag keeps icacls silent without changing its stdio.
    use std::os::windows::process::CommandExt as _;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let user = std::env::var("USERNAME").map_err(|e| {
        DaemonError::Internal(format!("cannot determine current user for ACL setup: {e}"))
    })?;
    if user.is_empty() {
        return Err(DaemonError::Internal(
            "cannot determine current user for ACL setup: USERNAME is empty".to_string(),
        ));
    }
    let grant = format!("{user}:(OI)(CI)F");
    // Reset first to discard *all* pre-existing explicit grants, including
    // grants to accounts other than the well-known groups below.
    for args in [
        vec!["/reset".to_string()],
        vec!["/inheritance:r".to_string(), "/grant:r".to_string(), grant],
        vec![
            "/remove:g".to_string(),
            "*S-1-1-0".to_string(),      // Everyone
            "*S-1-5-32-545".to_string(), // BUILTIN\\Users
            "*S-1-5-11".to_string(),     // Authenticated Users
        ],
    ] {
        let output = std::process::Command::new("icacls")
            .creation_flags(CREATE_NO_WINDOW)
            .arg(dir)
            .args(&args)
            .output()
            .map_err(|e| {
                DaemonError::Internal(format!("running icacls to secure state dir: {e}"))
            })?;
        if !output.status.success() {
            return Err(DaemonError::Internal(format!(
                "icacls failed to restrict state dir ACL (exit {:?}): {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
    }
    let acl = std::process::Command::new("icacls")
        .creation_flags(CREATE_NO_WINDOW)
        .arg(dir)
        .output()
        .map_err(|e| DaemonError::Internal(format!("verifying state dir ACL: {e}")))?;
    let text = String::from_utf8_lossy(&acl.stdout).to_ascii_lowercase();
    if !acl.status.success() || !state_dir_acl_is_user_only(&text, dir, &user) {
        return Err(DaemonError::Internal(
            "state dir ACL verification failed".to_string(),
        ));
    }
    Ok(())
}

/// Whether the (already lowercased) `icacls` output shows the directory's
/// DACL granted to the current user and nothing else.
///
/// The tightening sequence (`/reset`, `/inheritance:r`, `/grant:r`) ends
/// with exactly one explicit ACE for the current user, so verification
/// checks *that* invariant instead of substring-matching well-known
/// group names — an account named e.g. `appusers` must not trip the old
/// `users:` check, while any genuinely foreign trustee (including
/// `Everyone`/`BUILTIN\Users`/`Authenticated Users` by name or SID) is
/// rejected because it is not the current user.
#[cfg(windows)]
fn state_dir_acl_is_user_only(text: &str, dir: &Path, user: &str) -> bool {
    let trustees = icacls_trustees(text, dir);
    let user = user.to_ascii_lowercase();
    let machine_suffix = format!("\\{user}");
    !trustees.is_empty()
        && trustees
            .iter()
            .all(|trustee| trustee == &user || trustee.ends_with(&machine_suffix))
}

/// Extract the trustee names from `icacls <path>` output.
///
/// ACE lines look like `MACHINE\user:(OI)(CI)(F)`, possibly several ACEs
/// on one line after the echoed path, and trustee names may contain
/// spaces (`NT AUTHORITY\Authenticated Users`). Anything without a
/// `trustee:(` shape (summary lines such as "Successfully processed 1
/// files") yields nothing.
#[cfg(windows)]
fn icacls_trustees(lowercased_output: &str, path: &Path) -> Vec<String> {
    let path_prefix = path.to_string_lossy().to_ascii_lowercase();
    let mut trustees = Vec::new();
    for line in lowercased_output.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("successfully processed")
            || line.starts_with("failed processing")
        {
            continue;
        }
        let rest = line.strip_prefix(&path_prefix).map_or(line, |after| after);
        trustees.extend(parse_ace_trustees(rest));
    }
    trustees
}

/// Scan `trustee:(rights)(rights) …` sequences out of one ACE line.
#[cfg(windows)]
fn parse_ace_trustees(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        // The trustee runs to the first `:(` (drive-letter colons and
        // colons inside names are never followed by a rights group).
        let start = i;
        let mut colon = None;
        let mut j = i;
        while j + 1 < chars.len() {
            if chars[j] == ':' && chars[j + 1] == '(' {
                colon = Some(j);
                break;
            }
            j += 1;
        }
        let Some(colon) = colon else {
            break;
        };
        out.push(chars[start..colon].iter().collect());
        // Consume the consecutive parenthesized rights groups.
        i = colon + 1;
        while i < chars.len() && chars[i] == '(' {
            match chars[i..].iter().position(|&c| c == ')') {
                Some(close) => i += close + 1,
                None => i = chars.len(),
            }
        }
    }
    out
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
    fn ensure_removes_preexisting_explicit_group_grants() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = DaemonPaths::new(tmp.path());
        fs::create_dir(&paths.dir).expect("state dir");
        let granted = std::process::Command::new("icacls")
            .arg(&paths.dir)
            .args(["/grant", "*S-1-1-0:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)F"])
            .status()
            .expect("grant explicit foreign-user groups");
        assert!(granted.success());
        paths.ensure().expect("secure preexisting state dir");
        write_secure_file(&paths.ipc_token_path(), b"test-token").expect("token file");
        for path in [&paths.dir, &paths.ipc_token_path()] {
            let output = std::process::Command::new("icacls")
                .arg(path)
                .output()
                .expect("query ACL");
            let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
            assert!(output.status.success());
            assert!(
                !text.contains("everyone:") && !text.contains("users:"),
                "{text}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn acl_verification_accepts_account_names_ending_in_users() {
        // Regression: substring matching on `users:` rejected an ACE for
        // an account actually named `appusers` even though the DACL was
        // correctly tightened to that user alone.
        let dir = Path::new(r"C:\state\daemon");
        let output = "c:\\state\\daemon machine\\appusers:(oi)(ci)(f)\r\n\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n";
        assert!(state_dir_acl_is_user_only(output, dir, "appusers"));
        assert!(!state_dir_acl_is_user_only(output, dir, "otheruser"));
    }

    #[cfg(windows)]
    #[test]
    fn acl_verification_rejects_foreign_trustees_by_name_or_sid() {
        let dir = Path::new(r"C:\state\daemon");
        for output in [
            // Foreign group by name (inherited markers included).
            "c:\\state\\daemon machine\\appusers:(oi)(ci)(f) builtin\\users:(i)(m)\r\n",
            // Well-known SID form.
            "c:\\state\\daemon *s-1-1-0:(f)\r\n",
            // Spaced trustee name.
            "c:\\state\\daemon nt authority\\authenticated users:(i)(m)\r\n",
            // No ACE line at all.
            "Successfully processed 0 files; Failed processing 1 files\r\n",
        ] {
            assert!(
                !state_dir_acl_is_user_only(output, dir, "appusers"),
                "must reject: {output}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn ace_trustee_parser_handles_realistic_icacls_lines() {
        assert_eq!(
            parse_ace_trustees(r"machine\appusers:(oi)(ci)(f)"),
            vec![r"machine\appusers".to_string()]
        );
        assert_eq!(
            parse_ace_trustees(
                r"machine\user:(oi)(ci)(f) builtin\users:(i)(m) nt authority\authenticated users:(i)(m)"
            ),
            vec![
                r"machine\user".to_string(),
                r"builtin\users".to_string(),
                r"nt authority\authenticated users".to_string(),
            ]
        );
        // Rights lists containing commas stay inside their group.
        assert_eq!(
            parse_ace_trustees(r"machine\user:(d,wdac)"),
            vec![r"machine\user".to_string()]
        );
        // Non-ACE text yields nothing.
        assert!(parse_ace_trustees("Successfully processed 1 files").is_empty());
        assert!(parse_ace_trustees("").is_empty());
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
