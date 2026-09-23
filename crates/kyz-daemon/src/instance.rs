//! Single-instance enforcement via an OS file lock.
//!
//! The authority for "is a daemon running" is an exclusive lock on
//! `daemon.lock`, held for the lifetime of the owning process. The PID file
//! is metadata for `status` output and operator diagnostics only — it is
//! never used to decide whether the daemon exists, because a `kill -9`
//! leaves stale PID files behind.

use std::fs::{self, File, OpenOptions};
use std::path::Path;

use fs2::FileExt;

use crate::state::{DaemonPaths, write_secure_file};
use crate::{DaemonError, Result};

/// Guard holding the exclusive `daemon.lock`. Released on drop.
#[derive(Debug)]
pub struct InstanceGuard {
    lock_file: Option<File>,
}

impl InstanceGuard {
    /// Try to acquire the single-instance lock.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::AlreadyRunning`] when another process holds
    /// the lock, or an I/O error when the lock file cannot be opened.
    pub fn acquire(lock_path: &Path) -> Result<Self> {
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(lock_path)?;
        FileExt::try_lock_exclusive(&file).map_err(|_| {
            DaemonError::AlreadyRunning(format!("another daemon holds {}", lock_path.display()))
        })?;
        Ok(Self {
            lock_file: Some(file),
        })
    }

    /// Explicitly release the lock (dropping has the same effect).
    pub fn release(&mut self) {
        if let Some(file) = self.lock_file.take() {
            let _ = FileExt::unlock(&file);
        }
    }
}

/// Read the PID metadata file, if present and parseable.
#[must_use]
pub fn read_pid(pid_path: &Path) -> Option<u32> {
    fs::read_to_string(pid_path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// Write the current PID metadata file with owner-only permissions.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub fn write_pid(pid_path: &Path, pid: u32) -> Result<()> {
    write_secure_file(pid_path, pid.to_string().as_bytes())?;
    Ok(())
}

/// Remove stale runtime files left behind by a crash (`kill -9`).
///
/// Called right after the instance lock is acquired; overwriting the stale
/// PID happens on the subsequent `write_pid`.
pub fn clear_stale_files(paths: &DaemonPaths) {
    #[cfg(unix)]
    crate::state::remove_if_exists(&paths.socket_path());
    crate::state::remove_if_exists(&paths.pid_path());
    crate::state::remove_if_exists(&paths.ipc_token_path());
    crate::state::remove_if_exists(&paths.proxy_token_path());
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

    fn lock_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "kyzd-lock-test-{}-{}.lock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ))
    }

    #[test]
    fn second_acquire_fails_while_first_held() {
        let path = lock_path();
        let first = InstanceGuard::acquire(&path).expect("first acquire");
        let second = InstanceGuard::acquire(&path);
        assert!(
            second.is_err(),
            "second lock acquisition must fail while the first is held"
        );
        drop(first);

        let retry = InstanceGuard::acquire(&path).expect("acquire after release");
        drop(retry);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn stale_pid_is_overwritten_by_next_start() {
        let path = lock_path();
        let _guard = InstanceGuard::acquire(&path).expect("acquire");

        // Simulate a stale PID left by kill -9.
        write_pid(&path.with_extension("pid"), 41_112).expect("write stale pid");
        write_pid(&path.with_extension("pid"), 41_113).expect("overwrite pid");
        assert_eq!(read_pid(&path.with_extension("pid")), Some(41_113));
        let _ = fs::remove_file(path.with_extension("pid"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn lock_blocks_across_threads_until_released() {
        let path = lock_path();
        let mut guard = InstanceGuard::acquire(&path).expect("acquire");

        let contender = std::thread::spawn(move || {
            for _ in 0..20 {
                if InstanceGuard::acquire(&path).is_ok() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        });

        std::thread::sleep(Duration::from_millis(50));
        guard.release();
        assert!(
            contender.join().expect("contender thread"),
            "lock must become available after release"
        );
    }
}
