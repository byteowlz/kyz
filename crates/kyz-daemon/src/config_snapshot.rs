//! Immutable configuration snapshots with atomic reload.
//!
//! A [`ConfigSnapshot`] is a fully validated `AppConfig` plus the SHA-256 of
//! the file bytes it was built from. The daemon publishes snapshots behind
//! an `Arc` swapped under a lock; request handlers read the current `Arc`
//! and never re-parse TOML per request.
//!
//! Reload semantics: a candidate is validated **completely** before it
//! replaces the active snapshot. On failure the active snapshot is
//! untouched and the validation error is returned to the caller — there is
//! never a half-loaded configuration.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use kyz_core::config::AppConfig;
use kyz_core::proxy_config::validate_app_config;

use crate::audit::AuditReason;
use crate::{DaemonError, Result};

/// A validated, immutable configuration snapshot.
#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    /// The validated configuration.
    pub config: AppConfig,
    /// Path of the file this snapshot was loaded from.
    pub file_path: PathBuf,
    /// Hex SHA-256 of the raw config file bytes.
    pub hash: String,
}

impl ConfigSnapshot {
    /// Read, parse, and validate the configuration at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Config`] when the file cannot be read, parsed,
    /// or fails semantic validation (all issues are included).
    pub fn load(path: &Path) -> Result<Self> {
        // Read once: the hash and the parsed config must describe the same
        // bytes even if the file is rewritten concurrently.
        let raw = fs::read(path)
            .map_err(|e| DaemonError::Config(format!("cannot read {}: {e}", path.display())))?;
        let config = AppConfig::load_from_bytes(&raw)
            .map_err(|e| DaemonError::Config(format!("cannot parse {}: {e}", path.display())))?;
        validate_app_config(&config)?;
        let hash = hex::encode(Sha256::digest(&raw));
        Ok(Self {
            config,
            file_path: path.to_path_buf(),
            hash,
        })
    }

    /// Compact description of the snapshot for `status` output.
    #[must_use]
    pub fn summary(&self) -> SnapshotSummary {
        SnapshotSummary {
            rules: self.config.proxy.rules.len(),
            credentials: self
                .config
                .proxy
                .rules
                .iter()
                .map(|r| r.credentials.len())
                .sum(),
            scripts: self.config.scripts.len(),
            listen: self.config.daemon.listen.clone(),
            timeout_secs: self.config.daemon.timeout_secs,
            hash: self.hash.clone(),
        }
    }
}

/// Non-sensitive snapshot summary returned over management IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSummary {
    /// Number of proxy routing rules.
    pub rules: usize,
    /// Total number of credential bindings across rules.
    pub credentials: usize,
    /// Number of pinned script grants.
    pub scripts: usize,
    /// Configured proxy listener, if any.
    pub listen: Option<String>,
    /// Configured daemon lifetime timeout.
    pub timeout_secs: u64,
    /// SHA-256 of the config file this snapshot was built from.
    pub hash: String,
}

/// Shared holder of the active snapshot.
#[derive(Debug, Default)]
pub struct SnapshotState {
    current: RwLock<Option<Arc<ConfigSnapshot>>>,
}

impl SnapshotState {
    /// Create an empty holder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically publish a snapshot.
    pub fn publish(&self, snapshot: ConfigSnapshot) -> Arc<ConfigSnapshot> {
        let arc = Arc::new(snapshot);
        if let Ok(mut current) = self.current.write() {
            *current = Some(Arc::clone(&arc));
        }
        arc
    }

    /// Read the active snapshot, if one has been published.
    ///
    /// # Errors
    ///
    /// Returns an error when no snapshot has been published yet.
    pub fn current(&self) -> Result<Arc<ConfigSnapshot>> {
        self.current
            .read()
            .ok()
            .and_then(|guard| guard.clone())
            .ok_or_else(|| DaemonError::Internal("no configuration snapshot published".to_string()))
    }

    /// Load and validate a candidate, then atomically replace the active
    /// snapshot on success.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Config`] (with every issue) when the candidate
    /// is invalid; the active snapshot is unchanged in that case.
    pub fn reload(&self, path: &Path) -> Result<Arc<ConfigSnapshot>> {
        let candidate = ConfigSnapshot::load(path)?;
        Ok(self.publish(candidate))
    }
}

/// Categorize a reload failure for the audit trail.
#[must_use]
pub const fn reload_failure_reason(error: &DaemonError) -> AuditReason {
    match error {
        DaemonError::Config(_) => AuditReason::ConfigRejected,
        _ => AuditReason::ConfigUnreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const VALID: &str = r"
[daemon]
timeout_secs = 0
";
    const INVALID: &str = r#"
[[proxy.rules]]
name = "bad"
host = "a.*.b"
upstream = "http://x"
"#;

    #[test]
    fn snapshot_loads_and_hashes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("config.toml");
        let mut file = fs::File::create(&path).expect("create");
        file.write_all(VALID.as_bytes()).expect("write");
        drop(file);

        let snapshot = ConfigSnapshot::load(&path).expect("valid config loads");
        assert_eq!(snapshot.hash.len(), 64);
        assert_eq!(snapshot.summary().rules, 0);
    }

    #[test]
    fn reload_rejects_invalid_and_keeps_active() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("config.toml");
        fs::write(&path, VALID).expect("write");

        let state = SnapshotState::new();
        let active = state.reload(&path).expect("initial load");
        let active_hash = active.hash.clone();

        fs::write(&path, INVALID).expect("write invalid");
        let err = state.reload(&path).expect_err("invalid config rejected");
        assert!(err.to_string().contains("configuration"), "got: {err}");

        // Active snapshot unchanged.
        assert_eq!(state.current().expect("still active").hash, active_hash);
    }

    #[test]
    fn publish_swaps_atomically() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("config.toml");
        fs::write(&path, VALID).expect("write");

        let state = SnapshotState::new();
        let first = state.reload(&path).expect("load");
        assert!(Arc::ptr_eq(&first, &state.current().expect("current")));

        // Same content -> new snapshot object replaces the Arc.
        let second = state.reload(&path).expect("reload");
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(&second, &state.current().expect("current")));
    }

    #[test]
    fn reload_failure_reason_maps_errors() {
        assert_eq!(
            reload_failure_reason(&DaemonError::Config("x".to_string())),
            AuditReason::ConfigRejected
        );
        assert_eq!(
            reload_failure_reason(&DaemonError::Io(std::io::Error::other("x"))),
            AuditReason::ConfigUnreadable
        );
    }
}
