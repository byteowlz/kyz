//! Trust-on-first-use registry for workspace vaults.
//!
//! Workspace vaults (`<dir>/.kyz/vault.json`) are repository-supplied files.
//! To stop a hostile repository from silently substituting secret values, the
//! first unlock of a workspace vault must be explicitly trusted; the registry
//! pins the file fingerprint so later content changes require
//! re-confirmation (the `direnv allow` equivalent for kyz).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::error::{CoreError, Result};
use crate::paths::AppPaths;

const REGISTRY_FILE: &str = "trusted-workspace-vaults.json";

/// Minimum characters required in a fingerprint before it is accepted.
const FINGERPRINT_LEN: usize = 64;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TrustedEntry {
    fingerprint: String,
    trusted_at: u64,
}

/// True when `vault_path` follows the workspace-vault convention
/// (`<dir>/.kyz/vault.json`), i.e. the file is repository-supplied.
#[must_use]
pub fn is_workspace_vault_path(vault_path: &Path) -> bool {
    vault_path.file_name().is_some_and(|f| f == "vault.json")
        && vault_path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|d| d == ".kyz")
}

/// SHA-256 hex fingerprint of the vault file bytes.
///
/// # Errors
///
/// Returns an error when the file cannot be read.
pub fn fingerprint(vault_path: &Path) -> Result<String> {
    let bytes = std::fs::read(vault_path)?;
    Ok(hex(&Sha256::digest(&bytes)))
}

/// Check whether the current content of `vault_path` is trusted in the
/// registry under `registry_path`.
#[must_use]
pub fn is_trusted_at(registry_path: &Path, vault_path: &Path) -> bool {
    let Ok(fp) = fingerprint(vault_path) else {
        return false;
    };
    load(registry_path)
        .get(&vault_path.to_string_lossy().to_string())
        .is_some_and(|e| e.fingerprint == fp)
}

/// Record trust for the current content of `vault_path` in the registry
/// under `registry_path`.
///
/// # Errors
///
/// Returns an error when hashing or writing the registry fails.
pub fn record_trust_at(registry_path: &Path, vault_path: &Path) -> Result<()> {
    if !is_workspace_vault_path(vault_path) {
        return Err(CoreError::Path(format!(
            "{} is not a workspace vault path (<dir>/.kyz/vault.json)",
            vault_path.display()
        )));
    }
    let fp = fingerprint(vault_path)?;
    if fp.len() != FINGERPRINT_LEN {
        return Err(CoreError::Path(
            "computed vault fingerprint has unexpected length".to_string(),
        ));
    }
    let mut registry = load(registry_path);
    registry.insert(
        vault_path.to_string_lossy().to_string(),
        TrustedEntry {
            fingerprint: fp,
            trusted_at: now_unix(),
        },
    );
    let data = serde_json::to_string_pretty(&registry)
        .map_err(|e| CoreError::Serialization(format!("serializing trust registry: {e}")))?;
    if let Some(parent) = registry_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(registry_path, data)?;
    Ok(())
}

/// Registry path for the given app paths.
#[must_use]
pub fn registry_path(paths: &AppPaths) -> PathBuf {
    paths.state_dir.join(REGISTRY_FILE)
}

/// Check trust using the default registry location.
#[must_use]
pub fn is_trusted(paths: &AppPaths, vault_path: &Path) -> bool {
    is_trusted_at(&registry_path(paths), vault_path)
}

/// Record trust using the default registry location.
///
/// # Errors
///
/// See [`record_trust_at`].
pub fn record_trust(paths: &AppPaths, vault_path: &Path) -> Result<()> {
    record_trust_at(&registry_path(paths), vault_path)
}

fn load(registry_path: &Path) -> BTreeMap<String, TrustedEntry> {
    std::fs::read_to_string(registry_path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_path_detection() {
        assert!(is_workspace_vault_path(Path::new("/repo/.kyz/vault.json")));
        assert!(is_workspace_vault_path(Path::new(".kyz/vault.json")));
        assert!(!is_workspace_vault_path(Path::new(
            "/home/u/.local/share/kyz/vault.json"
        )));
        assert!(!is_workspace_vault_path(Path::new("/repo/.kyz/other.json")));
        assert!(!is_workspace_vault_path(Path::new("/repo/vault.json")));
    }

    #[test]
    fn trust_round_trip_and_change_detection() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let registry = tmp.path().join("reg.json");
        let kyz_dir = tmp.path().join(".kyz");
        std::fs::create_dir_all(&kyz_dir).expect("mkdir");
        let vault = kyz_dir.join("vault.json");
        std::fs::write(&vault, b"version3-bytes").expect("write vault");

        assert!(!is_trusted_at(&registry, &vault));
        record_trust_at(&registry, &vault).expect("record");
        assert!(is_trusted_at(&registry, &vault));

        // Content change invalidates trust.
        std::fs::write(&vault, b"tampered").expect("rewrite vault");
        assert!(!is_trusted_at(&registry, &vault));

        // Non-workspace paths are refused.
        let other = tmp.path().join("vault.json");
        std::fs::write(&other, b"x").expect("write");
        assert!(record_trust_at(&registry, &other).is_err());
    }
}
