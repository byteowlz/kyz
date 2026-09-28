//! Secret scanning: detect leaked vault values in project files.
//!
//! Scans files for actual decrypted secret values from the vault. Matches
//! against real values (not regex patterns) for zero false positives.
//! Never includes secret values in output—only the secret name and location.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use secrecy::ExposeSecret as _;

use crate::error::CoreError;
use crate::store::SecretEntry;
use crate::vault_v3::{DK_LEN, VaultFileV3, decrypt_entry_v3};
use crate::vault_v4::VaultFileV4;

/// A match found during scanning.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanMatch {
    /// Path to the file containing the leak.
    pub file: PathBuf,
    /// 1-based line number where the match was found.
    pub line: usize,
    /// The secret name (service/key:field) that was found.
    pub secret_name: String,
}

/// Result of a scan operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResult {
    /// Files that were scanned.
    pub files_scanned: usize,
    /// Matches found.
    pub matches: Vec<ScanMatch>,
}

/// Options for scanning.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Only scan staged files (for pre-commit hook use).
    pub staged_only: bool,
    /// Scan a specific directory instead of cwd.
    pub path: Option<PathBuf>,
}

/// Index one entry's field values under `service/key:field` display
/// names, skipping very short values (too many false positives).
fn index_entry_fields(entry: &SecretEntry, index: &mut BTreeMap<String, String>) {
    for (field_name, field_value) in &entry.fields {
        let value = field_value.expose_secret();
        if value.len() < 4 {
            continue;
        }
        let display_name = format!("{}/{}:{}", entry.service, entry.key, field_name);
        index.insert(value.to_string(), display_name);
    }
}

/// Build a map of secret values → display names for scanning.
///
/// # Errors
///
/// Returns an error if decryption fails.
pub fn build_secret_index(
    vault: &VaultFileV3,
    dk: &[u8; DK_LEN],
) -> Result<BTreeMap<String, String>, CoreError> {
    let mut index: BTreeMap<String, String> = BTreeMap::new();

    for encrypted in vault.entries.values() {
        let entry: SecretEntry = decrypt_entry_v3(encrypted, dk)?;
        index_entry_fields(&entry, &mut index);
    }

    Ok(index)
}

/// Build the scan index from a v4 vault: every visible entry's winning
/// snapshot (conflict losers and pruned snapshots are not live values).
///
/// Hidden entries (delete-wins tombstones) are skipped — they hold no
/// live values — but every other failure is loud: a scan that silently
/// skipped an entry whose current snapshot failed to decrypt would
/// under-report leaks with exit code 0.
///
/// # Errors
///
/// Returns an error if the vault fails verification, projection, or the
/// winning snapshot of any visible entry fails to decrypt.
pub fn build_secret_index_v4(
    vault: &VaultFileV4,
    dk: &[u8; DK_LEN],
) -> Result<BTreeMap<String, String>, CoreError> {
    vault.verify_mac(dk)?;
    let mut index: BTreeMap<String, String> = BTreeMap::new();
    for ck in vault.entries.keys() {
        let Some((service, key)) = VaultFileV4::split_compound_key(ck) else {
            continue;
        };
        // One causal walk per entry: `decrypt_current` reports hidden
        // (delete-wins) entries as SecretNotFound, which is the skip
        // condition; every other failure stays loud.
        match vault.decrypt_current(dk, &service, &key) {
            Ok(snapshot) => index_entry_fields(&snapshot.to_entry(), &mut index),
            Err(CoreError::SecretNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(index)
}

/// Get the list of files to scan.
///
/// # Errors
///
/// Returns an error if git commands fail.
pub fn get_files_to_scan(opts: &ScanOptions) -> Result<Vec<PathBuf>, CoreError> {
    let work_dir = opts
        .path
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| CoreError::Path("cannot determine working directory".to_string()))?;

    let mut cmd = Command::new("git");
    if opts.staged_only {
        cmd.args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"]);
    } else {
        cmd.args(["ls-files"]);
    }
    cmd.current_dir(&work_dir);

    let output = cmd
        .output()
        .map_err(|e| CoreError::Path(format!("failed to run git: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::Path(format!("git failed: {stderr}")));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<PathBuf> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| work_dir.join(l))
        .filter(|p| p.is_file())
        .collect();

    Ok(files)
}

/// Scan files for leaked secret values.
///
/// # Errors
///
/// Returns an error if files cannot be read.
pub fn scan_files(
    files: &[PathBuf],
    secret_index: &BTreeMap<String, String>,
    base_dir: &Path,
) -> Result<ScanResult, CoreError> {
    let mut matches = Vec::new();

    // Sort secrets by length descending (match longer values first)
    let mut secrets: Vec<(&str, &str)> = secret_index
        .iter()
        .map(|(v, n)| (v.as_str(), n.as_str()))
        .collect();
    secrets.sort_by_key(|&(v, _)| std::cmp::Reverse(v.len()));

    for file_path in files {
        // Skip binary files (heuristic: check for null bytes in first 8KB)
        let content = match std::fs::read(file_path) {
            Ok(bytes) => {
                let check_len = bytes.len().min(8192);
                if bytes[..check_len].contains(&0) {
                    continue; // likely binary
                }
                match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => continue, // not valid UTF-8
                }
            }
            Err(_) => continue, // skip unreadable files
        };

        let display_path = file_path
            .strip_prefix(base_dir)
            .unwrap_or(file_path)
            .to_path_buf();

        for (line_num, line) in content.lines().enumerate() {
            for &(secret_value, secret_name) in &secrets {
                if line.contains(secret_value) {
                    matches.push(ScanMatch {
                        file: display_path.clone(),
                        line: line_num + 1,
                        secret_name: secret_name.to_string(),
                    });
                    // Only report the first secret match per line to avoid noise
                    break;
                }
            }
        }
    }

    Ok(ScanResult {
        files_scanned: files.len(),
        matches,
    })
}
