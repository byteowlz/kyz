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
use crate::store::{SecretEntry, VaultFileV2, decrypt_entry};

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

/// Build a map of secret values → display names for scanning.
///
/// # Errors
///
/// Returns an error if decryption fails.
pub fn build_secret_index(
    vault: &VaultFileV2,
    passphrase: &secrecy::SecretString,
) -> Result<BTreeMap<String, String>, CoreError> {
    let mut index: BTreeMap<String, String> = BTreeMap::new();

    for encrypted in vault.entries.values() {
        let entry: SecretEntry = decrypt_entry(encrypted, passphrase)?;
        for (field_name, field_value) in &entry.fields {
            let value = field_value.expose_secret();
            // Skip very short values (too many false positives)
            if value.len() < 4 {
                continue;
            }
            let display_name = format!("{}/{}:{}", entry.service, entry.key, field_name);
            index.insert(value.to_string(), display_name);
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
