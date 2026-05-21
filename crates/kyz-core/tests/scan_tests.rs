//! Integration tests for secret scanning.

use std::collections::BTreeMap;
use std::io::Write as _;

use secrecy::SecretString;

use kyz_core::store::SecretEntry;
use kyz_core::vault_v3::VaultFileV3;

#[test]
fn build_secret_index_creates_entries() {
    let passphrase = SecretString::from("a-very-strong-passphrase-123".to_string());
    let (mut v3, dk) = VaultFileV3::create(&passphrase).expect("create");

    let entry = SecretEntry::single("github", "token", "ghp_abcdef123456");
    v3.set(&entry, &*dk).expect("set");

    let index = kyz_core::scan::build_secret_index(&v3, &*dk).expect("build index");
    assert!(index.contains_key("ghp_abcdef123456"));
    assert_eq!(index["ghp_abcdef123456"], "github/token:value");
}

#[test]
fn build_secret_index_skips_short_values() {
    let passphrase = SecretString::from("a-very-strong-passphrase-123".to_string());
    let (mut v3, dk) = VaultFileV3::create(&passphrase).expect("create");

    // Short values (<4 chars) should be excluded to avoid false positives
    let entry = SecretEntry::single("svc", "key", "ab");
    v3.set(&entry, &*dk).expect("set");

    let index = kyz_core::scan::build_secret_index(&v3, &*dk).expect("build index");
    assert!(index.is_empty(), "short values should be excluded");
}

#[test]
fn build_secret_index_multi_field() {
    let passphrase = SecretString::from("a-very-strong-passphrase-123".to_string());
    let (mut v3, dk) = VaultFileV3::create(&passphrase).expect("create");

    let mut fields = BTreeMap::new();
    fields.insert(
        "username".to_string(),
        SecretString::from("admin-user".to_string()),
    );
    fields.insert(
        "password".to_string(),
        SecretString::from("super-secret-pass".to_string()),
    );
    let entry = SecretEntry::new("db", "prod", fields);
    v3.set(&entry, &*dk).expect("set");

    let index = kyz_core::scan::build_secret_index(&v3, &*dk).expect("build index");
    assert!(index.contains_key("admin-user"));
    assert!(index.contains_key("super-secret-pass"));
}

#[test]
fn scan_files_finds_leaked_secrets() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Create a file with a "leaked" secret
    let file_path = dir.path().join("config.env");
    let mut f = std::fs::File::create(&file_path).expect("create");
    writeln!(f, "DB_HOST=localhost").expect("write");
    writeln!(f, "DB_PASSWORD=super-secret-pass-123").expect("write");
    writeln!(f, "DEBUG=true").expect("write");

    let files = vec![file_path];
    let mut index = BTreeMap::new();
    index.insert(
        "super-secret-pass-123".to_string(),
        "db/prod:password".to_string(),
    );

    let result = kyz_core::scan::scan_files(&files, &index, dir.path()).expect("scan");
    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].line, 2);
    assert_eq!(result.matches[0].secret_name, "db/prod:password");
}

#[test]
fn scan_files_no_false_positives() {
    let dir = tempfile::tempdir().expect("tempdir");

    let file_path = dir.path().join("clean.txt");
    let mut f = std::fs::File::create(&file_path).expect("create");
    writeln!(f, "This file has no secrets").expect("write");
    writeln!(f, "Just normal content").expect("write");

    let files = vec![file_path];
    let mut index = BTreeMap::new();
    index.insert("my-secret-value".to_string(), "svc/key:value".to_string());

    let result = kyz_core::scan::scan_files(&files, &index, dir.path()).expect("scan");
    assert_eq!(result.files_scanned, 1);
    assert!(result.matches.is_empty());
}

#[test]
fn scan_files_skips_binary() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Create a binary file with null bytes
    let file_path = dir.path().join("binary.dat");
    let mut data = vec![0u8; 100];
    data.extend_from_slice(b"my-secret-value");
    std::fs::write(&file_path, &data).expect("write");

    let files = vec![file_path];
    let mut index = BTreeMap::new();
    index.insert("my-secret-value".to_string(), "svc/key:value".to_string());

    let result = kyz_core::scan::scan_files(&files, &index, dir.path()).expect("scan");
    // Binary files should be skipped
    assert!(result.matches.is_empty());
}

#[test]
fn scan_files_multiple_matches() {
    let dir = tempfile::tempdir().expect("tempdir");

    let file1 = dir.path().join("file1.txt");
    let mut f = std::fs::File::create(&file1).expect("create");
    writeln!(f, "token = ghp_leaked_token_abc").expect("write");

    let file2 = dir.path().join("file2.txt");
    let mut f = std::fs::File::create(&file2).expect("create");
    writeln!(f, "safe line").expect("write");
    writeln!(f, "also has ghp_leaked_token_abc in it").expect("write");

    let files = vec![file1, file2];
    let mut index = BTreeMap::new();
    index.insert(
        "ghp_leaked_token_abc".to_string(),
        "github/token:value".to_string(),
    );

    let result = kyz_core::scan::scan_files(&files, &index, dir.path()).expect("scan");
    assert_eq!(result.files_scanned, 2);
    assert_eq!(result.matches.len(), 2);
}

#[test]
fn scan_options_defaults() {
    let opts = kyz_core::scan::ScanOptions::default();
    assert!(!opts.staged_only);
    assert!(opts.path.is_none());
}
