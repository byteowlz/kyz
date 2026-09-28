#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::panic_in_result_fn,
        reason = "tests assert outcomes: expect/unwrap/panic are the failure mechanism"
    )
)]
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
    v3.set(&entry, &dk).expect("set");

    let index = kyz_core::scan::build_secret_index(&v3, &dk).expect("build index");
    assert!(index.contains_key("ghp_abcdef123456"));
    assert_eq!(index["ghp_abcdef123456"], "github/token:value");
}

#[test]
fn build_secret_index_skips_short_values() {
    let passphrase = SecretString::from("a-very-strong-passphrase-123".to_string());
    let (mut v3, dk) = VaultFileV3::create(&passphrase).expect("create");

    // Short values (<4 chars) should be excluded to avoid false positives
    let entry = SecretEntry::single("svc", "key", "ab");
    v3.set(&entry, &dk).expect("set");

    let index = kyz_core::scan::build_secret_index(&v3, &dk).expect("build index");
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
    v3.set(&entry, &dk).expect("set");

    let index = kyz_core::scan::build_secret_index(&v3, &dk).expect("build index");
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

    let paths = vec![file1, file2];
    let mut index = BTreeMap::new();
    index.insert(
        "ghp_leaked_token_abc".to_string(),
        "github/token:value".to_string(),
    );

    let result = kyz_core::scan::scan_files(&paths, &index, dir.path()).expect("scan");
    assert_eq!(result.files_scanned, 2);
    assert_eq!(result.matches.len(), 2);
}

#[test]
fn scan_options_defaults() {
    let opts = kyz_core::scan::ScanOptions::default();
    assert!(!opts.staged_only);
    assert!(opts.path.is_none());
}

#[test]
fn build_secret_index_v4_is_loud_on_undecryptable_winner() {
    use std::collections::BTreeSet;

    use kyz_core::{Hlc, OpId, SnapshotPlain, VaultFileV4};

    let passphrase = SecretString::from("a-very-strong-passphrase-123".to_string());
    let (mut vault, dk) = VaultFileV4::create(&passphrase).expect("create");

    let snap = |service: &str, key: &str, value: &str| SnapshotPlain {
        service: service.to_string(),
        key: key.to_string(),
        fields: BTreeMap::from([("value".to_string(), value.to_string())]),
        tags: BTreeSet::new(),
        created_at: 1,
        updated_at: 1,
    };
    let actor = "0123456789abcdef0123456789abcdef";
    let mut counter = 0u64;
    let mut next_id = || {
        counter += 1;
        OpId::new(actor, counter).expect("op id")
    };

    // A healthy visible entry.
    vault
        .append_put(
            &snap("svc", "ok", "good-value-1234"),
            next_id(),
            vec![],
            Hlc::zero(),
            &dk,
        )
        .expect("put");
    // A tombstoned entry: hidden, no live values — must be skipped.
    let gone = next_id();
    vault
        .append_put(
            &snap("svc", "gone", "deleted-value-99"),
            gone.clone(),
            vec![],
            Hlc::zero(),
            &dk,
        )
        .expect("put");
    vault.append_delete("svc", "gone", next_id(), vec![gone], Hlc::zero());
    // A visible entry whose winner has no ciphertext (pruned-winner shape).
    vault
        .append_put(
            &snap("svc", "broken", "lost-value-777"),
            next_id(),
            vec![],
            Hlc::zero(),
            &dk,
        )
        .expect("put");
    vault.entries.get_mut("svc/broken").expect("entry")[0].blob = None;
    vault.finalize(&dk).expect("finalize");

    // Control: without the broken entry the index builds, and the
    // tombstoned value is absent from it.
    let mut healthy = vault.clone();
    healthy.entries.remove("svc/broken");
    healthy.finalize(&dk).expect("finalize");
    let index = kyz_core::scan::build_secret_index_v4(&healthy, &dk).expect("index");
    assert!(index.contains_key("good-value-1234"));
    assert!(!index.contains_key("deleted-value-99"));

    // The broken winner must fail the whole scan — silently skipping it
    // would under-report leaks with exit code 0.
    let err = kyz_core::scan::build_secret_index_v4(&vault, &dk).expect_err("must fail loudly");
    assert!(
        format!("{err}").contains("ciphertext"),
        "unexpected error: {err}"
    );
}
