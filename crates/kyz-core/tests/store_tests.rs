//! Integration tests for the secret store layer.
//!
//! Tests cover `SecretEntry`, `VaultData`, `VaultFileV2`, encryption,
//! vault store CRUD, sessions, environments, and edge cases.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::SecretString;

use kyz_core::SecretStore;
use kyz_core::store::{
    SecretEntry, SecretSummary, VaultData, VaultFileV2, VaultSession, VaultStore, decrypt_entry,
    encrypt_entry, encrypt_vault, env_vault_path,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_vault_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "kyz-test-{label}-{}-{nanos}.json",
        std::process::id()
    ))
}

fn strong_passphrase() -> &'static str {
    "a-very-strong-passphrase-123"
}

fn setup_vault(label: &str) -> (VaultStore, PathBuf) {
    let vault_path = temp_vault_path(label);
    let store = VaultStore::new(vault_path.clone());
    store
        .init(strong_passphrase(), false)
        .expect("vault init should succeed");
    store
        .unlock(strong_passphrase(), 300)
        .expect("vault unlock should succeed");
    (store, vault_path)
}

fn cleanup(store: &VaultStore, vault_path: &PathBuf) {
    let _ = store.lock();
    let _ = std::fs::remove_file(vault_path);
}

// =========================================================================
// SecretEntry unit tests
// =========================================================================

#[test]
fn secret_entry_single_field() {
    let entry = SecretEntry::single("github", "token", "ghp_abc123");
    assert_eq!(entry.service, "github");
    assert_eq!(entry.key, "token");
    assert_eq!(entry.value(), Some("ghp_abc123"));
    assert!(entry.tags.is_empty());
    assert!(entry.created_at > 0);
    assert_eq!(entry.created_at, entry.updated_at);
}

#[test]
fn secret_entry_multi_field() {
    let mut fields = BTreeMap::new();
    fields.insert(
        "username".to_string(),
        SecretString::from("alice".to_string()),
    );
    fields.insert(
        "password".to_string(),
        SecretString::from("s3cr3t".to_string()),
    );
    fields.insert("url".to_string(), SecretString::from("pg://db".to_string()));

    let entry = SecretEntry::new("postgres", "prod-db", fields);
    assert_eq!(entry.field("username"), Some("alice"));
    assert_eq!(entry.field("password"), Some("s3cr3t"));
    assert_eq!(entry.field("url"), Some("pg://db"));
    assert_eq!(entry.field("nonexistent"), None);
}

#[test]
fn secret_entry_tags() {
    let mut entry = SecretEntry::single("svc", "key", "val");
    assert!(!entry.has_tag("prod"));

    entry.add_tag("prod");
    entry.add_tag("critical");
    assert!(entry.has_tag("prod"));
    assert!(entry.has_tag("critical"));

    entry.remove_tag("prod");
    assert!(!entry.has_tag("prod"));
    assert!(entry.has_tag("critical"));
}

#[test]
fn secret_entry_with_tags_builder() {
    let tags: BTreeSet<String> = ["deploy", "ci"].iter().map(|s| s.to_string()).collect();
    let entry = SecretEntry::single("svc", "key", "val").with_tags(tags.clone());
    assert_eq!(entry.tags, tags);
}

#[test]
fn secret_entry_set_field_updates_timestamp() {
    let mut entry = SecretEntry::single("svc", "key", "v1");
    let original_ts = entry.updated_at;
    // Sleep briefly to ensure timestamp advances
    std::thread::sleep(std::time::Duration::from_millis(10));
    entry.set_field("extra", "data");
    assert_eq!(entry.field("extra"), Some("data"));
    assert!(entry.updated_at >= original_ts);
}

#[test]
fn secret_entry_debug_redacts_fields() {
    let entry = SecretEntry::single("svc", "key", "super-secret-value");
    let debug_output = format!("{entry:?}");
    assert!(!debug_output.contains("super-secret-value"));
    assert!(debug_output.contains("[REDACTED]"));
}

#[test]
fn secret_summary_from_entry() {
    let mut entry = SecretEntry::single("github", "token", "ghp_abc");
    entry.add_tag("prod");
    let summary = SecretSummary::from(&entry);
    assert_eq!(summary.key, "token");
    assert_eq!(summary.service, "github");
    assert_eq!(summary.field_names, vec!["value"]);
    assert!(summary.tags.contains("prod"));
}

// =========================================================================
// VaultData tests
// =========================================================================

#[test]
fn vault_data_new_is_empty() {
    let data = VaultData::new();
    assert_eq!(data.version, 1);
    assert!(data.entries.is_empty());
}

#[test]
fn vault_data_compound_key() {
    assert_eq!(VaultData::compound_key("github", "token"), "github/token");
    assert_eq!(VaultData::compound_key("a", "b"), "a/b");
}

#[test]
fn vault_data_set_and_get() {
    let mut data = VaultData::new();
    let entry = SecretEntry::single("github", "token", "ghp_abc");
    data.set(entry);

    let fetched = data.get("github", "token").expect("entry should exist");
    assert_eq!(fetched.value(), Some("ghp_abc"));
}

#[test]
fn vault_data_set_merges_fields() {
    let mut data = VaultData::new();

    let entry1 = SecretEntry::single("svc", "creds", "v1");
    data.set(entry1);

    let mut fields2 = BTreeMap::new();
    fields2.insert("token".to_string(), SecretString::from("abc".to_string()));
    let entry2 = SecretEntry::new("svc", "creds", fields2);
    data.set(entry2);

    let merged = data.get("svc", "creds").expect("merged entry");
    assert_eq!(merged.value(), Some("v1"));
    assert_eq!(merged.field("token"), Some("abc"));
}

#[test]
fn vault_data_set_merges_tags() {
    let mut data = VaultData::new();

    let mut entry1 = SecretEntry::single("svc", "k", "v");
    entry1.add_tag("prod");
    data.set(entry1);

    let mut entry2 = SecretEntry::single("svc", "k", "v");
    entry2.add_tag("ci");
    data.set(entry2);

    let merged = data.get("svc", "k").expect("merged entry");
    assert!(merged.has_tag("prod"));
    assert!(merged.has_tag("ci"));
}

#[test]
fn vault_data_remove() {
    let mut data = VaultData::new();
    data.set(SecretEntry::single("svc", "key", "val"));
    assert!(data.remove("svc", "key"));
    assert!(!data.remove("svc", "key")); // already removed
    assert!(data.get("svc", "key").is_none());
}

#[test]
fn vault_data_list_service() {
    let mut data = VaultData::new();
    data.set(SecretEntry::single("github", "token1", "a"));
    data.set(SecretEntry::single("github", "token2", "b"));
    data.set(SecretEntry::single("aws", "key1", "c"));

    let github_entries = data.list_service("github");
    assert_eq!(github_entries.len(), 2);

    let aws_entries = data.list_service("aws");
    assert_eq!(aws_entries.len(), 1);

    let empty_entries = data.list_service("nonexistent");
    assert!(empty_entries.is_empty());
}

#[test]
fn vault_data_services() {
    let mut data = VaultData::new();
    data.set(SecretEntry::single("zebra", "k", "v"));
    data.set(SecretEntry::single("alpha", "k", "v"));
    data.set(SecretEntry::single("alpha", "k2", "v"));

    let services = data.services();
    assert_eq!(services, vec!["alpha", "zebra"]);
}

// =========================================================================
// VaultFileV2 tests
// =========================================================================

#[test]
fn vault_file_v2_new_is_empty() {
    let v2 = VaultFileV2::new();
    assert_eq!(v2.version, 2);
    assert!(!v2.passphrase_policy_checked);
    assert!(v2.entries.is_empty());
}

#[test]
fn vault_file_v2_set_and_decrypt() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());
    let entry = SecretEntry::single("svc", "key", "secret-value");

    v2.set(&entry, &passphrase).expect("set should succeed");

    let enc = v2.get_encrypted("svc", "key").expect("entry should exist");
    assert_eq!(enc.key, "key");
    assert_eq!(enc.service, "svc");
    assert!(enc.field_names.contains(&"value".to_string()));
    assert!(enc.history.is_empty());

    let decrypted = decrypt_entry(enc, &passphrase).expect("decrypt should succeed");
    assert_eq!(decrypted.value(), Some("secret-value"));
}

#[test]
fn vault_file_v2_update_creates_history() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());

    v2.set(&SecretEntry::single("svc", "key", "v1"), &passphrase)
        .expect("set v1");
    v2.set(&SecretEntry::single("svc", "key", "v2"), &passphrase)
        .expect("set v2");

    let enc = v2.get_encrypted("svc", "key").expect("entry");
    assert_eq!(enc.history.len(), 1);
    assert_eq!(enc.history[0].version, 1);

    let current = decrypt_entry(enc, &passphrase).expect("decrypt");
    assert_eq!(current.value(), Some("v2"));
}

#[test]
fn vault_file_v2_history_retention() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());

    for i in 0..10 {
        let entry = SecretEntry::single("svc", "key", &format!("v{i}"));
        v2.set_with_retention(&entry, &passphrase, 3)
            .expect("set should succeed");
    }

    let enc = v2.get_encrypted("svc", "key").expect("entry");
    assert_eq!(enc.history.len(), 3, "history should be trimmed to 3");
}

#[test]
fn vault_file_v2_rollback() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());

    v2.set(&SecretEntry::single("svc", "key", "v1"), &passphrase)
        .expect("v1");
    v2.set(&SecretEntry::single("svc", "key", "v2"), &passphrase)
        .expect("v2");
    v2.set(&SecretEntry::single("svc", "key", "v3"), &passphrase)
        .expect("v3");

    // Rollback to version 1
    v2.rollback("svc", "key", 1, &passphrase)
        .expect("rollback should succeed");

    let enc = v2.get_encrypted("svc", "key").expect("entry");
    let current = decrypt_entry(enc, &passphrase).expect("decrypt");
    assert_eq!(current.value(), Some("v1"));
    // History should have 3 entries (v3 archived by rollback, v2, v1)
    assert_eq!(enc.history.len(), 3);
}

#[test]
fn vault_file_v2_rollback_nonexistent_entry() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());

    let result = v2.rollback("svc", "missing", 1, &passphrase);
    assert!(result.is_err());
}

#[test]
fn vault_file_v2_rollback_nonexistent_version() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());

    v2.set(&SecretEntry::single("svc", "key", "v1"), &passphrase)
        .expect("v1");
    v2.set(&SecretEntry::single("svc", "key", "v2"), &passphrase)
        .expect("v2");

    let result = v2.rollback("svc", "key", 99, &passphrase);
    assert!(result.is_err());
}

#[test]
fn vault_file_v2_remove() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());

    v2.set(&SecretEntry::single("svc", "key", "val"), &passphrase)
        .expect("set");
    assert!(v2.remove("svc", "key"));
    assert!(!v2.remove("svc", "key")); // already removed
    assert!(v2.get_encrypted("svc", "key").is_none());
}

#[test]
fn vault_file_v2_summaries() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());

    v2.set(&SecretEntry::single("github", "token1", "a"), &passphrase)
        .expect("set");
    v2.set(&SecretEntry::single("github", "token2", "b"), &passphrase)
        .expect("set");
    v2.set(&SecretEntry::single("aws", "key1", "c"), &passphrase)
        .expect("set");

    let summaries = v2.summaries("github");
    assert_eq!(summaries.len(), 2);

    let services = v2.services();
    assert_eq!(services, vec!["aws", "github"]);
}

#[test]
fn vault_file_v2_tags_preserved() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());

    let mut entry = SecretEntry::single("svc", "key", "val");
    entry.add_tag("prod");
    entry.add_tag("critical");

    v2.set(&entry, &passphrase).expect("set");
    let enc = v2.get_encrypted("svc", "key").expect("entry");
    assert!(enc.tags.contains("prod"));
    assert!(enc.tags.contains("critical"));
}

// =========================================================================
// Encryption / decryption tests
// =========================================================================

#[test]
fn encrypt_decrypt_entry_roundtrip() {
    let passphrase = SecretString::from(strong_passphrase().to_string());
    let mut fields = BTreeMap::new();
    fields.insert("user".to_string(), SecretString::from("alice".to_string()));
    fields.insert(
        "pass".to_string(),
        SecretString::from("hunter2".to_string()),
    );
    let entry = SecretEntry::new("db", "prod", fields);

    let encrypted = encrypt_entry(&entry, &passphrase).expect("encrypt");
    let decrypted = decrypt_entry(&encrypted, &passphrase).expect("decrypt");

    assert_eq!(decrypted.service, "db");
    assert_eq!(decrypted.key, "prod");
    assert_eq!(decrypted.field("user"), Some("alice"));
    assert_eq!(decrypted.field("pass"), Some("hunter2"));
}

#[test]
fn decrypt_with_wrong_passphrase_fails() {
    let passphrase = SecretString::from(strong_passphrase().to_string());
    let entry = SecretEntry::single("svc", "key", "secret");
    let encrypted = encrypt_entry(&entry, &passphrase).expect("encrypt");

    let wrong = SecretString::from("wrong-passphrase-entirely".to_string());
    let result = decrypt_entry(&encrypted, &wrong);
    assert!(result.is_err());
}

#[test]
fn encrypt_vault_v1_roundtrip() {
    let passphrase = SecretString::from(strong_passphrase().to_string());
    let mut data = VaultData::new();
    data.set(SecretEntry::single("svc", "key", "val"));

    let encrypted = encrypt_vault(&data, &passphrase).expect("encrypt");
    let decrypted = kyz_core::store::decrypt_vault(&encrypted, &passphrase).expect("decrypt");

    assert_eq!(decrypted.version, 1);
    let entry = decrypted.get("svc", "key").expect("entry");
    assert_eq!(entry.value(), Some("val"));
}

#[test]
fn detect_vault_version_v2_json() {
    let v2 = VaultFileV2::new();
    let json = serde_json::to_vec(&v2).expect("serialize");
    assert_eq!(kyz_core::store::detect_vault_version(&json), 2);
}

#[test]
fn detect_vault_version_v1_binary() {
    // age-encrypted data starts with binary magic, not '{'
    let binary_data = b"\x00\x01\x02\x03not-json";
    assert_eq!(kyz_core::store::detect_vault_version(binary_data), 1);
}

// =========================================================================
// VaultStore CRUD integration tests
// =========================================================================

#[test]
fn vault_store_init_creates_file() {
    let vault_path = temp_vault_path("init");
    let store = VaultStore::new(vault_path.clone());
    store
        .init(strong_passphrase(), false)
        .expect("init should succeed");
    assert!(vault_path.exists());

    let _ = std::fs::remove_file(&vault_path);
}

#[test]
fn vault_store_init_rejects_weak_passphrase() {
    let vault_path = temp_vault_path("weak");
    let store = VaultStore::new(vault_path.clone());
    let result = store.init("abc", false);
    assert!(result.is_err());
    let _ = std::fs::remove_file(&vault_path);
}

#[test]
fn vault_store_init_no_overwrite_without_force() {
    let vault_path = temp_vault_path("no-overwrite");
    let store = VaultStore::new(vault_path.clone());
    store.init(strong_passphrase(), false).expect("first init");

    let result = store.init(strong_passphrase(), false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already exists"));

    let _ = std::fs::remove_file(&vault_path);
}

#[test]
fn vault_store_init_force_overwrites() {
    let vault_path = temp_vault_path("force-overwrite");
    let store = VaultStore::new(vault_path.clone());
    store.init(strong_passphrase(), false).expect("first init");

    // Add a secret
    store.unlock(strong_passphrase(), 60).expect("unlock");
    store
        .set("svc", "key", &SecretEntry::single("svc", "key", "val"))
        .expect("set");
    let _ = store.lock();

    // Force re-init should succeed and wipe data
    store.init(strong_passphrase(), true).expect("force init");
    store.unlock(strong_passphrase(), 60).expect("unlock");
    let result = store.get("svc", "key");
    assert!(result.is_err());

    cleanup(&store, &vault_path);
}

#[test]
fn vault_store_full_crud_lifecycle() {
    let (store, vault_path) = setup_vault("lifecycle");

    // Set
    let entry = SecretEntry::single("app", "api-key", "token-abc");
    store.set("app", "api-key", &entry).expect("set");

    // Get
    let fetched = store.get("app", "api-key").expect("get");
    assert_eq!(fetched.value(), Some("token-abc"));

    // List
    let summaries = store.list("app").expect("list");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].key, "api-key");

    // List services
    let services = store.list_services().expect("list services");
    assert!(services.contains(&"app".to_string()));

    // Update
    let updated = SecretEntry::single("app", "api-key", "token-xyz");
    store.set("app", "api-key", &updated).expect("update");
    let fetched = store.get("app", "api-key").expect("get after update");
    assert_eq!(fetched.value(), Some("token-xyz"));

    // Delete
    store.delete("app", "api-key").expect("delete");
    let result = store.get("app", "api-key");
    assert!(result.is_err());

    cleanup(&store, &vault_path);
}

#[test]
fn vault_store_multiple_services() {
    let (store, vault_path) = setup_vault("multi-svc");

    store
        .set(
            "github",
            "token",
            &SecretEntry::single("github", "token", "ghp_abc"),
        )
        .expect("set github");
    store
        .set("aws", "key", &SecretEntry::single("aws", "key", "AKIA123"))
        .expect("set aws");
    store
        .set(
            "aws",
            "secret",
            &SecretEntry::single("aws", "secret", "s3cr3t"),
        )
        .expect("set aws secret");

    let github = store.list("github").expect("list github");
    assert_eq!(github.len(), 1);

    let aws = store.list("aws").expect("list aws");
    assert_eq!(aws.len(), 2);

    let services = store.list_services().expect("services");
    assert_eq!(services.len(), 2);
    assert!(services.contains(&"github".to_string()));
    assert!(services.contains(&"aws".to_string()));

    cleanup(&store, &vault_path);
}

#[test]
fn vault_store_delete_nonexistent_fails() {
    let (store, vault_path) = setup_vault("del-missing");

    let result = store.delete("svc", "nonexistent");
    assert!(result.is_err());

    cleanup(&store, &vault_path);
}

#[test]
fn vault_store_get_nonexistent_fails() {
    let (store, vault_path) = setup_vault("get-missing");

    let result = store.get("svc", "nonexistent");
    assert!(result.is_err());

    cleanup(&store, &vault_path);
}

#[test]
fn vault_store_unlock_wrong_passphrase() {
    let vault_path = temp_vault_path("wrong-pass");
    let store = VaultStore::new(vault_path.clone());
    store.init(strong_passphrase(), false).expect("init");

    // First unlock with correct passphrase (marks policy checked)
    store.unlock(strong_passphrase(), 60).expect("first unlock");
    let _ = store.lock();

    // Add an entry so there's something to decrypt
    store.unlock(strong_passphrase(), 60).expect("unlock");
    store
        .set("svc", "key", &SecretEntry::single("svc", "key", "val"))
        .expect("set");
    let _ = store.lock();

    // Now try with wrong passphrase
    let result = store.unlock("wrong-passphrase-entirely", 60);
    assert!(result.is_err());

    let _ = std::fs::remove_file(&vault_path);
}

// =========================================================================
// VaultSession tests
// =========================================================================

#[test]
fn vault_session_expiry() {
    let passphrase = SecretString::from("test".to_string());
    let path = PathBuf::from("/tmp/fake-vault.json");

    let session = VaultSession::new(passphrase.clone(), &path, 3600);
    assert!(!session.is_expired());
    assert!(session.remaining_secs() > 3500);

    // Create an already-expired session
    let expired = VaultSession {
        passphrase,
        expires_at: 0,
        vault_path: path,
    };
    assert!(expired.is_expired());
    assert_eq!(expired.remaining_secs(), 0);
}

#[test]
fn vault_session_debug_redacts_passphrase() {
    let session = VaultSession::new(
        SecretString::from("super-secret".to_string()),
        &PathBuf::from("/tmp/vault.json"),
        3600,
    );
    let debug = format!("{session:?}");
    assert!(!debug.contains("super-secret"));
    assert!(debug.contains("[REDACTED]"));
}

#[test]
fn vault_session_dir_deterministic() {
    let dir1 = VaultSession::session_dir().expect("session dir");
    let dir2 = VaultSession::session_dir().expect("session dir");
    assert_eq!(dir1, dir2);
}

#[test]
fn vault_session_file_for_different_vaults() {
    let file1 =
        VaultSession::session_file_for(&PathBuf::from("/a/vault.json")).expect("session file");
    let file2 =
        VaultSession::session_file_for(&PathBuf::from("/b/vault.json")).expect("session file");
    assert_ne!(file1, file2);
}

// =========================================================================
// VaultStore status and lock tests
// =========================================================================

#[test]
fn vault_store_status_lifecycle() {
    let vault_path = temp_vault_path("status");
    let store = VaultStore::new(vault_path.clone());

    // Before init: should indicate no vault
    let status = store.status().expect("status");
    assert!(!status.exists);
    assert!(!status.unlocked);

    // After init but before unlock
    store.init(strong_passphrase(), false).expect("init");
    let status = store.status().expect("status");
    assert!(status.exists);
    assert!(!status.unlocked);

    // After unlock
    store.unlock(strong_passphrase(), 300).expect("unlock");
    let status = store.status().expect("status");
    assert!(status.exists);
    assert!(status.unlocked);
    assert!(status.expires_at.is_some());
    assert!(status.remaining_secs.is_some());

    // After lock
    let _ = store.lock();
    let status = store.status().expect("status");
    assert!(status.exists);
    assert!(!status.unlocked);

    let _ = std::fs::remove_file(&vault_path);
}

// =========================================================================
// Environment vault tests
// =========================================================================

#[test]
fn env_vault_path_contains_env_name() {
    let path = env_vault_path("staging").expect("env vault path");
    let path_str = path.to_string_lossy();
    assert!(path_str.contains("staging"));
    assert!(path_str.contains("vault.json"));
}

#[test]
fn env_vault_path_different_envs() {
    let staging = env_vault_path("staging").expect("staging");
    let prod = env_vault_path("production").expect("production");
    assert_ne!(staging, prod);
}

// =========================================================================
// VaultFileV2 serialization tests
// =========================================================================

#[test]
fn vault_file_v2_json_roundtrip() {
    let mut v2 = VaultFileV2::new();
    let passphrase = SecretString::from(strong_passphrase().to_string());

    let mut entry = SecretEntry::single("svc", "key", "secret");
    entry.add_tag("prod");
    v2.set(&entry, &passphrase).expect("set");

    let json = serde_json::to_string_pretty(&v2).expect("serialize");
    let parsed: VaultFileV2 = serde_json::from_str(&json).expect("parse");

    assert_eq!(parsed.version, 2);
    let enc = parsed.get_encrypted("svc", "key").expect("entry");
    assert!(enc.tags.contains("prod"));

    // Decrypt should still work
    let decrypted = decrypt_entry(enc, &passphrase).expect("decrypt");
    assert_eq!(decrypted.value(), Some("secret"));
}

#[test]
fn vault_file_v2_default_is_new() {
    let v2: VaultFileV2 = VaultFileV2::default();
    assert_eq!(v2.version, 2);
    assert!(v2.entries.is_empty());
}

// =========================================================================
// Edge cases
// =========================================================================

#[test]
fn secret_entry_empty_field_value() {
    let entry = SecretEntry::single("svc", "key", "");
    assert_eq!(entry.value(), Some(""));
}

#[test]
fn secret_entry_unicode_values() {
    let entry = SecretEntry::single("svc", "key", "パスワード🔐");
    assert_eq!(entry.value(), Some("パスワード🔐"));
}

#[test]
fn encrypt_decrypt_unicode_roundtrip() {
    let passphrase = SecretString::from(strong_passphrase().to_string());
    let entry = SecretEntry::single("svc", "key", "Ünîcödé Tëst 🦀");

    let encrypted = encrypt_entry(&entry, &passphrase).expect("encrypt");
    let decrypted = decrypt_entry(&encrypted, &passphrase).expect("decrypt");
    assert_eq!(decrypted.value(), Some("Ünîcödé Tëst 🦀"));
}

#[test]
fn encrypt_decrypt_large_value() {
    let passphrase = SecretString::from(strong_passphrase().to_string());
    let large_value = "x".repeat(100_000);
    let entry = SecretEntry::single("svc", "key", &large_value);

    let encrypted = encrypt_entry(&entry, &passphrase).expect("encrypt");
    let decrypted = decrypt_entry(&encrypted, &passphrase).expect("decrypt");
    assert_eq!(decrypted.value(), Some(large_value.as_str()));
}

#[test]
fn vault_store_concurrent_read_write() {
    let (store, vault_path) = setup_vault("concurrent");

    // Sequential writes shouldn't corrupt the vault
    for i in 0..10 {
        let entry = SecretEntry::single("svc", &format!("key-{i}"), &format!("val-{i}"));
        store.set("svc", &format!("key-{i}"), &entry).expect("set");
    }

    // Verify all entries
    for i in 0..10 {
        let fetched = store.get("svc", &format!("key-{i}")).expect("get");
        assert_eq!(fetched.value(), Some(format!("val-{i}").as_str()));
    }

    let summaries = store.list("svc").expect("list");
    assert_eq!(summaries.len(), 10);

    cleanup(&store, &vault_path);
}

#[test]
fn vault_store_multi_field_entry() {
    let (store, vault_path) = setup_vault("multi-field");

    let mut fields = BTreeMap::new();
    fields.insert(
        "host".to_string(),
        SecretString::from("db.prod".to_string()),
    );
    fields.insert("port".to_string(), SecretString::from("5432".to_string()));
    fields.insert(
        "password".to_string(),
        SecretString::from("s3cr3t".to_string()),
    );
    let entry = SecretEntry::new("postgres", "prod", fields);

    store.set("postgres", "prod", &entry).expect("set");

    let fetched = store.get("postgres", "prod").expect("get");
    assert_eq!(fetched.field("host"), Some("db.prod"));
    assert_eq!(fetched.field("port"), Some("5432"));
    assert_eq!(fetched.field("password"), Some("s3cr3t"));

    cleanup(&store, &vault_path);
}

// ---------------------------------------------------------------------------
// resolve_with_env: AGENT_CTX_WORKSPACE_PATH defaulting
// ---------------------------------------------------------------------------

#[test]
fn resolve_with_env_uses_workspace_hint_when_vault_present() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let kyz_dir = workspace.path().join(".kyz");
    std::fs::create_dir_all(&kyz_dir).expect("create .kyz");
    let vault_file = kyz_dir.join("vault.json");
    std::fs::write(&vault_file, "{}").expect("seed vault file");

    let store = VaultStore::resolve_with_env(None, None, Some(workspace.path()))
        .expect("resolve_with_env should succeed");
    assert_eq!(store.vault_path(), vault_file);
}

#[test]
fn resolve_with_env_explicit_vault_wins_over_workspace_hint() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    std::fs::create_dir_all(workspace.path().join(".kyz")).expect("create .kyz");
    std::fs::write(workspace.path().join(".kyz/vault.json"), "{}").expect("seed vault");

    let explicit = temp_vault_path("explicit-wins");
    let store = VaultStore::resolve_with_env(Some(&explicit), None, Some(workspace.path()))
        .expect("resolve");
    assert_eq!(store.vault_path(), explicit);
}

#[test]
fn resolve_with_env_ignores_hint_without_workspace_vault() {
    // Hint points at a directory with no .kyz/vault.json; resolution must fall
    // through to cwd/central rather than fabricating a path under the hint.
    let empty = tempfile::tempdir().expect("empty tempdir");
    let store = VaultStore::resolve_with_env(None, None, Some(empty.path())).expect("resolve");
    assert_ne!(
        store.vault_path(),
        empty.path().join(".kyz/vault.json"),
        "hint without an existing vault must not be returned as the resolved path",
    );
}
