#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::panic_in_result_fn,
        reason = "tests assert outcomes"
    )
)]
//! Trusted-service session-free vault tests, using isolated synthetic vaults.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use kyz_core::{CoreError, SecretEntry, UnlockedVault, VaultSession, VaultStore};
use secrecy::{ExposeSecret as _, SecretString};

const PASSWORD: &str = "session-free-fixture-passphrase-123456";

fn password() -> SecretString {
    SecretString::from(PASSWORD.to_owned())
}

fn fixture() -> (tempfile::TempDir, VaultStore, UnlockedVault) {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = VaultStore::new(temp.path().join("vault.json"));
    store.init(PASSWORD, false).expect("init");
    let vault = store.open_in_memory(&password()).expect("open");
    (temp, store, vault)
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).expect("directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).expect("relative").to_owned(),
                    std::fs::read(path).expect("read"),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn values(vault: &UnlockedVault) -> BTreeMap<String, String> {
    vault
        .get("app", "key")
        .expect("get")
        .fields
        .into_iter()
        .map(|(k, v)| (k, v.expose_secret().to_owned()))
        .collect()
}

fn entry(field: &str, value: &str) -> SecretEntry {
    SecretEntry::new(
        "app",
        "key",
        BTreeMap::from([(field.to_owned(), SecretString::from(value.to_owned()))]),
    )
}

fn assert_no_session(store: &VaultStore) {
    assert!(
        !VaultSession::session_file_for(store.vault_path())
            .expect("session path")
            .exists()
    );
    assert!(
        !store.status().expect("status").unlocked,
        "disk session remains locked"
    );
}

#[test]
fn preserve_first_open_refuses_legacy_without_modifying_bytes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("vault.json");
    let (v3, _) = kyz_core::vault_v3::VaultFileV3::create(&password()).expect("v3");
    let before = serde_json::to_vec(&v3).expect("serialize");
    std::fs::write(&path, &before).expect("write");
    let store = VaultStore::new(path.clone());
    assert!(matches!(
        store.open_in_memory(&password()),
        Err(CoreError::MigrationRequired { version: 3 })
    ));
    assert_eq!(std::fs::read(path).expect("read"), before);
    assert_eq!(std::fs::read_dir(temp.path()).expect("files").count(), 1);
    assert_no_session(&store);
}

#[test]
fn preserve_first_open_does_not_update_policy_or_remove_conflict_copy() {
    use kyz_core::vault_v5::{Manifest, VaultDir};
    let (temp, store, _) = fixture();
    let raw = std::fs::read(store.vault_path()).expect("manifest");
    let mut manifest = Manifest::parse(&raw).expect("parse");
    let (_, dk) = manifest.unwrap_dk(&password()).expect("DK");
    manifest.passphrase_policy_checked = false;
    VaultDir::new(store.vault_path())
        .write_manifest(&mut manifest, &dk)
        .expect("write fixture flag");
    std::fs::copy(
        store.vault_path(),
        temp.path().join("vault.sync-conflict-test.json"),
    )
    .expect("conflict fixture");
    let before = snapshot(temp.path());
    let vault = store.open_in_memory(&password()).expect("open");
    assert!(vault.list_services().expect("services").is_empty());
    assert_eq!(snapshot(temp.path()), before);
    assert_no_session(&store);
}

#[test]
fn legacy_headers_and_missing_vault_are_refused_without_writes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = VaultStore::new(temp.path().join("vault.json"));
    assert!(
        matches!(store.open_in_memory(&password()), Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound)
    );
    assert_eq!(std::fs::read_dir(temp.path()).expect("files").count(), 0);
    for version in [1, 2, 4] {
        // Header-only fixtures prove rejection occurs before legacy parsing or writes.
        std::fs::write(store.vault_path(), format!("{{\"version\":{version}}}")).expect("header");
        let before = snapshot(temp.path());
        assert!(
            matches!(store.open_in_memory(&password()), Err(CoreError::MigrationRequired { version: v }) if v == version)
        );
        assert_eq!(snapshot(temp.path()), before);
    }
}

#[test]
fn replacement_with_legacy_format_does_not_trigger_implicit_migration() {
    let (temp, store, vault) = fixture();
    let (mut legacy, dk) = kyz_core::vault_v3::VaultFileV3::create(&password()).expect("legacy");
    legacy
        .set_with_retention(&entry("token", "legacy-value"), &dk, 0)
        .expect("legacy put");
    std::fs::write(
        store.vault_path(),
        serde_json::to_vec(&legacy).expect("JSON"),
    )
    .expect("replace");
    let before = snapshot(temp.path());
    assert!(matches!(
        vault.get("app", "key"),
        Err(CoreError::MigrationRequired { version: 3 })
    ));
    assert!(matches!(
        vault.list("app"),
        Err(CoreError::MigrationRequired { version: 3 })
    ));
    assert!(matches!(
        vault.list_services(),
        Err(CoreError::MigrationRequired { version: 3 })
    ));
    assert!(matches!(
        vault.set("app", "key", &entry("token", "new-value")),
        Err(CoreError::MigrationRequired { version: 3 })
    ));
    assert!(matches!(
        vault.delete("app", "key"),
        Err(CoreError::MigrationRequired { version: 3 })
    ));
    assert_eq!(snapshot(temp.path()), before);
    assert_no_session(&store);
}

#[test]
fn exact_values_metadata_and_tombstone_lifecycle_without_session() {
    let (temp, store, vault) = fixture();
    let exact = " \tUnicode-雪\r\nwith\0nul\n ";
    vault
        .set("app", "key", &entry("token", exact))
        .expect("set");
    assert_eq!(
        values(&vault),
        BTreeMap::from([("token".to_owned(), exact.to_owned())])
    );
    vault
        .set("app", "key", &entry("other", "second"))
        .expect("overlay");
    let summaries = vault.list("app").expect("metadata");
    assert_eq!(
        serde_json::to_value(&summaries).expect("JSON"),
        serde_json::json!([{
            "service":"app", "key":"key", "field_names":["other","token"], "updated_at": vault.get("app", "key").expect("get").updated_at
        }])
    );
    assert_eq!(vault.list_services().expect("services"), vec!["app"]);
    let encoded = serde_json::to_string(&summaries).expect("metadata JSON");
    assert!(!encoded.contains("second"));
    assert_no_session(&store);
    let before = snapshot(temp.path());
    assert!(
        vault
            .resolve_fields("app", "key", &["token".to_owned(), "missing".to_owned()])
            .is_err()
    );
    assert!(vault.delete("app", "missing").is_err());
    assert_eq!(snapshot(temp.path()), before);
    vault.delete("app", "key").expect("delete");
    assert!(vault.get("app", "key").is_err());
    assert!(vault.list("app").expect("metadata").is_empty());
    let deleted = snapshot(temp.path());
    assert!(vault.set("app", "key", &entry("new", "fresh")).is_err());
    assert!(vault.delete("app", "key").is_err());
    assert_eq!(snapshot(temp.path()), deleted);
    vault
        .set_with_options("app", "key", &entry("new", "fresh"), true)
        .expect("recreate");
    assert_eq!(
        values(&vault),
        BTreeMap::from([("new".to_owned(), "fresh".to_owned())])
    );
    assert_no_session(&store);
    assert!(!format!("{vault:?}").contains(exact));
}

#[test]
fn concurrent_threads_preserve_all_overlaid_fields() {
    let (_temp, store, vault) = fixture();
    let vault = Arc::new(vault);
    let workers: Vec<_> = (0..8)
        .map(|n| {
            let vault = Arc::clone(&vault);
            std::thread::spawn(move || {
                vault
                    .set("app", "key", &entry(&format!("f{n}"), &format!("v{n}")))
                    .expect("set")
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("join");
    }
    assert_eq!(
        values(&vault),
        (0..8).map(|n| (format!("f{n}"), format!("v{n}"))).collect()
    );
    assert_no_session(&store);
}

#[test]
fn session_free_child_writer() {
    let Ok(path) = std::env::var("KYZ_SESSION_FREE_TEST_VAULT") else {
        return;
    };
    let field = std::env::var("KYZ_SESSION_FREE_TEST_FIELD").expect("field");
    let store = VaultStore::new(PathBuf::from(path));
    let vault = store.open_in_memory(&password()).expect("child open");
    vault
        .set("app", "key", &entry(&field, &field))
        .expect("child set");
    assert_no_session(&store);
}

#[test]
fn concurrent_processes_preserve_all_overlaid_fields() {
    let (_temp, store, vault) = fixture();
    let children: Vec<_> = (0..4)
        .map(|n| {
            Command::new(std::env::current_exe().expect("test binary"))
                .args(["--exact", "session_free_child_writer"])
                .env("KYZ_SESSION_FREE_TEST_VAULT", store.vault_path())
                .env("KYZ_SESSION_FREE_TEST_FIELD", format!("process{n}"))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn")
        })
        .collect();
    for mut child in children {
        assert!(child.wait().expect("wait").success());
    }
    assert_eq!(
        values(&vault),
        (0..4)
            .map(|n| (format!("process{n}"), format!("process{n}")))
            .collect()
    );
    assert_no_session(&store);
}

#[test]
fn wrong_password_and_replaced_vault_fail_without_writes() {
    let (temp, store, vault) = fixture();
    let before = snapshot(temp.path());
    let wrong = SecretString::from("synthetic-wrong-password".to_owned());
    let err = store.open_in_memory(&wrong).expect_err("wrong password");
    assert!(!err.to_string().contains(wrong.expose_secret()));
    assert_eq!(snapshot(temp.path()), before);
    let (_other_temp, other, _) = fixture();
    std::fs::copy(other.vault_path(), store.vault_path()).expect("replace manifest");
    let replaced = snapshot(temp.path());
    assert!(vault.get("app", "key").is_err());
    assert!(vault.list("app").is_err());
    assert!(vault.list_services().is_err());
    assert!(
        vault
            .set("app", "key", &entry("token", "synthetic-secret"))
            .is_err()
    );
    assert!(vault.delete("app", "key").is_err());
    assert_eq!(snapshot(temp.path()), replaced);
    assert_no_session(&store);
}
