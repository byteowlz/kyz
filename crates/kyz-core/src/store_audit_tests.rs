//! Deterministic synthetic filesystem interleavings for credential API audits.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "synthetic regression assertions"
)]

use super::*;
use std::cell::RefCell;

type Hook = Box<dyn FnOnce()>;
thread_local! {
    static AFTER_ENTRY_COMMIT: RefCell<Option<Hook>> = const { RefCell::new(None) };
    static AFTER_LIST_LOAD: RefCell<Option<Hook>> = const { RefCell::new(None) };
    static AFTER_MANIFEST_MERGE: RefCell<Option<Hook>> = const { RefCell::new(None) };
}

/// Run this thread's one-shot synthetic post-commit fault.
pub fn after_entry_commit() {
    let hook = AFTER_ENTRY_COMMIT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
/// Run this thread's one-shot synthetic external listing update.
pub fn after_list_load() {
    let hook = AFTER_LIST_LOAD.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
/// Run this thread's one-shot synthetic manifest-copy replacement.
pub fn after_manifest_merge() {
    let hook = AFTER_MANIFEST_MERGE.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

const PASS: &str = "audit-only-synthetic-passphrase-1234567890";
fn fixture() -> (tempfile::TempDir, VaultStore, UnlockedVault) {
    crate::paths::isolate_state_dir().expect("isolated state");
    let root = tempfile::tempdir().expect("fixture");
    let store = VaultStore::new(root.path().join("vault.json"));
    store.init(PASS, false).expect("init");
    let vault = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .expect("open");
    (root, store, vault)
}
fn entry(field: &str) -> SecretEntry {
    SecretEntry::new(
        "app",
        "key",
        BTreeMap::from([(
            field.to_owned(),
            SecretString::from("synthetic-only".to_owned()),
        )]),
    )
}
fn entry_path(store: &VaultStore) -> PathBuf {
    fs::read_dir(VaultDir::new(store.vault_path()).entries_dir())
        .expect("entries")
        .map(|entry| entry.expect("entry").path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .expect("entry file")
}

#[test]
fn audit_rotation_ack_does_not_reread_after_commit() {
    let (_root, store, vault) = fixture();
    let old = vault
        .compare_set("app", "key", &entry("before"), None)
        .expect("create");
    let manifest = store.vault_path().to_owned();
    let saved = manifest.with_extension("saved");
    let (from, to) = (manifest.clone(), saved.clone());
    AFTER_ENTRY_COMMIT.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            fs::rename(from, to).expect("simulate unavailable manifest");
        }));
    });
    let result = vault.compare_set("app", "key", &entry("after"), Some(&old));
    fs::rename(saved, manifest).expect("restore synthetic manifest");
    let observed = vault
        .get_versioned("app", "key")
        .expect("read committed rotation");
    assert_eq!(
        result.expect("successful commit must be acknowledged"),
        observed.1
    );
    assert!(observed.0.fields.contains_key("after"));
    assert_ne!(old, observed.1);
}

#[test]
fn audit_listing_pairs_metadata_and_revision_from_one_observation() {
    let (_root, store, vault) = fixture();
    let old = vault
        .compare_set("app", "key", &entry("before"), None)
        .expect("create");
    let path = entry_path(&store);
    let old_bytes = fs::read(&path).expect("old bytes");
    vault
        .set("app", "key", &entry("after"))
        .expect("prepare authenticated replacement");
    let replacement = fs::read(&path).expect("replacement bytes");
    fs::write(&path, old_bytes).expect("restore old observation");
    AFTER_LIST_LOAD.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            fs::write(path, replacement).expect("external replacement bypasses advisory lock");
        }));
    });
    let rows = vault.list_versioned("app").expect("list");
    let pairs: Vec<_> = rows
        .into_iter()
        .map(|(meta, revision)| (meta.field_names, revision))
        .collect();
    assert_eq!(pairs, vec![(vec!["before".to_owned()], old)]);
    assert!(
        vault
            .get("app", "key")
            .expect("new external state")
            .fields
            .contains_key("after")
    );
}

#[test]
fn audit_ack_matches_canonical_log_with_retained_conflicts() {
    let (_root, store, vault) = fixture();
    let first = vault
        .compare_set("app", "key", &entry("before"), None)
        .expect("create");
    let path = entry_path(&store);
    let copy = path.with_file_name(format!(
        "{}.sync-conflict-canonical.json",
        path.file_stem().expect("stem").to_string_lossy()
    ));
    fs::copy(&path, &copy).expect("old copy");
    let committed = vault
        .compare_set("app", "key", &entry("after"), Some(&first))
        .expect("rotate");
    assert_eq!(
        committed,
        vault
            .get_versioned("app", "key")
            .expect("read with retained copy")
            .1
    );
    assert_eq!(
        committed,
        vault
            .list_versioned("app")
            .expect("list with retained copy")
            .remove(0)
            .1
    );
    assert!(copy.exists());
}

#[test]
fn audit_ack_describes_own_commit_not_external_replacement() {
    let (_root, store, vault) = fixture();
    let first = vault
        .compare_set("app", "key", &entry("before"), None)
        .expect("create");
    let path = entry_path(&store);
    let original = fs::read(&path).expect("original");
    vault
        .set("app", "key", &entry("external"))
        .expect("prepare replacement");
    let external_revision = vault
        .get_versioned("app", "key")
        .expect("external revision")
        .1;
    let replacement = fs::read(&path).expect("external bytes");
    fs::write(&path, original).expect("restore original");
    let written_bytes = std::rc::Rc::new(RefCell::new(None));
    let captured = std::rc::Rc::clone(&written_bytes);
    let replaced = path.clone();
    AFTER_ENTRY_COMMIT.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            *captured.borrow_mut() = Some(fs::read(&replaced).expect("capture own commit"));
            fs::write(replaced, replacement).expect("external replacement after commit");
        }));
    });
    let committed = vault
        .compare_set("app", "key", &entry("local"), Some(&first))
        .expect("write acknowledgement");
    assert_ne!(committed, external_revision);
    assert_eq!(
        vault.get_versioned("app", "key").expect("external state").1,
        external_revision
    );
    fs::write(
        path,
        written_bytes.borrow_mut().take().expect("captured commit"),
    )
    .expect("restore own commit");
    assert_eq!(
        committed,
        vault
            .get_versioned("app", "key")
            .expect("own committed state")
            .1
    );
}

#[test]
fn audit_cleanup_preserves_replaced_entry_conflict_copy() {
    let (_root, store, vault) = fixture();
    vault
        .compare_set("app", "key", &entry("before"), None)
        .expect("create");
    let path = entry_path(&store);
    let original = fs::read(&path).expect("old bytes");
    vault
        .set("app", "key", &entry("external"))
        .expect("prepare authenticated replacement");
    let replacement = fs::read(&path).expect("new bytes");
    fs::write(&path, &original).expect("restore main");
    let copy = path.with_file_name(format!(
        "{}.sync-conflict-audit.json",
        path.file_stem().expect("stem").to_string_lossy()
    ));
    fs::write(&copy, original).expect("copy");
    let replaced = copy.clone();
    let expected = replacement.clone();
    AFTER_ENTRY_COMMIT.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            fs::write(replaced, replacement).expect("sync replacement after absorb");
        }));
    });
    vault
        .set("app", "key", &entry("local"))
        .expect("local write");
    assert_eq!(fs::read(copy).expect("replacement must survive"), expected);
}

#[test]
fn audit_cleanup_preserves_replaced_manifest_conflict_copy() {
    let (_root, store, vault) = fixture();
    let copy = store
        .vault_path()
        .with_file_name("vault.sync-conflict-audit.json");
    fs::copy(store.vault_path(), &copy).expect("verified conflict copy");
    let replaced = copy.clone();
    AFTER_MANIFEST_MERGE.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            fs::write(replaced, b"synthetic unverified replacement")
                .expect("sync replacement after verification");
        }));
    });
    let _lock = VaultFileLock::exclusive(store.vault_path()).expect("maintenance lock");
    store.maintain_v5_locked(&vault.dk).expect("maintenance");
    assert_eq!(
        fs::read(&copy).expect("unverified replacement must survive"),
        b"synthetic unverified replacement"
    );
    // A later maintenance pass must still ignore, never trust, the replacement.
    store
        .maintain_v5_locked(&vault.dk)
        .expect("ignore unverified copy");
    assert_eq!(
        fs::read(copy).expect("copy remains"),
        b"synthetic unverified replacement"
    );
}

#[test]
fn audit_retained_copies_do_not_force_repeated_maintenance_writes() {
    let (root, store, vault) = fixture();
    vault
        .compare_set("app", "key", &entry("before"), None)
        .expect("create");
    let path = entry_path(&store);
    let copy = path.with_file_name(format!(
        "{}.sync-conflict-idempotence.json",
        path.file_stem().expect("stem").to_string_lossy()
    ));
    fs::copy(&path, &copy).expect("old copy");
    vault
        .set("app", "key", &entry("after"))
        .expect("fold copy into new write");
    let _lock = VaultFileLock::exclusive(store.vault_path()).expect("maintenance lock");
    store
        .maintain_v5_locked(&vault.dk)
        .expect("initial maintenance");
    let marker = root.path().join("unexpected-entry-write");
    let written = marker.clone();
    AFTER_ENTRY_COMMIT.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            fs::write(written, b"unexpected write").expect("write marker");
        }));
    });
    let result = store.maintain_v5_locked(&vault.dk);
    AFTER_ENTRY_COMMIT.with(|slot| {
        slot.borrow_mut().take();
    });
    result.expect("second maintenance");
    assert!(
        !marker.exists(),
        "already folded copies must not force writes"
    );
    assert!(copy.exists(), "retention remains necessary");
}
