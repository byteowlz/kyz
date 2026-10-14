//! Synthetic session-free revision fencing and concurrent-writer proofs.
#![expect(clippy::unwrap_used, reason = "synthetic test assertions")]
use kyz_core::{CoreError, SecretEntry, VaultSession, VaultStore};
use secrecy::SecretString;
use std::collections::BTreeMap;

const PASS: &str = "revision-fence-synthetic-only-strong-passphrase-123";
fn entry(value: &str) -> SecretEntry {
    SecretEntry::new(
        "app",
        "key",
        BTreeMap::from([("token".into(), SecretString::from(value.to_owned()))]),
    )
}

#[test]
fn stale_update_delete_and_recreation_never_write() {
    let root = tempfile::tempdir().unwrap();
    let store = VaultStore::new(root.path().join("vault.json"));
    store.init(PASS, false).unwrap();
    let first = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .unwrap();
    let second = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .unwrap();
    first
        .compare_set("app", "key", &entry("one"), None)
        .unwrap();
    let (_, r1) = first.get_versioned("app", "key").unwrap();
    // The ordinary writer API (also used by CLI) shares the lock and changes
    // the opaque revision even if both writes happen in the same second.
    second.set("app", "key", &entry("two")).unwrap();
    let (_, r2) = first.get_versioned("app", "key").unwrap();
    assert_ne!(r1, r2);
    assert!(matches!(
        first.compare_set("app", "key", &entry("stale"), Some(&r1)),
        Err(CoreError::RevisionConflict)
    ));
    assert!(matches!(
        first.compare_delete("app", "key", &r1),
        Err(CoreError::RevisionConflict)
    ));
    assert_eq!(first.get_versioned("app", "key").unwrap().1, r2);
    first.compare_delete("app", "key", &r2).unwrap();
    assert!(first.get_versioned("app", "key").is_err());
    assert!(matches!(
        first.compare_set("app", "key", &entry("recreate"), None),
        Err(CoreError::RevisionConflict)
    ));
    assert!(
        !VaultSession::session_file_for(store.vault_path())
            .unwrap()
            .exists()
    );
}

#[test]
fn concurrent_handles_have_exactly_one_winner() {
    let root = tempfile::tempdir().unwrap();
    let store = VaultStore::new(root.path().join("vault.json"));
    store.init(PASS, false).unwrap();
    let first = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .unwrap();
    let second = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .unwrap();
    first
        .compare_set("app", "key", &entry("initial"), None)
        .unwrap();
    let (_, revision) = first.get_versioned("app", "key").unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let b = barrier.clone();
        let r = revision.clone();
        let worker = scope.spawn(move || {
            b.wait();
            first.compare_set("app", "key", &entry("first"), Some(&r))
        });
        barrier.wait();
        let other = second.compare_set("app", "key", &entry("second"), Some(&revision));
        [worker.join().unwrap(), other]
    });
    assert_eq!(results.iter().filter(|v| v.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|v| matches!(v, Err(CoreError::RevisionConflict)))
            .count(),
        1
    );
}
