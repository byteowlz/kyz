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
    // Repeated reads of an unchanged entry yield a stable revision.
    let third = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .unwrap();
    assert_eq!(
        third.get_versioned("app", "key").unwrap().1,
        third.get_versioned("app", "key").unwrap().1
    );
    assert_eq!(
        results
            .iter()
            .filter(|v| matches!(v, Err(CoreError::RevisionConflict)))
            .count(),
        1
    );
}

#[test]
fn revision_fence_child_writer() {
    let (Ok(path), Ok(revision)) = (
        std::env::var("KYZ_REVISION_FENCE_VAULT"),
        std::env::var("KYZ_REVISION_FENCE_REVISION"),
    ) else {
        return;
    };
    let store = VaultStore::new(std::path::PathBuf::from(path));
    let vault = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .unwrap();
    match vault.compare_set("app", "key", &entry("child"), Some(&revision)) {
        Ok(()) => {}
        Err(CoreError::RevisionConflict) => std::process::exit(3),
        Err(_) => std::process::exit(4),
    }
}

#[test]
fn concurrent_processes_have_exactly_one_winner() {
    let root = tempfile::tempdir().unwrap();
    let store = VaultStore::new(root.path().join("vault.json"));
    store.init(PASS, false).unwrap();
    let vault = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .unwrap();
    vault
        .compare_set("app", "key", &entry("initial"), None)
        .unwrap();
    let (_, revision) = vault.get_versioned("app", "key").unwrap();
    let children: Vec<_> = (0..4)
        .map(|_| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "revision_fence_child_writer"])
                .env("KYZ_REVISION_FENCE_VAULT", store.vault_path())
                .env("KYZ_REVISION_FENCE_REVISION", &revision)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    let mut codes: Vec<_> = children
        .into_iter()
        .map(|mut child| child.wait().unwrap().code())
        .collect();
    codes.sort_unstable();
    assert_eq!(codes, vec![Some(0), Some(3), Some(3), Some(3)]);
    assert_ne!(vault.get_versioned("app", "key").unwrap().1, revision);
}
