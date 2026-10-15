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
    let outcome = match vault.compare_set("app", "key", &entry("child"), Some(&revision)) {
        Ok(_) => "won",
        Err(CoreError::RevisionConflict) => "conflict",
        Err(_) => "error",
    };
    println!("FENCE_OUTCOME={outcome}");
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
    // Spawn every child before waiting on any, so they race for the lock.
    #[expect(
        clippy::needless_collect,
        reason = "all children must be running before the first wait"
    )]
    let children: Vec<_> = (0..4)
        .map(|_| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "revision_fence_child_writer", "--nocapture"])
                .env("KYZ_REVISION_FENCE_VAULT", store.vault_path())
                .env("KYZ_REVISION_FENCE_REVISION", &revision)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    let mut outcomes: Vec<String> = children
        .into_iter()
        .map(|child| {
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix("FENCE_OUTCOME="))
                .unwrap()
                .to_owned()
        })
        .collect();
    outcomes.sort_unstable();
    assert_eq!(outcomes, ["conflict", "conflict", "conflict", "won"]);
    assert_ne!(vault.get_versioned("app", "key").unwrap().1, revision);
}

#[test]
fn compare_set_returns_the_written_revision() {
    let root = tempfile::tempdir().unwrap();
    let store = VaultStore::new(root.path().join("vault.json"));
    store.init(PASS, false).unwrap();
    let vault = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .unwrap();
    let created = vault
        .compare_set("app", "key", &entry("one"), None)
        .unwrap();
    assert_eq!(vault.get_versioned("app", "key").unwrap().1, created);
    let rotated = vault
        .compare_set("app", "key", &entry("two"), Some(&created))
        .unwrap();
    assert_ne!(rotated, created);
    assert_eq!(vault.get_versioned("app", "key").unwrap().1, rotated);
    // The returned revision is directly usable as the next fence.
    vault.compare_delete("app", "key", &rotated).unwrap();
    assert!(vault.get_versioned("app", "key").is_err());
}

#[test]
fn list_versioned_is_value_free_and_matches_get_versioned() {
    let root = tempfile::tempdir().unwrap();
    let store = VaultStore::new(root.path().join("vault.json"));
    store.init(PASS, false).unwrap();
    let vault = store
        .open_in_memory(&SecretString::from(PASS.to_owned()))
        .unwrap();
    for key in ["a", "b", "gone"] {
        vault.compare_set("app", key, &entry(key), None).unwrap();
    }
    vault.compare_set("other", "c", &entry("c"), None).unwrap();
    let gone = vault.get_versioned("app", "gone").unwrap().1;
    vault.compare_delete("app", "gone", &gone).unwrap();
    // An ordinary writer changes `b`; the listing must reflect it.
    vault.set("app", "b", &entry("b2")).unwrap();

    let listed: Vec<(String, Vec<String>, String)> = vault
        .list_versioned("app")
        .unwrap()
        .into_iter()
        .map(|(summary, revision)| (summary.key, summary.field_names, revision))
        .collect();
    let expected: Vec<(String, Vec<String>, String)> = ["a", "b"]
        .into_iter()
        .map(|key| {
            (
                key.to_owned(),
                vec!["token".to_owned()],
                vault.get_versioned("app", key).unwrap().1,
            )
        })
        .collect();
    assert_eq!(listed, expected);
}
