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
//! End-to-end vault lifecycle tests over real files (v5 layout: manifest
//! plus one file per entry): creation, forked replicas, explicit merge,
//! delete-wins, explicit rebuild, rollback, merge-input rejection
//! (tampering, independent vaults, idempotent re-merge without writes),
//! key slots and passphrase changes across replicas, sync conflict copies,
//! and migration from v3 and single-file v4.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use kyz_core::store::{VaultStore, detect_vault_version};
use kyz_core::vault_v5::entries_dir_for;
use kyz_core::{SecretEntry, SecretStore, VaultFileV3, VaultFileV4};
use secrecy::SecretString;

mod common;

/// Fresh directory per vault; returns `<dir>/vault.json` (the manifest
/// path — entries live next to it in `vault.entries/`).
fn temp_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "kyz-sync-e2e-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create vault dir");
    dir.join("vault.json")
}

fn cleanup(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Copy a vault replica: manifest plus entries directory.
fn copy_vault(from: &Path, to: &Path) {
    std::fs::copy(from, to).expect("copy manifest");
    let (src, dst) = (entries_dir_for(from), entries_dir_for(to));
    std::fs::create_dir_all(&dst).expect("create entries dir");
    for item in std::fs::read_dir(&src).expect("read entries") {
        let item = item.expect("entry");
        std::fs::copy(item.path(), dst.join(item.file_name())).expect("copy entry");
    }
}

/// Every file of a vault (manifest and entries) by name, for no-write
/// assertions.
fn snapshot(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    out.insert(
        "vault.json".to_string(),
        std::fs::read(path).expect("read manifest"),
    );
    if let Ok(items) = std::fs::read_dir(entries_dir_for(path)) {
        for item in items {
            let item = item.expect("entry");
            out.insert(
                format!("entries/{}", item.file_name().to_string_lossy()),
                std::fs::read(item.path()).expect("read entry"),
            );
        }
    }
    out
}

fn entry_files(path: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(entries_dir_for(path))
        .expect("read entries")
        .map(|i| i.expect("entry").path())
        .collect();
    out.sort();
    out
}

const PASS: &str = "a-very-strong-passphrase-123";

fn fresh_unlocked(label: &str) -> (VaultStore, PathBuf) {
    common::isolate_state_dir();
    let path = temp_path(label);
    let store = VaultStore::new(path.clone());
    store.init(PASS, false).expect("init");
    store.unlock(PASS, 60).expect("unlock");
    (store, path)
}

fn set(store: &VaultStore, service: &str, key: &str, value: &str) {
    store
        .set(service, key, &SecretEntry::single(service, key, value))
        .expect("set");
}

fn set_recreate(store: &VaultStore, service: &str, key: &str, value: &str) {
    store
        .set_with_options(
            service,
            key,
            &SecretEntry::single(service, key, value),
            true,
        )
        .expect("set recreate");
}

/// Winning snapshot's `value` field, or `None` when the entry is hidden.
fn current_value(store: &VaultStore, service: &str, key: &str) -> Option<String> {
    match store.get(service, key) {
        Ok(entry) => Some(entry.value().unwrap_or_default().to_string()),
        Err(kyz_core::CoreError::SecretNotFound(_)) => None,
        Err(e) => panic!("get {service}/{key}: {e}"),
    }
}

#[test]
fn forked_replicas_merge_with_conflict_delete_wins_and_rebuild() {
    let (a, path_a) = fresh_unlocked("fork-a");
    set(&a, "svc", "shared", "base");
    set(&a, "svc", "only-a", "a-value");

    // Fork: replica B starts from A's bytes (as Syncthing would before the
    // conflict) and both sides diverge.
    let path_b = temp_path("fork-b");
    copy_vault(&path_a, &path_b);
    let b = VaultStore::new(path_b.clone());
    b.unlock(PASS, 60).expect("unlock b");

    // Diverge: concurrent writes to the same entry on both replicas.
    set(&a, "svc", "shared", "written-by-a");
    set(&b, "svc", "shared", "written-by-b");
    // B deletes an entry A concurrently updates.
    set(&a, "svc", "only-a", "updated-by-a");
    b.delete("svc", "only-a").expect("delete on b");
    // B adds an entry A never saw.
    set(&b, "svc", "only-b", "b-value");

    let report = a.merge_vault_from(&path_b, false, false).expect("merge");
    assert!(report.changed);
    assert!(report.ops_added >= 3);
    assert!(report.new_entries.contains(&"svc/only-b".to_string()));
    assert!(report.updated_entries.contains(&"svc/shared".to_string()));
    // Concurrent delete vs update: delete wins.
    assert!(report.deleted_entries.contains(&"svc/only-a".to_string()));
    assert!(
        report.conflicts.iter().any(|c| c.entry == "svc/shared"),
        "concurrent writes must surface as a conflict: {report:?}"
    );

    let shared = current_value(&a, "svc", "shared").expect("shared must stay visible");
    assert_ne!(shared, "base", "stale pre-fork value must not win");
    assert!(
        shared == "written-by-a" || shared == "written-by-b",
        "winner must be one of the concurrent writes, got {shared}"
    );
    assert_eq!(current_value(&a, "svc", "only-a"), None, "delete must win");
    assert_eq!(
        current_value(&a, "svc", "only-b").as_deref(),
        Some("b-value")
    );

    // Re-merge is a no-op that does not touch any file.
    let bytes_before = snapshot(&path_a);
    let report = a.merge_vault_from(&path_b, false, false).expect("re-merge");
    assert!(!report.changed);
    assert_eq!(report.ops_added, 0);
    assert_eq!(
        bytes_before,
        snapshot(&path_a),
        "idempotent merge must not write"
    );

    // Dry-run computes the same report without writing.
    let report = a.merge_vault_from(&path_b, true, false).expect("dry merge");
    assert!(!report.changed);
    assert_eq!(bytes_before, snapshot(&path_a));

    // The reverse merge converges B to exactly A's state.
    b.merge_vault_from(&path_a, false, false)
        .expect("reverse merge");
    let (sa, sb) = (snapshot(&path_a), snapshot(&path_b));
    let entries = |s: &BTreeMap<String, Vec<u8>>| {
        s.iter()
            .filter(|(k, _)| k.starts_with("entries/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(
        entries(&sa),
        entries(&sb),
        "replicas must converge byte-identically"
    );

    // Plain set on the deleted entry refuses; deleting it again keeps
    // SecretNotFound semantics; the explicit rebuild then succeeds.
    assert!(
        a.set("svc", "only-a", &SecretEntry::single("svc", "only-a", "x"))
            .is_err()
    );
    assert!(a.delete("svc", "only-a").is_err());
    set_recreate(&a, "svc", "only-a", "reborn");
    assert_eq!(
        current_value(&a, "svc", "only-a").as_deref(),
        Some("reborn")
    );

    // Trait-level recreate: library callers (kyz-runtime's VaultRef::set)
    // re-add a tombstoned entry without the interactive --yes gate.
    a.delete("svc", "only-a").expect("delete again");
    a.set_recreating(
        "svc",
        "only-a",
        &SecretEntry::single("svc", "only-a", "via-trait"),
    )
    .expect("trait-level recreate");
    assert_eq!(
        current_value(&a, "svc", "only-a").as_deref(),
        Some("via-trait")
    );

    // Rollback restores an earlier snapshot as a new write.
    set(&a, "svc", "shared", "third");
    let items = a.history_v4("svc", "shared").expect("history");
    assert!(items.len() >= 3);
    let before_rollback = items.len();
    // Sequence numbers count from the oldest operation: seq 1 is the
    // pre-merge base snapshot.
    a.rollback_v4("svc", "shared", "1").expect("rollback");
    let items = a.history_v4("svc", "shared").expect("history");
    assert_eq!(
        items.len(),
        before_rollback + 1,
        "rollback adds exactly one op"
    );
    assert_eq!(items[0].role, kyz_core::HistoryRole::Current);

    let _ = a.lock();
    let _ = b.lock();
    cleanup(&path_a);
    cleanup(&path_b);
}

#[test]
fn rollback_rejects_out_of_range_seq_and_refreshes_updated_at() {
    common::isolate_state_dir();
    let path = temp_path("rollback-guard");
    let pass = SecretString::from(PASS.to_string());
    let (mut v3, dk) = VaultFileV3::create(&pass).expect("create v3");
    v3.passphrase_policy_checked = true;
    // A legacy snapshot with an unmissably old updated_at (2001); v3
    // preserves it for new entries, and the migration carries it into the
    // op's metadata projection.
    let mut legacy = SecretEntry::single("app", "key", "legacy-value");
    legacy.updated_at = 1_000_000_000;
    v3.set(&legacy, &dk).expect("set v3");
    std::fs::write(&path, serde_json::to_string_pretty(&v3).expect("ser")).expect("write v3");

    let store = VaultStore::new(path.clone());
    store.unlock(PASS, 60).expect("unlock migrates");
    set(&store, "app", "key", "modern-value");

    // Sequence numbering is 1-based counting from the oldest operation
    // (matching v3 version numbers): 0 and past-the-end targets are
    // rejected instead of silently resolving to another version.
    assert!(store.rollback_v4("app", "key", "0").is_err());
    assert!(store.rollback_v4("app", "key", "99").is_err());

    // Roll back to the legacy snapshot (seq 1: the oldest operation).
    store.rollback_v4("app", "key", "1").expect("rollback");
    let fetched = store.get("app", "key").expect("get");
    assert_eq!(fetched.value(), Some("legacy-value"));
    assert!(
        fetched.updated_at >= 1_700_000_000,
        "rollback must refresh updated_at (v3 semantics), got {}",
        fetched.updated_at
    );

    let _ = store.lock();
    cleanup(&path);
}

#[test]
fn merge_gates_v3_era_resurrections_behind_explicit_yes() {
    common::isolate_state_dir();
    // A v3 vault is forked to B; A deletes svc/api-key under v3 semantics
    // (physical removal, no tombstone); both sides unlock independently
    // (same kdf/wrapped_dk → same vault id). Merging the stale B copy
    // would silently resurrect the deleted secret — the merge must
    // refuse without --yes and write nothing.
    let path_a = temp_path("res-a");
    let path_b = temp_path("res-b");
    let pass = SecretString::from(PASS.to_string());
    let (mut v3, dk) = VaultFileV3::create(&pass).expect("create v3");
    v3.passphrase_policy_checked = true;
    v3.set_with_retention(&SecretEntry::single("svc", "api-key", "revoked"), &dk, 3)
        .expect("set api-key");
    v3.set_with_retention(&SecretEntry::single("svc", "keep", "kept"), &dk, 3)
        .expect("set keep");
    let v3_bytes = serde_json::to_string_pretty(&v3).expect("ser");

    let mut v3_a = v3.clone();
    assert!(v3_a.remove("svc", "api-key"), "v3 remove must succeed");
    std::fs::write(&path_a, serde_json::to_string_pretty(&v3_a).expect("ser")).expect("write a");
    std::fs::write(&path_b, &v3_bytes).expect("write b");

    let a = VaultStore::new(path_a.clone());
    a.unlock(PASS, 60).expect("unlock a migrates");
    let b = VaultStore::new(path_b.clone());
    b.unlock(PASS, 60).expect("unlock b migrates");

    // Refused without --yes, vault untouched.
    let bytes_before = snapshot(&path_a);
    let err = a
        .merge_vault_from(&path_b, false, false)
        .expect_err("resurrection must be refused");
    assert!(
        format!("{err}").contains("svc/api-key"),
        "error must name the entry: {err}"
    );
    assert_eq!(
        snapshot(&path_a),
        bytes_before,
        "refused merge must not write"
    );

    // Dry-run reports the candidate without erroring or writing.
    let report = a
        .merge_vault_from(&path_b, true, false)
        .expect("dry-run reports");
    assert_eq!(report.legacy_resurrections, vec!["svc/api-key".to_string()]);
    assert_eq!(snapshot(&path_a), bytes_before, "dry-run must not write");

    // With the explicit acceptance the merge proceeds; common history
    // (svc/keep) deduplicates without being flagged.
    let report = a
        .merge_vault_from(&path_b, false, true)
        .expect("merge with --yes");
    assert_eq!(report.legacy_resurrections, vec!["svc/api-key".to_string()]);
    assert_eq!(
        current_value(&a, "svc", "api-key").as_deref(),
        Some("revoked"),
        "accepted merge re-introduces the entry"
    );
    assert_eq!(current_value(&a, "svc", "keep").as_deref(), Some("kept"));

    let _ = a.lock();
    let _ = b.lock();
    cleanup(&path_a);
    cleanup(&path_b);
}

#[test]
fn merge_rejects_tampered_and_foreign_sources() {
    let (a, path_a) = fresh_unlocked("guard-a");
    set(&a, "svc", "k", "v1");

    let (other, path_other) = fresh_unlocked("guard-other");
    set(&other, "svc", "k", "foreign");
    // Independent vaults never merge.
    let err = a
        .merge_vault_from(&path_other, false, false)
        .expect_err("foreign");
    assert!(
        format!("{err}").contains("not a replica"),
        "unexpected error: {err}"
    );

    // Tampered replica entries fail verification: metadata projection
    // and ciphertext are both MAC-covered.
    let tampered_path = temp_path("guard-tampered");
    let write_tampered = |mutate: &dyn Fn(&mut serde_json::Value)| {
        cleanup(&tampered_path);
        std::fs::create_dir_all(tampered_path.parent().expect("parent")).expect("dir");
        copy_vault(&path_a, &tampered_path);
        let file = entry_files(&tampered_path).remove(0);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).expect("read entry")).expect("parse");
        mutate(&mut value);
        std::fs::write(&file, serde_json::to_vec_pretty(&value).expect("ser")).expect("write");
    };

    write_tampered(&|v| {
        v["ops"][0]["meta"]["field_names"]
            .as_array_mut()
            .expect("field names")
            .push("injected".into());
    });
    let err = a
        .merge_vault_from(&tampered_path, false, false)
        .expect_err("tampered meta");
    assert!(format!("{err}").contains("MAC"), "unexpected error: {err}");

    write_tampered(&|v| {
        let blob = v["ops"][0]["blob"].as_str().expect("blob").to_string();
        v["ops"][0]["blob"] = format!("A{blob}").into();
    });
    let err = a
        .merge_vault_from(&tampered_path, false, false)
        .expect_err("tampered blob");
    assert!(format!("{err}").contains("MAC"), "unexpected error: {err}");

    // A tampered entry file in the vault itself fails reads the same way.
    let file = entry_files(&path_a).remove(0);
    let original = std::fs::read(&file).expect("read");
    let mut value: serde_json::Value = serde_json::from_slice(&original).expect("parse");
    value["ops"][0]["changed_at"]["phys"] = 1.into();
    std::fs::write(&file, serde_json::to_vec_pretty(&value).expect("ser")).expect("write");
    let err = a.get("svc", "k").expect_err("tampered entry");
    assert!(format!("{err}").contains("MAC"), "unexpected error: {err}");
    std::fs::write(&file, original).expect("restore");

    let _ = a.lock();
    let _ = other.lock();
    cleanup(&path_a);
    cleanup(&path_other);
    cleanup(&tampered_path);
}

#[test]
fn v3_vault_unlock_migrates_and_keeps_everything_readable() {
    let path = temp_path("migrate-v3");
    let pass = SecretString::from(PASS.to_string());
    let (mut v3, dk) = VaultFileV3::create(&pass).expect("create v3");
    v3.passphrase_policy_checked = true;
    let mut fields = BTreeMap::new();
    fields.insert(
        "value".to_string(),
        SecretString::from("legacy-secret".to_string()),
    );
    v3.set_with_retention(&SecretEntry::new("app", "legacy", fields), &dk, 3)
        .expect("set v3");
    std::fs::write(&path, serde_json::to_string_pretty(&v3).expect("ser")).expect("write v3");

    let store = VaultStore::new(path.clone());
    store.unlock(PASS, 60).expect("unlock migrates");
    assert_eq!(
        detect_vault_version(&std::fs::read(&path).expect("read")),
        5
    );

    let entry = store.get("app", "legacy").expect("get after migrate");
    assert_eq!(entry.value(), Some("legacy-secret"));

    // The v3 archived snapshot remains in the derived history view.
    let items = store.history_v4("app", "legacy").expect("history");
    assert!(!items.is_empty());

    let _ = store.lock();
    cleanup(&path);
}

#[test]
fn delete_on_v3_vault_upgrades_the_vault_to_v5() {
    common::isolate_state_dir();
    let path = temp_path("v3-delete-upgrade");
    let pass = SecretString::from(PASS.to_string());
    let (mut v3, dk) = VaultFileV3::create(&pass).expect("create v3");
    v3.passphrase_policy_checked = true;
    v3.set_with_retention(&SecretEntry::single("app", "keep", "kept"), &dk, 3)
        .expect("set keep");
    v3.set_with_retention(&SecretEntry::single("app", "gone", "deleted"), &dk, 3)
        .expect("set gone");
    let v3_bytes = serde_json::to_string_pretty(&v3).expect("ser v3");
    std::fs::write(&path, &v3_bytes).expect("write v3");

    let store = VaultStore::new(path.clone());
    store.unlock(PASS, 60).expect("unlock creates session");
    // Replant the v3 bytes: the session key matches (same kdf/wrapped_dk),
    // so `delete` must upgrade the file inside its write transaction, the
    // same way `set` does.
    std::fs::write(&path, &v3_bytes).expect("replant v3");
    assert_eq!(
        detect_vault_version(&std::fs::read(&path).expect("read")),
        3
    );

    // A failed delete (missing entry) writes nothing: the file stays v3.
    store.delete("app", "missing").expect_err("missing entry");
    assert_eq!(
        detect_vault_version(&std::fs::read(&path).expect("read")),
        3
    );

    // A successful delete upgrades the vault to v5 in the same transaction.
    store.delete("app", "gone").expect("delete upgrades");
    assert_eq!(
        detect_vault_version(&std::fs::read(&path).expect("read")),
        5
    );
    assert!(store.get("app", "gone").is_err());
    let kept = store.get("app", "keep").expect("kept entry survives");
    assert_eq!(kept.value(), Some("kept"));

    let _ = store.lock();
    cleanup(&path);
}

#[test]
fn rollback_on_v3_vault_uses_v3_versions_and_stays_v3() {
    common::isolate_state_dir();
    let path = temp_path("v3-rollback");
    let pass = SecretString::from(PASS.to_string());
    let (mut v3, dk) = VaultFileV3::create(&pass).expect("create v3");
    v3.passphrase_policy_checked = true;
    v3.set_with_retention(&SecretEntry::single("app", "key", "v1"), &dk, 3)
        .expect("set v1");
    v3.set_with_retention(&SecretEntry::single("app", "key", "v2"), &dk, 3)
        .expect("set v2");
    let v3_bytes = serde_json::to_string_pretty(&v3).expect("ser v3");
    std::fs::write(&path, &v3_bytes).expect("write v3");

    let store = VaultStore::new(path.clone());
    store.unlock(PASS, 60).expect("unlock creates session");
    std::fs::write(&path, &v3_bytes).expect("replant v3");

    // The store dispatches to v3 semantics: numeric version targets, file
    // written back as v3 (the one v3 write that does not upgrade).
    store.rollback("app", "key", "1", 3).expect("rollback v3");
    assert_eq!(
        detect_vault_version(&std::fs::read(&path).expect("read")),
        3,
        "v3 rollback must keep the v3 format"
    );
    let entry = store.get("app", "key").expect("get after rollback");
    assert_eq!(entry.value(), Some("v1"));

    // Non-numeric targets are rejected with the v3-specific message.
    let err = store
        .rollback("app", "key", "00000000000000000000000000000001:1", 3)
        .expect_err("v3 accepts numeric versions only");
    assert!(err.to_string().contains("numeric versions only"));

    let _ = store.lock();
    cleanup(&path);
}

const NEW_PASS: &str = "another-very-strong-passphrase-456";

#[test]
fn passphrase_change_on_one_replica_keeps_merging_both_ways() {
    let (a, path_a) = fresh_unlocked("slots-a");
    set(&a, "svc", "k", "base");
    let path_b = temp_path("slots-b");
    copy_vault(&path_a, &path_b);
    let b = VaultStore::new(path_b.clone());
    b.unlock(PASS, 60).expect("unlock b");

    // A changes its passphrase; both sides keep writing.
    a.change_passphrase(PASS, NEW_PASS)
        .expect("change passphrase");
    set(&a, "svc", "from-a", "a");
    set(&b, "svc", "from-b", "b");

    // B merges A: entries flow and the slot change (new slot, old slot
    // removed) propagates.
    let report = b
        .merge_vault_from(&path_a, false, false)
        .expect("merge a into b");
    assert!(
        report.keyslots_changed,
        "slot change must propagate: {report:?}"
    );
    assert_eq!(current_value(&b, "svc", "from-a").as_deref(), Some("a"));

    // A merges B the other way round.
    let report = a
        .merge_vault_from(&path_b, false, false)
        .expect("merge b into a");
    assert!(!report.keyslots_changed);
    assert_eq!(current_value(&a, "svc", "from-b").as_deref(), Some("b"));

    // After merging, both replicas open with the new passphrase only.
    for path in [&path_a, &path_b] {
        let store = VaultStore::new(path.clone());
        store.lock().expect("lock");
        assert!(store.unlock(PASS, 60).is_err(), "old passphrase must fail");
        store.unlock(NEW_PASS, 60).expect("new passphrase unlocks");
        let slots = store.key_slots().expect("slots");
        assert_eq!(slots.len(), 2);
        assert_eq!(slots.iter().filter(|s| s.removed_at.is_none()).count(), 1);
        assert_eq!(current_value(&store, "svc", "k").as_deref(), Some("base"));
        let _ = store.lock();
    }

    cleanup(&path_a);
    cleanup(&path_b);
}

#[test]
fn wrong_current_passphrase_and_last_slot_are_refused() {
    let (a, path) = fresh_unlocked("slots-guard");
    let before = snapshot(&path);
    assert!(a.change_passphrase("not-the-passphrase", NEW_PASS).is_err());
    assert!(
        a.change_passphrase(PASS, "short").is_err(),
        "strength policy applies"
    );
    assert_eq!(before, snapshot(&path), "refused changes must not write");
    let _ = a.lock();
    cleanup(&path);
}

#[test]
fn tampered_manifest_is_rejected_on_unlock() {
    let (a, path) = fresh_unlocked("manifest-tamper");
    a.lock().expect("lock");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
    let slots = value["keyslots"].as_object_mut().expect("slots");
    let (_, slot) = slots.iter_mut().next().expect("one slot");
    slot["label"] = "attacker".into();
    std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("ser")).expect("write");
    let err = a.unlock(PASS, 60).expect_err("tampered manifest");
    assert!(format!("{err}").contains("MAC"), "unexpected error: {err}");
    cleanup(&path);
}

#[test]
fn entry_names_are_not_visible_on_disk() {
    let (a, path) = fresh_unlocked("hidden-names");
    set(&a, "github-service", "deploy-token-name", "ghp_value");
    let files = entry_files(&path);
    assert_eq!(files.len(), 1);
    let name = files[0]
        .file_name()
        .expect("name")
        .to_string_lossy()
        .into_owned();
    assert!(
        !name.contains("github") && !name.contains("deploy"),
        "{name}"
    );
    let body = std::fs::read_to_string(&files[0]).expect("read");
    for needle in ["github-service", "deploy-token-name", "ghp_value"] {
        assert!(!body.contains(needle), "entry file leaks {needle}");
    }
    assert!(
        !std::fs::read_to_string(&path)
            .expect("manifest")
            .contains("github")
    );
    let _ = a.lock();
    cleanup(&path);
}

#[test]
fn sync_conflict_copies_are_read_and_absorbed() {
    let (a, path_a) = fresh_unlocked("conflict-a");
    set(&a, "svc", "k", "base");
    let path_b = temp_path("conflict-b");
    copy_vault(&path_a, &path_b);
    let b = VaultStore::new(path_b.clone());
    b.unlock(PASS, 60).expect("unlock b");
    set(&a, "svc", "k", "from-a");
    set(&b, "svc", "k", "from-b");

    // Simulate Syncthing: B's version of the entry lands next to A's as a
    // conflict copy.
    let b_file = entry_files(&path_b).remove(0);
    let id = b_file
        .file_stem()
        .expect("stem")
        .to_string_lossy()
        .into_owned();
    let copy =
        entries_dir_for(&path_a).join(format!("{id}.sync-conflict-20260928-120000-ABCDEFG.json"));
    std::fs::copy(&b_file, &copy).expect("plant conflict copy");

    // Reads already see both versions: one wins, the other is a conflict.
    let items = a.history_v4("svc", "k").expect("history");
    assert!(
        items
            .iter()
            .any(|i| i.role == kyz_core::HistoryRole::Conflict),
        "conflict copy must surface as a conflict version: {items:?}"
    );
    assert!(copy.exists(), "reads never delete");

    // The next write of the entry absorbs and removes the copy.
    set(&a, "svc", "k", "resolved");
    assert!(!copy.exists(), "write must absorb the conflict copy");
    assert_eq!(current_value(&a, "svc", "k").as_deref(), Some("resolved"));

    // Unlock absorbs copies of entries nobody writes.
    set(&b, "svc", "other", "b-only");
    let other_file = entry_files(&path_b)
        .into_iter()
        .find(|f| f.file_name() != b_file.file_name())
        .expect("other entry");
    let other_id = other_file
        .file_stem()
        .expect("stem")
        .to_string_lossy()
        .into_owned();
    let copy2 = entries_dir_for(&path_a).join(format!("{other_id}.sync-conflict-x.json"));
    std::fs::copy(&other_file, &copy2).expect("plant second copy");
    a.lock().expect("lock");
    a.unlock(PASS, 60).expect("unlock absorbs");
    assert!(!copy2.exists());
    assert!(
        entries_dir_for(&path_a)
            .join(format!("{other_id}.json"))
            .exists()
    );
    assert_eq!(current_value(&a, "svc", "other").as_deref(), Some("b-only"));

    // A copy from another vault is ignored and left alone.
    let (foreign, path_f) = fresh_unlocked("conflict-foreign");
    set(&foreign, "svc", "k", "foreign");
    let foreign_file = entry_files(&path_f).remove(0);
    let bogus = entries_dir_for(&path_a).join(format!("{id}.sync-conflict-foreign.json"));
    std::fs::copy(&foreign_file, &bogus).expect("plant foreign copy");
    assert_eq!(current_value(&a, "svc", "k").as_deref(), Some("resolved"));
    set(&a, "svc", "k", "after-foreign");
    assert!(bogus.exists(), "unverifiable copies must never be deleted");

    let _ = a.lock();
    let _ = b.lock();
    let _ = foreign.lock();
    cleanup(&path_a);
    cleanup(&path_b);
    cleanup(&path_f);
}

#[test]
fn single_file_v4_vault_migrates_and_merges() {
    common::isolate_state_dir();
    let pass = SecretString::from(PASS.to_string());
    let (mut v4, dk) = VaultFileV4::create(&pass).expect("create v4");
    v4.passphrase_policy_checked = true;
    let snapshot_plain =
        kyz_core::SnapshotPlain::from_entry(&SecretEntry::single("svc", "k", "v4-value"));
    let id = kyz_core::OpId::new("0123456789abcdef0123456789abcdef", 1).expect("op id");
    v4.append_put(
        &snapshot_plain,
        id,
        Vec::new(),
        kyz_core::Hlc::tick(None),
        &dk,
    )
    .expect("append");
    v4.finalize(&dk).expect("finalize");
    let v4_bytes = v4.to_bytes_pretty().expect("bytes");

    // A v4 file migrates on unlock.
    let path = temp_path("v4-migrate");
    std::fs::write(&path, &v4_bytes).expect("write v4");
    let store = VaultStore::new(path.clone());
    store.unlock(PASS, 60).expect("unlock migrates v4");
    assert_eq!(
        detect_vault_version(&std::fs::read(&path).expect("read")),
        5
    );
    assert_eq!(
        current_value(&store, "svc", "k").as_deref(),
        Some("v4-value")
    );
    set(&store, "svc", "k2", "new");

    // A v4 file of the same vault merges into the migrated v5 vault.
    let v4_copy = temp_path("v4-source");
    std::fs::write(&v4_copy, &v4_bytes).expect("write v4 copy");
    let report = store
        .merge_vault_from(&v4_copy, false, false)
        .expect("merge v4");
    assert_eq!(report.ops_added, 0, "migration keeps op ids: {report:?}");
    assert_eq!(current_value(&store, "svc", "k2").as_deref(), Some("new"));

    let _ = store.lock();
    cleanup(&path);
    cleanup(&v4_copy);
}

#[test]
fn edits_lost_to_a_concurrent_delete_are_reported_in_both_directions() {
    let (a, path_a) = fresh_unlocked("lost-a");
    set(&a, "svc", "k", "base");
    let path_b = temp_path("lost-b");
    copy_vault(&path_a, &path_b);
    let b = VaultStore::new(path_b.clone());
    b.unlock(PASS, 60).expect("unlock b");
    a.delete("svc", "k").expect("delete on a");
    set(&b, "svc", "k", "edited-on-b");

    // B (edit) merges A (delete): the entry disappears on B.
    let report = b
        .merge_vault_from(&path_a, false, false)
        .expect("merge a into b");
    assert_eq!(report.deleted_entries, vec!["svc/k".to_string()]);
    assert_eq!(report.lost_to_delete.len(), 1);
    assert_eq!(report.lost_to_delete[0].entry, "svc/k");
    assert_eq!(report.lost_to_delete[0].losing.len(), 1);

    // A (already deleted) merges B: nothing becomes hidden, but the
    // incoming edit is still reported instead of vanishing silently.
    let report = a
        .merge_vault_from(&path_b, false, false)
        .expect("merge b into a");
    assert!(report.deleted_entries.is_empty());
    assert_eq!(report.lost_to_delete.len(), 1, "{report:?}");

    // Neither side calls a hidden version current.
    for store in [&a, &b] {
        let items = store.history_v4("svc", "k").expect("history");
        assert!(
            items
                .iter()
                .all(|i| i.role != kyz_core::HistoryRole::Current),
            "{items:?}"
        );
        assert_eq!(current_value(store, "svc", "k"), None);
    }

    // Re-merging reports nothing new.
    let report = a.merge_vault_from(&path_b, false, false).expect("re-merge");
    assert!(report.lost_to_delete.is_empty());

    let _ = a.lock();
    let _ = b.lock();
    cleanup(&path_a);
    cleanup(&path_b);
}
