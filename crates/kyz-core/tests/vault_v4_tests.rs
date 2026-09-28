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
//! End-to-end v4 vault lifecycle tests over real files: creation, forked
//! replicas, explicit merge, delete-wins, explicit rebuild, rollback, and
//! merge-input rejection (tampering, independent vaults, idempotent
//! re-merge without writes).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use kyz_core::store::{VaultContents, VaultStore, detect_vault_version};
use kyz_core::{Projection, SecretEntry, SecretStore, VaultFileV3, VaultFileV4};
use secrecy::SecretString;

mod common;

fn temp_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "kyz-v4-e2e-{label}-{}-{nanos}.json",
        std::process::id()
    ))
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
    let dk = store.require_session_pub().expect("session");
    let VaultContents::V4(vault) = store.read_contents_pub().expect("contents") else {
        panic!("vault must be v4 after unlock");
    };
    match vault.projection(service, key).expect("projection") {
        Projection::Hidden => None,
        Projection::Visible { .. } => Some(
            vault
                .decrypt_current(&dk, service, key)
                .expect("decrypt")
                .fields
                .get("value")
                .cloned()
                .unwrap_or_default(),
        ),
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
    std::fs::copy(&path_a, &path_b).expect("copy replica");
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

    // Re-merge is a no-op that does not touch the file.
    let bytes_before = std::fs::read(&path_a).expect("read a");
    let report = a.merge_vault_from(&path_b, false, false).expect("re-merge");
    assert!(!report.changed);
    assert_eq!(report.ops_added, 0);
    let bytes_after = std::fs::read(&path_a).expect("re-read a");
    assert_eq!(bytes_before, bytes_after, "idempotent merge must not write");

    // Dry-run computes the same report without writing.
    let report = a.merge_vault_from(&path_b, true, false).expect("dry merge");
    assert!(!report.changed);
    let bytes_after = std::fs::read(&path_a).expect("re-read a");
    assert_eq!(bytes_before, bytes_after);

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
    let _ = std::fs::remove_file(&path_a);
    let _ = std::fs::remove_file(&path_b);
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
    let _ = std::fs::remove_file(&path);
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

    // Refused without --yes, file untouched.
    let bytes_before = std::fs::read(&path_a).expect("read a");
    let err = a
        .merge_vault_from(&path_b, false, false)
        .expect_err("resurrection must be refused");
    assert!(
        format!("{err}").contains("svc/api-key"),
        "error must name the entry: {err}"
    );
    assert_eq!(
        std::fs::read(&path_a).expect("re-read"),
        bytes_before,
        "refused merge must not write"
    );

    // Dry-run reports the candidate without erroring or writing.
    let report = a
        .merge_vault_from(&path_b, true, false)
        .expect("dry-run reports");
    assert_eq!(report.legacy_resurrections, vec!["svc/api-key".to_string()]);
    assert_eq!(
        std::fs::read(&path_a).expect("re-read"),
        bytes_before,
        "dry-run must not write"
    );

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
    let _ = std::fs::remove_file(&path_a);
    let _ = std::fs::remove_file(&path_b);
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

    // Tampered source metadata (tags projection) fails the MAC.
    let tampered_path = temp_path("guard-tampered");
    let write_tampered = |mutate: &dyn Fn(&mut VaultFileV4)| {
        let raw = std::fs::read(&path_a).expect("read a");
        let mut vault: VaultFileV4 = serde_json::from_slice(&raw).expect("parse");
        mutate(&mut vault);
        std::fs::write(
            &tampered_path,
            serde_json::to_string_pretty(&vault).expect("ser"),
        )
        .expect("write tampered");
    };

    write_tampered(&|vault| {
        vault.entries.get_mut("svc/k").expect("entry")[0]
            .meta
            .as_mut()
            .expect("meta")
            .field_names
            .push("injected".to_string());
    });
    let err = a
        .merge_vault_from(&tampered_path, false, false)
        .expect_err("tampered meta");
    assert!(format!("{err}").contains("MAC"), "unexpected error: {err}");

    write_tampered(&|vault| {
        let blob = vault.entries.get_mut("svc/k").expect("entry")[0]
            .blob
            .as_mut()
            .expect("blob");
        blob.insert(0, 'A');
    });
    let err = a
        .merge_vault_from(&tampered_path, false, false)
        .expect_err("tampered blob");
    assert!(format!("{err}").contains("MAC"), "unexpected error: {err}");

    let _ = a.lock();
    let _ = other.lock();
    let _ = std::fs::remove_file(&path_a);
    let _ = std::fs::remove_file(&path_other);
    let _ = std::fs::remove_file(&tampered_path);
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
        4
    );

    let entry = store.get("app", "legacy").expect("get after migrate");
    assert_eq!(entry.value(), Some("legacy-secret"));

    // The v3 archived snapshot remains in the derived history view.
    let items = store.history_v4("app", "legacy").expect("history");
    assert!(!items.is_empty());

    let _ = store.lock();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn delete_on_v3_vault_upgrades_the_file_to_v4() {
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

    // A successful delete upgrades the file to v4 in the same transaction.
    store.delete("app", "gone").expect("delete upgrades");
    assert_eq!(
        detect_vault_version(&std::fs::read(&path).expect("read")),
        4
    );
    assert!(store.get("app", "gone").is_err());
    let kept = store.get("app", "keep").expect("kept entry survives");
    assert_eq!(kept.value(), Some("kept"));

    let _ = store.lock();
    let _ = std::fs::remove_file(&path);
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
    let _ = std::fs::remove_file(&path);
}
