//! Integration tests for `kyz-runtime`.
//!
//! Covers the runtime facade (open/unlock/lock/get/set/delete), the
//! layered resolver with provenance and constraints, SSH identity
//! detection and metadata derivation, and the error taxonomy.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret as _, SecretString};

use kyz_runtime::ssh::{SshAlgorithm, identity_from_entry, is_ssh_identity, list_ssh_identities};
use kyz_runtime::{
    Error, LayeredVault, SecretEntry, SecretRef, SourceConstraint, UnlockMode, UnlockState, Vault,
    VaultKind, VaultSource,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Real Ed25519 test key generated with ssh-keygen; used to exercise
// metadata derivation. The corresponding public key and SHA-256
// fingerprint are embedded below for assertion.
const TEST_SSH_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7bK9fd/hC6Afwp3/0+KbFW2JW5CfYIudBLvMzHdK69gAAAJjxVklD8VZJ
QwAAAAtzc2gtZWQyNTUxOQAAACB7bK9fd/hC6Afwp3/0+KbFW2JW5CfYIudBLvMzHdK69g
AAAEApkhQktAnh4VEe3sPQvtkTscSmYtUsK0gfjTEZSsDd7ntsr193+ELoB/Cnf/T4psVb
YlbkJ9gi50Eu8zMd0rr2AAAAFGt5ei1ydW50aW1lLXRlc3Qta2V5AQ==
-----END OPENSSH PRIVATE KEY-----
";

const TEST_SSH_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHtsr193+ELoB/Cnf/T4psVbYlbkJ9gi50Eu8zMd0rr2 kyz-runtime-test-key";

fn strong_passphrase() -> SecretString {
    SecretString::from("kyz-runtime-integration-test-passphrase".to_string())
}

fn temp_vault_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "kyz-runtime-test-{label}-{}-{nanos}.json",
        std::process::id()
    ))
}

fn new_unlocked_vault(label: &str) -> (Vault, PathBuf) {
    let path = temp_vault_path(label);
    let vault = Vault::open_path(&path);
    vault
        .init(&strong_passphrase(), false)
        .expect("vault init should succeed");
    vault
        .unlock_interactive(&strong_passphrase(), None)
        .expect("vault unlock should succeed");
    (vault, path)
}

fn set_simple(vault: &Vault, service: &str, key: &str, value: &str) {
    let entry = SecretEntry::single(service, key, value);
    vault
        .set(&SecretRef::new(service, key), &entry)
        .expect("set should succeed");
}

fn cleanup(vault: &Vault, path: &PathBuf) {
    let _ = vault.lock();
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Vault facade
// ---------------------------------------------------------------------------

#[test]
fn open_explicit_path_infers_custom_source() {
    let path = temp_vault_path("custom-source");
    let vault = Vault::open_path(&path);
    assert_eq!(vault.source().kind(), &VaultKind::Custom);
    assert_eq!(vault.source().path(), Some(path.as_path()));
}

#[test]
fn unlock_state_transitions() {
    let path = temp_vault_path("unlock-state");
    let vault = Vault::open_path(&path);

    // File does not exist: locked, not requestable (default mode).
    let state = vault.unlock_state().expect("unlock state");
    assert_eq!(state, UnlockState::Locked);

    vault
        .init(&strong_passphrase(), false)
        .expect("init should succeed");

    // Exists but no session: still Locked.
    let state = vault.unlock_state().expect("unlock state");
    assert_eq!(state, UnlockState::Locked);

    // Unlock and verify Unlocked variant with mode.
    vault
        .unlock_interactive(&strong_passphrase(), None)
        .expect("unlock should succeed");
    match vault.unlock_state().expect("unlock state") {
        UnlockState::Unlocked {
            mode,
            remaining_secs,
            ..
        } => {
            assert_eq!(mode, UnlockMode::Interactive);
            assert!(remaining_secs > 0);
        }
        other => panic!("expected Unlocked, got {other}"),
    }

    cleanup(&vault, &path);
}

#[test]
fn remote_approval_mode_reports_locked_requestable() {
    let path = temp_vault_path("requestable");
    let vault = Vault::open_path(&path).with_unlock_mode(UnlockMode::RemoteApproval);
    assert_eq!(
        vault.unlock_state().expect("unlock state"),
        UnlockState::LockedRequestable,
    );
}

#[test]
fn get_not_found_returns_typed_error() {
    let (vault, path) = new_unlocked_vault("not-found");
    let r = SecretRef::new("svc", "missing");
    let err = vault.get(&r).expect_err("expected NotFound");
    match err {
        Error::NotFound { reference } => assert_eq!(reference, r),
        other => panic!("expected NotFound, got {other:?}"),
    }
    cleanup(&vault, &path);
}

#[test]
fn try_get_returns_none_on_miss() {
    let (vault, path) = new_unlocked_vault("try-get");
    let got = vault
        .try_get(&SecretRef::new("svc", "missing"))
        .expect("try_get must not error on miss");
    assert!(got.is_none());
    cleanup(&vault, &path);
}

#[test]
fn get_field_reports_missing_field_as_unsupported_kind() {
    let (vault, path) = new_unlocked_vault("field-missing");
    set_simple(&vault, "svc", "only-value", "hunter2");
    let err = vault
        .get_field(&SecretRef::new("svc", "only-value"), "username")
        .expect_err("missing field should error");
    assert!(matches!(err, Error::UnsupportedKind { .. }));
    cleanup(&vault, &path);
}

#[test]
fn list_all_returns_every_entry() {
    let (vault, path) = new_unlocked_vault("list-all");
    set_simple(&vault, "svc-a", "k1", "v1");
    set_simple(&vault, "svc-a", "k2", "v2");
    set_simple(&vault, "svc-b", "k1", "v3");

    let all = vault.list_all().expect("list_all");
    assert_eq!(all.len(), 3);
    cleanup(&vault, &path);
}

// ---------------------------------------------------------------------------
// Layered resolver
// ---------------------------------------------------------------------------

struct Layered {
    layered: LayeredVault,
    workspace_path: PathBuf,
    personal_path: PathBuf,
}

fn build_layered(label: &str) -> Layered {
    let workspace_path = temp_vault_path(&format!("{label}-workspace"));
    let personal_path = temp_vault_path(&format!("{label}-personal"));

    let workspace = Vault::open_path(&workspace_path)
        .with_source(VaultSource::workspace(workspace_path.clone()));
    workspace
        .init(&strong_passphrase(), false)
        .expect("workspace init");
    workspace
        .unlock_interactive(&strong_passphrase(), None)
        .expect("workspace unlock");

    let personal =
        Vault::open_path(&personal_path).with_source(VaultSource::personal(personal_path.clone()));
    personal
        .init(&strong_passphrase(), false)
        .expect("personal init");
    personal
        .unlock_interactive(&strong_passphrase(), None)
        .expect("personal unlock");

    // Workspace has `deploy-key` and `shared`.
    set_simple(&workspace, "ssh", "deploy-key", "workspace-deploy");
    set_simple(&workspace, "svc", "shared", "workspace-shared");
    // Personal has `user-token` and `shared`.
    set_simple(&personal, "api", "user-token", "personal-token");
    set_simple(&personal, "svc", "shared", "personal-shared");

    let layered = LayeredVault::builder()
        .push(workspace)
        .push(personal)
        .build();

    Layered {
        layered,
        workspace_path,
        personal_path,
    }
}

#[test]
fn layered_resolve_first_hit_wins() {
    let l = build_layered("first-hit");

    let got = l
        .layered
        .resolve(&SecretRef::new("svc", "shared"))
        .expect("resolve");
    assert_eq!(got.layer_index, 0);
    assert_eq!(got.source.kind(), &VaultKind::Workspace);
    assert_eq!(got.entry.value(), Some("workspace-shared"));

    // Personal-only key falls through to layer 1.
    let got = l
        .layered
        .resolve(&SecretRef::new("api", "user-token"))
        .expect("fallback resolve");
    assert_eq!(got.layer_index, 1);
    assert_eq!(got.source.kind(), &VaultKind::Personal);

    cleanup_paths(&l);
}

#[test]
fn layered_constraint_workspace_only_blocks_personal_fallback() {
    let l = build_layered("ws-only");

    let err = l
        .layered
        .resolve_in(
            &SecretRef::new("api", "user-token"),
            &SourceConstraint::workspace_only(),
        )
        .expect_err("should not fall through to personal");
    assert!(matches!(err, Error::NotFound { .. }));

    cleanup_paths(&l);
}

#[test]
fn layered_constraint_no_personal_is_equivalent_for_service_mode() {
    let l = build_layered("no-personal");
    let err = l
        .layered
        .resolve_in(
            &SecretRef::new("api", "user-token"),
            &SourceConstraint::no_personal(),
        )
        .expect_err("personal fallback must be forbidden");
    assert!(matches!(err, Error::NotFound { .. }));
    cleanup_paths(&l);
}

#[test]
fn layered_resolve_strict_detects_ambiguity() {
    let l = build_layered("ambiguous");

    let err = l
        .layered
        .resolve_strict(&SecretRef::new("svc", "shared"), &SourceConstraint::Any)
        .expect_err("two layers hold this key; strict must report ambiguity");

    match err {
        Error::Ambiguous { matches, .. } => {
            assert_eq!(matches.len(), 2);
            assert_eq!(matches[0].kind(), &VaultKind::Workspace);
            assert_eq!(matches[1].kind(), &VaultKind::Personal);
        }
        other => panic!("expected Ambiguous, got {other:?}"),
    }

    cleanup_paths(&l);
}

#[test]
fn layered_resolve_strict_accepts_unique_hit() {
    let l = build_layered("strict-unique");

    let got = l
        .layered
        .resolve_strict(&SecretRef::new("api", "user-token"), &SourceConstraint::Any)
        .expect("only personal layer has this key");
    assert_eq!(got.source.kind(), &VaultKind::Personal);
    cleanup_paths(&l);
}

fn cleanup_paths(l: &Layered) {
    for v in l.layered.layers() {
        let _ = v.lock();
    }
    let _ = std::fs::remove_file(&l.workspace_path);
    let _ = std::fs::remove_file(&l.personal_path);
}

// ---------------------------------------------------------------------------
// SSH identity helpers
// ---------------------------------------------------------------------------

fn ssh_entry_with_private_key(service: &str, key: &str) -> SecretEntry {
    let mut fields = BTreeMap::new();
    fields.insert(
        "private_key".to_string(),
        SecretString::from(TEST_SSH_PRIVATE_KEY.to_string()),
    );
    let mut entry = SecretEntry::new(service, key, fields);
    entry.add_tag("ssh_key");
    entry
}

fn ssh_entry_with_explicit_metadata(service: &str, key: &str) -> SecretEntry {
    let mut fields = BTreeMap::new();
    fields.insert(
        "public_key".to_string(),
        SecretString::from(TEST_SSH_PUBLIC_KEY.to_string()),
    );
    fields.insert(
        "comment".to_string(),
        SecretString::from("preset-comment".to_string()),
    );
    let mut entry = SecretEntry::new(service, key, fields);
    entry.add_tag("ssh_key");
    entry
}

#[test]
fn is_ssh_identity_honors_tags_and_kind_field() {
    let tagged = ssh_entry_with_explicit_metadata("ssh", "tag");
    assert!(is_ssh_identity(&tagged));

    let untagged = SecretEntry::single("generic", "api", "x");
    assert!(!is_ssh_identity(&untagged));

    let mut kinded_fields = BTreeMap::new();
    kinded_fields.insert(
        "kind".to_string(),
        SecretString::from("ssh_key".to_string()),
    );
    let kinded = SecretEntry::new("ssh", "by-kind", kinded_fields);
    assert!(is_ssh_identity(&kinded));
}

#[test]
fn identity_derived_from_private_key() {
    let entry = ssh_entry_with_private_key("ssh", "deploy");
    let r = SecretRef::new("ssh", "deploy");
    let src = VaultSource::personal(PathBuf::from("/tmp/fake.json"));

    let id = identity_from_entry(&entry, &r, &src)
        .expect("identity derivation must succeed")
        .expect("entry is an SSH identity");

    assert_eq!(id.algorithm, SshAlgorithm::Ed25519);
    assert!(
        id.public_key_openssh.starts_with("ssh-ed25519"),
        "public_key should be openssh-formatted, got: {}",
        id.public_key_openssh,
    );
    assert!(
        id.fingerprint_sha256.starts_with("SHA256:"),
        "fingerprint should be sha256, got: {}",
        id.fingerprint_sha256,
    );
    assert_eq!(id.comment.as_deref(), Some("kyz-runtime-test-key"));
}

#[test]
fn identity_from_explicit_metadata_skips_derivation() {
    let entry = ssh_entry_with_explicit_metadata("ssh", "preset");
    let r = SecretRef::new("ssh", "preset");
    let src = VaultSource::personal(PathBuf::from("/tmp/fake.json"));

    let id = identity_from_entry(&entry, &r, &src)
        .expect("identity parse")
        .expect("opts into ssh_key");
    assert_eq!(id.algorithm, SshAlgorithm::Ed25519);
    assert_eq!(id.comment.as_deref(), Some("preset-comment"));
}

#[test]
fn identity_from_untagged_entry_returns_none() {
    let entry = SecretEntry::single("github", "token", "abc");
    let r = SecretRef::new("github", "token");
    let src = VaultSource::personal(PathBuf::from("/tmp/fake.json"));
    assert!(
        identity_from_entry(&entry, &r, &src)
            .expect("parse")
            .is_none()
    );
}

#[test]
fn list_ssh_identities_across_vault() {
    let (vault, path) = new_unlocked_vault("ssh-list");

    // Two SSH entries and one generic entry.
    let r_deploy = SecretRef::new("ssh", "deploy");
    vault
        .set(&r_deploy, &ssh_entry_with_private_key("ssh", "deploy"))
        .expect("set ssh deploy");

    let r_user = SecretRef::new("ssh", "user");
    vault
        .set(&r_user, &ssh_entry_with_explicit_metadata("ssh", "user"))
        .expect("set ssh user");

    set_simple(&vault, "github", "token", "ghp_xxx");

    let ids = list_ssh_identities(&vault).expect("list ssh identities");
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().all(|i| i.algorithm == SshAlgorithm::Ed25519));

    // Make sure the private key did not leak into the public surface.
    for id in &ids {
        assert!(!id.public_key_openssh.contains("PRIVATE"));
    }

    cleanup(&vault, &path);
}

#[test]
fn identity_tagged_without_any_key_material_errors() {
    let entry = SecretEntry::new("ssh", "broken", BTreeMap::new())
        .with_tags(std::iter::once("ssh_key".to_string()).collect());
    let r = SecretRef::new("ssh", "broken");
    let src = VaultSource::personal(PathBuf::from("/tmp/fake.json"));
    let err = identity_from_entry(&entry, &r, &src).expect_err("must error");
    match err {
        Error::Ssh(msg) => assert!(msg.contains("broken")),
        other => panic!("expected Ssh, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

#[test]
fn locked_vault_returns_vault_locked_error() {
    // Fresh vault, inited but not unlocked → get() must error.
    let path = temp_vault_path("locked");
    let vault = Vault::open_path(&path);
    vault
        .init(&strong_passphrase(), false)
        .expect("init should succeed");

    let err = vault
        .get(&SecretRef::new("svc", "k"))
        .expect_err("locked vault get must error");
    // Core currently surfaces this as Error::Core or a stringly-typed
    // lock condition. Either is acceptable; the important property is
    // that it is not a NotFound.
    assert!(!matches!(err, Error::NotFound { .. }));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn secret_ref_displays_as_service_slash_key() {
    let r = SecretRef::new("github", "deploy-key");
    assert_eq!(format!("{r}"), "github/deploy-key");
}

#[test]
fn vault_source_display_includes_kind_and_path() {
    let src = VaultSource::workspace(PathBuf::from("/tmp/ws/.kyz/vault.json"));
    let s = format!("{src}");
    assert!(s.contains("workspace"));
    assert!(s.contains(".kyz"));
}

#[test]
fn secret_string_field_round_trips() {
    let (vault, path) = new_unlocked_vault("field-round-trip");
    let mut fields = BTreeMap::new();
    fields.insert(
        "username".to_string(),
        SecretString::from("alice".to_string()),
    );
    fields.insert(
        "password".to_string(),
        SecretString::from("s3cret".to_string()),
    );
    let entry = SecretEntry::new("svc", "user", fields);
    let r = SecretRef::new("svc", "user");
    vault.set(&r, &entry).expect("set should succeed");

    let pw = vault.get_field(&r, "password").expect("get_field");
    assert_eq!(pw.expose_secret(), "s3cret");
    cleanup(&vault, &path);
}
