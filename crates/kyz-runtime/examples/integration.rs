//! Minimal library-only integration example.
//!
//! Demonstrates:
//!   1. Opening two vault sources (workspace + personal) via the
//!      runtime facade.
//!   2. Composing them into a `LayeredVault` with workspace-first,
//!      personal-fallback precedence.
//!   3. Resolving a [`SecretRef`] and inspecting provenance.
//!   4. Enforcing service-mode semantics by forbidding personal
//!      fallback.
//!
//! Run with:
//!
//! ```bash
//! cargo run --example integration -p kyz-runtime
//! ```

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::SecretString;

use kyz_runtime::{
    LayeredVault, SecretEntry, SecretRef, SourceConstraint, UnlockMode, Vault, VaultSource,
};

fn main() -> Result<(), Box<dyn StdError>> {
    let root = tempdir_path("kyz-runtime-example");
    let workspace_path = root.join("ws/.kyz/vault.json");
    let personal_path = root.join("central/vault.json");

    let workspace_dir = workspace_path
        .parent()
        .ok_or("workspace path has no parent")?;
    let personal_dir = personal_path
        .parent()
        .ok_or("personal path has no parent")?;
    std::fs::create_dir_all(workspace_dir)?;
    std::fs::create_dir_all(personal_dir)?;

    let passphrase = SecretString::from("demo-passphrase-please-change".to_string());

    // Open + init + unlock the workspace vault.
    let workspace = Vault::open_path(workspace_path.clone())
        .with_source(VaultSource::workspace(workspace_path))
        .with_unlock_mode(UnlockMode::Interactive);
    workspace.init(&passphrase, false)?;
    workspace.unlock_interactive(&passphrase, None)?;

    // Open + init + unlock the personal vault.
    let personal = Vault::open_path(personal_path.clone())
        .with_source(VaultSource::personal(personal_path))
        .with_unlock_mode(UnlockMode::Interactive);
    personal.init(&passphrase, false)?;
    personal.unlock_interactive(&passphrase, None)?;

    // Seed workspace with a deploy key; personal with a user token.
    let r_deploy = SecretRef::new("ssh", "deploy-key");
    workspace.set(
        &r_deploy,
        &entry("ssh", "deploy-key", "workspace-deploy-value"),
    )?;
    let r_user = SecretRef::new("api", "user-token");
    personal.set(&r_user, &entry("api", "user-token", "personal-token-value"))?;

    // Compose the layered vault: workspace first, personal fallback.
    let layered = LayeredVault::builder()
        .push(workspace)
        .push(personal)
        .build();

    // Workspace-scoped resolve: deploy key comes from workspace.
    let hit = layered.resolve(&r_deploy)?;
    println!(
        "deploy-key resolved from source={} (layer {})",
        hit.source, hit.layer_index,
    );

    // Falls through to personal for a user-scoped secret.
    let hit = layered.resolve(&r_user)?;
    println!(
        "user-token resolved from source={} (layer {})",
        hit.source, hit.layer_index,
    );

    // Service-mode semantics: forbid personal fallback. This must
    // fail for the user token, because it only lives in the personal
    // vault.
    let result = layered.resolve_in(&r_user, &SourceConstraint::no_personal());
    println!("service-mode personal fallback denied? {}", result.is_err());

    // Tear down sessions and the scratch directory.
    for v in layered.layers() {
        v.lock()?;
    }
    let _ = std::fs::remove_dir_all(&root);

    Ok(())
}

fn entry(service: &str, key: &str, value: &str) -> SecretEntry {
    let mut fields = BTreeMap::new();
    fields.insert("value".to_string(), SecretString::from(value.to_string()));
    SecretEntry::new(service, key, fields)
}

fn tempdir_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("{label}-{}-{nanos}", std::process::id()))
}
