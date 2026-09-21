//! Regression tests for audit run-2 fixes: grant upsert hijack (F3), env-name
//! safety filter (run-1 F3), KDF parameter clamping (run-1 F5), policy
//! unioning (F2).

use kyz_core::jit::{DecisionReason, GrantScope, GrantStore, GrantUseContext, JitGrant};
use kyz_core::policy::{Policy, default_policy, is_safe_exec_env_name, union_deny_lists};
use kyz_core::vault_v3::KdfParams;

fn grant(token: &str, expires_at: u64, use_count: u32, commands: Vec<&str>) -> JitGrant {
    JitGrant {
        token: token.to_string(),
        scope: GrantScope {
            secret_refs: vec!["github/token".to_string()],
            commands: commands.iter().map(|c| (*c).to_string()).collect(),
            workspaces: Vec::new(),
        },
        expires_at,
        use_count,
    }
}

#[test]
fn live_grant_cannot_be_overwritten() {
    let mut store = GrantStore::new();
    let now = 1_000_u64;

    store
        .insert(grant("grant-1", 2_000, 1, vec!["gh"]), now)
        .expect("initial insert");

    // A second issuer must not silently widen the pending grant.
    let hijack = store.insert(grant("grant-1", 9_999, 999, Vec::new()), now);
    assert_eq!(hijack, Err(DecisionReason::AlreadyExists));

    // The original narrow scope is still in force.
    let ctx = GrantUseContext {
        secret_ref: "github/token",
        command: "curl",
        workspace: "/tmp",
    };
    assert_eq!(
        store.validate_and_consume("grant-1", &ctx, now),
        Err(DecisionReason::OutOfScope)
    );
}

#[test]
fn expired_grant_may_be_replaced() {
    let mut store = GrantStore::new();
    store
        .insert(grant("grant-1", 1_000, 1, vec!["gh"]), 500)
        .expect("initial insert");
    store
        .insert(grant("grant-1", 3_000, 5, Vec::new()), 2_000)
        .expect("replace after expiry");
}

#[test]
fn unsafe_env_names_are_rejected() {
    assert!(!is_safe_exec_env_name("LD_PRELOAD"));
    assert!(!is_safe_exec_env_name("DYLD_INSERT_LIBRARIES"));
    assert!(!is_safe_exec_env_name("LD_LIBRARY_PATH"));
    assert!(!is_safe_exec_env_name("PATH"));
    assert!(!is_safe_exec_env_name("BASH_ENV"));
    assert!(!is_safe_exec_env_name("IFS"));
    assert!(!is_safe_exec_env_name("KYZ_VAULT_PASSWORD"));
    assert!(!is_safe_exec_env_name("1EVIL"));
    assert!(!is_safe_exec_env_name("A B"));

    assert!(is_safe_exec_env_name("GH_TOKEN"));
    assert!(is_safe_exec_env_name("DATABASE_URL"));
    assert!(is_safe_exec_env_name("_PRIVATE"));
    assert!(is_safe_exec_env_name("VALUE"));
}

#[test]
fn repo_policy_unions_with_defaults_instead_of_replacing() {
    // A hostile `{}` policy must not disable the default deny-lists.
    let mut hostile = serde_json::from_str::<Policy>("{}").expect("parse");
    union_deny_lists(&mut hostile, &default_policy());
    assert!(hostile.check_command("cat").is_err());
    assert!(hostile.check_command("printenv").is_err());
    assert!(hostile.check_args("cat", &["-c".to_string()]).is_err());

    // A repo policy may still tighten beyond the defaults.
    let mut repo = Policy {
        deny_commands: vec!["curl".to_string()],
        ..Policy::default()
    };
    union_deny_lists(&mut repo, &default_policy());
    assert!(repo.check_command("curl").is_err());
    assert!(repo.check_command("cat").is_err());
    // Per-secret restrictions from the repo are preserved.
    assert!(repo.secrets.is_empty());
}

#[test]
fn hostile_kdf_parameters_are_rejected_before_derivation() {
    let mut hostile = KdfParams::with_random_salt().expect("params");
    hostile.log_n = 30; // 1 TiB working area — must be refused, not allocated
    assert!(hostile.validate_params().is_err());

    hostile.log_n = 5; // below floor
    assert!(hostile.validate_params().is_err());

    let mut bad_r = KdfParams::with_random_salt().expect("params");
    bad_r.r = 0;
    assert!(bad_r.validate_params().is_err());

    let mut bad_p = KdfParams::with_random_salt().expect("params");
    bad_p.p = u32::MAX;
    assert!(bad_p.validate_params().is_err());

    let good = KdfParams::with_random_salt().expect("params");
    assert!(good.validate_params().is_ok());
}
