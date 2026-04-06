//! Integration tests for the policy engine.

use std::path::Path;

use kyz_core::policy::{Policy, PolicyViolation, default_policy, resolve_policy};

#[test]
fn default_policy_blocks_dangerous_commands() {
    let policy = default_policy();
    assert!(policy.check_command("cat").is_err());
    assert!(policy.check_command("less").is_err());
    assert!(policy.check_command("more").is_err());
    assert!(policy.check_command("head").is_err());
    assert!(policy.check_command("tail").is_err());
    assert!(policy.check_command("tee").is_err());
    assert!(policy.check_command("echo").is_err());
    assert!(policy.check_command("printf").is_err());
    assert!(policy.check_command("env").is_err());
    assert!(policy.check_command("printenv").is_err());
}

#[test]
fn default_policy_allows_database_tools() {
    let policy = default_policy();
    assert!(policy.check_command("psql").is_ok());
    assert!(policy.check_command("mysql").is_ok());
}

#[test]
fn default_policy_blocks_dangerous_args() {
    let policy = default_policy();
    let args: Vec<String> = vec!["-c".to_string(), "cat /etc/passwd".to_string()];
    assert!(policy.check_args("bash", &args).is_err());
}

#[test]
fn default_policy_allows_safe_args() {
    let policy = default_policy();
    let args: Vec<String> = vec!["--host".to_string(), "db.example.com".to_string()];
    assert!(policy.check_args("psql", &args).is_ok());
}

#[test]
fn policy_per_secret_allowlist() {
    let json = r#"{
        "secrets": {
            "db/prod-password": {
                "allow_commands": ["psql"]
            }
        }
    }"#;
    let policy: Policy = serde_json::from_str(json).expect("parse policy");

    // psql is allowed for this secret
    assert!(
        policy
            .check_secret_command("db/prod-password", "psql")
            .is_ok()
    );

    // curl is NOT allowed for this secret
    assert!(
        policy
            .check_secret_command("db/prod-password", "curl")
            .is_err()
    );

    // other secrets aren't restricted
    assert!(policy.check_secret_command("other/secret", "curl").is_ok());
}

#[test]
fn policy_allowlist_mode() {
    let json = r#"{
        "allow_commands": ["psql", "mysql"]
    }"#;
    let policy: Policy = serde_json::from_str(json).expect("parse policy");

    assert!(policy.check_command("psql").is_ok());
    assert!(policy.check_command("mysql").is_ok());
    assert!(policy.check_command("curl").is_err());
    assert!(policy.check_command("node").is_err());
}

#[test]
fn empty_policy_allows_everything() {
    let policy = Policy::default();
    assert!(policy.check_command("anything").is_ok());
    assert!(policy.check_args("cmd", &["--flag".to_string()]).is_ok());
}

#[test]
fn policy_check_all_validates_everything() {
    let policy = default_policy();
    // Safe command + safe args + no per-secret restriction
    assert!(
        policy
            .check_all(
                "psql",
                &["--host".to_string(), "db".to_string()],
                &["generic/secret".to_string()]
            )
            .is_ok()
    );

    // Dangerous command
    assert!(
        policy
            .check_all("cat", &[], &["generic/secret".to_string()])
            .is_err()
    );

    // Dangerous args
    assert!(
        policy
            .check_all(
                "psql",
                &["-c".to_string(), "cat /etc/passwd".to_string()],
                &["generic/secret".to_string()]
            )
            .is_err()
    );
}

#[test]
fn resolve_policy_with_no_policy_flag() {
    let policy = resolve_policy(None, true).expect("resolve");
    // no_policy should return an empty (permissive) policy
    assert!(policy.check_command("cat").is_ok());
}

#[test]
fn resolve_policy_missing_explicit_path_errors() {
    let result = resolve_policy(Some(Path::new("/nonexistent/policy.json")), false);
    assert!(result.is_err());
}

#[test]
fn resolve_policy_default_when_no_file() {
    // No explicit path, no_policy=false, and no local policy file
    // Should fall back to default_policy
    let policy = resolve_policy(None, false).expect("resolve");
    assert!(policy.check_command("cat").is_err());
}

#[test]
fn policy_violation_display() {
    let violation = PolicyViolation {
        reason: "test reason".to_string(),
    };
    let display = format!("{violation}");
    assert!(display.contains("test reason"));
    assert!(display.contains("policy violation"));
}

#[test]
fn policy_deny_args_blocks_eval_flags() {
    let policy = default_policy();
    for flag in &["-c", "-e", "--eval", "-exec", "--exec"] {
        let args = vec![flag.to_string()];
        assert!(
            policy.check_args("cmd", &args).is_err(),
            "flag {flag} should be denied"
        );
    }
}

#[test]
fn policy_allows_full_path_commands() {
    let policy = default_policy();
    assert!(policy.check_command("/usr/bin/psql").is_ok());
    assert!(policy.check_command("/usr/bin/cat").is_err());
}

#[test]
fn policy_per_secret_with_full_path() {
    let json = r#"{
        "secrets": {
            "db/prod": {
                "allow_commands": ["psql"]
            }
        }
    }"#;
    let policy: Policy = serde_json::from_str(json).expect("parse policy");

    assert!(
        policy
            .check_secret_command("db/prod", "/usr/bin/psql")
            .is_ok()
    );
    assert!(
        policy
            .check_secret_command("db/prod", "/usr/bin/curl")
            .is_err()
    );
}

#[test]
fn policy_load_from_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_file = dir.path().join("policy.json");
    std::fs::write(
        &policy_file,
        r#"{"deny_commands": ["custom-cmd"], "allow_commands": []}"#,
    )
    .expect("write");

    let policy = kyz_core::policy::load_policy(&policy_file).expect("load");
    assert!(policy.check_command("custom-cmd").is_err());
    assert!(policy.check_command("other").is_ok());
}

#[test]
fn policy_serialization_roundtrip() {
    let policy = default_policy();
    let json = serde_json::to_string(&policy).expect("serialize");
    let parsed: Policy = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed.deny_commands.len(), policy.deny_commands.len());
    assert_eq!(parsed.deny_args.len(), policy.deny_args.len());
}
