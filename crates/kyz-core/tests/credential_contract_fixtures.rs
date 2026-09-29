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
//! Conformance fixtures for the credential access contract
//! (`docs/contracts/credential-access`): every valid fixture must pass the
//! schema and every invalid fixture must fail it.

use std::path::{Path, PathBuf};

fn contract_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts/credential-access")
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn fixtures(kind: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(contract_dir().join("fixtures").join(kind))
        .expect("fixture dir")
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
}

fn validator() -> jsonschema::Validator {
    let schema = read_json(&contract_dir().join("credential-access.schema.json"));
    jsonschema::draft202012::new(&schema).expect("schema compiles")
}

#[test]
fn valid_fixtures_pass_the_schema() {
    let validator = validator();
    let paths = fixtures("valid");
    assert!(
        paths.len() >= 10,
        "expected valid fixtures, found {}",
        paths.len()
    );
    for path in paths {
        let message = read_json(&path);
        let errors: Vec<String> = validator
            .iter_errors(&message)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "{} rejected: {errors:#?}",
            path.display()
        );
    }
}

#[test]
fn invalid_fixtures_fail_the_schema() {
    let validator = validator();
    let paths = fixtures("invalid");
    assert!(
        paths.len() >= 10,
        "expected invalid fixtures, found {}",
        paths.len()
    );
    for path in paths {
        let fixture = read_json(&path);
        let why = fixture["why"].as_str().expect("invalid fixture states why");
        assert!(
            !validator.is_valid(&fixture["message"]),
            "{} accepted, but must fail: {why}",
            path.display()
        );
    }
}
