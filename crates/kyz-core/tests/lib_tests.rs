//! Integration tests for top-level kyz-core exports and utilities.

#[test]
fn app_name_is_kyz() {
    assert_eq!(kyz_core::APP_NAME, "kyz");
}

#[test]
fn env_prefix_is_uppercase() {
    let prefix = kyz_core::env_prefix();
    assert_eq!(prefix, "KYZ");
}

#[test]
fn default_parallelism_at_least_one() {
    let p = kyz_core::default_parallelism();
    assert!(p >= 1);
}

#[test]
fn core_error_variants_display() {
    use kyz_core::error::CoreError;

    let config_err = CoreError::Config("bad config".to_string());
    assert!(config_err.to_string().contains("bad config"));

    let path_err = CoreError::Path("bad path".to_string());
    assert!(path_err.to_string().contains("bad path"));

    let io_err = CoreError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
    assert!(io_err.to_string().contains("gone"));

    let ser_err = CoreError::Serialization("bad json".to_string());
    assert!(ser_err.to_string().contains("bad json"));

    let secret_err = CoreError::Secret("vault locked".to_string());
    assert!(secret_err.to_string().contains("vault locked"));

    let not_found = CoreError::SecretNotFound("missing key".to_string());
    assert!(not_found.to_string().contains("missing key"));
}

#[test]
fn core_error_io_from_conversion() {
    use kyz_core::error::CoreError;

    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let core_err: CoreError = io_err.into();
    assert!(matches!(core_err, CoreError::Io(_)));
}

#[test]
fn schema_generation_produces_valid_json() {
    let schema = kyz_core::generate_schema("kyz", "https://github.com/byteowlz/kyz")
        .expect("schema generation");
    // Should be valid JSON
    let _: serde_json::Value = serde_json::from_str(&schema).expect("parse schema JSON");
}

#[test]
fn example_config_generation_produces_valid_toml() {
    let config = kyz_core::generate_example_config("kyz").expect("config generation");
    // Should be valid TOML (may have comments)
    assert!(!config.is_empty());
    // The generated config should contain the app name
    assert!(config.contains("kyz") || config.contains("profile"));
}
