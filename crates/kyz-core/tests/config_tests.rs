//! Integration tests for configuration loading, defaults, and overrides.

use std::collections::BTreeMap;
use std::io::Write as _;

use kyz_core::config::{AliasConfig, AppConfig, LogLevel, PathsConfig, RuntimeConfig};

#[test]
fn default_config_has_sane_values() {
    let cfg = AppConfig::default();
    assert_eq!(cfg.profile, "default");
    assert!(matches!(cfg.logging.level, LogLevel::Info));
    assert!(cfg.runtime.fail_fast);
    assert_eq!(cfg.runtime.timeout, Some(60));
    assert_eq!(cfg.history_retention, 10);
    assert!(cfg.aliases.is_empty());
}

#[test]
fn config_profile_override() {
    let cfg = AppConfig::default().with_profile_override(Some("staging".to_string()));
    assert_eq!(cfg.profile, "staging");
}

#[test]
fn config_profile_override_none_keeps_default() {
    let cfg = AppConfig::default().with_profile_override(None);
    assert_eq!(cfg.profile, "default");
}

#[test]
fn config_serialization_roundtrip() {
    let cfg = AppConfig::default();
    let toml_str = toml::to_string_pretty(&cfg).expect("serializing default config should succeed");
    let parsed: AppConfig =
        toml::from_str(&toml_str).expect("parsing serialized config should succeed");
    assert_eq!(parsed.profile, cfg.profile);
    assert_eq!(parsed.history_retention, cfg.history_retention);
}

#[test]
fn alias_config_default_is_empty() {
    let alias = AliasConfig::default();
    assert!(alias.secrets.is_empty());
    assert!(alias.tags.is_empty());
    assert!(alias.env_map.is_empty());
}

#[test]
fn alias_config_serialization_roundtrip() {
    let mut alias = AliasConfig::default();
    alias.secrets = vec!["github/token".to_string()];
    alias.tags = vec!["prod".to_string()];
    alias.env_map = BTreeMap::from([("GH_TOKEN".to_string(), "github/token:value".to_string())]);

    let json = serde_json::to_string(&alias).expect("serialize alias");
    let parsed: AliasConfig = serde_json::from_str(&json).expect("parse alias");
    assert_eq!(parsed.secrets, alias.secrets);
    assert_eq!(parsed.tags, alias.tags);
    assert_eq!(parsed.env_map, alias.env_map);
}

#[test]
fn runtime_config_defaults() {
    let rt = RuntimeConfig::default();
    assert!(rt.parallelism.is_none());
    assert_eq!(rt.timeout, Some(60));
    assert!(rt.fail_fast);
}

#[test]
fn paths_config_defaults_are_none() {
    let paths = PathsConfig::default();
    assert!(paths.data_dir.is_none());
    assert!(paths.state_dir.is_none());
}

#[test]
fn log_level_display() {
    assert_eq!(format!("{}", LogLevel::Error), "error");
    assert_eq!(format!("{}", LogLevel::Warn), "warn");
    assert_eq!(format!("{}", LogLevel::Info), "info");
    assert_eq!(format!("{}", LogLevel::Debug), "debug");
    assert_eq!(format!("{}", LogLevel::Trace), "trace");
}

#[test]
fn config_load_from_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_file = dir.path().join("config.toml");
    let mut f = std::fs::File::create(&config_file).expect("create config");
    writeln!(f, "profile = \"test-profile\"").expect("write");
    writeln!(f, "history_retention = 5").expect("write");
    writeln!(f, "[logging]").expect("write");
    writeln!(f, "level = \"debug\"").expect("write");

    let cfg = AppConfig::load_from_path(&config_file).expect("load config");
    assert_eq!(cfg.profile, "test-profile");
    assert_eq!(cfg.history_retention, 5);
    assert!(matches!(cfg.logging.level, LogLevel::Debug));
}

#[test]
fn config_load_missing_file_uses_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_file = dir.path().join("nonexistent.toml");

    let cfg = AppConfig::load_from_path(&config_file).expect("load config");
    assert_eq!(cfg.profile, "default");
}

#[test]
fn config_with_aliases() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_file = dir.path().join("config.toml");
    let mut f = std::fs::File::create(&config_file).expect("create config");
    writeln!(f, "[aliases.deploy]").expect("write");
    writeln!(f, "secrets = [\"aws/prod-key\"]").expect("write");
    writeln!(f, "tags = [\"deploy\"]").expect("write");

    let cfg = AppConfig::load_from_path(&config_file).expect("load config");
    assert!(cfg.aliases.contains_key("deploy"));
    let alias = &cfg.aliases["deploy"];
    assert_eq!(alias.secrets, vec!["aws/prod-key"]);
    assert_eq!(alias.tags, vec!["deploy"]);
}
