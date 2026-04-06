//! Integration tests for XDG path resolution.

use std::path::PathBuf;

use kyz_core::paths::{AppPaths, default_cache_dir};

#[test]
fn app_paths_discover_default() {
    let paths = AppPaths::discover(None).expect("discover paths");
    assert!(paths.config_file.to_string_lossy().contains("kyz"));
    assert!(paths.data_dir.to_string_lossy().contains("kyz"));
    assert!(paths.state_dir.to_string_lossy().contains("kyz"));
}

#[test]
fn app_paths_discover_with_override_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let custom = dir.path().join("custom-config.toml");
    std::fs::write(&custom, "").expect("create file");

    let paths = AppPaths::discover(Some(&custom)).expect("discover paths");
    assert_eq!(paths.config_file, custom);
}

#[test]
fn app_paths_discover_with_override_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths::discover(Some(dir.path())).expect("discover paths");
    assert!(paths.config_file.ends_with("config.toml"));
    assert!(
        paths
            .config_file
            .parent()
            .expect("parent")
            .ends_with(dir.path().file_name().expect("name"))
    );
}

#[test]
fn app_paths_ensure_directories() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths {
        config_file: dir.path().join("kyz/config.toml"),
        data_dir: dir.path().join("kyz-data"),
        state_dir: dir.path().join("kyz-state"),
    };

    paths.ensure_directories().expect("ensure dirs");
    assert!(dir.path().join("kyz-data").is_dir());
    assert!(dir.path().join("kyz-state").is_dir());
}

#[test]
fn app_paths_display() {
    let paths = AppPaths {
        config_file: PathBuf::from("/a/config.toml"),
        data_dir: PathBuf::from("/b/data"),
        state_dir: PathBuf::from("/c/state"),
    };
    let display = format!("{paths}");
    assert!(display.contains("/a/config.toml"));
    assert!(display.contains("/b/data"));
    assert!(display.contains("/c/state"));
}

#[test]
fn default_cache_dir_contains_app_name() {
    let dir = default_cache_dir().expect("cache dir");
    assert!(dir.to_string_lossy().contains("kyz"));
}

#[test]
fn app_paths_apply_overrides() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths {
        config_file: dir.path().join("config.toml"),
        data_dir: dir.path().join("default-data"),
        state_dir: dir.path().join("default-state"),
    };

    let mut config = kyz_core::AppConfig::default();
    let override_data = dir.path().join("custom-data");
    config.paths.data_dir = Some(override_data.to_string_lossy().to_string());

    let overridden = paths.apply_overrides(&config).expect("apply overrides");
    assert_eq!(overridden.data_dir, override_data);
    // state_dir should remain unchanged since we didn't override it
    assert_eq!(overridden.state_dir, dir.path().join("default-state"));
}
