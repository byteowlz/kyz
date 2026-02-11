//! Core library for kyz - a cross-platform secrets manager.
//!
//! This crate provides:
//! - Configuration loading and management
//! - XDG-compliant path resolution
//! - Schema and example config generation
//! - Multi-field secret entry data model
//! - Secret store abstraction trait
//! - OS keyring backend (desktop sessions)
//! - Age-encrypted vault backend (headless/agent use)
//! - Vault session management (unlock/lock lifecycle)
//! - Common types and error handling

pub mod config;
pub mod error;
pub mod paths;
pub mod schema;
pub mod store;

pub use config::{AppConfig, LogLevel, LoggingConfig, PathsConfig, RuntimeConfig};
pub use error::{CoreError, Result};
pub use paths::{AppPaths, default_cache_dir};
pub use schema::{generate_example_config, generate_schema, write_generated_files};
pub use store::{
    KeyringStore, SecretEntry, SecretStore, SecretSummary, VaultData, VaultSession, VaultStatus,
    VaultStore,
};

/// Application name used for config directories and environment prefix.
pub const APP_NAME: &str = "kyz";

/// Returns the environment variable prefix for this application.
#[must_use]
pub fn env_prefix() -> String {
    APP_NAME
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Returns the default parallelism based on available CPU cores.
#[must_use]
pub fn default_parallelism() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
}
