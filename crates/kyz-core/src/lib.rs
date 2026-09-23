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

pub mod agent_ctx;
pub mod audit;
pub mod auth_request;
pub mod config;
pub mod error;
pub mod jit;
pub mod paths;
pub mod policy;
pub mod proxy_config;
pub mod scan;
pub mod schema;
pub mod store;
pub mod vault_v3;
pub mod workspace_trust;

pub use agent_ctx::{AgentContext, RunMode};
pub use auth_request::{
    AuthRequest, AuthRequestEvent, AuthRequestId, AuthRequestStatus, AuthRequestStore,
    CreateAuthRequest, DenyAuthRequest, generate_pickup_capability,
};
pub use config::{
    AliasConfig, AppConfig, DaemonConfig, LogLevel, LoggingConfig, PathsConfig, ProxyAuthMode,
    ProxyConfig, ProxyCredentialConfig, ProxyRuleConfig, RuntimeConfig, ScriptGrantConfig,
};
pub use error::{CoreError, Result};
pub use jit::{
    DecisionReason, GrantScope, GrantStore, GrantUseContext, JitGrant, OneTimeSecretSubmission,
    OneTimeSubmissionStore, OriginMetadata, StoredSubmission,
};
pub use paths::{AppPaths, default_cache_dir};
pub use policy::{Policy, PolicyViolation, default_policy, is_safe_exec_env_name, resolve_policy};
pub use proxy_config::{
    ConfigValidationError, RuleMatch, TemplateRenderError, TemplateVar, host_matches, match_rule,
    method_allowed, normalize_host, parse_secret_ref, parse_template_vars, render_template,
    upstream_host, validate_app_config, validate_host_pattern, validate_upstream,
};
pub use schema::{generate_example_config, generate_schema, write_generated_files};
pub use store::{
    DEFAULT_HISTORY_RETENTION, EncryptedEntry, HistoryEntry, KeyringStore, SecretEntry,
    SecretStore, SecretSummary, UnlockedVault, VaultData, VaultFileV2, VaultSession, VaultStatus,
    VaultStore, decrypt_entry, encrypt_entry, env_vault_path, fnv1a_64, list_environments,
};
pub use vault_v3::{
    DK_LEN, EncryptedEntryV3, HistoryEntryV3, KdfParams, MAX_KDF_LOG_N, MAX_KDF_P, MAX_KDF_R,
    MIN_KDF_LOG_N, VaultFileV3, decrypt_entry_v3, derive_kek, encrypt_entry_v3, migrate_v2_to_v3,
};
pub use workspace_trust::{
    fingerprint as workspace_vault_fingerprint, is_trusted as workspace_vault_is_trusted,
    is_workspace_vault_path, record_trust as workspace_vault_record_trust,
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
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}
