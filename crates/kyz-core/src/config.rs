//! Configuration types and loading for the application.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use config::{Config, Environment, File, FileFormat, Source};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::paths::{expand_str_path, write_default_config};
use crate::{AppPaths, default_parallelism, env_prefix};

/// Main application configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(
    title = "Application Configuration",
    description = "Main configuration for the application"
)]
pub struct AppConfig {
    /// JSON Schema reference for editor support.
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    #[schemars(skip)]
    pub schema: Option<String>,

    /// Active configuration profile.
    #[schemars(default = "default_profile")]
    pub profile: String,

    /// Logging configuration.
    pub logging: LoggingConfig,

    /// Runtime behavior configuration.
    pub runtime: RuntimeConfig,

    /// Custom paths for data and state directories.
    pub paths: PathsConfig,

    /// Maximum number of history versions to retain per secret entry.
    /// Older versions are discarded on each update. Set to 0 to disable history.
    #[serde(default = "default_history_retention")]
    #[schemars(range(min = 0, max = 100))]
    pub history_retention: u32,

    /// Named aliases for `kyz exec`. Each alias resolves a set of secrets
    /// to inject as environment variables when wrapping a process.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aliases: BTreeMap<String, AliasConfig>,

    /// Credential daemon configuration.
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// HTTP credential proxy configuration.
    #[serde(default)]
    pub proxy: ProxyConfig,

    /// Pinned script grants for `kyz run` (grant name → definition).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scripts: BTreeMap<String, ScriptGrantConfig>,
}

fn default_profile() -> String {
    "default".to_string()
}

impl AppConfig {
    /// Override the profile if a value is provided.
    #[must_use]
    pub fn with_profile_override(mut self, profile: Option<String>) -> Self {
        if let Some(profile) = profile {
            self.profile = profile;
        }
        self
    }

    /// Load configuration from file and environment, creating defaults if needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file cannot be read, parsed, or written.
    pub fn load(paths: &AppPaths, dry_run: bool) -> Result<Self> {
        if !paths.config_file.exists() {
            if dry_run {
                log::info!(
                    "dry-run: would create default config at {}",
                    paths.config_file.display()
                );
            } else {
                write_default_config(&paths.config_file)?;
            }
        }

        Self::load_from_path(&paths.config_file)
    }

    /// Load configuration from a specific path.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file cannot be read or parsed.
    pub fn load_from_path(config_file: &Path) -> Result<Self> {
        Self::load_with_file_source(
            File::from(config_file)
                .format(FileFormat::Toml)
                .required(false),
        )
    }

    /// Load configuration from raw TOML bytes plus environment overrides.
    ///
    /// Callers that already read the file (e.g. to hash it) use this to
    /// parse exactly those bytes, without a second read.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not valid UTF-8 or parsing fails.
    pub fn load_from_bytes(raw: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(raw)
            .map_err(|e| anyhow::anyhow!("config is not valid UTF-8: {e}"))?;
        Self::load_with_file_source(File::from_str(text, FileFormat::Toml))
    }

    /// Build the configuration from a TOML file source plus environment.
    fn load_with_file_source(file: impl Source + Send + Sync + 'static) -> Result<Self> {
        let env_prefix = env_prefix();
        let built = Config::builder()
            .set_default("profile", "default")?
            .set_default("logging.level", "info")?
            .set_default("runtime.parallelism", default_parallelism() as i64)?
            .set_default("runtime.timeout", 60_i64)?
            .set_default("runtime.fail_fast", true)?
            .add_source(file)
            .add_source(Environment::with_prefix(env_prefix.as_str()).separator("__"))
            .build()?;

        let mut config: Self = built.try_deserialize()?;

        if let Some(ref file) = config.logging.file {
            let expanded = expand_str_path(file)?;
            config.logging.file = Some(expanded.display().to_string());
        }

        Ok(config)
    }
}

const fn default_history_retention() -> u32 {
    10
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema: None,
            profile: "default".to_string(),
            logging: LoggingConfig::default(),
            runtime: RuntimeConfig::default(),
            paths: PathsConfig::default(),
            history_retention: default_history_retention(),
            aliases: BTreeMap::new(),
            daemon: DaemonConfig::default(),
            proxy: ProxyConfig::default(),
            scripts: BTreeMap::new(),
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(description = "Logging configuration")]
pub struct LoggingConfig {
    /// Log level (error, warn, info, debug, trace).
    #[schemars(default = "default_log_level")]
    pub level: LogLevel,

    /// Optional path for log file output. Supports ~ and environment variables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

/// Log level enumeration for schema validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Only emit error-level messages.
    Error,
    /// Emit warnings and errors.
    Warn,
    /// Emit informational messages and above (default).
    #[default]
    Info,
    /// Emit debug diagnostics and above.
    Debug,
    /// Emit all messages including fine-grained traces.
    Trace,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => write!(f, "error"),
            Self::Warn => write!(f, "warn"),
            Self::Info => write!(f, "info"),
            Self::Debug => write!(f, "debug"),
            Self::Trace => write!(f, "trace"),
        }
    }
}

const fn default_log_level() -> LogLevel {
    LogLevel::Info
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file: None,
        }
    }
}

/// Runtime behavior configuration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(description = "Runtime behavior configuration")]
pub struct RuntimeConfig {
    /// Worker pool size. Defaults to logical CPU count when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub parallelism: Option<usize>,

    /// Timeout in seconds for long-running operations (default: 60).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub timeout: Option<u64>,

    /// Stop on first error.
    pub fail_fast: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            parallelism: None,
            timeout: Some(60),
            fail_fast: true,
        }
    }
}

/// An alias definition for `kyz exec`.
///
/// Aliases resolve secrets by explicit key references and/or tags. Each
/// resolved secret's fields are injected as environment variables into the
/// wrapped process.
///
/// Field-to-env mapping: by default fields are uppercased
/// (`service/key:field` → `FIELD`). Use `env_map` for explicit overrides.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(description = "Named alias for kyz exec secret injection")]
#[derive(Default)]
pub struct AliasConfig {
    /// Explicit secret references as `"service/key"` strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,

    /// Tags to match. All secrets with *any* of these tags are included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Explicit env-var mappings: `{ "ENV_VAR" = "service/key:field" }`.
    ///
    /// These override the default field-name uppercasing for specific fields.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_map: BTreeMap<String, String>,
}

/// Path override configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(description = "Custom paths for data and state directories")]
pub struct PathsConfig {
    /// Directory for persistent data. Supports ~ and environment variables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,

    /// Directory for state files. Supports ~ and environment variables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<String>,
}

/// Default request body limit for the credential proxy (10 `MiB`).
pub const DEFAULT_REQUEST_BODY_LIMIT_BYTES: u64 = 10 * 1024 * 1024;

/// Default response body limit for the credential proxy (20 `MiB`).
pub const DEFAULT_RESPONSE_BODY_LIMIT_BYTES: u64 = 20 * 1024 * 1024;

/// Default maximum number of in-flight proxy requests.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 32;

/// Maximum accepted `daemon.timeout_secs` / `--timeout` value (366 days).
///
/// Anything larger is indistinguishable from "run until stopped" and is
/// rejected at load time rather than risking an `Instant + Duration`
/// overflow when the deadline is computed.
pub const MAX_TIMEOUT_SECS: u64 = 366 * 24 * 60 * 60;

/// Credential daemon lifecycle and listener configuration.
///
/// Unknown keys are rejected so that multi-vault declarations fail loudly
/// instead of being silently ignored (single-vault is the only supported
/// mode in this version).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(description = "Credential daemon lifecycle and listener configuration")]
pub struct DaemonConfig {
    /// Loopback address the credential proxy binds to (e.g. "127.0.0.1:8477").
    /// Must be a loopback socket address; the management IPC endpoint is not
    /// affected by this setting.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Loopback SocketAddr for the HTTP credential proxy listener")]
    pub listen: Option<String>,

    /// Daemon lifetime in seconds. 0 means run until `kyz daemon stop`,
    /// crash, or reboot. This is independent of vault session timeouts.
    #[schemars(range(min = 0))]
    pub timeout_secs: u64,

    /// Maximum concurrent in-flight proxy requests.
    #[schemars(range(min = 1))]
    pub max_in_flight: usize,

    /// Maximum accepted request body size in bytes.
    #[schemars(range(min = 1))]
    pub request_body_limit_bytes: u64,

    /// Maximum accepted response body size in bytes.
    #[schemars(range(min = 1))]
    pub response_body_limit_bytes: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen: None,
            timeout_secs: 0,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            request_body_limit_bytes: DEFAULT_REQUEST_BODY_LIMIT_BYTES,
            response_body_limit_bytes: DEFAULT_RESPONSE_BODY_LIMIT_BYTES,
        }
    }
}

/// Authentication mode for the HTTP credential proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
#[schemars(description = "Credential proxy authentication mode")]
pub enum ProxyAuthMode {
    /// Require the per-daemon bearer token (default).
    #[default]
    Token,
    /// No proxy authentication (loopback only; same-user attacks remain).
    None,
}

/// HTTP credential proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(default)]
#[schemars(description = "HTTP credential proxy configuration")]
pub struct ProxyConfig {
    /// Proxy authentication mode (default: token).
    pub auth: ProxyAuthMode,

    /// Routing rules. Matching semantics and validation live in
    /// [`crate::proxy_config`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ProxyRuleConfig>,
}

/// Headers stripped from client requests before credentials are injected.
///
/// Additive only: the proxy request sanitizer always strips Authorization,
/// Cookie, Proxy-Authorization, and every injected header name, even when
/// this list is empty.
pub const DEFAULT_STRIP_HEADERS: &[&str] = &["X-Api-Key"];

fn default_strip() -> Vec<String> {
    DEFAULT_STRIP_HEADERS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// One credential proxy routing rule.
///
/// Unknown keys are rejected so per-rule vault declarations fail loudly
/// (single-vault only in this version).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(description = "Credential proxy routing rule")]
pub struct ProxyRuleConfig {
    /// Unique rule name (used in audit events).
    pub name: String,

    /// Host this rule matches after normalization. Exact hostname or a
    /// left-side single-label wildcard (`*.example.com`).
    pub host: String,

    /// Path prefix this rule matches (longest prefix wins). Defaults to `/`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,

    /// Allowed HTTP methods. Defaults to common API methods. `CONNECT` and
    /// `TRACE` are rejected regardless of this list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,

    /// Upstream base URL. Must be `https://` without userinfo.
    pub upstream: String,

    /// Additional client headers stripped before credential injection.
    /// Authorization, Cookie, Proxy-Authorization, and all injected header
    /// names are always stripped, even if this list is empty.
    #[serde(default = "default_strip")]
    pub strip: Vec<String>,

    /// Credentials this rule may resolve, referenced by alias from templates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<ProxyCredentialConfig>,

    /// Header templates. Values support literal text plus `{{alias.field}}`
    /// substitutions only.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,

    /// Static headers added verbatim (no templates allowed here).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub static_headers: BTreeMap<String, String>,
}

impl Default for ProxyRuleConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            host: String::new(),
            path_prefix: None,
            methods: None,
            upstream: String::new(),
            strip: default_strip(),
            credentials: Vec::new(),
            headers: BTreeMap::new(),
            static_headers: BTreeMap::new(),
        }
    }
}

/// A credential binding referenced by alias from header templates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(description = "Credential binding for a proxy rule")]
pub struct ProxyCredentialConfig {
    /// Unique alias within the rule, used as `{{alias.field}}` in templates.
    pub alias: String,

    /// Vault service namespace of the secret entry.
    pub service: String,

    /// Vault key of the secret entry.
    pub key: String,

    /// Fields this credential is allowed to resolve (explicit allowlist).
    pub fields: Vec<String>,
}

/// A pinned script grant for `kyz run`.
///
/// Unknown keys are rejected so per-script vault declarations fail loudly
/// (single-vault only in this version).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(description = "Pinned script grant for kyz run")]
pub struct ScriptGrantConfig {
    /// Canonical absolute path of the script.
    pub path: String,

    /// Hex SHA-256 of the script contents (64 characters).
    pub sha256: String,

    /// Environment the grant may receive: `ENV_VAR -> "service/key:field"`.
    /// This map is the entire permission boundary — fields not listed are
    /// never exposed to the script.
    pub env: BTreeMap<String, String>,
}
