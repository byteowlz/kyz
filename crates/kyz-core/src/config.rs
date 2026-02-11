//! Configuration types and loading for the application.

use std::path::Path;

use anyhow::Result;
use config::{Config, Environment, File, FileFormat};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::paths::{expand_str_path, write_default_config};
use crate::{default_parallelism, env_prefix, AppPaths};

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
        let env_prefix = env_prefix();
        let built = Config::builder()
            .set_default("profile", "default")?
            .set_default("logging.level", "info")?
            .set_default("runtime.parallelism", default_parallelism() as i64)?
            .set_default("runtime.timeout", 60_i64)?
            .set_default("runtime.fail_fast", true)?
            .add_source(
                File::from(config_file)
                    .format(FileFormat::Toml)
                    .required(false),
            )
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

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema: None,
            profile: "default".to_string(),
            logging: LoggingConfig::default(),
            runtime: RuntimeConfig::default(),
            paths: PathsConfig::default(),
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
