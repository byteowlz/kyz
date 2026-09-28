//! XDG-compliant path resolution for application directories.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(feature = "test-util")]
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};

use crate::{APP_NAME, AppConfig};

/// Application paths for config, data, and state directories.
#[derive(Debug, Clone)]
pub struct AppPaths {
    /// Path to the configuration file.
    pub config_file: PathBuf,
    /// Directory for persistent application data.
    pub data_dir: PathBuf,
    /// Directory for application state files.
    pub state_dir: PathBuf,
}

impl AppPaths {
    /// Discover application paths, optionally overriding the config file location.
    ///
    /// # Errors
    ///
    /// Returns an error if paths cannot be resolved or expanded.
    pub fn discover(override_path: Option<&Path>) -> Result<Self> {
        let config_file = match override_path {
            Some(path) => {
                let expanded = expand_path(path)?;
                if expanded.is_dir() {
                    expanded.join("config.toml")
                } else {
                    expanded
                }
            }
            None => default_config_dir()?.join("config.toml"),
        };

        if config_file.parent().is_none() {
            return Err(anyhow!(
                "invalid config file path: {}",
                config_file.display()
            ));
        }

        let data_dir = default_data_dir()?;
        let state_dir = default_state_dir()?;

        Ok(Self {
            config_file,
            data_dir,
            state_dir,
        })
    }

    /// Apply path overrides from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if override paths cannot be expanded.
    pub fn apply_overrides(mut self, cfg: &AppConfig) -> Result<Self> {
        if let Some(ref data_override) = cfg.paths.data_dir {
            self.data_dir = expand_str_path(data_override)?;
        }
        if let Some(ref state_override) = cfg.paths.state_dir {
            self.state_dir = expand_str_path(state_override)?;
        }
        Ok(self)
    }

    /// Ensure all required directories exist.
    ///
    /// # Errors
    ///
    /// Returns an error if directories cannot be created.
    pub fn ensure_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("creating data directory {}", self.data_dir.display()))?;
        fs::create_dir_all(&self.state_dir)
            .with_context(|| format!("creating state directory {}", self.state_dir.display()))?;
        Ok(())
    }

    /// Log directory creation in dry-run mode.
    pub fn log_dry_run(&self) {
        log::info!(
            "dry-run: would ensure data dir {} and state dir {}",
            self.data_dir.display(),
            self.state_dir.display()
        );
    }
}

impl std::fmt::Display for AppPaths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "config: {}, data: {}, state: {}",
            self.config_file.display(),
            self.data_dir.display(),
            self.state_dir.display()
        )
    }
}

/// Expand a `PathBuf`, resolving ~ and environment variables.
///
/// # Errors
///
/// Returns an error if shell expansion fails.
pub fn expand_path(path: &Path) -> Result<PathBuf> {
    path.to_str()
        .map_or_else(|| Ok(path.to_path_buf()), expand_str_path)
}

/// Expand a string path, resolving ~ and environment variables.
///
/// # Errors
///
/// Returns an error if shell expansion fails.
pub fn expand_str_path(text: &str) -> Result<PathBuf> {
    let expanded = shellexpand::full(text).context("expanding path")?;
    Ok(PathBuf::from(expanded.to_string()))
}

/// Resolve a base directory following the "XDG-everywhere" rule.
///
/// An explicit, absolute `XDG_*` value wins on any operating system. Otherwise,
/// on Windows the platform-specific directory (`%APPDATA%`/`%LOCALAPPDATA%`) is
/// used; on every other platform (including macOS) the XDG-style relative path
/// under `$HOME` is used.
fn resolve_base(
    xdg: Option<PathBuf>,
    home: Option<PathBuf>,
    win_dir: Option<PathBuf>,
    is_windows: bool,
    unix_rel: &str,
) -> Option<PathBuf> {
    if let Some(p) = xdg.filter(|p| p.is_absolute()) {
        return Some(p);
    }
    if is_windows {
        win_dir
    } else {
        home.map(|h| h.join(unix_rel))
    }
}

/// Resolve a base directory from environment variables, then join [`APP_NAME`].
fn base_dir(xdg_var: &str, unix_rel: &str, win_var: &str) -> Result<PathBuf> {
    resolve_base(
        env::var_os(xdg_var).map(PathBuf::from),
        env::var_os("HOME").map(PathBuf::from),
        env::var_os(win_var).map(PathBuf::from),
        cfg!(windows),
        unix_rel,
    )
    .ok_or_else(|| anyhow!("unable to determine base directory ({xdg_var})"))
}

/// Get the default configuration directory (`XDG_CONFIG_HOME` or fallback).
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined.
pub fn default_config_dir() -> Result<PathBuf> {
    Ok(base_dir("XDG_CONFIG_HOME", ".config", "APPDATA")?.join(APP_NAME))
}

/// Get the default data directory (`XDG_DATA_HOME` or fallback).
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined.
pub fn default_data_dir() -> Result<PathBuf> {
    Ok(base_dir("XDG_DATA_HOME", ".local/share", "APPDATA")?.join(APP_NAME))
}

/// Process-wide state-directory override (only compiled for this crate's
/// own tests via the `test-util` feature).
#[cfg(feature = "test-util")]
static STATE_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Override [`default_state_dir`] for the rest of this process.
///
/// Test-only (gated on the `test-util` feature, never enabled for
/// downstream builds): keeps v4-write tests from reading and writing the
/// developer's real actor-state file. Idempotent; the first path wins.
#[cfg(feature = "test-util")]
pub fn set_state_dir_override(path: PathBuf) {
    let _ = STATE_DIR_OVERRIDE.set(path);
}

/// Point [`default_state_dir`] at an isolated per-process temp dir.
///
/// Test-only, like [`set_state_dir_override`]. Shared by this crate's unit
/// tests and integration tests (`tests/common`): v4 writes allocate op ids
/// through the global actor-state directory, and without this every test
/// would accumulate counters for random vault ids in the developer's real
/// `actor-state.json` and contend with a running `kyz` for the actor lock.
///
/// # Errors
///
/// Returns an error if the temp directory cannot be created.
#[cfg(feature = "test-util")]
pub fn isolate_state_dir() -> Result<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static DONE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(dir) = DONE.get() {
        set_state_dir_override(dir.clone());
        return Ok(());
    }
    let dir = std::env::temp_dir().join(format!("kyz-test-state-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating isolated state dir {}", dir.display()))?;
    set_state_dir_override(DONE.get_or_init(|| dir).clone());
    Ok(())
}

/// Get the default state directory (`XDG_STATE_HOME` or fallback).
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined.
pub fn default_state_dir() -> Result<PathBuf> {
    #[cfg(feature = "test-util")]
    if let Some(dir) = STATE_DIR_OVERRIDE.get() {
        return Ok(dir.clone());
    }
    Ok(base_dir("XDG_STATE_HOME", ".local/state", "LOCALAPPDATA")?.join(APP_NAME))
}

/// Get the default cache directory (`XDG_CACHE_HOME` or fallback).
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined.
pub fn default_cache_dir() -> Result<PathBuf> {
    Ok(base_dir("XDG_CACHE_HOME", ".cache", "LOCALAPPDATA")?.join(APP_NAME))
}

/// Write the default configuration file to the specified path.
///
/// # Errors
///
/// Returns an error if the file cannot be written or the directory cannot be created.
pub fn write_default_config(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating config directory {}", parent.display()))?;
    }

    let config = AppConfig::default();
    let toml_str = toml::to_string_pretty(&config).context("serializing default config to TOML")?;
    let mut body = default_config_header(path);
    body.push_str(&toml_str);
    fs::write(path, body).with_context(|| format!("writing config file to {}", path.display()))
}

fn default_config_header(path: &Path) -> String {
    let mut buffer = String::new();
    buffer.push_str("# Configuration for ");
    buffer.push_str(APP_NAME);
    buffer.push('\n');
    buffer.push_str("# File: ");
    buffer.push_str(&path.display().to_string());
    buffer.push('\n');
    buffer.push('\n');
    buffer
}

#[cfg(test)]
mod tests {
    use super::resolve_base;
    use std::path::PathBuf;

    /// Absolute variant of a Unix-style path on the current platform
    /// (`Path::is_absolute` requires a drive prefix on Windows).
    fn abs(p: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:\\{p}"))
        } else {
            PathBuf::from(format!("/{p}"))
        }
    }

    #[test]
    fn absolute_xdg_wins_on_unix() {
        let got = resolve_base(
            Some(abs("xdg/config")),
            Some(PathBuf::from("/home/user")),
            Some(PathBuf::from("C:\\AppData")),
            false,
            ".config",
        );
        assert_eq!(got, Some(abs("xdg/config")));
    }

    #[test]
    fn absolute_xdg_wins_on_windows() {
        let got = resolve_base(
            Some(abs("xdg/config")),
            Some(PathBuf::from("/home/user")),
            Some(PathBuf::from("C:\\AppData")),
            true,
            ".config",
        );
        assert_eq!(got, Some(abs("xdg/config")));
    }

    #[test]
    fn relative_xdg_is_ignored() {
        let got = resolve_base(
            Some(PathBuf::from("relative/config")),
            Some(PathBuf::from("/home/user")),
            None,
            false,
            ".config",
        );
        assert_eq!(got, Some(PathBuf::from("/home/user/.config")));
    }

    #[test]
    fn unix_falls_back_to_home_join_rel() {
        let got = resolve_base(
            None,
            Some(PathBuf::from("/home/user")),
            Some(PathBuf::from("C:\\AppData")),
            false,
            ".local/state",
        );
        assert_eq!(got, Some(PathBuf::from("/home/user/.local/state")));
    }

    #[test]
    fn macos_uses_xdg_style_not_library() {
        // macOS is treated as unix here: no ~/Library.
        let got = resolve_base(
            None,
            Some(PathBuf::from("/Users/user")),
            None,
            false,
            ".config",
        );
        assert_eq!(got, Some(PathBuf::from("/Users/user/.config")));
    }

    #[test]
    fn windows_uses_win_dir() {
        let got = resolve_base(
            None,
            Some(PathBuf::from("/home/user")),
            Some(PathBuf::from("C:\\Users\\u\\AppData\\Roaming")),
            true,
            ".config",
        );
        assert_eq!(got, Some(PathBuf::from("C:\\Users\\u\\AppData\\Roaming")));
    }

    #[test]
    fn unix_without_home_is_none() {
        let got = resolve_base(
            None,
            None,
            Some(PathBuf::from("C:\\AppData")),
            false,
            ".config",
        );
        assert_eq!(got, None);
    }

    #[test]
    fn windows_without_win_dir_is_none() {
        let got = resolve_base(
            None,
            Some(PathBuf::from("/home/user")),
            None,
            true,
            ".config",
        );
        assert_eq!(got, None);
    }
}
