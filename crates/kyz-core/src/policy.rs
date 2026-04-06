//! Command policy engine for kyz secret injection.
//!
//! Controls which commands can receive secrets via `kyz exec`, `kyz pipe`,
//! and `kyz wrap`. Blocks dangerous commands that could trivially exfiltrate
//! secret values (e.g., `cat`, `echo`, `env`).
//!
//! Policies are loaded from `.kyz-policy.json` in the current directory,
//! workspace, or `$XDG_CONFIG_HOME/kyz/policy.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

/// Command policy for secret injection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    /// Commands that are always denied (basename matching).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_commands: Vec<String>,

    /// If non-empty, only these commands are allowed (allowlist mode).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_commands: Vec<String>,

    /// Command arguments that suggest shell-like inline execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_args: Vec<String>,

    /// Per-secret command restrictions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretPolicy>,
}

/// Per-secret policy overrides.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretPolicy {
    /// Only these commands may use this secret.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_commands: Vec<String>,
}

/// Result of a policy check.
#[derive(Debug, Clone)]
pub struct PolicyViolation {
    /// Human-readable reason for the violation.
    pub reason: String,
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy violation: {}", self.reason)
    }
}

// ---------------------------------------------------------------------------
// Default policy
// ---------------------------------------------------------------------------

/// Commands that trivially exfiltrate env vars or stdin to stdout.
const DANGEROUS_COMMANDS: &[&str] = &[
    "cat", "echo", "printf", "tee", "less", "more", "head", "tail", "xxd", "hexdump", "od",
    "strings", "base64", "env", "printenv", "set", "export",
];

/// Command arguments that enable arbitrary inline code execution.
const DANGEROUS_ARGS: &[&str] = &["-c", "-e", "--eval", "-exec", "--exec"];

/// Returns the default secure policy.
#[must_use]
pub fn default_policy() -> Policy {
    Policy {
        deny_commands: DANGEROUS_COMMANDS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        allow_commands: Vec::new(),
        deny_args: DANGEROUS_ARGS.iter().map(|s| (*s).to_string()).collect(),
        secrets: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Policy checking
// ---------------------------------------------------------------------------

impl Policy {
    /// Check if a command is allowed by this policy.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyViolation` if the command is denied.
    pub fn check_command(&self, command: &str) -> Result<(), PolicyViolation> {
        let base = Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command);

        // Check deny list
        for denied in &self.deny_commands {
            if base == denied || command == denied {
                return Err(PolicyViolation {
                    reason: format!("command '{base}' is denied by policy (could expose secrets)"),
                });
            }
        }

        // If allow list exists, command must be in it
        if !self.allow_commands.is_empty()
            && !self
                .allow_commands
                .iter()
                .any(|a| base == a || command == a)
        {
            return Err(PolicyViolation {
                reason: format!("command '{base}' is not in the allowed commands list"),
            });
        }

        Ok(())
    }

    /// Check if command arguments contain dangerous patterns.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyViolation` if dangerous args are found.
    pub fn check_args(&self, command: &str, args: &[String]) -> Result<(), PolicyViolation> {
        let base = Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command);

        for arg in args {
            if self.deny_args.iter().any(|d| arg == d) {
                return Err(PolicyViolation {
                    reason: format!(
                        "argument '{arg}' to '{base}' could enable arbitrary code execution — use --no-policy to override"
                    ),
                });
            }
        }

        Ok(())
    }

    /// Check if a specific secret is allowed with a specific command.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyViolation` if the secret cannot be used with the command.
    pub fn check_secret_command(
        &self,
        secret_name: &str,
        command: &str,
    ) -> Result<(), PolicyViolation> {
        // First check global policy
        self.check_command(command)?;

        // Then check per-secret restrictions
        if let Some(rule) = self.secrets.get(secret_name)
            && !rule.allow_commands.is_empty()
        {
            let base = Path::new(command)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(command);

            if !rule
                .allow_commands
                .iter()
                .any(|a| base == a || command == a)
            {
                return Err(PolicyViolation {
                    reason: format!("secret '{secret_name}' cannot be used with command '{base}'"),
                });
            }
        }

        Ok(())
    }

    /// Run all checks for a command + args + secret names.
    ///
    /// # Errors
    ///
    /// Returns the first `PolicyViolation` found.
    pub fn check_all(
        &self,
        command: &str,
        args: &[String],
        secret_names: &[String],
    ) -> Result<(), PolicyViolation> {
        self.check_command(command)?;
        self.check_args(command, args)?;
        for secret in secret_names {
            self.check_secret_command(secret, command)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

/// Search for a policy file in standard locations.
///
/// Order: `.kyz-policy.json` (cwd) → `.kyz/policy.json` (workspace) →
/// `$XDG_CONFIG_HOME/kyz/policy.json` (global).
#[must_use]
pub fn find_policy_file() -> Option<PathBuf> {
    // Current directory
    let cwd = Path::new(".kyz-policy.json");
    if cwd.exists() {
        return Some(cwd.to_path_buf());
    }

    // Workspace
    let workspace = Path::new(".kyz/policy.json");
    if workspace.exists() {
        return Some(workspace.to_path_buf());
    }

    // XDG config
    if let Some(config_dir) = dirs::config_dir() {
        let global = config_dir.join("kyz").join("policy.json");
        if global.exists() {
            return Some(global);
        }
    }

    None
}

/// Load a policy from a file path.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("reading policy file: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("parsing policy: {e}"))
}

/// Resolve the active policy: explicit path → auto-discovered → default.
///
/// # Errors
///
/// Returns an error if an explicit policy file cannot be loaded.
pub fn resolve_policy(explicit_path: Option<&Path>, no_policy: bool) -> Result<Policy, String> {
    if no_policy {
        return Ok(Policy::default());
    }

    if let Some(path) = explicit_path {
        return load_policy(path);
    }

    if let Some(path) = find_policy_file() {
        return load_policy(&path);
    }

    Ok(default_policy())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_blocks_cat() {
        let policy = default_policy();
        assert!(policy.check_command("cat").is_err());
        assert!(policy.check_command("/usr/bin/cat").is_err());
    }

    #[test]
    fn test_default_allows_psql() {
        let policy = default_policy();
        assert!(policy.check_command("psql").is_ok());
    }

    #[test]
    fn test_deny_args_blocks_dash_c() {
        let policy = default_policy();
        assert!(
            policy
                .check_args("bash", &["-c".to_string(), "echo hi".to_string()])
                .is_err()
        );
    }

    #[test]
    fn test_allow_bash_with_script() {
        let policy = default_policy();
        assert!(policy.check_command("bash").is_ok());
        assert!(
            policy
                .check_args("bash", &["deploy.sh".to_string()])
                .is_ok()
        );
    }

    #[test]
    fn test_per_secret_allowlist() {
        let mut policy = default_policy();
        policy.secrets.insert(
            "db-password".to_string(),
            SecretPolicy {
                allow_commands: vec!["psql".to_string(), "mysql".to_string()],
            },
        );

        assert!(policy.check_secret_command("db-password", "psql").is_ok());
        assert!(policy.check_secret_command("db-password", "aws").is_err());
        // Other secrets are unrestricted
        assert!(policy.check_secret_command("api-key", "aws").is_ok());
    }

    #[test]
    fn test_allowlist_mode() {
        let policy = Policy {
            allow_commands: vec!["psql".to_string(), "mysql".to_string()],
            ..Policy::default()
        };
        assert!(policy.check_command("psql").is_ok());
        assert!(policy.check_command("curl").is_err());
    }

    #[test]
    fn test_no_policy_allows_everything() {
        let policy = Policy::default();
        assert!(policy.check_command("cat").is_ok());
        assert!(policy.check_command("echo").is_ok());
    }

    #[test]
    fn test_check_all() {
        let policy = default_policy();
        assert!(
            policy
                .check_all(
                    "psql",
                    &["-U".to_string(), "admin".to_string()],
                    &["db-pass".to_string()]
                )
                .is_ok()
        );
        assert!(
            policy
                .check_all("cat", &[], &["secret".to_string()])
                .is_err()
        );
        assert!(
            policy
                .check_all(
                    "bash",
                    &["-c".to_string(), "echo".to_string()],
                    &["secret".to_string()]
                )
                .is_err()
        );
    }
}
