//! Vault source identity and provenance types.
//!
//! Every [`crate::Vault`] opened through the runtime carries a
//! [`VaultSource`] describing *where* it came from. Layered resolution
//! attaches this provenance to every hit so callers can apply their own
//! policy (for example, forbidding personal-vault fallback in a service
//! context) without re-parsing paths or configuration.

use std::fmt;
use std::path::{Path, PathBuf};

/// Coarse classification of a vault source.
///
/// This is the category consumers usually branch on. For finer-grained
/// identity use the full [`VaultSource`], which also carries a caller-
/// supplied name and the underlying path (when file-backed).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VaultKind {
    /// A workspace-scoped vault, e.g. `<cwd>/.kyz/vault.json`.
    Workspace,
    /// The personal/user-level vault, typically the XDG central vault.
    Personal,
    /// A named environment vault such as `dev`, `staging`, or `prod`.
    Environment(String),
    /// The OS keyring backend (no file path).
    Keyring,
    /// An explicit/custom source — e.g. a file path passed directly by
    /// the caller that does not fit the other categories.
    Custom,
}

impl fmt::Display for VaultKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace => f.write_str("workspace"),
            Self::Personal => f.write_str("personal"),
            Self::Environment(name) => write!(f, "environment:{name}"),
            Self::Keyring => f.write_str("keyring"),
            Self::Custom => f.write_str("custom"),
        }
    }
}

/// Full provenance record for a vault.
///
/// `name` is the caller-facing label (e.g. "workspace", "user",
/// "prod-shared"). It is distinct from [`VaultKind`]: a single layered
/// resolver may legitimately hold multiple vaults of the same kind with
/// different names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultSource {
    name: String,
    kind: VaultKind,
    path: Option<PathBuf>,
}

impl VaultSource {
    /// Build a source descriptor.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: VaultKind, path: Option<PathBuf>) -> Self {
        Self {
            name: name.into(),
            kind,
            path,
        }
    }

    /// Build a workspace source with a conventional name.
    #[must_use]
    pub fn workspace(path: impl Into<PathBuf>) -> Self {
        Self::new("workspace", VaultKind::Workspace, Some(path.into()))
    }

    /// Build a personal/user source with a conventional name.
    #[must_use]
    pub fn personal(path: impl Into<PathBuf>) -> Self {
        Self::new("personal", VaultKind::Personal, Some(path.into()))
    }

    /// Build a named-environment source.
    #[must_use]
    pub fn environment(env_name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        let env_name = env_name.into();
        Self::new(
            env_name.clone(),
            VaultKind::Environment(env_name),
            Some(path.into()),
        )
    }

    /// Build a keyring source (no path).
    #[must_use]
    pub fn keyring() -> Self {
        Self::new("keyring", VaultKind::Keyring, None)
    }

    /// Caller-facing label for this source.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Coarse classification.
    #[must_use]
    pub const fn kind(&self) -> &VaultKind {
        &self.kind
    }

    /// Underlying path, if file-backed.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

impl fmt::Display for VaultSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(p) => write!(f, "{} [{}] {}", self.name, self.kind, p.display()),
            None => write!(f, "{} [{}]", self.name, self.kind),
        }
    }
}
