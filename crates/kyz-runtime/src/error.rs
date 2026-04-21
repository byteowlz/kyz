//! Runtime error taxonomy.
//!
//! The taxonomy is deliberately narrow so consumers can match on the
//! conditions that actually drive control flow (locked vault, missing
//! entry, ambiguous match, unsupported kind) without reasoning about
//! backend-specific strings.

use kyz_core::CoreError;
use thiserror::Error;

use crate::reference::SecretRef;
use crate::source::VaultSource;

/// Result alias for runtime operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the runtime facade.
#[derive(Debug, Error)]
pub enum Error {
    /// The vault exists but is currently locked.
    ///
    /// Callers should unlock the vault, attach an existing session, or
    /// switch to a layered resolver that can satisfy the lookup from
    /// another source.
    #[error("vault is locked: {path}")]
    VaultLocked {
        /// Filesystem path of the locked vault, if applicable.
        path: String,
    },

    /// The vault's unlock session has expired.
    #[error("vault session expired")]
    SessionExpired,

    /// The requested secret was not found in any consulted source.
    #[error("secret not found: {reference}")]
    NotFound {
        /// The ref that produced the miss.
        reference: SecretRef,
    },

    /// Multiple layers matched the ref and no explicit constraint was
    /// supplied to pick one.
    #[error("ambiguous match for {reference}: {} candidate(s)", .matches.len())]
    Ambiguous {
        /// The ref that produced the ambiguity.
        reference: SecretRef,
        /// Sources that each had an entry for the ref.
        matches: Vec<VaultSource>,
    },

    /// The entry exists but is not of the kind the caller requested
    /// (e.g. SSH helpers invoked on a non-SSH entry).
    #[error("unsupported kind: expected {expected}, got {actual}")]
    UnsupportedKind {
        /// What the caller asked for.
        expected: &'static str,
        /// What the entry actually looks like.
        actual: String,
    },

    /// The OS keyring backend is not available on this host.
    ///
    /// On Linux this typically means no D-Bus / Secret Service is present
    /// and the keyutils fallback also declined. Headless callers should
    /// prefer the [`crate::unlock::UnlockMode::MachineService`] flow or a
    /// file-backed vault.
    #[error("OS keyring is unavailable")]
    KeyringUnavailable,

    /// An SSH identity could not be parsed or derived.
    #[error("ssh identity error: {0}")]
    Ssh(String),

    /// A lower-level core error that does not map onto a specific variant.
    #[error(transparent)]
    Core(#[from] CoreError),
}

impl Error {
    /// Build a `VaultLocked` error from a path-like value.
    #[must_use]
    pub fn vault_locked(path: impl std::fmt::Display) -> Self {
        Self::VaultLocked {
            path: path.to_string(),
        }
    }

    /// Map a [`CoreError`] to a more specific runtime error when possible.
    ///
    /// Core errors are stringly typed for some conditions (notably vault
    /// lock and missing-vault), so we inspect the message to recover a
    /// typed variant. Unknown cases fall through to [`Error::Core`].
    #[must_use]
    pub fn from_core(err: CoreError, reference: Option<&SecretRef>) -> Self {
        match &err {
            CoreError::SecretNotFound(_) => reference.map_or(Self::Core(err), |r| Self::NotFound {
                reference: r.clone(),
            }),
            CoreError::Secret(msg) if msg.contains("vault is locked") => {
                Self::VaultLocked { path: String::new() }
            }
            _ => Self::Core(err),
        }
    }
}
