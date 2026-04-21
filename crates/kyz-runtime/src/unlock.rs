//! Unlock modes and lifecycle semantics.
//!
//! kyz already has the underlying pieces — vault sessions, keyring /
//! keyutils-backed passphrase storage, and a headless auth-request flow
//! — but the operational model was implicit. This module formalises the
//! supported modes so applications and operators can reason about them
//! explicitly, and so library callers can record *how* a vault was
//! unlocked alongside the vault itself.
//!
//! # Modes
//!
//! | Mode | Typical context | Trust boundary |
//! |------|-----------------|----------------|
//! | [`UnlockMode::Interactive`] | Workstation, terminal-attached | User typed the passphrase at a trusted prompt. |
//! | [`UnlockMode::MachineService`] | Long-running service / agent runner | Passphrase (or derived key) was retrieved from a machine-bound credential store. No user interaction at unlock time. |
//! | [`UnlockMode::RemoteApproval`] | Headless / CI / agent that pings a human | Unlock was gated by an out-of-band approval flow (see [`kyz_core::auth_request`]). |
//!
//! # Lifecycle
//!
//! Across restarts the kyz session survives as long as its underlying
//! session file and keyring entry survive. On Linux, keyutils-backed
//! passphrases are cleared at reboot, which transitions a session from
//! [`UnlockState::Unlocked`] to [`UnlockState::Locked`] silently. The
//! runtime facade reports this state via [`crate::Vault::unlock_state`]
//! so callers can re-unlock (or request approval) without racing on the
//! underlying file.
//!
//! # Guidance for integrators
//!
//! - **Desktop apps** — use [`UnlockMode::Interactive`]. Prefer the OS
//!   session timeout behavior kyz already provides; do not cache the
//!   passphrase in app memory beyond the unlock call.
//! - **Services / daemons** — use [`UnlockMode::MachineService`] with a
//!   non-personal (workspace or dedicated) vault. Do not fall back to a
//!   personal vault; combine with
//!   [`crate::SourceConstraint`] when using layered resolution.
//! - **Headless agents** — prefer [`UnlockMode::RemoteApproval`] when a
//!   human approver is reachable. Otherwise treat locked vaults as
//!   [`UnlockState::LockedRequestable`] and surface the pending request
//!   id to the approver UI.

use std::fmt;

/// How a vault was unlocked (or is expected to be unlocked).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnlockMode {
    /// User-supplied passphrase at an interactive prompt.
    Interactive,
    /// Non-interactive unlock via a machine-bound credential.
    MachineService,
    /// Unlock gated by an out-of-band approval flow.
    RemoteApproval,
}

impl fmt::Display for UnlockMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interactive => f.write_str("interactive"),
            Self::MachineService => f.write_str("machine-service"),
            Self::RemoteApproval => f.write_str("remote-approval"),
        }
    }
}

/// Runtime unlock state for a vault.
///
/// This is the runtime-facing counterpart to
/// [`kyz_core::VaultStatus`]. The core type reports raw booleans; this
/// enum folds them into the four states integrators actually care about
/// (including the "locked but a request can be issued" case, which is
/// the correct default for headless agents).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockState {
    /// No session; operations that require unlock will fail.
    Locked,
    /// No session, but the caller has declared this vault supports the
    /// remote-approval flow. A headless consumer should create an auth
    /// request instead of prompting locally.
    LockedRequestable,
    /// A live session exists.
    Unlocked {
        /// How the vault was unlocked.
        mode: UnlockMode,
        /// Unix timestamp when the session expires.
        expires_at: u64,
        /// Seconds remaining until expiry.
        remaining_secs: u64,
    },
}

impl UnlockState {
    /// True if any operation requiring decryption can succeed right now.
    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        matches!(self, Self::Unlocked { .. })
    }

    /// True if the caller should issue an auth request rather than
    /// prompt locally.
    #[must_use]
    pub const fn is_requestable(&self) -> bool {
        matches!(self, Self::LockedRequestable)
    }
}

impl fmt::Display for UnlockState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("locked"),
            Self::LockedRequestable => f.write_str("locked (requestable)"),
            Self::Unlocked {
                mode,
                remaining_secs,
                ..
            } => write!(f, "unlocked ({mode}, {remaining_secs}s left)"),
        }
    }
}
