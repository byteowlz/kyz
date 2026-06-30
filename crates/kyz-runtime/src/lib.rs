//! High-level integration surface for kyz.
//!
//! `kyz-runtime` is a thin, stable facade over [`kyz_core`]. It is intended
//! for application code that wants to resolve, list, and operate on secrets
//! without shelling out to the `kyz` CLI and without depending on low-level
//! store/vault internals.
//!
//! # Scope
//!
//! - [`Vault`] — open a single vault source (workspace, personal, named
//!   environment, OS keyring, or explicit path), query unlock state, and
//!   resolve entries.
//! - [`LayeredVault`] — resolve a [`SecretRef`] across ordered vault sources
//!   with explicit provenance so callers know which layer supplied the value.
//! - [`ssh`] — typed helpers for SSH-capable entries: safe listing and
//!   metadata derivation without exposing private key material.
//! - [`unlock`] — explicit [`unlock::UnlockMode`] /
//!   [`unlock::UnlockState`] enums describing how a vault is unlocked
//!   (interactive, machine/service, remote approval, or locked-but-requestable).
//!
//! # Non-goals
//!
//! - Policy evaluation. Consumers (e.g. agent harnesses, Oqto) layer their
//!   own policy on top of resolver provenance.
//! - Re-implementing async runtime concerns. The local operations exposed
//!   here are synchronous; integrators wrap with their preferred executor
//!   when needed.
//! - CLI semantics. No stdout parsing, no child-process orchestration.

pub mod error;
pub mod reference;
pub mod resolver;
pub mod source;
pub mod ssh;
pub mod unlock;
pub mod vault;

pub use error::{Error, Result};
pub use reference::SecretRef;
pub use resolver::{LayeredVault, LayeredVaultBuilder, Resolved, SourceConstraint};
pub use source::{VaultKind, VaultSource};
pub use unlock::{UnlockMode, UnlockState};
pub use vault::{Vault, VaultStatus};

// Re-export core types that appear in the public surface so consumers do
// not have to depend on kyz-core directly for everyday integration.
pub use kyz_core::{SecretEntry, SecretSummary};
