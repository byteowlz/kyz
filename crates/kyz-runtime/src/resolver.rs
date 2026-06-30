//! Layered resolver for workspace-first / personal-fallback lookups.
//!
//! Many integrations need a predictable multi-source lookup model:
//! resolve a [`SecretRef`] against an ordered set of [`crate::Vault`]s
//! and return the first match, together with provenance so the caller
//! can apply policy on *which* source supplied the value.
//!
//! # Not-found vs ambiguous
//!
//! - [`LayeredVault::resolve`] — returns the first hit in layer order.
//!   Missing from every layer is [`crate::Error::NotFound`].
//! - [`LayeredVault::resolve_strict`] — errors with
//!   [`crate::Error::Ambiguous`] if more than one layer has a hit,
//!   letting the caller force an explicit choice (for example, in a
//!   service context where accidental personal-fallback is a bug).
//! - [`SourceConstraint`] — restrict resolution to a subset of layers
//!   (e.g. workspace-only).

use kyz_core::{SecretEntry, SecretSummary};

use crate::error::{Error, Result};
use crate::reference::SecretRef;
use crate::source::{VaultKind, VaultSource};
use crate::vault::Vault;

/// A successful resolution: the entry plus where it came from.
#[derive(Debug)]
pub struct Resolved {
    /// The resolved entry.
    pub entry: SecretEntry,
    /// The source that supplied the entry.
    pub source: VaultSource,
    /// Zero-based index of the layer in the layered vault.
    pub layer_index: usize,
}

/// A listing hit across layers — summaries with provenance.
#[derive(Debug)]
pub struct ResolvedSummary {
    /// Entry summary (no secret values).
    pub summary: SecretSummary,
    /// Source that supplied the summary.
    pub source: VaultSource,
    /// Layer index.
    pub layer_index: usize,
}

/// Restrict which layers participate in a resolve call.
#[derive(Debug, Clone)]
pub enum SourceConstraint {
    /// Consult every layer (default).
    Any,
    /// Only consult layers whose kind appears in the allow-list.
    OnlyKinds(Vec<VaultKind>),
    /// Consult every layer except those whose kind appears in the deny-list.
    ///
    /// The headless-service guidance is
    /// `ExcludeKinds(vec![VaultKind::Personal])`.
    ExcludeKinds(Vec<VaultKind>),
    /// Only consult the layer(s) with one of these names.
    OnlyNames(Vec<String>),
}

impl SourceConstraint {
    /// Convenience: workspace-only.
    #[must_use]
    pub fn workspace_only() -> Self {
        Self::OnlyKinds(vec![VaultKind::Workspace])
    }

    /// Convenience: personal-only (central user vault).
    #[must_use]
    pub fn personal_only() -> Self {
        Self::OnlyKinds(vec![VaultKind::Personal])
    }

    /// Convenience: forbid the personal vault (common for service mode).
    #[must_use]
    pub fn no_personal() -> Self {
        Self::ExcludeKinds(vec![VaultKind::Personal])
    }

    fn includes(&self, source: &VaultSource) -> bool {
        match self {
            Self::Any => true,
            Self::OnlyKinds(kinds) => kinds.iter().any(|k| kind_matches(k, source.kind())),
            Self::ExcludeKinds(kinds) => !kinds.iter().any(|k| kind_matches(k, source.kind())),
            Self::OnlyNames(names) => names.iter().any(|n| n == source.name()),
        }
    }
}

fn kind_matches(wanted: &VaultKind, got: &VaultKind) -> bool {
    match (wanted, got) {
        // Environment: match any env when wanted has an empty name, else by name.
        (VaultKind::Environment(w), VaultKind::Environment(g)) => w.is_empty() || w == g,
        (a, b) => a == b,
    }
}

/// Builder for [`LayeredVault`].
#[derive(Debug, Default)]
pub struct LayeredVaultBuilder {
    layers: Vec<Vault>,
}

impl LayeredVaultBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a layer. Order matters: earlier layers win by default.
    #[must_use]
    pub fn push(mut self, vault: Vault) -> Self {
        self.layers.push(vault);
        self
    }

    /// Build the layered vault.
    #[must_use]
    pub fn build(self) -> LayeredVault {
        LayeredVault {
            layers: self.layers,
        }
    }
}

/// Ordered, multi-source resolver.
#[derive(Debug)]
pub struct LayeredVault {
    layers: Vec<Vault>,
}

impl LayeredVault {
    /// Start building a layered vault.
    #[must_use]
    pub fn builder() -> LayeredVaultBuilder {
        LayeredVaultBuilder::new()
    }

    /// Number of layers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.layers.len()
    }

    /// True if no layers were added.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Iterate over the layers in order.
    pub fn layers(&self) -> impl Iterator<Item = &Vault> {
        self.layers.iter()
    }

    /// Resolve a ref, returning the first hit under the given constraint.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no layer matched, or a backend
    /// error if one of the consulted layers failed.
    pub fn resolve_in(&self, r: &SecretRef, constraint: &SourceConstraint) -> Result<Resolved> {
        for (idx, vault) in self.layers.iter().enumerate() {
            if !constraint.includes(vault.source()) {
                continue;
            }
            if let Some(entry) = vault.try_get(r)? {
                return Ok(Resolved {
                    entry,
                    source: vault.source().clone(),
                    layer_index: idx,
                });
            }
        }
        Err(Error::NotFound {
            reference: r.clone(),
        })
    }

    /// Resolve a ref: first hit wins (no constraint).
    ///
    /// # Errors
    ///
    /// See [`LayeredVault::resolve_in`].
    pub fn resolve(&self, r: &SecretRef) -> Result<Resolved> {
        self.resolve_in(r, &SourceConstraint::Any)
    }

    /// Resolve a ref, failing with [`Error::Ambiguous`] if more than
    /// one layer supplies a hit.
    ///
    /// Use this in contexts where silent precedence is a risk — e.g.
    /// service runtimes that must not silently fall through to a
    /// personal vault.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no layer matched.
    /// - [`Error::Ambiguous`] if more than one layer matched.
    pub fn resolve_strict(&self, r: &SecretRef, constraint: &SourceConstraint) -> Result<Resolved> {
        let mut hits: Vec<(usize, VaultSource, SecretEntry)> = Vec::new();
        for (idx, vault) in self.layers.iter().enumerate() {
            if !constraint.includes(vault.source()) {
                continue;
            }
            if let Some(entry) = vault.try_get(r)? {
                hits.push((idx, vault.source().clone(), entry));
            }
        }
        match hits.len() {
            0 => Err(Error::NotFound {
                reference: r.clone(),
            }),
            1 => {
                let (layer_index, source, entry) = hits.into_iter().next().ok_or_else(|| {
                    Error::Ssh("internal: hits vector drained unexpectedly".to_string())
                })?;
                Ok(Resolved {
                    entry,
                    source,
                    layer_index,
                })
            }
            _ => Err(Error::Ambiguous {
                reference: r.clone(),
                matches: hits.into_iter().map(|(_, s, _)| s).collect(),
            }),
        }
    }

    /// List every entry across every consulted layer, with provenance.
    ///
    /// Earlier layers appear first. The same service/key may appear in
    /// multiple entries if several layers hold it; callers decide
    /// whether to deduplicate.
    ///
    /// # Errors
    ///
    /// Returns an error if a layer backend fails.
    pub fn list_all(&self, constraint: &SourceConstraint) -> Result<Vec<ResolvedSummary>> {
        let mut out = Vec::new();
        for (idx, vault) in self.layers.iter().enumerate() {
            if !constraint.includes(vault.source()) {
                continue;
            }
            for summary in vault.list_all()? {
                out.push(ResolvedSummary {
                    summary,
                    source: vault.source().clone(),
                    layer_index: idx,
                });
            }
        }
        Ok(out)
    }
}
