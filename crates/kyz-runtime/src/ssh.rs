//! First-class SSH identity metadata helpers.
//!
//! Consumers that integrate with SSH (deploy, signing, remote exec)
//! need a safe way to enumerate *which* vault entries represent SSH
//! identities without parsing arbitrary secret payloads ad-hoc. This
//! module provides:
//!
//! - A lightweight convention for tagging entries as SSH identities.
//! - [`SshIdentity`] — a display-safe record holding algorithm,
//!   fingerprint, public key, and optional comment.
//! - Helpers to derive that metadata from the entry's private key
//!   material (when present) or from explicit metadata fields.
//!
//! # Identifying SSH entries
//!
//! An entry is considered an SSH identity if **any** of the following
//! is true:
//!
//! - It has the `ssh_key` or `ssh` tag.
//! - It has a field named `kind` whose value is `ssh_key`.
//!
//! This is deliberately opt-in: generic secrets that happen to have a
//! `private_key` field (e.g. service account JSON blobs) are not swept
//! up by [`list_ssh_identities`].
//!
//! # Field conventions
//!
//! When building metadata, the helpers consult the following field
//! names, all optional:
//!
//! | Field         | Purpose |
//! |---------------|---------|
//! | `private_key` | OpenSSH/PEM-encoded private key. If present, metadata is derived from it. |
//! | `public_key`  | OpenSSH-format public key. Overrides derivation. |
//! | `algorithm`   | Textual algorithm hint (e.g. `ssh-ed25519`). Overrides derivation. |
//! | `fingerprint` | Pre-computed SHA-256 fingerprint. Overrides derivation. |
//! | `comment`     | Human-readable label. Also read from the `OpenSSH` comment. |
//!
//! Private key field values are parsed in-memory and never returned
//! from any public API.

use kyz_core::SecretEntry;
use ssh_key::{HashAlg, PrivateKey, PublicKey};

use crate::error::{Error, Result};
use crate::reference::SecretRef;
use crate::resolver::LayeredVault;
use crate::source::VaultSource;
use crate::vault::Vault;

/// Recognised algorithm families for SSH identities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SshAlgorithm {
    /// Ed25519.
    Ed25519,
    /// RSA.
    Rsa,
    /// ECDSA (NIST P-256/384/521). The string captures the specific curve.
    Ecdsa(String),
    /// DSA (legacy).
    Dsa,
    /// Anything else, reported verbatim.
    Other(String),
}

impl SshAlgorithm {
    /// The `OpenSSH` name for this algorithm (e.g. `ssh-ed25519`).
    #[must_use]
    pub const fn openssh_name(&self) -> &str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::Rsa => "ssh-rsa",
            Self::Ecdsa(curve) => curve.as_str(),
            Self::Dsa => "ssh-dss",
            Self::Other(name) => name.as_str(),
        }
    }

    fn from_openssh(name: &str) -> Self {
        match name {
            "ssh-ed25519" => Self::Ed25519,
            "ssh-rsa" => Self::Rsa,
            "ssh-dss" => Self::Dsa,
            n if n.starts_with("ecdsa-") => Self::Ecdsa(n.to_string()),
            other => Self::Other(other.to_string()),
        }
    }
}

/// Display-safe metadata for a single SSH identity.
///
/// An `SshIdentity` never carries private key material. Callers that
/// need to use the private key should fetch the underlying
/// [`SecretEntry`] explicitly via [`Vault::get`].
#[derive(Debug, Clone)]
pub struct SshIdentity {
    /// Ref that produced this identity.
    pub reference: SecretRef,
    /// Source vault.
    pub source: VaultSource,
    /// Algorithm family.
    pub algorithm: SshAlgorithm,
    /// OpenSSH-format public key (e.g. `ssh-ed25519 AAAA... user@host`).
    pub public_key_openssh: String,
    /// SHA-256 fingerprint, `SHA256:<base64>` form.
    pub fingerprint_sha256: String,
    /// Optional human-readable comment.
    pub comment: Option<String>,
}

/// True if the entry opts into SSH-identity metadata.
#[must_use]
pub fn is_ssh_identity(entry: &SecretEntry) -> bool {
    entry.has_tag("ssh_key")
        || entry.has_tag("ssh")
        || entry.field("kind").is_some_and(|v| v == "ssh_key")
}

/// Derive [`SshIdentity`] metadata from an entry, without exposing the
/// private key.
///
/// Explicit fields (`public_key`, `algorithm`, `fingerprint`,
/// `comment`) are preferred. If not present, the function falls back to
/// parsing the `private_key` field. Returns `Ok(None)` when the entry
/// is not an SSH identity.
///
/// # Errors
///
/// Returns [`Error::Ssh`] if the entry is marked as an SSH identity
/// but its key material cannot be parsed.
pub fn identity_from_entry(
    entry: &SecretEntry,
    reference: &SecretRef,
    source: &VaultSource,
) -> Result<Option<SshIdentity>> {
    if !is_ssh_identity(entry) {
        return Ok(None);
    }

    let comment = entry.field("comment").map(str::to_string);

    // Prefer explicit public_key field.
    if let Some(pk_str) = entry.field("public_key") {
        let public_key = PublicKey::from_openssh(pk_str)
            .map_err(|e| Error::Ssh(format!("parsing public_key: {e}")))?;
        return Ok(Some(build_from_public(
            &public_key,
            reference,
            source,
            comment,
        )));
    }

    // Derive from private_key if present.
    if let Some(priv_str) = entry.field("private_key") {
        let private_key = PrivateKey::from_openssh(priv_str.as_bytes())
            .map_err(|e| Error::Ssh(format!("parsing private_key: {e}")))?;
        let public_key = private_key.public_key();
        let derived_comment = comment.or_else(|| {
            let c = public_key.comment();
            if c.is_empty() {
                None
            } else {
                Some(c.to_string())
            }
        });
        return Ok(Some(build_from_public(
            public_key,
            reference,
            source,
            derived_comment,
        )));
    }

    // Entry is tagged as ssh_key but has neither a private nor public
    // key — accept explicit metadata if present, otherwise error.
    if let (Some(algo), Some(fp)) = (entry.field("algorithm"), entry.field("fingerprint")) {
        return Ok(Some(SshIdentity {
            reference: reference.clone(),
            source: source.clone(),
            algorithm: SshAlgorithm::from_openssh(algo),
            public_key_openssh: entry.field("public_key").unwrap_or("").to_string(),
            fingerprint_sha256: fp.to_string(),
            comment,
        }));
    }

    Err(Error::Ssh(format!(
        "entry {reference} is tagged ssh_key but has no public_key, private_key, or explicit metadata",
    )))
}

fn build_from_public(
    public_key: &PublicKey,
    reference: &SecretRef,
    source: &VaultSource,
    comment: Option<String>,
) -> SshIdentity {
    let algorithm = SshAlgorithm::from_openssh(public_key.algorithm().as_str());
    let fingerprint_sha256 = public_key.fingerprint(HashAlg::Sha256).to_string();
    let public_key_openssh = public_key
        .to_openssh()
        .unwrap_or_else(|_| String::from("<unrepresentable>"));
    SshIdentity {
        reference: reference.clone(),
        source: source.clone(),
        algorithm,
        public_key_openssh,
        fingerprint_sha256,
        comment,
    }
}

/// List every SSH identity in a single vault.
///
/// Entries that are not tagged as SSH identities are silently skipped.
/// Entries that *are* tagged but fail to parse yield an error; callers
/// that want to tolerate partial failures should list summaries and
/// call [`identity_from_entry`] per entry themselves.
///
/// # Errors
///
/// Returns an error if listing, fetching, or parsing fails.
pub fn list_ssh_identities(vault: &Vault) -> Result<Vec<SshIdentity>> {
    let mut out = Vec::new();
    for summary in vault.list_all()? {
        // list returns summaries only; we need the entry to check tags
        // and fields. This is still a metadata-only decryption (fields
        // names are plaintext in v2, but field *values* require
        // decryption for non-keyring backends).
        let reference = SecretRef::new(summary.service.clone(), summary.key.clone());
        // Cheap pre-filter: if the tag set is present and doesn't look
        // SSH, skip the fetch entirely.
        if !summary.tags.contains("ssh_key") && !summary.tags.contains("ssh") {
            // Tags are authoritative when present; if absent, we still
            // need the entry to check the `kind` field.
            if !summary.field_names.iter().any(|n| n == "kind") {
                continue;
            }
        }
        let entry = vault.get(&reference)?;
        if let Some(identity) = identity_from_entry(&entry, &reference, vault.source())? {
            out.push(identity);
        }
    }
    Ok(out)
}

/// List SSH identities across every layer of a [`LayeredVault`], with
/// provenance attached via [`SshIdentity::source`].
///
/// # Errors
///
/// Returns an error if any layer fails.
pub fn list_ssh_identities_layered(layered: &LayeredVault) -> Result<Vec<SshIdentity>> {
    let mut out = Vec::new();
    for vault in layered.layers() {
        out.extend(list_ssh_identities(vault)?);
    }
    Ok(out)
}
