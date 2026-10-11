//! Vault format v5: the v4 operation-log model stored one entry per file,
//! with mergeable key slots.
//!
//! Layout for a vault whose path is `<dir>/vault.json`:
//!
//! - `<dir>/vault.json` — the **manifest**: vault id, key slots, the
//!   passphrase-policy flag, and a MAC. It only changes when key slots
//!   change, so workspace-vault trust pins it without re-prompting on
//!   every secret write.
//! - `<dir>/vault.entries/<file_id>.json` — one file per entry: the
//!   entry's encrypted name, its operation log, and a MAC. `file_id` is a
//!   keyed hash of `service/key`, so the directory listing reveals neither
//!   service nor key names.
//!
//! Reads and writes touch only the manifest and one entry file, so their
//! cost no longer grows with the size of the vault. Merge semantics are
//! exactly v4's ([`crate::vault_v4::merge_ops`]) applied per entry.
//!
//! **Key slots.** The data key (DK) is wrapped once per slot. Replicas
//! may carry different slot sets; manifests merge as a union where a
//! removal always wins. Replica identity is the `vault_id` plus proof of
//! the same DK (every MAC verifies under it) — never the wrapping, so a
//! passphrase change on one replica does not break merging. Removing a
//! slot erases its wrapped DK, but older copies of the manifest still
//! hold it: revoking a leaked passphrase for good requires rotating the
//! DK itself.
//!
//! **Sync conflict copies.** File synchronizers write concurrent edits as
//! sibling copies (Syncthing: `<file_id>.sync-conflict-….json`). Every
//! read unions verified copies of the entry it touches, and the next
//! write of that entry absorbs and removes them. Unverifiable copies are
//! ignored with a warning and never deleted.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::store::now_unix;
use crate::vault_v3::{DK_LEN, KdfParams, XCHACHA_NONCE_LEN};
use crate::vault_v4::{self, Op, OpLog, VAULT_ID_LEN, VaultFileV4, validate_hex_id};

type HmacSha256 = Hmac<Sha256>;

/// Schema version of the manifest and of every entry file.
pub const VERSION: u32 = 5;

/// Byte length of an entry file id (hex-encoded as 32 characters).
pub const FILE_ID_LEN: usize = 16;

/// Byte length of a key slot id (hex-encoded as 32 characters).
pub const SLOT_ID_LEN: usize = 16;

const HKDF_SALT: &[u8] = b"kyz-vault-v5";
const INFO_MANIFEST_MAC: &[u8] = b"kyz-v5-manifest-mac";
const INFO_ENTRY_MAC: &[u8] = b"kyz-v5-entry-mac";
const INFO_ENTRY_ID: &[u8] = b"kyz-v5-entry-id";
const INFO_NAME_ENC: &[u8] = b"kyz-v5-name-enc";

/// Domain-separated 32-byte subkey of the DK.
fn subkey(dk: &[u8; DK_LEN], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), dk);
    let mut key = Zeroizing::new([0u8; 32]);
    // HKDF expand only fails when the output exceeds 255 hash blocks.
    let _ = hk.expand(info, key.as_mut_slice());
    key
}

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> Result<HmacSha256, CoreError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| CoreError::Secret(format!("MAC init: {e}")))?;
    for part in parts {
        <HmacSha256 as Mac>::update(&mut mac, &(part.len() as u64).to_le_bytes());
        <HmacSha256 as Mac>::update(&mut mac, part);
    }
    Ok(mac)
}

fn mac_hex(key: &[u8; 32], body: &[u8]) -> Result<String, CoreError> {
    Ok(hex::encode(hmac(key, &[body])?.finalize().into_bytes()))
}

fn verify_mac_hex(key: &[u8; 32], body: &[u8], tag_hex: &str, what: &str) -> Result<(), CoreError> {
    let tag = hex::decode(tag_hex)
        .map_err(|_| CoreError::Secret(format!("{what} MAC is not valid hex")))?;
    hmac(key, &[body])?.verify_slice(&tag).map_err(|_| {
        CoreError::Secret(format!(
            "{what} MAC verification failed (corrupt, tampered, or wrong key)"
        ))
    })
}

fn random_hex_id(len: usize) -> Result<String, CoreError> {
    let mut raw = vec![0u8; len];
    getrandom::fill(&mut raw).map_err(|e| CoreError::Secret(format!("getrandom id: {e}")))?;
    Ok(hex::encode(raw))
}

/// Stable entry file id: keyed hash of the compound `service/key`.
///
/// # Errors
///
/// Returns an error if the MAC primitive cannot be initialized.
pub fn entry_file_id(dk: &[u8; DK_LEN], compound_key: &str) -> Result<String, CoreError> {
    let key = subkey(dk, INFO_ENTRY_ID);
    let tag = hmac(&key, &[b"id", compound_key.as_bytes()])?
        .finalize()
        .into_bytes();
    Ok(hex::encode(&tag[..FILE_ID_LEN]))
}

/// Deterministically encrypt an entry name, bound to its file id.
///
/// The nonce is derived from the name itself, so equal names always
/// produce equal ciphertexts. That leaks nothing beyond what the file id
/// already reveals (equality) and keeps replicas byte-identical.
fn encrypt_name(dk: &[u8; DK_LEN], compound_key: &str, file_id: &str) -> Result<String, CoreError> {
    let key = subkey(dk, INFO_NAME_ENC);
    let nonce_tag = hmac(&key, &[b"nonce", compound_key.as_bytes()])?
        .finalize()
        .into_bytes();
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    nonce.copy_from_slice(&nonce_tag[..XCHACHA_NONCE_LEN]);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: compound_key.as_bytes(),
                aad: file_id.as_bytes(),
            },
        )
        .map_err(|e| CoreError::Secret(format!("AEAD encrypt name: {e}")))?;
    let mut out = Vec::with_capacity(XCHACHA_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

fn decrypt_name(dk: &[u8; DK_LEN], blob: &str, file_id: &str) -> Result<String, CoreError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|e| CoreError::Serialization(format!("invalid entry name base64: {e}")))?;
    if raw.len() <= XCHACHA_NONCE_LEN {
        return Err(CoreError::Secret("entry name blob too short".to_string()));
    }
    let (nonce, ct) = raw.split_at(XCHACHA_NONCE_LEN);
    let key = subkey(dk, INFO_NAME_ENC);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    let plain = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: file_id.as_bytes(),
            },
        )
        .map_err(|_| CoreError::Secret("entry name decryption failed".to_string()))?;
    String::from_utf8(plain).map_err(|_| CoreError::Secret("entry name is not UTF-8".to_string()))
}

// ---------------------------------------------------------------------------
// Manifest and key slots
// ---------------------------------------------------------------------------

/// How a key slot's wrapping key is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SlotKind {
    /// scrypt(passphrase) wraps the DK.
    Passphrase,
}

/// One wrapped copy of the DK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySlot {
    /// Wrapping-key derivation.
    pub kind: SlotKind,
    /// KDF parameters for the wrapping key.
    pub kdf: KdfParams,
    /// DK wrapped under the slot key; empty once the slot is removed.
    pub wrapped_dk: String,
    /// Optional human label (e.g. device name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Creation time (unix seconds; 0 for slots migrated from v3/v4).
    pub created_at: u64,
    /// Removal time; a removed slot carries no key material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<u64>,
}

impl KeySlot {
    /// Whether the slot can still unwrap the DK.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.removed_at.is_none()
    }
}

/// Public, value-free description of a key slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySlotInfo {
    /// Slot id.
    pub id: String,
    /// Slot kind.
    pub kind: SlotKind,
    /// Optional label.
    pub label: Option<String>,
    /// Creation time (unix seconds).
    pub created_at: u64,
    /// Removal time, if removed.
    pub removed_at: Option<u64>,
}

/// The v5 manifest (`vault.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version. Always 5.
    pub version: u32,
    /// Stable vault identity (shared by all replicas of one vault).
    pub vault_id: String,
    /// Whether passphrase strength policy has already been checked.
    #[serde(default)]
    pub passphrase_policy_checked: bool,
    /// Key slots by id.
    pub keyslots: BTreeMap<String, KeySlot>,
    /// Hex HMAC-SHA256 over the canonical manifest with an empty `mac`.
    #[serde(default)]
    pub mac: String,
}

/// Deterministic id for the single slot of a migrated v3/v4 vault, so
/// replicas migrating independently end up with the same slot.
fn legacy_slot_id(vault_id: &str, wrapped_dk: &str) -> String {
    let digest = Sha256::digest(
        [
            b"kyz-v5-legacy-slot".as_slice(),
            vault_id.as_bytes(),
            wrapped_dk.as_bytes(),
        ]
        .join(&0u8),
    );
    hex::encode(&digest[..SLOT_ID_LEN])
}

fn wrap_dk(dk: &[u8; DK_LEN], passphrase: &SecretString) -> Result<(KdfParams, String), CoreError> {
    let kdf = KdfParams::with_random_salt()?;
    let kek = crate::vault_v3::derive_kek(passphrase, &kdf)?;
    let wrapped = crate::vault_v3::aead_encrypt_b64(&kek, dk, &[])?;
    Ok((kdf, wrapped))
}

impl Manifest {
    /// Create a new vault manifest with a fresh DK and one passphrase slot.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS RNG or scrypt fails.
    pub fn create(passphrase: &SecretString) -> Result<(Self, Zeroizing<[u8; DK_LEN]>), CoreError> {
        let dk = crate::vault_v3::generate_dk()?;
        let mut manifest = Self {
            version: VERSION,
            vault_id: random_hex_id(VAULT_ID_LEN)?,
            passphrase_policy_checked: false,
            keyslots: BTreeMap::new(),
            mac: String::new(),
        };
        manifest.add_passphrase_slot(&dk, passphrase, None)?;
        Ok((manifest, dk))
    }

    /// Manifest for a vault migrated from v3/v4: its single `kdf` +
    /// `wrapped_dk` pair becomes one passphrase slot with a deterministic
    /// id.
    #[must_use]
    pub fn from_legacy(
        vault_id: &str,
        kdf: &KdfParams,
        wrapped_dk: &str,
        passphrase_policy_checked: bool,
    ) -> Self {
        let mut keyslots = BTreeMap::new();
        keyslots.insert(
            legacy_slot_id(vault_id, wrapped_dk),
            KeySlot {
                kind: SlotKind::Passphrase,
                kdf: kdf.clone(),
                wrapped_dk: wrapped_dk.to_string(),
                label: None,
                created_at: 0,
                removed_at: None,
            },
        );
        Self {
            version: VERSION,
            vault_id: vault_id.to_string(),
            passphrase_policy_checked,
            keyslots,
            mac: String::new(),
        }
    }

    /// Parse and structurally validate manifest bytes (no MAC check).
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not a valid v5 manifest.
    pub fn parse(raw: &[u8]) -> Result<Self, CoreError> {
        let manifest: Self = serde_json::from_slice(raw)
            .map_err(|e| CoreError::Serialization(format!("parsing v5 manifest: {e}")))?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), CoreError> {
        if self.version != VERSION {
            return Err(CoreError::Secret(format!(
                "unsupported vault manifest version {}",
                self.version
            )));
        }
        validate_hex_id("vault_id", &self.vault_id, VAULT_ID_LEN)?;
        for (id, slot) in &self.keyslots {
            validate_hex_id("key slot id", id, SLOT_ID_LEN)?;
            if slot.is_active() {
                slot.kdf.validate_params()?;
                if slot.wrapped_dk.is_empty() {
                    return Err(CoreError::Secret(format!(
                        "active key slot {id} has no wrapped key"
                    )));
                }
            } else if !slot.wrapped_dk.is_empty() {
                return Err(CoreError::Secret(format!(
                    "removed key slot {id} still carries a wrapped key"
                )));
            }
        }
        if !self.keyslots.values().any(KeySlot::is_active) {
            return Err(CoreError::Secret(
                "vault manifest has no active key slot".to_string(),
            ));
        }
        Ok(())
    }

    fn mac_body_bytes(&self) -> Result<Vec<u8>, CoreError> {
        let mut body = self.clone();
        body.mac = String::new();
        serde_json::to_vec(&body)
            .map_err(|e| CoreError::Serialization(format!("serializing manifest: {e}")))
    }

    /// Compute and set the MAC.
    ///
    /// # Errors
    ///
    /// Returns an error on serialization failure.
    pub fn finalize(&mut self, dk: &[u8; DK_LEN]) -> Result<(), CoreError> {
        self.mac = mac_hex(&subkey(dk, INFO_MANIFEST_MAC), &self.mac_body_bytes()?)?;
        Ok(())
    }

    /// Verify the MAC under the DK (proves this manifest belongs to a vault
    /// sharing the DK and was not tampered with).
    ///
    /// # Errors
    ///
    /// Returns an error when the MAC does not verify.
    pub fn verify_mac(&self, dk: &[u8; DK_LEN]) -> Result<(), CoreError> {
        verify_mac_hex(
            &subkey(dk, INFO_MANIFEST_MAC),
            &self.mac_body_bytes()?,
            &self.mac,
            "vault manifest",
        )
    }

    /// Serialize for disk (pretty JSON).
    ///
    /// # Errors
    ///
    /// Returns an error on serialization failure.
    pub fn to_bytes_pretty(&self) -> Result<Vec<u8>, CoreError> {
        serde_json::to_string_pretty(self)
            .map(String::into_bytes)
            .map_err(|e| CoreError::Serialization(format!("serializing manifest: {e}")))
    }

    /// Unwrap the DK by trying every active passphrase slot, newest first.
    /// Pays one scrypt per slot tried. The manifest MAC is verified with
    /// the recovered DK before it is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if no slot accepts the passphrase or the MAC fails.
    pub fn unwrap_dk(
        &self,
        passphrase: &SecretString,
    ) -> Result<(String, Zeroizing<[u8; DK_LEN]>), CoreError> {
        let mut slots: Vec<(&String, &KeySlot)> = self
            .keyslots
            .iter()
            .filter(|(_, s)| s.is_active() && s.kind == SlotKind::Passphrase)
            .collect();
        slots.sort_by(|a, b| (b.1.created_at, b.0).cmp(&(a.1.created_at, a.0)));
        for (id, slot) in slots {
            if let Ok(dk) = crate::vault_v3::unwrap_dk_from(&slot.kdf, &slot.wrapped_dk, passphrase)
            {
                self.verify_mac(&dk)?;
                return Ok((id.clone(), dk));
            }
        }
        Err(CoreError::Secret(
            "wrong passphrase or vault corrupt".to_string(),
        ))
    }

    /// Add a passphrase slot wrapping `dk`. Returns the new slot id. The
    /// caller finalizes and writes the manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS RNG or scrypt fails.
    pub fn add_passphrase_slot(
        &mut self,
        dk: &[u8; DK_LEN],
        passphrase: &SecretString,
        label: Option<String>,
    ) -> Result<String, CoreError> {
        let (kdf, wrapped_dk) = wrap_dk(dk, passphrase)?;
        let id = random_hex_id(SLOT_ID_LEN)?;
        self.keyslots.insert(
            id.clone(),
            KeySlot {
                kind: SlotKind::Passphrase,
                kdf,
                wrapped_dk,
                label,
                created_at: now_unix(),
                removed_at: None,
            },
        );
        Ok(id)
    }

    /// Remove a slot: erase its wrapped DK and mark it removed. Refuses to
    /// remove the last active slot.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown or already removed slots, or when the
    /// slot is the last active one.
    pub fn remove_slot(&mut self, id: &str) -> Result<(), CoreError> {
        let active = self.keyslots.values().filter(|s| s.is_active()).count();
        let slot = self
            .keyslots
            .get_mut(id)
            .ok_or_else(|| CoreError::Secret(format!("no key slot '{id}'")))?;
        if !slot.is_active() {
            return Err(CoreError::Secret(format!(
                "key slot '{id}' is already removed"
            )));
        }
        if active <= 1 {
            return Err(CoreError::Secret(
                "refusing to remove the last active key slot".to_string(),
            ));
        }
        slot.wrapped_dk = String::new();
        slot.removed_at = Some(now_unix());
        Ok(())
    }

    /// Value-free slot descriptions, sorted by creation time.
    #[must_use]
    pub fn slot_infos(&self) -> Vec<KeySlotInfo> {
        let mut out: Vec<KeySlotInfo> = self
            .keyslots
            .iter()
            .map(|(id, s)| KeySlotInfo {
                id: id.clone(),
                kind: s.kind,
                label: s.label.clone(),
                created_at: s.created_at,
                removed_at: s.removed_at,
            })
            .collect();
        out.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        out
    }

    /// Union another replica's slots into this manifest. A removal always
    /// wins over an active copy of the same slot (earliest removal time
    /// between two removals), so revocations propagate. Returns whether
    /// anything changed. Both manifests must already be MAC-verified.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifests belong to different vaults.
    pub fn merge_from(&mut self, other: &Self) -> Result<bool, CoreError> {
        if self.vault_id != other.vault_id {
            return Err(CoreError::Secret(format!(
                "manifest of vault {} is not a replica of vault {}",
                other.vault_id, self.vault_id
            )));
        }
        let before = self.clone();
        self.passphrase_policy_checked |= other.passphrase_policy_checked;
        for (id, theirs) in &other.keyslots {
            match self.keyslots.get_mut(id) {
                None => {
                    self.keyslots.insert(id.clone(), theirs.clone());
                }
                Some(ours) => match (ours.removed_at, theirs.removed_at) {
                    (None, Some(_)) => *ours = theirs.clone(),
                    (Some(a), Some(b)) if b < a => ours.removed_at = Some(b),
                    _ => {}
                },
            }
        }
        Ok(*self != before)
    }
}

// ---------------------------------------------------------------------------
// Entry files
// ---------------------------------------------------------------------------

/// One entry file: encrypted entry name plus its operation log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFile {
    /// Schema version. Always 5.
    pub version: u32,
    /// Owning vault id.
    pub vault_id: String,
    /// Deterministically encrypted `service/key`, bound to the file id.
    pub name: String,
    /// The entry's operations, sorted by op id.
    pub ops: Vec<Op>,
    /// Hex HMAC-SHA256 over the body and the file id.
    #[serde(default)]
    pub mac: String,
}

impl EntryFile {
    fn mac_body_bytes(&self, file_id: &str) -> Result<Vec<u8>, CoreError> {
        #[derive(Serialize)]
        struct Body<'a> {
            version: u32,
            vault_id: &'a str,
            file_id: &'a str,
            name: &'a str,
            ops: &'a [Op],
        }
        serde_json::to_vec(&Body {
            version: self.version,
            vault_id: &self.vault_id,
            file_id,
            name: &self.name,
            ops: &self.ops,
        })
        .map_err(|e| CoreError::Serialization(format!("serializing entry MAC body: {e}")))
    }

    /// Parse and structurally validate entry-file bytes (no MAC or key
    /// check): schema version, vault-id encoding, and op-log structure.
    /// This is the no-DK entry point exercised by the fuzz harness and by
    /// callers that only need to shade a hostile file before any crypto.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not a structurally valid v5
    /// entry file.
    pub fn parse(raw: &[u8]) -> Result<Self, CoreError> {
        let file: Self = serde_json::from_slice(raw)
            .map_err(|e| CoreError::Serialization(format!("parsing entry file: {e}")))?;
        if file.version != VERSION {
            return Err(CoreError::Secret(format!(
                "entry file has unsupported version {}",
                file.version
            )));
        }
        validate_hex_id("entry vault id", &file.vault_id, VAULT_ID_LEN)?;
        let mut log = OpLog::new(&file.vault_id);
        log.entries.insert(String::new(), file.ops.clone());
        log.validate_entries()?;
        Ok(file)
    }
}

/// Result of reading one entry: its unioned ops plus the sync conflict
/// copies that were folded in (removed by the next write of the entry).
#[derive(Debug, Clone, Default)]
pub struct EntryRead {
    /// Operations of the entry (empty when it has never been written).
    pub ops: Vec<Op>,
    /// Verified conflict copies included in `ops`.
    pub absorbed: Vec<PathBuf>,
}

/// The whole vault read into memory (list, merge, scan, migration).
#[derive(Debug, Clone, Default)]
pub struct AllEntries {
    /// Every entry's operations.
    pub log: OpLog,
    /// Verified conflict copies folded into `log`, per compound key.
    pub absorbed: BTreeMap<String, Vec<PathBuf>>,
}

/// What a file name inside the entries directory is.
enum EntryName<'a> {
    Main(&'a str),
    ConflictCopy(&'a str),
}

fn classify_entry_name(name: &str) -> Option<EntryName<'_>> {
    let id_len = FILE_ID_LEN * 2;
    if name.len() <= id_len || !name.is_char_boundary(id_len) {
        return None;
    }
    let (id, rest) = name.split_at(id_len);
    let is_json = Path::new(name).extension().is_some_and(|ext| ext == "json");
    if validate_hex_id("entry file id", id, FILE_ID_LEN).is_err() || !is_json {
        return None;
    }
    if rest == ".json" {
        Some(EntryName::Main(id))
    } else if rest.contains(".tmp-") {
        None
    } else {
        Some(EntryName::ConflictCopy(id))
    }
}

/// Entries directory of the vault whose manifest is at `manifest_path`
/// (`vault.json` → `vault.entries`).
#[must_use]
pub fn entries_dir_for(manifest_path: &Path) -> PathBuf {
    let stem = manifest_path
        .file_stem()
        .map_or_else(|| "vault".into(), |s| s.to_string_lossy().into_owned());
    manifest_path.with_file_name(format!("{stem}.entries"))
}

/// A v5 vault on disk. Locking is the caller's job (the vault lock file
/// next to the manifest guards the manifest and all entry files).
#[derive(Debug, Clone)]
pub struct VaultDir {
    manifest_path: PathBuf,
    entries_dir: PathBuf,
}

impl VaultDir {
    /// Vault whose manifest lives at `manifest_path`.
    #[must_use]
    pub fn new(manifest_path: &Path) -> Self {
        Self {
            manifest_path: manifest_path.to_path_buf(),
            entries_dir: entries_dir_for(manifest_path),
        }
    }

    /// Manifest path.
    #[must_use]
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Entries directory.
    #[must_use]
    pub fn entries_dir(&self) -> &Path {
        &self.entries_dir
    }

    /// Read and structurally validate the manifest (MAC not checked).
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is missing or invalid.
    pub fn read_manifest(&self) -> Result<Manifest, CoreError> {
        let raw = fs::read(&self.manifest_path).map_err(CoreError::Io)?;
        Manifest::parse(&raw)
    }

    /// Read the manifest and verify it under `dk`.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is missing, invalid, or fails MAC
    /// verification.
    pub fn read_verified_manifest(&self, dk: &[u8; DK_LEN]) -> Result<Manifest, CoreError> {
        let manifest = self.read_manifest()?;
        manifest.verify_mac(dk)?;
        Ok(manifest)
    }

    /// Finalize and atomically write the manifest. Creates the entries
    /// directory so a fresh vault is complete on disk.
    ///
    /// # Errors
    ///
    /// Returns an error on serialization or I/O failure.
    pub fn write_manifest(
        &self,
        manifest: &mut Manifest,
        dk: &[u8; DK_LEN],
    ) -> Result<(), CoreError> {
        manifest.validate()?;
        manifest.finalize(dk)?;
        self.ensure_entries_dir()?;
        crate::atomic::write_atomic(&self.manifest_path, &manifest.to_bytes_pretty()?)
    }

    fn ensure_entries_dir(&self) -> Result<(), CoreError> {
        fs::create_dir_all(&self.entries_dir).map_err(CoreError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&self.entries_dir, fs::Permissions::from_mode(0o700))
                .map_err(CoreError::Io)?;
        }
        Ok(())
    }

    fn main_path(&self, file_id: &str) -> PathBuf {
        self.entries_dir.join(format!("{file_id}.json"))
    }

    /// Parse and fully verify one entry file (main or conflict copy):
    /// version, vault id, MAC (bound to `file_id`), decrypted name
    /// hashing back to `file_id`, and op-log structure.
    fn load_entry_file(
        path: &Path,
        file_id: &str,
        vault_id: &str,
        dk: &[u8; DK_LEN],
    ) -> Result<(String, Vec<Op>), CoreError> {
        let raw = fs::read(path).map_err(CoreError::Io)?;
        let file: EntryFile = serde_json::from_slice(&raw).map_err(|e| {
            CoreError::Serialization(format!("parsing entry file {}: {e}", path.display()))
        })?;
        if file.version != VERSION {
            return Err(CoreError::Secret(format!(
                "entry file {} has unsupported version {}",
                path.display(),
                file.version
            )));
        }
        if file.vault_id != vault_id {
            return Err(CoreError::Secret(format!(
                "entry file {} belongs to vault {}, not {vault_id}",
                path.display(),
                file.vault_id
            )));
        }
        verify_mac_hex(
            &subkey(dk, INFO_ENTRY_MAC),
            &file.mac_body_bytes(file_id)?,
            &file.mac,
            "entry file",
        )?;
        let ck = decrypt_name(dk, &file.name, file_id)?;
        if entry_file_id(dk, &ck)? != file_id {
            return Err(CoreError::Secret(format!(
                "entry file {} name does not match its file id",
                path.display()
            )));
        }
        let mut log = OpLog::new(vault_id);
        log.entries.insert(ck.clone(), file.ops);
        log.validate_entries()?;
        let ops = log.entries.remove(&ck).unwrap_or_default();
        Ok((ck, ops))
    }

    /// Whether any entry conflict copy exists in the entries directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be listed.
    pub fn has_entry_conflict_copies(&self) -> Result<bool, CoreError> {
        let dir = match fs::read_dir(&self.entries_dir) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(CoreError::Io(e)),
        };
        for item in dir {
            let name = item.map_err(CoreError::Io)?.file_name();
            if matches!(
                classify_entry_name(&name.to_string_lossy()),
                Some(EntryName::ConflictCopy(_))
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Conflict copies of `file_id` currently in the entries directory.
    fn conflict_copies_of(&self, file_id: &str) -> Result<Vec<PathBuf>, CoreError> {
        let mut out = Vec::new();
        let dir = match fs::read_dir(&self.entries_dir) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(CoreError::Io(e)),
        };
        for item in dir {
            let item = item.map_err(CoreError::Io)?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            if let Some(EntryName::ConflictCopy(id)) = classify_entry_name(&name)
                && id == file_id
            {
                out.push(item.path());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Union verified conflict copies into `log` (one entry). Copies that
    /// fail verification are skipped with a warning and left on disk.
    fn absorb_copies(
        log: &mut OpLog,
        copies: Vec<PathBuf>,
        file_id: &str,
        expected_ck: Option<&str>,
        dk: &[u8; DK_LEN],
    ) -> Result<Vec<(String, PathBuf)>, CoreError> {
        let mut absorbed = Vec::new();
        for copy in copies {
            match Self::load_entry_file(&copy, file_id, &log.vault_id.clone(), dk) {
                Ok((ck, ops)) => {
                    if expected_ck.is_some_and(|e| e != ck) {
                        log::warn!("ignoring conflict copy {}: name mismatch", copy.display());
                        continue;
                    }
                    let mut source = OpLog::new(&log.vault_id);
                    source.entries.insert(ck.clone(), ops);
                    vault_v4::merge_ops(log, &source, dk)?;
                    absorbed.push((ck, copy));
                }
                Err(e) => log::warn!(
                    "ignoring unverifiable conflict copy {}: {e}",
                    copy.display()
                ),
            }
        }
        Ok(absorbed)
    }

    /// Read one entry's operation log, including verified sync conflict
    /// copies.
    ///
    /// # Errors
    ///
    /// Returns an error if the main entry file fails verification.
    pub fn read_entry(
        &self,
        dk: &[u8; DK_LEN],
        vault_id: &str,
        compound_key: &str,
    ) -> Result<EntryRead, CoreError> {
        let file_id = entry_file_id(dk, compound_key)?;
        let main = self.main_path(&file_id);
        let mut log = OpLog::new(vault_id);
        if main.exists() {
            let (ck, ops) = Self::load_entry_file(&main, &file_id, vault_id, dk)?;
            if ck != compound_key {
                return Err(CoreError::Secret(format!(
                    "entry file {} does not hold '{compound_key}'",
                    main.display()
                )));
            }
            log.entries.insert(ck, ops);
        }
        let copies = self.conflict_copies_of(&file_id)?;
        let absorbed = if copies.is_empty() {
            Vec::new()
        } else {
            Self::absorb_copies(&mut log, copies, &file_id, Some(compound_key), dk)?
                .into_iter()
                .map(|(_, path)| path)
                .collect()
        };
        Ok(EntryRead {
            ops: log.entries.remove(compound_key).unwrap_or_default(),
            absorbed,
        })
    }

    /// Canonicalize, MAC and atomically write one entry file, then remove
    /// the conflict copies whose operations it now contains. Must run
    /// under the exclusive vault lock.
    ///
    /// # Errors
    ///
    /// Returns an error on graph violations, serialization or I/O failure.
    pub fn write_entry(
        &self,
        dk: &[u8; DK_LEN],
        vault_id: &str,
        compound_key: &str,
        ops: Vec<Op>,
        absorbed: &[PathBuf],
    ) -> Result<(), CoreError> {
        let mut log = OpLog::new(vault_id);
        log.entries.insert(compound_key.to_string(), ops);
        log.canonicalize()?;
        let ops = log.entries.remove(compound_key).unwrap_or_default();
        let file_id = entry_file_id(dk, compound_key)?;
        let mut file = EntryFile {
            version: VERSION,
            vault_id: vault_id.to_string(),
            name: encrypt_name(dk, compound_key, &file_id)?,
            ops,
            mac: String::new(),
        };
        file.mac = mac_hex(&subkey(dk, INFO_ENTRY_MAC), &file.mac_body_bytes(&file_id)?)?;
        let bytes = serde_json::to_string_pretty(&file)
            .map_err(|e| CoreError::Serialization(format!("serializing entry file: {e}")))?;
        self.ensure_entries_dir()?;
        crate::atomic::write_atomic(&self.main_path(&file_id), bytes.as_bytes())?;
        for copy in absorbed {
            if let Err(e) = fs::remove_file(copy) {
                log::warn!(
                    "could not remove absorbed conflict copy {}: {e}",
                    copy.display()
                );
            }
        }
        Ok(())
    }

    /// Read every entry (main files and verified conflict copies).
    ///
    /// # Errors
    ///
    /// Returns an error if any main entry file fails verification.
    pub fn read_all(&self, dk: &[u8; DK_LEN], vault_id: &str) -> Result<AllEntries, CoreError> {
        let mut all = AllEntries {
            log: OpLog::new(vault_id),
            absorbed: BTreeMap::new(),
        };
        let dir = match fs::read_dir(&self.entries_dir) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(all),
            Err(e) => return Err(CoreError::Io(e)),
        };
        let mut mains: BTreeSet<String> = BTreeSet::new();
        let mut copies: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
        for item in dir {
            let item = item.map_err(CoreError::Io)?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            match classify_entry_name(&name) {
                Some(EntryName::Main(id)) => {
                    mains.insert(id.to_string());
                }
                Some(EntryName::ConflictCopy(id)) => {
                    copies.entry(id.to_string()).or_default().push(item.path());
                }
                None => {}
            }
        }
        for file_id in &mains {
            let (ck, ops) = Self::load_entry_file(&self.main_path(file_id), file_id, vault_id, dk)?;
            all.log.entries.insert(ck, ops);
        }
        for (file_id, mut paths) in copies {
            paths.sort();
            for (ck, path) in Self::absorb_copies(&mut all.log, paths, &file_id, None, dk)? {
                all.absorbed.entry(ck).or_default().push(path);
            }
        }
        Ok(all)
    }

    /// Sibling conflict copies of the manifest itself (e.g. Syncthing's
    /// `vault.sync-conflict-….json`, or `vault (conflicted copy …).json`).
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest directory cannot be listed.
    pub fn manifest_conflict_copies(&self) -> Result<Vec<PathBuf>, CoreError> {
        let Some(parent) = self.manifest_path.parent() else {
            return Ok(Vec::new());
        };
        let stem = self
            .manifest_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ext = self
            .manifest_path
            .extension()
            .map(|s| format!(".{}", s.to_string_lossy()))
            .unwrap_or_default();
        let mut out = Vec::new();
        for item in fs::read_dir(parent).map_err(CoreError::Io)? {
            let item = item.map_err(CoreError::Io)?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            let Some(rest) = name.strip_prefix(stem.as_str()) else {
                continue;
            };
            if name.ends_with(ext.as_str())
                && (rest.starts_with(".sync-conflict-") || rest.starts_with(" ("))
            {
                out.push(item.path());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Write an in-memory v4 vault (freshly migrated from v3, or a legacy
    /// single-file v4) as v5. Entry files are unioned with any already on
    /// disk (leftovers of an interrupted migration, or entries synced from
    /// a replica that migrated first); the manifest is written last, so
    /// it is the commit point. Must run under the exclusive vault lock.
    ///
    /// # Errors
    ///
    /// Returns an error on verification, serialization or I/O failure.
    pub fn write_from_v4(
        &self,
        v4: &VaultFileV4,
        dk: &[u8; DK_LEN],
    ) -> Result<Manifest, CoreError> {
        for (ck, ops) in &v4.entries {
            let existing = self.read_entry(dk, &v4.vault_id, ck)?;
            let mut target = OpLog::new(&v4.vault_id);
            target.entries.insert(ck.clone(), existing.ops);
            let mut source = OpLog::new(&v4.vault_id);
            source.entries.insert(ck.clone(), ops.clone());
            vault_v4::merge_ops(&mut target, &source, dk)?;
            let merged = target.entries.remove(ck).unwrap_or_default();
            self.write_entry(dk, &v4.vault_id, ck, merged, &existing.absorbed)?;
        }
        let mut manifest = Manifest::from_legacy(
            &v4.vault_id,
            &v4.kdf,
            &v4.wrapped_dk,
            v4.passphrase_policy_checked,
        );
        self.write_manifest(&mut manifest, dk)?;
        Ok(manifest)
    }
}

/// Write every entry of `after` whose ops differ from `before` (plus any
/// entry with absorbed conflict copies, which are then removed). Must run
/// under the exclusive vault lock.
///
/// # Errors
///
/// Returns an error if a write fails.
pub fn write_changed(
    dir: &VaultDir,
    before: &AllEntries,
    after: &OpLog,
    dk: &[u8; DK_LEN],
) -> Result<usize, CoreError> {
    let mut written = 0;
    for (ck, ops) in &after.entries {
        let absorbed = before.absorbed.get(ck).map_or(&[][..], Vec::as_slice);
        if before.log.entries.get(ck) != Some(ops) || !absorbed.is_empty() {
            dir.write_entry(dk, &after.vault_id, ck, ops.clone(), absorbed)?;
            written += 1;
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests assert outcomes: expect/unwrap are the failure mechanism"
    )]

    use super::*;

    #[test]
    fn classify_entry_names() {
        let id = "0123456789abcdef0123456789abcdef";
        assert!(matches!(
            classify_entry_name(&format!("{id}.json")),
            Some(EntryName::Main(x)) if x == id
        ));
        assert!(matches!(
            classify_entry_name(&format!("{id}.sync-conflict-20260928-120000-ABC.json")),
            Some(EntryName::ConflictCopy(x)) if x == id
        ));
        assert!(classify_entry_name(&format!(".{id}.json.tmp-123")).is_none());
        assert!(classify_entry_name(&format!("{id}.json.tmp-123.json")).is_none());
        assert!(classify_entry_name("notes.json").is_none());
        assert!(classify_entry_name(&format!("{}.json", id.to_uppercase())).is_none());
    }

    #[test]
    fn name_encryption_is_deterministic_and_bound_to_file_id() {
        let dk = [7u8; DK_LEN];
        let id = entry_file_id(&dk, "svc/key").unwrap();
        let a = encrypt_name(&dk, "svc/key", &id).unwrap();
        let b = encrypt_name(&dk, "svc/key", &id).unwrap();
        assert_eq!(a, b);
        assert_eq!(decrypt_name(&dk, &a, &id).unwrap(), "svc/key");
        let other = entry_file_id(&dk, "svc/other").unwrap();
        assert!(decrypt_name(&dk, &a, &other).is_err());
    }

    #[test]
    fn manifest_slot_merge_removal_wins() {
        let dk = [9u8; DK_LEN];
        let pass = SecretString::from("first passphrase for tests".to_string());
        let mut a = Manifest::from_legacy(
            "00112233445566778899aabbccddeeff",
            &KdfParams::with_random_salt().unwrap(),
            "wrapped",
            true,
        );
        let legacy_id = a.keyslots.keys().next().unwrap().clone();
        let mut b = a.clone();
        let new_id = b
            .add_passphrase_slot(&dk, &pass, Some("laptop".into()))
            .unwrap();
        b.remove_slot(&legacy_id).unwrap();

        assert!(a.merge_from(&b).unwrap());
        assert_eq!(a.keyslots, b.keyslots);
        assert!(!a.keyslots[&legacy_id].is_active());
        assert_eq!(a.keyslots[&legacy_id].wrapped_dk, "");
        assert!(a.keyslots[&new_id].is_active());
        // Idempotent.
        assert!(!a.merge_from(&b).unwrap());
    }

    #[test]
    fn remove_last_active_slot_is_refused() {
        let mut m = Manifest::from_legacy(
            "00112233445566778899aabbccddeeff",
            &KdfParams::with_random_salt().unwrap(),
            "wrapped",
            true,
        );
        let id = m.keyslots.keys().next().unwrap().clone();
        assert!(m.remove_slot(&id).is_err());
    }
}
