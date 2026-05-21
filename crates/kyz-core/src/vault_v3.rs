//! Vault format v3: one-time scrypt + DK-wrapped XChaCha20-Poly1305.
//!
//! Crypto layering:
//! - **KEK** = `scrypt(passphrase, salt, log_n=17, r=8, p=1)` → 32 bytes.
//!   Derived once at unlock. This is the only intentionally-slow step.
//! - **DK** = random 32 bytes generated at vault init. Wrapped under KEK with
//!   XChaCha20-Poly1305 (24-byte random nonce) and stored in the vault file
//!   header. After unlock, the unwrapped DK lives in the OS keyring.
//! - **Per-entry** field blobs are XChaCha20-Poly1305(DK, random nonce, JSON).
//!
//! Net effect: scrypt runs once per unlock; subsequent get/set do only AEAD
//! (sub-millisecond).

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use scrypt::Params as ScryptParams;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::store::{
    DEFAULT_HISTORY_RETENTION, HistoryEntry, SecretEntry, SecretSummary, VaultFileV2,
    decrypt_entry, now_unix,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of the data key in bytes (XChaCha20-Poly1305 takes a 256-bit key).
pub const DK_LEN: usize = 32;

/// Length of the XChaCha20-Poly1305 nonce in bytes (192 bits).
pub const XCHACHA_NONCE_LEN: usize = 24;

/// Length of the Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;

/// Length of the scrypt salt in bytes.
pub const KDF_SALT_LEN: usize = 16;

/// Default scrypt cost parameter (N = 2^17 = 131072).
///
/// On a modern CPU this takes roughly 0.5-1.0 seconds — slow enough to deter
/// brute-force, fast enough to be tolerable at unlock time.
pub const DEFAULT_KDF_LOG_N: u8 = 17;

/// Default scrypt block size parameter.
pub const DEFAULT_KDF_R: u32 = 8;

/// Default scrypt parallelism parameter.
pub const DEFAULT_KDF_P: u32 = 1;

// ---------------------------------------------------------------------------
// KDF parameters (stored in vault file header)
// ---------------------------------------------------------------------------

/// Scrypt parameters and salt persisted alongside the vault.
///
/// The salt is unique per vault and never reused. `log_n`/`r`/`p` are stored
/// so a future tuning of defaults does not invalidate existing vaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// KDF algorithm identifier. Always `"scrypt"` in v3.
    pub algo: String,
    /// Scrypt cost parameter (`N = 2^log_n`).
    pub log_n: u8,
    /// Scrypt block size parameter.
    pub r: u32,
    /// Scrypt parallelism parameter.
    pub p: u32,
    /// Base64-encoded salt (16 random bytes).
    pub salt_b64: String,
}

impl KdfParams {
    /// Create a fresh `KdfParams` with default cost and a random salt.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS RNG fails.
    pub fn with_random_salt() -> Result<Self, CoreError> {
        let mut salt = [0u8; KDF_SALT_LEN];
        getrandom::fill(&mut salt)
            .map_err(|e| CoreError::Secret(format!("getrandom for KDF salt: {e}")))?;
        Ok(Self {
            algo: "scrypt".to_string(),
            log_n: DEFAULT_KDF_LOG_N,
            r: DEFAULT_KDF_R,
            p: DEFAULT_KDF_P,
            salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
        })
    }

    fn salt_bytes(&self) -> Result<Vec<u8>, CoreError> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.salt_b64)
            .map_err(|e| CoreError::Serialization(format!("invalid KDF salt base64: {e}")))
    }

    fn scrypt_params(&self) -> Result<ScryptParams, CoreError> {
        if self.algo != "scrypt" {
            return Err(CoreError::Secret(format!(
                "unsupported KDF algorithm '{}'",
                self.algo
            )));
        }
        ScryptParams::new(self.log_n, self.r, self.p, DK_LEN)
            .map_err(|e| CoreError::Secret(format!("invalid scrypt params: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Vault file structure
// ---------------------------------------------------------------------------

/// Vault file format v3: one-time scrypt-derived KEK wraps a per-vault DK;
/// entries are encrypted under the DK with XChaCha20-Poly1305.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFileV3 {
    /// Schema version. Always 3.
    pub version: u32,
    /// KDF parameters used to derive the KEK from the passphrase.
    pub kdf: KdfParams,
    /// The DK encrypted under the KEK. Base64 of `nonce(24) || ct || tag`.
    pub wrapped_dk: String,
    /// Whether passphrase strength policy has already been checked.
    #[serde(default = "default_true")]
    pub passphrase_policy_checked: bool,
    /// Entries keyed by `"service/key"`.
    pub entries: BTreeMap<String, EncryptedEntryV3>,
}

/// An entry with plaintext metadata and DK-encrypted field values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEntryV3 {
    /// The key (name) of the secret.
    pub key: String,
    /// The service namespace.
    pub service: String,
    /// Tags for categorization (plaintext).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<String>,
    /// Field names (plaintext so listing works without DK).
    pub field_names: Vec<String>,
    /// Unix timestamp when created.
    pub created_at: u64,
    /// Unix timestamp when last modified.
    pub updated_at: u64,
    /// Base64 of `nonce(24) || ct || tag` of the JSON field map.
    pub fields_blob: String,
    /// Previous versions, newest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntryV3>,
}

/// A historical version of an entry's encrypted fields (v3 layout).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntryV3 {
    /// Monotonic version number (1-based).
    pub version: u32,
    /// Unix timestamp when this version was archived.
    pub archived_at: u64,
    /// Field names at the time of this version.
    pub field_names: Vec<String>,
    /// Base64 of `nonce(24) || ct || tag` of the JSON field map.
    pub fields_blob: String,
}

const fn default_true() -> bool {
    true
}

impl VaultFileV3 {
    /// Current schema version.
    pub const CURRENT_VERSION: u32 = 3;

    /// Create a brand new v3 vault with a freshly generated DK.
    ///
    /// Returns both the on-disk file structure (with DK wrapped under KEK) and
    /// the unwrapped DK for the caller to retain for the active session.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS RNG or scrypt fails.
    pub fn create(passphrase: &SecretString) -> Result<(Self, Zeroizing<[u8; DK_LEN]>), CoreError> {
        let kdf = KdfParams::with_random_salt()?;
        let kek = derive_kek(passphrase, &kdf)?;
        let dk = generate_dk()?;
        let wrapped_dk = aead_encrypt_b64(&kek, &*dk)?;
        let file = Self {
            version: Self::CURRENT_VERSION,
            kdf,
            wrapped_dk,
            passphrase_policy_checked: false,
            entries: BTreeMap::new(),
        };
        Ok((file, dk))
    }

    /// Build a compound key from service and entry key.
    #[must_use]
    pub fn compound_key(service: &str, key: &str) -> String {
        format!("{service}/{key}")
    }

    /// Unwrap the data key using the passphrase. Pays one scrypt.
    ///
    /// # Errors
    ///
    /// Returns an error if the passphrase is wrong or the file is corrupt.
    pub fn unwrap_dk(
        &self,
        passphrase: &SecretString,
    ) -> Result<Zeroizing<[u8; DK_LEN]>, CoreError> {
        let kek = derive_kek(passphrase, &self.kdf)?;
        let bytes = aead_decrypt_b64(&kek, &self.wrapped_dk)
            .map_err(|_| CoreError::Secret("wrong passphrase or vault corrupt".to_string()))?;
        if bytes.len() != DK_LEN {
            return Err(CoreError::Secret(format!(
                "unexpected DK length {} (want {DK_LEN})",
                bytes.len()
            )));
        }
        let mut dk = Zeroizing::new([0u8; DK_LEN]);
        dk.copy_from_slice(&bytes);
        Ok(dk)
    }

    /// List summaries for a service (no decryption needed).
    #[must_use]
    pub fn summaries(&self, service: &str) -> Vec<SecretSummary> {
        self.entries
            .values()
            .filter(|e| e.service == service)
            .map(|e| SecretSummary {
                key: e.key.clone(),
                service: e.service.clone(),
                field_names: e.field_names.clone(),
                tags: e.tags.clone(),
                updated_at: e.updated_at,
            })
            .collect()
    }

    /// List all service names (no decryption needed).
    #[must_use]
    pub fn services(&self) -> Vec<String> {
        let mut svcs: Vec<String> = self.entries.values().map(|e| e.service.clone()).collect();
        svcs.sort();
        svcs.dedup();
        svcs
    }

    /// Get an encrypted entry by service/key.
    #[must_use]
    pub fn get_encrypted(&self, service: &str, key: &str) -> Option<&EncryptedEntryV3> {
        self.entries.get(&Self::compound_key(service, key))
    }

    /// Insert or update an entry. Uses [`DEFAULT_HISTORY_RETENTION`].
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or decryption (for merging) fails.
    pub fn set(&mut self, entry: &SecretEntry, dk: &[u8; DK_LEN]) -> Result<(), CoreError> {
        self.set_with_retention(entry, dk, DEFAULT_HISTORY_RETENTION)
    }

    /// Insert or update an entry with a specific history retention limit.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or decryption (for merging) fails.
    pub fn set_with_retention(
        &mut self,
        entry: &SecretEntry,
        dk: &[u8; DK_LEN],
        max_history: u32,
    ) -> Result<(), CoreError> {
        let ck = Self::compound_key(&entry.service, &entry.key);

        if let Some(existing) = self.entries.get(&ck) {
            let mut merged = decrypt_entry_v3(existing, dk)?;

            let mut history = existing.history.clone();
            let next_version = history.first().map_or(1, |h| h.version + 1);
            history.insert(
                0,
                HistoryEntryV3 {
                    version: next_version,
                    archived_at: now_unix(),
                    field_names: existing.field_names.clone(),
                    fields_blob: existing.fields_blob.clone(),
                },
            );
            if max_history > 0 {
                history.truncate(max_history as usize);
            }

            for (name, value) in &entry.fields {
                merged.fields.insert(name.clone(), value.clone());
            }
            merged.tags.extend(entry.tags.iter().cloned());
            merged.updated_at = now_unix();
            let mut encrypted = encrypt_entry_v3(&merged, dk)?;
            encrypted.history = history;
            self.entries.insert(ck, encrypted);
        } else {
            let encrypted = encrypt_entry_v3(entry, dk)?;
            self.entries.insert(ck, encrypted);
        }
        Ok(())
    }

    /// Rollback an entry to a specific history version.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry/version is missing or AEAD fails.
    pub fn rollback_with_retention(
        &mut self,
        service: &str,
        key: &str,
        target_version: u32,
        dk: &[u8; DK_LEN],
        max_history: u32,
    ) -> Result<(), CoreError> {
        let ck = Self::compound_key(service, key);
        let existing = self.entries.get(&ck).ok_or_else(|| {
            CoreError::SecretNotFound(format!("secret '{key}' not found in service '{service}'"))
        })?;

        let target_idx = existing
            .history
            .iter()
            .position(|h| h.version == target_version)
            .ok_or_else(|| {
                CoreError::Secret(format!(
                    "version {target_version} not found in history for '{service}/{key}'"
                ))
            })?;
        let target = &existing.history[target_idx];

        // Decrypt the target version's fields directly.
        let restored_fields_json = aead_decrypt_b64(dk, &target.fields_blob)?;
        let restored_fields: BTreeMap<String, String> =
            serde_json::from_slice(&restored_fields_json)
                .map_err(|e| CoreError::Serialization(format!("parsing restored fields: {e}")))?;

        let restored = SecretEntry {
            key: existing.key.clone(),
            service: existing.service.clone(),
            fields: restored_fields
                .into_iter()
                .map(|(k, v)| (k, SecretString::from(v)))
                .collect(),
            tags: existing.tags.clone(),
            created_at: existing.created_at,
            updated_at: now_unix(),
        };

        // Archive current version before rollback.
        let mut history = existing.history.clone();
        let next_version = history.first().map_or(1, |h| h.version + 1);
        history.insert(
            0,
            HistoryEntryV3 {
                version: next_version,
                archived_at: now_unix(),
                field_names: existing.field_names.clone(),
                fields_blob: existing.fields_blob.clone(),
            },
        );
        if max_history > 0 {
            history.truncate(max_history as usize);
        }

        let mut new_entry = encrypt_entry_v3(&restored, dk)?;
        new_entry.history = history;
        self.entries.insert(ck, new_entry);
        Ok(())
    }

    /// Convenience wrapper using the default retention.
    ///
    /// # Errors
    ///
    /// See [`Self::rollback_with_retention`].
    pub fn rollback(
        &mut self,
        service: &str,
        key: &str,
        target_version: u32,
        dk: &[u8; DK_LEN],
    ) -> Result<(), CoreError> {
        self.rollback_with_retention(service, key, target_version, dk, DEFAULT_HISTORY_RETENTION)
    }

    /// Remove an entry. Returns true if it existed.
    pub fn remove(&mut self, service: &str, key: &str) -> bool {
        self.entries
            .remove(&Self::compound_key(service, key))
            .is_some()
    }
}

// ---------------------------------------------------------------------------
// Crypto primitives
// ---------------------------------------------------------------------------

/// Derive a 32-byte KEK from a passphrase + KDF parameters using scrypt.
///
/// # Errors
///
/// Returns an error if scrypt fails.
pub fn derive_kek(
    passphrase: &SecretString,
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; DK_LEN]>, CoreError> {
    let params = kdf.scrypt_params()?;
    let salt = kdf.salt_bytes()?;
    let mut kek = Zeroizing::new([0u8; DK_LEN]);
    scrypt::scrypt(
        passphrase.expose_secret().as_bytes(),
        &salt,
        &params,
        kek.as_mut_slice(),
    )
    .map_err(|e| CoreError::Secret(format!("scrypt KEK derivation failed: {e}")))?;
    Ok(kek)
}

/// Generate a fresh random 32-byte data key from the OS RNG.
///
/// # Errors
///
/// Returns an error if the OS RNG fails.
pub fn generate_dk() -> Result<Zeroizing<[u8; DK_LEN]>, CoreError> {
    let mut dk = Zeroizing::new([0u8; DK_LEN]);
    getrandom::fill(dk.as_mut_slice())
        .map_err(|e| CoreError::Secret(format!("getrandom DK: {e}")))?;
    Ok(dk)
}

/// AEAD-encrypt `plaintext` under `key` with a random nonce.
///
/// Returns base64 of `nonce(24) || ciphertext || tag(16)`.
fn aead_encrypt_b64(key: &[u8; DK_LEN], plaintext: &[u8]) -> Result<String, CoreError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| CoreError::Secret(format!("getrandom AEAD nonce: {e}")))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CoreError::Secret(format!("AEAD encrypt: {e}")))?;
    let mut out = Vec::with_capacity(XCHACHA_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(base64::engine::general_purpose::STANDARD.encode(&out))
}

fn aead_decrypt_b64(key: &[u8; DK_LEN], blob_b64: &str) -> Result<Vec<u8>, CoreError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .map_err(|e| CoreError::Serialization(format!("invalid AEAD blob base64: {e}")))?;
    if raw.len() < XCHACHA_NONCE_LEN + TAG_LEN {
        return Err(CoreError::Secret("AEAD blob too short".to_string()));
    }
    let (nonce_bytes, ct) = raw.split_at(XCHACHA_NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| CoreError::Secret(format!("AEAD decrypt failed: {e}")))
}

// ---------------------------------------------------------------------------
// Entry encrypt / decrypt
// ---------------------------------------------------------------------------

/// Encrypt a [`SecretEntry`]'s fields into an [`EncryptedEntryV3`] using the DK.
///
/// # Errors
///
/// Returns an error if serialization or AEAD fails.
pub fn encrypt_entry_v3(
    entry: &SecretEntry,
    dk: &[u8; DK_LEN],
) -> Result<EncryptedEntryV3, CoreError> {
    let plain_fields: BTreeMap<&str, &str> = entry
        .fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.expose_secret()))
        .collect();
    let json = serde_json::to_vec(&plain_fields)
        .map_err(|e| CoreError::Serialization(format!("serializing entry fields: {e}")))?;
    let fields_blob = aead_encrypt_b64(dk, &json)?;

    Ok(EncryptedEntryV3 {
        key: entry.key.clone(),
        service: entry.service.clone(),
        tags: entry.tags.clone(),
        field_names: entry.fields.keys().cloned().collect(),
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        fields_blob,
        history: Vec::new(),
    })
}

/// Decrypt an [`EncryptedEntryV3`] back into a [`SecretEntry`] using the DK.
///
/// # Errors
///
/// Returns an error if AEAD fails or the blob is malformed.
pub fn decrypt_entry_v3(
    entry: &EncryptedEntryV3,
    dk: &[u8; DK_LEN],
) -> Result<SecretEntry, CoreError> {
    let plain = aead_decrypt_b64(dk, &entry.fields_blob)?;
    let plain_fields: BTreeMap<String, String> = serde_json::from_slice(&plain)
        .map_err(|e| CoreError::Serialization(format!("parsing decrypted fields: {e}")))?;
    let fields: BTreeMap<String, SecretString> = plain_fields
        .into_iter()
        .map(|(k, v)| (k, SecretString::from(v)))
        .collect();
    Ok(SecretEntry {
        key: entry.key.clone(),
        service: entry.service.clone(),
        fields,
        tags: entry.tags.clone(),
        created_at: entry.created_at,
        updated_at: entry.updated_at,
    })
}

// ---------------------------------------------------------------------------
// Migration from V2
// ---------------------------------------------------------------------------

/// Convert a v2 vault (per-entry scrypt-age) to a v3 vault (DK-wrapped AEAD).
///
/// Decrypts each v2 entry with the passphrase (paying one scrypt per entry,
/// one-time cost), then re-encrypts under a freshly generated DK. The returned
/// [`VaultFileV3`] is ready to write; the returned DK is what the caller
/// should put in the new session.
///
/// # Errors
///
/// Returns an error if any v2 entry fails to decrypt (wrong passphrase) or if
/// re-encryption fails.
pub fn migrate_v2_to_v3(
    v2: &VaultFileV2,
    passphrase: &SecretString,
) -> Result<(VaultFileV3, Zeroizing<[u8; DK_LEN]>), CoreError> {
    let kdf = KdfParams::with_random_salt()?;
    let kek = derive_kek(passphrase, &kdf)?;
    let dk = generate_dk()?;
    let wrapped_dk = aead_encrypt_b64(&kek, &*dk)?;

    let mut v3_entries: BTreeMap<String, EncryptedEntryV3> = BTreeMap::new();
    for (ck, v2_entry) in &v2.entries {
        // Decrypt under passphrase (legacy v2 per-entry scrypt-age path).
        let plain = decrypt_entry(v2_entry, passphrase)?;
        let mut v3_entry = encrypt_entry_v3(&plain, &dk)?;
        // Re-encrypt history blobs too.
        v3_entry.history = migrate_v2_history(&v2_entry.history, passphrase, &dk)?;
        v3_entries.insert(ck.clone(), v3_entry);
    }

    Ok((
        VaultFileV3 {
            version: VaultFileV3::CURRENT_VERSION,
            kdf,
            wrapped_dk,
            passphrase_policy_checked: v2.passphrase_policy_checked,
            entries: v3_entries,
        },
        dk,
    ))
}

fn migrate_v2_history(
    v2_history: &[HistoryEntry],
    passphrase: &SecretString,
    dk: &[u8; DK_LEN],
) -> Result<Vec<HistoryEntryV3>, CoreError> {
    use base64::Engine as _;

    let mut out = Vec::with_capacity(v2_history.len());
    for h in v2_history {
        // Each v2 history blob is a standalone scrypt-age ciphertext.
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(&h.encrypted_fields)
            .map_err(|e| CoreError::Serialization(format!("invalid history base64: {e}")))?;
        let decryptor = age::Decryptor::new(&encrypted[..])
            .map_err(|e| CoreError::Secret(format!("history age decrypt: {e}")))?;
        let identity = age::scrypt::Identity::new(passphrase.clone());
        let mut plain = Vec::new();
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| CoreError::Secret(format!("history decrypt: {e}")))?;
        std::io::Read::read_to_end(&mut reader, &mut plain)
            .map_err(|e| CoreError::Secret(format!("history read: {e}")))?;
        let fields_blob = aead_encrypt_b64(dk, &plain)?;
        out.push(HistoryEntryV3 {
            version: h.version,
            archived_at: h.archived_at,
            field_names: h.field_names.clone(),
            fields_blob,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_entry(service: &str, key: &str, val: &str) -> SecretEntry {
        let mut fields = BTreeMap::new();
        fields.insert("value".to_string(), SecretString::from(val.to_string()));
        SecretEntry::new(service, key, fields)
    }

    #[test]
    fn dk_unwrap_roundtrip() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let (file, dk) = VaultFileV3::create(&pass).expect("create");
        let unwrapped = file.unwrap_dk(&pass).expect("unwrap");
        assert_eq!(&*dk, unwrapped.as_ref());
    }

    #[test]
    fn dk_unwrap_wrong_passphrase_fails() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let wrong = SecretString::from("incorrect horse battery staple".to_string());
        let (file, _dk) = VaultFileV3::create(&pass).expect("create");
        assert!(file.unwrap_dk(&wrong).is_err());
    }

    #[test]
    fn entry_encrypt_decrypt_roundtrip() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let (mut file, dk) = VaultFileV3::create(&pass).expect("create");
        let entry = make_entry("svc", "tok", "hunter2");
        file.set(&entry, &*dk).expect("set");

        let enc = file.get_encrypted("svc", "tok").expect("present");
        let dec = decrypt_entry_v3(enc, &*dk).expect("decrypt");
        assert_eq!(dec.value(), Some("hunter2"));
    }

    #[test]
    fn entry_with_wrong_dk_fails() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let (mut file, dk) = VaultFileV3::create(&pass).expect("create");
        let entry = make_entry("svc", "tok", "hunter2");
        file.set(&entry, &*dk).expect("set");

        let bad_dk = [0u8; DK_LEN];
        let enc = file.get_encrypted("svc", "tok").expect("present");
        assert!(decrypt_entry_v3(enc, &bad_dk).is_err());
    }

    #[test]
    fn history_archived_on_overwrite() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let (mut file, dk) = VaultFileV3::create(&pass).expect("create");
        file.set(&make_entry("svc", "tok", "v1"), &*dk)
            .expect("set v1");
        file.set(&make_entry("svc", "tok", "v2"), &*dk)
            .expect("set v2");

        let enc = file.get_encrypted("svc", "tok").expect("present");
        assert_eq!(enc.history.len(), 1);
        assert_eq!(decrypt_entry_v3(enc, &*dk).unwrap().value(), Some("v2"));

        // history[0] should still decrypt to v1
        let h0 = &enc.history[0];
        let plain = aead_decrypt_b64(&*dk, &h0.fields_blob).expect("decrypt history");
        let map: BTreeMap<String, String> = serde_json::from_slice(&plain).unwrap();
        assert_eq!(map.get("value"), Some(&"v1".to_string()));
    }

    #[test]
    fn rollback_restores_version() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let (mut file, dk) = VaultFileV3::create(&pass).expect("create");
        file.set(&make_entry("svc", "tok", "v1"), &*dk).unwrap();
        file.set(&make_entry("svc", "tok", "v2"), &*dk).unwrap();
        let prior = file.get_encrypted("svc", "tok").unwrap().history[0].version;

        file.rollback("svc", "tok", prior, &*dk).expect("rollback");
        let enc = file.get_encrypted("svc", "tok").unwrap();
        let dec = decrypt_entry_v3(enc, &*dk).unwrap();
        assert_eq!(dec.value(), Some("v1"));
    }

    #[test]
    fn migrate_v2_to_v3_preserves_entries() {
        use crate::store::VaultFileV2;
        let pass = SecretString::from("correct horse battery staple".to_string());

        let mut v2 = VaultFileV2::new();
        v2.passphrase_policy_checked = true;
        v2.set(&make_entry("svc", "a", "alpha"), &pass).unwrap();
        v2.set(&make_entry("svc", "b", "beta"), &pass).unwrap();

        let (v3, dk) = migrate_v2_to_v3(&v2, &pass).expect("migrate");
        assert_eq!(v3.version, 3);
        assert_eq!(v3.entries.len(), 2);

        let a = v3.get_encrypted("svc", "a").unwrap();
        assert_eq!(decrypt_entry_v3(a, &*dk).unwrap().value(), Some("alpha"));
        let b = v3.get_encrypted("svc", "b").unwrap();
        assert_eq!(decrypt_entry_v3(b, &*dk).unwrap().value(), Some("beta"));
    }
}
