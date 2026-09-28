//! Secret store abstraction, data model, and backends.
//!
//! Provides:
//! - [`SecretEntry`] with multi-field support (username, password, url, etc.)
//! - [`SecretStore`] trait for CRUD operations
//! - [`KeyringStore`] backed by OS keyring (desktop sessions)
//! - [`VaultStore`] backed by age-encrypted JSON file (headless/agent use)
//! - [`VaultSession`] for unlock/lock lifecycle with tmpfs session files

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::actor::ActorState;
use crate::error::CoreError;
use crate::vault_v3::{DK_LEN, EncryptedEntryV3, VaultFileV3, decrypt_entry_v3, migrate_v2_to_v3};
use crate::vault_v4::{
    self, HistoryItem, Hlc, MergeReport, OpId, Projection, SnapshotPlain, VaultFileV4,
};

/// Default service name used when none is specified.
pub const DEFAULT_SERVICE: &str = "kyz";

/// Default session timeout in seconds (30 minutes).
pub const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 1800;

/// Vault filename.
pub const VAULT_FILENAME: &str = "vault.json";

/// Workspace vault directory name.
pub const WORKSPACE_VAULT_DIR: &str = ".kyz";

/// A stored secret entry with multiple named fields.
///
/// Each entry belongs to a service namespace and has a key (name).
/// Fields hold the actual secret data (username, password, url, notes, etc.).
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// The key (name) of the secret.
    pub key: String,
    /// The service namespace this secret belongs to.
    pub service: String,
    /// Named fields containing the secret data.
    #[serde(with = "secret_fields_serde")]
    pub fields: BTreeMap<String, SecretString>,
    /// Optional tags for categorization and alias matching.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<String>,
    /// Unix timestamp when the entry was created.
    pub created_at: u64,
    /// Unix timestamp when the entry was last modified.
    pub updated_at: u64,
}

impl SecretEntry {
    /// Create a new entry with the given service, key, and fields.
    #[must_use]
    pub fn new(service: &str, key: &str, fields: BTreeMap<String, SecretString>) -> Self {
        let now = now_unix();
        Self {
            key: key.to_string(),
            service: service.to_string(),
            fields,
            tags: BTreeSet::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new entry with tags.
    #[must_use]
    pub fn with_tags(mut self, tags: BTreeSet<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Check if this entry has a specific tag.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }

    /// Create a new entry with a single "value" field (backwards compat).
    #[must_use]
    pub fn single(service: &str, key: &str, value: &str) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("value".to_string(), SecretString::from(value.to_string()));
        Self::new(service, key, fields)
    }

    /// Add a tag to this entry.
    pub fn add_tag(&mut self, tag: &str) {
        self.tags.insert(tag.to_string());
        self.updated_at = now_unix();
    }

    /// Remove a tag from this entry.
    pub fn remove_tag(&mut self, tag: &str) {
        self.tags.remove(tag);
        self.updated_at = now_unix();
    }

    /// Get a specific field value.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .get(name)
            .map(secrecy::ExposeSecret::expose_secret)
    }

    /// Get the "value" field (convenience for single-value entries).
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.field("value")
    }

    /// Set a field, updating the modification timestamp.
    pub fn set_field(&mut self, name: &str, value: &str) {
        self.fields
            .insert(name.to_string(), SecretString::from(value.to_string()));
        self.updated_at = now_unix();
    }
}

impl fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_fields: BTreeMap<&String, &str> =
            self.fields.keys().map(|k| (k, "[REDACTED]")).collect();

        f.debug_struct("SecretEntry")
            .field("key", &self.key)
            .field("service", &self.service)
            .field("fields", &redacted_fields)
            .field("tags", &self.tags)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Summary of a secret entry for listing (no field values exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSummary {
    /// The key (name) of the secret.
    pub key: String,
    /// The service namespace.
    pub service: String,
    /// Names of fields present in this entry.
    pub field_names: Vec<String>,
    /// Tags assigned to this entry.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<String>,
    /// Unix timestamp when last modified.
    pub updated_at: u64,
}

impl From<&SecretEntry> for SecretSummary {
    fn from(entry: &SecretEntry) -> Self {
        Self {
            key: entry.key.clone(),
            service: entry.service.clone(),
            field_names: entry.fields.keys().cloned().collect(),
            tags: entry.tags.clone(),
            updated_at: entry.updated_at,
        }
    }
}

/// Trait for secret store backends.
///
/// Implementations provide CRUD operations for multi-field secret entries
/// organized by service namespace and key name.
pub trait SecretStore: fmt::Debug + Send + Sync {
    /// Retrieve a secret entry by service and key.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret is not found or the backend fails.
    fn get(&self, service: &str, key: &str) -> Result<SecretEntry, CoreError>;

    /// Store or update a secret entry.
    ///
    /// If the entry already exists, fields are merged (new fields added,
    /// existing fields overwritten). To replace entirely, delete first.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to persist the secret.
    fn set(&self, service: &str, key: &str, entry: &SecretEntry) -> Result<(), CoreError>;

    /// Store a secret entry, recreating it when the backend reports the
    /// entry as deleted (tombstoned).
    ///
    /// Backends with physical removal semantics (or no tombstones at all)
    /// implement this identically to [`Self::set`]; the default
    /// implementation does exactly that. Tombstoning backends override it
    /// so library callers can re-add a deleted entry without going
    /// through the interactive `--yes` confirmation the CLI requires.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to persist the secret.
    fn set_recreating(
        &self,
        service: &str,
        key: &str,
        entry: &SecretEntry,
    ) -> Result<(), CoreError> {
        self.set(service, key, entry)
    }

    /// Remove a secret entry by service and key.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret is not found or the backend fails.
    fn delete(&self, service: &str, key: &str) -> Result<(), CoreError>;

    /// List all secret entries for a given service (metadata only, no values).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to enumerate secrets.
    fn list(&self, service: &str) -> Result<Vec<SecretSummary>, CoreError>;

    /// List all services that have entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails.
    fn list_services(&self) -> Result<Vec<String>, CoreError>;
}

/// In-memory representation of the vault's plaintext contents.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// All secret entries, keyed by "service/key".
    pub entries: BTreeMap<String, SecretEntry>,
}

impl VaultData {
    /// Current schema version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new empty vault.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            entries: BTreeMap::new(),
        }
    }

    /// Build a compound key from service and entry key.
    #[must_use]
    pub fn compound_key(service: &str, key: &str) -> String {
        format!("{service}/{key}")
    }

    /// Get an entry by service and key.
    #[must_use]
    pub fn get(&self, service: &str, key: &str) -> Option<&SecretEntry> {
        self.entries.get(&Self::compound_key(service, key))
    }

    /// Insert or merge an entry.
    pub fn set(&mut self, entry: SecretEntry) {
        let ck = Self::compound_key(&entry.service, &entry.key);
        if let Some(existing) = self.entries.get_mut(&ck) {
            for (field_name, field_value) in &entry.fields {
                existing
                    .fields
                    .insert(field_name.clone(), field_value.clone());
            }
            existing.tags.extend(entry.tags.iter().cloned());
            existing.updated_at = now_unix();
        } else {
            self.entries.insert(ck, entry);
        }
    }

    /// Remove an entry. Returns true if it existed.
    pub fn remove(&mut self, service: &str, key: &str) -> bool {
        self.entries
            .remove(&Self::compound_key(service, key))
            .is_some()
    }

    /// List entries for a service.
    #[must_use]
    pub fn list_service(&self, service: &str) -> Vec<&SecretEntry> {
        let prefix = format!("{service}/");
        self.entries
            .values()
            .filter(|e| {
                e.service == service || Self::compound_key(&e.service, &e.key).starts_with(&prefix)
            })
            .collect()
    }

    /// List all distinct service names.
    #[must_use]
    pub fn services(&self) -> Vec<String> {
        let mut svcs: Vec<String> = self.entries.values().map(|e| e.service.clone()).collect();
        svcs.sort();
        svcs.dedup();
        svcs
    }
}

/// Encrypt vault data with a passphrase using age (scrypt KDF + ChaCha20-Poly1305).
///
/// # Errors
///
/// Returns an error if serialization or encryption fails.
pub fn encrypt_vault(data: &VaultData, passphrase: &SecretString) -> Result<Vec<u8>, CoreError> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| CoreError::Serialization(format!("serializing vault: {e}")))?;

    let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| CoreError::Secret(format!("creating age encryptor: {e}")))?;
    writer
        .write_all(json.as_bytes())
        .map_err(|e| CoreError::Secret(format!("encrypting vault: {e}")))?;
    writer
        .finish()
        .map_err(|e| CoreError::Secret(format!("finalizing encryption: {e}")))?;

    Ok(encrypted)
}

/// Decrypt vault data with a passphrase.
///
/// # Errors
///
/// Returns an error if decryption fails (wrong password) or the data is corrupt.
pub fn decrypt_vault(encrypted: &[u8], passphrase: &SecretString) -> Result<VaultData, CoreError> {
    let decryptor = age::Decryptor::new(encrypted)
        .map_err(|e| CoreError::Secret(format!("reading encrypted vault: {e}")))?;

    if !decryptor.is_scrypt() {
        return Err(CoreError::Secret(
            "vault is not passphrase-encrypted".to_string(),
        ));
    }

    let identity = age::scrypt::Identity::new(passphrase.clone());

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| CoreError::Secret(format!("decryption failed (wrong password?): {e}")))?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| CoreError::Secret(format!("reading decrypted data: {e}")))?;

    let data: VaultData = serde_json::from_slice(&decrypted)
        .map_err(|e| CoreError::Serialization(format!("parsing decrypted vault: {e}")))?;

    Ok(data)
}

/// Vault file format v2: per-entry encrypted fields with plaintext metadata.
///
/// Entry names, services, tags, and timestamps are plaintext JSON. Only field
/// values are individually age-encrypted. This allows:
/// - Listing secrets without unlocking
/// - Decrypting individual entries on demand (scoped access)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFileV2 {
    /// Schema version (always 2).
    pub version: u32,
    /// Whether passphrase strength policy has already been checked for this vault.
    ///
    /// New vaults start as `false` and are validated on first unlock.
    /// Legacy vaults missing this field default to `true` to avoid lockouts.
    #[serde(default = "default_policy_checked")]
    pub passphrase_policy_checked: bool,
    /// Entries keyed by "service/key", with encrypted field blobs.
    pub entries: BTreeMap<String, EncryptedEntry>,
}

/// An entry with plaintext metadata and age-encrypted field values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEntry {
    /// The key (name) of the secret.
    pub key: String,
    /// The service namespace.
    pub service: String,
    /// Tags for categorization (plaintext for filtering).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<String>,
    /// Field names (plaintext, so list output works without decrypt).
    pub field_names: Vec<String>,
    /// Unix timestamp when created.
    pub created_at: u64,
    /// Unix timestamp when last modified.
    pub updated_at: u64,
    /// Base64-encoded age-encrypted JSON blob of field name→value pairs.
    pub encrypted_fields: String,
    /// Previous versions of this entry, newest first (max retained by config).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
}

/// A historical version of a secret entry's encrypted fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Monotonic version number (1-based, increments on each update).
    pub version: u32,
    /// Unix timestamp when this version was archived (i.e., when it was replaced).
    pub archived_at: u64,
    /// Field names at the time of this version.
    pub field_names: Vec<String>,
    /// Base64-encoded age-encrypted JSON blob of field values at that time.
    pub encrypted_fields: String,
}

/// Default number of history versions to retain per entry.
pub const DEFAULT_HISTORY_RETENTION: u32 = 10;

const fn default_policy_checked() -> bool {
    true
}

impl VaultFileV2 {
    /// Current schema version.
    pub const CURRENT_VERSION: u32 = 2;

    /// Create a new empty v2 vault.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            passphrase_policy_checked: false,
            entries: BTreeMap::new(),
        }
    }

    /// Build a compound key from service and entry key.
    #[must_use]
    pub fn compound_key(service: &str, key: &str) -> String {
        format!("{service}/{key}")
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
    pub fn get_encrypted(&self, service: &str, key: &str) -> Option<&EncryptedEntry> {
        self.entries.get(&Self::compound_key(service, key))
    }

    /// Insert or update an entry (encrypts field values).
    ///
    /// When updating an existing entry, the current version is archived
    /// into the `history` field before being overwritten.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn set(&mut self, entry: &SecretEntry, passphrase: &SecretString) -> Result<(), CoreError> {
        self.set_with_retention(entry, passphrase, DEFAULT_HISTORY_RETENTION)
    }

    /// Insert or update an entry with a specific history retention limit.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn set_with_retention(
        &mut self,
        entry: &SecretEntry,
        passphrase: &SecretString,
        max_history: u32,
    ) -> Result<(), CoreError> {
        let ck = Self::compound_key(&entry.service, &entry.key);

        if let Some(existing) = self.entries.get(&ck) {
            let mut merged = decrypt_entry(existing, passphrase)?;

            let mut history = existing.history.clone();
            let next_version = history.first().map_or(1, |h| h.version + 1);
            history.insert(
                0,
                HistoryEntry {
                    version: next_version,
                    archived_at: now_unix(),
                    field_names: existing.field_names.clone(),
                    encrypted_fields: existing.encrypted_fields.clone(),
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
            let mut encrypted = encrypt_entry(&merged, passphrase)?;
            encrypted.history = history;
            self.entries.insert(ck, encrypted);
        } else {
            let encrypted = encrypt_entry(entry, passphrase)?;
            self.entries.insert(ck, encrypted);
        }
        Ok(())
    }

    /// Rollback an entry to a specific history version.
    ///
    /// The current entry is archived (so rollback is reversible) and the
    /// requested version's fields are restored as the active entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry or version is not found, or decryption fails.
    pub fn rollback(
        &mut self,
        service: &str,
        key: &str,
        target_version: u32,
        passphrase: &SecretString,
    ) -> Result<(), CoreError> {
        self.rollback_with_retention(
            service,
            key,
            target_version,
            passphrase,
            DEFAULT_HISTORY_RETENTION,
        )
    }

    /// Rollback with a specific history retention limit.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry or version is not found, or decryption fails.
    pub fn rollback_with_retention(
        &mut self,
        service: &str,
        key: &str,
        target_version: u32,
        passphrase: &SecretString,
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

        let target_entry = EncryptedEntry {
            key: existing.key.clone(),
            service: existing.service.clone(),
            tags: existing.tags.clone(),
            field_names: target.field_names.clone(),
            created_at: existing.created_at,
            updated_at: now_unix(),
            encrypted_fields: target.encrypted_fields.clone(),
            history: Vec::new(),
        };
        let restored = decrypt_entry(&target_entry, passphrase)?;

        // Archive current version before rollback (so rollback is reversible)
        let mut history = existing.history.clone();
        let next_version = history.first().map_or(1, |h| h.version + 1);
        history.insert(
            0,
            HistoryEntry {
                version: next_version,
                archived_at: now_unix(),
                field_names: existing.field_names.clone(),
                encrypted_fields: existing.encrypted_fields.clone(),
            },
        );
        if max_history > 0 {
            history.truncate(max_history as usize);
        }

        let mut new_entry = encrypt_entry(&restored, passphrase)?;
        new_entry.history = history;
        self.entries.insert(ck, new_entry);
        Ok(())
    }

    /// Remove an entry. Returns true if it existed.
    pub fn remove(&mut self, service: &str, key: &str) -> bool {
        self.entries
            .remove(&Self::compound_key(service, key))
            .is_some()
    }
}

impl Default for VaultFileV2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt a `SecretEntry`'s fields into an `EncryptedEntry`.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn encrypt_entry(
    entry: &SecretEntry,
    passphrase: &SecretString,
) -> Result<EncryptedEntry, CoreError> {
    use base64::Engine as _;

    // Serialize fields to JSON (exposing secret values for encryption)
    let plain_fields: BTreeMap<&str, &str> = entry
        .fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.expose_secret()))
        .collect();
    let json = serde_json::to_string(&plain_fields)
        .map_err(|e| CoreError::Serialization(format!("serializing entry fields: {e}")))?;

    let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| CoreError::Secret(format!("creating entry encryptor: {e}")))?;
    writer
        .write_all(json.as_bytes())
        .map_err(|e| CoreError::Secret(format!("encrypting entry: {e}")))?;
    writer
        .finish()
        .map_err(|e| CoreError::Secret(format!("finalizing entry encryption: {e}")))?;

    Ok(EncryptedEntry {
        key: entry.key.clone(),
        service: entry.service.clone(),
        tags: entry.tags.clone(),
        field_names: entry.fields.keys().cloned().collect(),
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        encrypted_fields: base64::engine::general_purpose::STANDARD.encode(&encrypted),
        history: Vec::new(),
    })
}

/// Decrypt an `EncryptedEntry` back into a `SecretEntry`.
///
/// # Errors
///
/// Returns an error if decryption fails (wrong passphrase or corrupt data).
pub fn decrypt_entry(
    entry: &EncryptedEntry,
    passphrase: &SecretString,
) -> Result<SecretEntry, CoreError> {
    use base64::Engine as _;

    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(&entry.encrypted_fields)
        .map_err(|e| CoreError::Serialization(format!("invalid base64 in entry: {e}")))?;

    let decryptor = age::Decryptor::new(&encrypted[..])
        .map_err(|e| CoreError::Secret(format!("reading encrypted entry: {e}")))?;

    let identity = age::scrypt::Identity::new(passphrase.clone());

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| CoreError::Secret(format!("entry decryption failed: {e}")))?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| CoreError::Secret(format!("reading decrypted entry: {e}")))?;

    let plain_fields: BTreeMap<String, String> = serde_json::from_slice(&decrypted)
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

/// Detect vault format version from raw file bytes.
///
/// V1: age binary (starts with `age-encryption.org` header).
/// V2: JSON (starts with `{`).
#[must_use]
pub fn detect_vault_version(data: &[u8]) -> u32 {
    if data.first() == Some(&b'{') {
        // JSON — could be v2
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(data)
            && let Some(v) = parsed.get("version").and_then(serde_json::Value::as_u64)
        {
            return v as u32;
        }
        return 2;
    }
    // Binary (age-encrypted) → v1
    1
}

/// Migrate a v1 vault (single age blob) to v2 (per-entry encrypted).
///
/// # Errors
///
/// Returns an error if decryption or re-encryption fails.
pub fn migrate_v1_to_v2(
    v1_data: &[u8],
    passphrase: &SecretString,
) -> Result<VaultFileV2, CoreError> {
    let v1 = decrypt_vault(v1_data, passphrase)?;
    let mut v2 = VaultFileV2::new();
    for entry in v1.entries.values() {
        let encrypted = encrypt_entry(entry, passphrase)?;
        let ck = VaultFileV2::compound_key(&entry.service, &entry.key);
        v2.entries.insert(ck, encrypted);
    }
    Ok(v2)
}

/// Metadata stored in the session file (no secrets).
///
/// The session file holds only non-sensitive data: expiry time and vault path.
/// The actual passphrase is stored in the OS keyring (macOS Keychain, Linux
/// kernel keyutils, or Windows Credential Manager).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionMeta {
    /// Unix timestamp when this session expires.
    expires_at: u64,
    /// Path to the vault file this session unlocks.
    vault_path: PathBuf,
}

/// A vault session tracks an unlocked vault's data key (DK) via the OS keyring.
///
/// In v3, the session holds the unwrapped 32-byte DK — not the passphrase.
/// The DK is stored base64-encoded in the platform-native credential store:
/// - **macOS**: Keychain (file-backed, works over SSH)
/// - **Linux**: kernel keyutils (in-memory, works headless, cleared on reboot)
/// - **Windows**: Credential Manager
///
/// A companion session file at `$XDG_RUNTIME_DIR/kyz/session-<hash>` holds
/// only non-sensitive metadata (expiry timestamp, vault path).
///
/// If the OS keyring is unavailable, falls back to an age-encrypted session
/// file with a machine-bound key.
#[derive(Clone)]
pub struct VaultSession {
    /// The vault data key (in memory only, zeroed on drop).
    pub dk: Zeroizing<[u8; DK_LEN]>,
    /// Unix timestamp when this session expires.
    pub expires_at: u64,
    /// Path to the vault file this session unlocks.
    pub vault_path: PathBuf,
}

impl fmt::Debug for VaultSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSession")
            .field("dk", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("vault_path", &self.vault_path)
            .finish()
    }
}

/// Keyring service name for vault session data keys.
///
/// Bumped to `-v3` so that any leftover v2 entries (which stored a passphrase
/// string) are never misinterpreted as a base64-encoded DK.
const SESSION_KEYRING_SERVICE: &str = "kyz-session-v3";
/// Legacy v2 keyring service name (kept only to clean up old entries).
const LEGACY_SESSION_KEYRING_SERVICE: &str = "kyz-session";

impl VaultSession {
    /// Create a new session from raw DK bytes.
    #[must_use]
    pub fn new(dk: Zeroizing<[u8; DK_LEN]>, vault_path: &Path, timeout_secs: u64) -> Self {
        Self {
            dk,
            expires_at: now_unix() + timeout_secs,
            vault_path: vault_path.to_path_buf(),
        }
    }

    /// Check if the session has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        now_unix() >= self.expires_at
    }

    /// Seconds remaining until expiry.
    #[must_use]
    pub fn remaining_secs(&self) -> u64 {
        self.expires_at.saturating_sub(now_unix())
    }

    /// Get the default session directory for this user.
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime directory cannot be determined.
    pub fn session_dir() -> Result<PathBuf, CoreError> {
        // Prefer XDG_RUNTIME_DIR (typically /run/user/<UID>, tmpfs)
        if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(dir).join("kyz"));
        }

        // Fallback: user-specific temp directory
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| format!("pid-{}", std::process::id()));
        let tmp = std::env::temp_dir().join(format!("kyz-{username}"));
        Ok(tmp)
    }

    /// Get the session file path for a given vault path.
    ///
    /// # Errors
    ///
    /// Returns an error if the session directory cannot be determined.
    pub fn session_file_for(vault_path: &Path) -> Result<PathBuf, CoreError> {
        let dir = Self::session_dir()?;
        let hash = simple_hash(&vault_path.to_string_lossy());
        Ok(dir.join(format!("session-{hash}")))
    }

    /// Derive the keyring username for a given vault path.
    fn keyring_user(vault_path: &Path) -> String {
        let hash = simple_hash(&vault_path.to_string_lossy());
        format!("vault-{hash}")
    }

    /// Store the DK bytes (base64-encoded) in the OS keyring.
    fn keyring_store(vault_path: &Path, dk: &[u8; DK_LEN]) -> Result<(), CoreError> {
        let user = Self::keyring_user(vault_path);
        let entry = keyring::Entry::new(SESSION_KEYRING_SERVICE, &user)
            .map_err(|e| CoreError::Secret(format!("creating keyring entry: {e}")))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(dk);
        entry
            .set_password(&encoded)
            .map_err(|e| CoreError::Secret(format!("storing DK in keyring: {e}")))?;
        Ok(())
    }

    /// Retrieve the DK bytes from the OS keyring.
    fn keyring_load(vault_path: &Path) -> Result<Option<Zeroizing<[u8; DK_LEN]>>, CoreError> {
        let user = Self::keyring_user(vault_path);
        let entry = keyring::Entry::new(SESSION_KEYRING_SERVICE, &user)
            .map_err(|e| CoreError::Secret(format!("creating keyring entry: {e}")))?;
        match entry.get_password() {
            Ok(encoded) => {
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(&encoded)
                    .map_err(|e| CoreError::Secret(format!("decoding DK from keyring: {e}")))?;
                if raw.len() != DK_LEN {
                    return Err(CoreError::Secret(format!(
                        "keyring DK has unexpected length {} (want {DK_LEN})",
                        raw.len()
                    )));
                }
                let mut dk = Zeroizing::new([0u8; DK_LEN]);
                dk.copy_from_slice(&raw);
                Ok(Some(dk))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CoreError::Secret(format!("reading DK from keyring: {e}"))),
        }
    }

    /// Remove the DK from the OS keyring (current and legacy entries).
    fn keyring_delete(vault_path: &Path) -> Result<(), CoreError> {
        let user = Self::keyring_user(vault_path);
        for service in [SESSION_KEYRING_SERVICE, LEGACY_SESSION_KEYRING_SERVICE] {
            let entry = keyring::Entry::new(service, &user)
                .map_err(|e| CoreError::Secret(format!("creating keyring entry: {e}")))?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => {
                    return Err(CoreError::Secret(format!("removing DK from keyring: {e}")));
                }
            }
        }
        Ok(())
    }

    /// Derive a machine-bound session encryption key (fallback only).
    ///
    /// Used when the OS keyring is unavailable. The key is derived from the
    /// vault path, the current user, and the hostname.
    fn fallback_encryption_key(vault_path: &Path) -> String {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| String::from("unknown"));

        let hostname = hostname::get().map_or_else(
            |_| String::from("localhost"),
            |h| h.to_string_lossy().to_string(),
        );

        let material = format!(
            "kyz-session:{}:{}:{}",
            vault_path.to_string_lossy(),
            user,
            hostname,
        );
        let h1 = simple_hash(&material);
        let h2 = simple_hash(&format!("{material}:extra"));
        format!("{h1}{h2}")
    }

    /// Write the session to disk and store the DK in the OS keyring.
    ///
    /// The DK is stored in the platform-native credential store. Only
    /// non-sensitive metadata (expiry, vault path) is written to the session
    /// file. If the keyring is unavailable, falls back to an age-encrypted
    /// session file holding the base64-encoded DK.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be persisted.
    pub fn save(&self) -> Result<PathBuf, CoreError> {
        let path = Self::session_file_for(&self.vault_path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(CoreError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                    .map_err(CoreError::Io)?;
            }
        }

        // Try OS keyring first (DK never touches disk).
        let keyring_ok = Self::keyring_store(&self.vault_path, &self.dk).is_ok();

        if keyring_ok {
            let meta = SessionMeta {
                expires_at: self.expires_at,
                vault_path: self.vault_path.clone(),
            };
            let json = serde_json::to_string(&meta)
                .map_err(|e| CoreError::Serialization(format!("serializing session meta: {e}")))?;
            fs::write(&path, json.as_bytes()).map_err(CoreError::Io)?;
        } else {
            log::debug!("OS keyring unavailable, falling back to encrypted session file");
            let full = FallbackSession {
                dk_b64: base64::engine::general_purpose::STANDARD.encode(*self.dk),
                expires_at: self.expires_at,
                vault_path: self.vault_path.clone(),
            };
            let json = serde_json::to_string(&full)
                .map_err(|e| CoreError::Serialization(format!("serializing session: {e}")))?;
            let key = Self::fallback_encryption_key(&self.vault_path);
            let encrypted = encrypt_session_data(json.as_bytes(), &key)?;
            fs::write(&path, &encrypted).map_err(CoreError::Io)?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(CoreError::Io)?;
        }

        Ok(path)
    }

    /// Load a session for a given vault path.
    ///
    /// Tries the OS keyring first (passphrase there, metadata in file). If
    /// the keyring entry is missing, attempts to decrypt the file as a
    /// fallback encrypted session. Returns `None` if no valid session exists.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failures.
    pub fn load(vault_path: &Path) -> Result<Option<Self>, CoreError> {
        let path = Self::session_file_for(vault_path)?;
        if !path.exists() {
            return Ok(None);
        }

        let raw = fs::read(&path).map_err(CoreError::Io)?;

        // Try loading as keyring-backed session (metadata-only JSON file)
        if let Some(session) = Self::load_keyring_session(vault_path, &raw)? {
            if session.is_expired() {
                let _ = Self::destroy(vault_path);
                return Ok(None);
            }
            return Ok(Some(session));
        }

        // Try loading as fallback encrypted session
        if let Some(session) = Self::load_fallback_session(vault_path, &raw) {
            if session.is_expired() {
                let _ = Self::destroy(vault_path);
                return Ok(None);
            }
            return Ok(Some(session));
        }

        // Unrecognized format, clean up
        let _ = fs::remove_file(&path);
        Ok(None)
    }

    /// Try to load a keyring-backed session from metadata JSON.
    fn load_keyring_session(vault_path: &Path, raw: &[u8]) -> Result<Option<Self>, CoreError> {
        let Ok(text) = std::str::from_utf8(raw) else {
            return Ok(None);
        };
        let Ok(meta) = serde_json::from_str::<SessionMeta>(text) else {
            return Ok(None);
        };

        let Some(dk) = Self::keyring_load(vault_path)? else {
            // Keyring entry gone (reboot on Linux keyutils, manual clear, etc.)
            let path = Self::session_file_for(vault_path)?;
            let _ = fs::remove_file(&path);
            return Ok(None);
        };

        Ok(Some(Self {
            dk,
            expires_at: meta.expires_at,
            vault_path: meta.vault_path,
        }))
    }

    /// Try to load a fallback age-encrypted session.
    fn load_fallback_session(vault_path: &Path, raw: &[u8]) -> Option<Self> {
        let key = Self::fallback_encryption_key(vault_path);
        let decrypted = decrypt_session_data(raw, &key).ok()?;
        let json = String::from_utf8(decrypted).ok()?;
        let fb: FallbackSession = serde_json::from_str(&json).ok()?;
        let raw_dk = base64::engine::general_purpose::STANDARD
            .decode(&fb.dk_b64)
            .ok()?;
        if raw_dk.len() != DK_LEN {
            return None;
        }
        let mut dk = Zeroizing::new([0u8; DK_LEN]);
        dk.copy_from_slice(&raw_dk);
        Some(Self {
            dk,
            expires_at: fb.expires_at,
            vault_path: fb.vault_path,
        })
    }

    /// Remove the session (keyring entry + session file).
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    pub fn destroy(vault_path: &Path) -> Result<(), CoreError> {
        let _ = Self::keyring_delete(vault_path);
        let path = Self::session_file_for(vault_path)?;
        if path.exists() {
            fs::remove_file(&path).map_err(CoreError::Io)?;
        }
        Ok(())
    }
}

/// Full session data for the encrypted-file fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FallbackSession {
    /// Base64-encoded vault data key.
    dk_b64: String,
    /// Unix timestamp when this session expires.
    expires_at: u64,
    /// Path to the vault file this session unlocks.
    vault_path: PathBuf,
}

/// Magic byte prefix for the fast session format (XChaCha20-Poly1305).
/// Distinguishes from the legacy age-encrypted session format.
const SESSION_MAGIC_V2: &[u8] = b"KYZS2";

/// Derive a 32-byte symmetric key from a machine-bound material string.
///
/// Uses a single SHA-256 round. Unlike a vault passphrase, this material is
/// derived from observable system properties (vault path, user, hostname),
/// so a slow KDF (scrypt) would add no security — only latency.
fn session_kdf(material: &str) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"kyz-session-v2");
    hasher.update(material.as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Encrypt session data using XChaCha20-Poly1305 with a SHA-256-derived key.
///
/// Layout on disk: `SESSION_MAGIC_V2 || nonce(24) || ciphertext || tag(16)`.
fn encrypt_session_data(plaintext: &[u8], material: &str) -> Result<Vec<u8>, CoreError> {
    use chacha20poly1305::{
        AeadCore as _, KeyInit as _, XChaCha20Poly1305,
        aead::{Aead, OsRng},
    };

    let key = session_kdf(material);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CoreError::Secret(format!("session AEAD encrypt failed: {e}")))?;

    let mut out = Vec::with_capacity(SESSION_MAGIC_V2.len() + nonce.len() + ct.len());
    out.extend_from_slice(SESSION_MAGIC_V2);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt session data. Supports both the new fast format (magic-prefixed
/// XChaCha20-Poly1305) and the legacy age-encrypted format for backward
/// compatibility.
fn decrypt_session_data(encrypted: &[u8], material: &str) -> Result<Vec<u8>, CoreError> {
    if encrypted.starts_with(SESSION_MAGIC_V2) {
        use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce, aead::Aead};

        let body = &encrypted[SESSION_MAGIC_V2.len()..];
        if body.len() < 24 + 16 {
            return Err(CoreError::Secret("session file truncated".to_string()));
        }
        let (nonce_bytes, ct) = body.split_at(24);
        let key = session_kdf(material);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let nonce = XNonce::from_slice(nonce_bytes);
        return cipher
            .decrypt(nonce, ct)
            .map_err(|e| CoreError::Secret(format!("session AEAD decrypt failed: {e}")));
    }

    // Legacy format: age-encrypted with scrypt. Decrypt for migration.
    let decryptor = age::Decryptor::new(encrypted)
        .map_err(|e| CoreError::Secret(format!("reading encrypted session: {e}")))?;

    if !decryptor.is_scrypt() {
        return Err(CoreError::Secret(
            "session file is not passphrase-encrypted".to_string(),
        ));
    }

    let identity = age::scrypt::Identity::new(SecretString::from(material.to_string()));

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| CoreError::Secret(format!("session decryption failed: {e}")))?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| CoreError::Secret(format!("reading decrypted session: {e}")))?;

    Ok(decrypted)
}

/// File-based vault backend using age encryption.
///
/// Secrets are stored in an age-encrypted JSON file. The vault must be
/// unlocked (session file present) before any operations.
///
/// Vault location resolution order:
/// 1. Explicit path (if provided)
/// 2. Named environment: `$XDG_DATA_HOME/kyz/envs/<name>/vault.json`
/// 3. Workspace vault: `<cwd>/.kyz/vault.json`
/// 4. Central vault: `$XDG_DATA_HOME/kyz/vault.json`
#[derive(Debug, Clone)]
pub struct VaultStore {
    /// Path to the vault file.
    vault_path: PathBuf,
}

/// Subdirectory name for named environment vaults.
pub const ENVS_DIR: &str = "envs";

impl VaultStore {
    /// Create a store for a specific vault file.
    #[must_use]
    pub const fn new(vault_path: PathBuf) -> Self {
        Self { vault_path }
    }

    /// Get the vault file path.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Resolve vault path: explicit > named env > workspace > central.
    ///
    /// # Errors
    ///
    /// Returns an error if no vault can be found or paths fail to resolve.
    pub fn resolve(explicit: Option<&Path>) -> Result<Self, CoreError> {
        Self::resolve_with_env(explicit, None, None)
    }

    /// Resolve vault path with optional named environment.
    ///
    /// When `env_name` is `Some`, the vault is stored under
    /// `$XDG_DATA_HOME/kyz/envs/<name>/vault.json`.
    ///
    /// `workspace_hint`, when set, is consulted before the process cwd as the
    /// candidate workspace directory. Callers typically derive this from
    /// `AGENT_CTX_WORKSPACE_PATH` so wrapped agents whose cwd does not match
    /// the user's workspace still resolve the expected workspace vault.
    /// The hint is metadata only; explicit args and named environments still
    /// take precedence.
    ///
    /// # Errors
    ///
    /// Returns an error if no vault can be found or paths fail to resolve.
    pub fn resolve_with_env(
        explicit: Option<&Path>,
        env_name: Option<&str>,
        workspace_hint: Option<&Path>,
    ) -> Result<Self, CoreError> {
        if let Some(p) = explicit {
            return Ok(Self::new(p.to_path_buf()));
        }

        // Named environment: $XDG_DATA_HOME/kyz/envs/<name>/vault.json
        if let Some(name) = env_name {
            let env_vault = env_vault_path(name)?;
            return Ok(Self::new(env_vault));
        }

        // Prefer the explicit workspace hint (e.g. AGENT_CTX_WORKSPACE_PATH)
        // over cwd-based discovery.
        if let Some(hint) = workspace_hint {
            let hinted = hint.join(WORKSPACE_VAULT_DIR).join(VAULT_FILENAME);
            if hinted.exists() {
                return Ok(Self::new(hinted));
            }
        }

        // Check for workspace vault in cwd
        let cwd = std::env::current_dir()
            .map_err(|e| CoreError::Path(format!("cannot determine cwd: {e}")))?;
        let workspace_vault = cwd.join(WORKSPACE_VAULT_DIR).join(VAULT_FILENAME);
        if workspace_vault.exists() {
            return Ok(Self::new(workspace_vault));
        }

        // Fall back to central vault
        let central = central_vault_path()?;
        Ok(Self::new(central))
    }

    /// Initialize a new vault with a passphrase.
    ///
    /// Creates an empty v4 vault file (operation logs + MAC, one-time
    /// scrypt + DK-wrapped AEAD). Fails if one already exists (use `force`
    /// to overwrite).
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists and force is false, or on I/O failure.
    pub fn init(&self, passphrase: &str, force: bool) -> Result<(), CoreError> {
        ensure_passphrase_strength(passphrase)?;
        if let Some(parent) = self.vault_path.parent() {
            fs::create_dir_all(parent).map_err(CoreError::Io)?;
        }
        let _lock = VaultFileLock::exclusive(&self.vault_path)?;

        if self.vault_path.exists() && !force {
            return Err(CoreError::Secret(format!(
                "vault already exists at {} (use --force to overwrite)",
                self.vault_path.display()
            )));
        }

        let passphrase_secret = SecretString::from(passphrase.to_string());
        let (mut v4, dk) = VaultFileV4::create(&passphrase_secret)?;
        // Strength was already checked above, so flag it.
        v4.passphrase_policy_checked = true;
        self.write_v4_unlocked(&mut v4, &dk)
    }

    /// Unlock the vault: derive the KEK, unwrap the DK, persist a session.
    ///
    /// Auto-migrates v1 (single-blob age), v2 (per-entry scrypt-age) and
    /// v3 (last-writer-wins) vaults to v4 on first unlock. After this
    /// call, hot-path operations (`get`/`set`/`list`) pay only AEAD
    /// cost — no scrypt.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault doesn't exist, the passphrase is wrong,
    /// or the session file cannot be written.
    pub fn unlock(&self, passphrase: &str, timeout_secs: u64) -> Result<PathBuf, CoreError> {
        if !self.vault_path.exists() {
            return Err(CoreError::Secret(format!(
                "vault not found at {}",
                self.vault_path.display()
            )));
        }

        let passphrase_secret = SecretString::from(passphrase.to_string());
        let dk = self.unlock_to_dk(&passphrase_secret)?;
        let session = VaultSession::new(dk, &self.vault_path, timeout_secs);
        session.save()
    }

    /// Helper: open the vault, migrate if needed, and return the DK.
    ///
    /// All migrations (v1/v2/v3 → v4) and the one-time passphrase-policy
    /// flag write run inside an exclusive file-lock transaction, so a
    /// concurrent CLI writer can never observe or clobber a half-migrated
    /// vault. The slow scrypt KDF runs **before** the lock wherever the
    /// on-disk version is already known; holding the exclusive lock across
    /// it would serialize unrelated concurrent `kyz get` calls.
    fn unlock_to_dk(
        &self,
        passphrase: &SecretString,
    ) -> Result<Zeroizing<[u8; DK_LEN]>, CoreError> {
        if !self.vault_path.exists() {
            return Err(CoreError::Secret(format!(
                "vault not found at {}",
                self.vault_path.display()
            )));
        }
        let raw = fs::read(&self.vault_path).map_err(CoreError::Io)?;
        match detect_vault_version(&raw) {
            // Migrations rewrite the vault file: re-read under the lock so
            // the whole detect -> migrate -> write sequence is one
            // transaction over the current bytes.
            1 | 2 => {
                let _lock = VaultFileLock::exclusive(&self.vault_path)?;
                let raw = fs::read(&self.vault_path).map_err(CoreError::Io)?;
                self.unlock_migrate_legacy(&raw, passphrase)
            }
            3 => {
                // Derive the DK outside the lock (scrypt), then migrate
                // under it.
                let (v3, dk) = Self::open_v3_file(&raw, passphrase)?;
                let _lock = VaultFileLock::exclusive(&self.vault_path)?;
                let raw = fs::read(&self.vault_path).map_err(CoreError::Io)?;
                match detect_vault_version(&raw) {
                    3 => {
                        let current: VaultFileV3 = serde_json::from_slice(&raw)
                            .map_err(|e| CoreError::Serialization(format!("parsing vault: {e}")))?;
                        // The DK was derived from the unlocked read's key
                        // material; if the file under the lock carries
                        // different kdf/wrapped_dk it was replaced during
                        // the scrypt window, and migrating it with this DK
                        // would sign foreign key material. Fail and retry.
                        if current.kdf != v3.kdf || current.wrapped_dk != v3.wrapped_dk {
                            return Err(CoreError::Secret(
                                "vault changed while unlocking; run unlock again".to_string(),
                            ));
                        }
                        log::info!("migrating vault from v3 to v4");
                        self.migrate_v3_and_write(&current, &dk)?;
                        Ok(dk)
                    }
                    4 => {
                        let current = VaultFileV4::parse(&raw)?;
                        self.finish_v4_unlock_locked(current, &dk)?;
                        Ok(dk)
                    }
                    other => Err(CoreError::Secret(format!(
                        "unsupported vault format version {other}"
                    ))),
                }
            }
            4 => {
                let (v4, dk) = Self::open_v4_file(&raw, passphrase)?;
                if v4.passphrase_policy_checked {
                    return Ok(dk);
                }
                let _lock = VaultFileLock::exclusive(&self.vault_path)?;
                let raw = fs::read(&self.vault_path).map_err(CoreError::Io)?;
                let current = VaultFileV4::parse(&raw)?;
                self.finish_v4_unlock_locked(current, &dk)?;
                Ok(dk)
            }
            other => Err(CoreError::Secret(format!(
                "unsupported vault format version {other}"
            ))),
        }
    }

    /// One-time passphrase-policy flag write on an unlocked v4 file.
    /// The caller must hold the exclusive vault lock.
    ///
    /// The re-read file is MAC-verified under the session DK before it is
    /// rewritten: a concurrent replace between the unlocked read and the
    /// lock acquisition must surface as a verification error, never as a
    /// silently re-signed foreign file.
    fn finish_v4_unlock_locked(
        &self,
        mut file: VaultFileV4,
        dk: &Zeroizing<[u8; DK_LEN]>,
    ) -> Result<(), CoreError> {
        file.verify_mac(dk)?;
        if !file.passphrase_policy_checked {
            file.passphrase_policy_checked = true;
            self.write_v4_unlocked(&mut file, dk)?;
        }
        Ok(())
    }

    /// Parse a v3 file, unwrap its DK, and enforce the one-time passphrase
    /// policy gate. Shared prelude of every unlock arm that opens v3 bytes.
    fn open_v3_file(
        raw: &[u8],
        passphrase: &SecretString,
    ) -> Result<(VaultFileV3, Zeroizing<[u8; DK_LEN]>), CoreError> {
        let v3: VaultFileV3 = serde_json::from_slice(raw)
            .map_err(|e| CoreError::Serialization(format!("parsing vault: {e}")))?;
        let dk = v3.unwrap_dk(passphrase)?;
        if !v3.passphrase_policy_checked {
            ensure_passphrase_strength(passphrase.expose_secret())?;
        }
        Ok((v3, dk))
    }

    /// Parse a v4 file, unwrap its DK, MAC-verify it against the DK, and
    /// enforce the one-time passphrase policy gate. Shared prelude of
    /// every unlock arm that opens v4 bytes. Verifying here keeps a
    /// corrupt or tampered vault from unlocking "successfully" and only
    /// failing on the first get/list with an unrelated error.
    fn open_v4_file(
        raw: &[u8],
        passphrase: &SecretString,
    ) -> Result<(VaultFileV4, Zeroizing<[u8; DK_LEN]>), CoreError> {
        let v4 = VaultFileV4::parse(raw)?;
        let dk = v4.unwrap_dk(passphrase)?;
        v4.verify_mac(&dk)?;
        if !v4.passphrase_policy_checked {
            ensure_passphrase_strength(passphrase.expose_secret())?;
        }
        Ok((v4, dk))
    }

    /// Legacy migration arms (v1/v2 → v4), run while holding the exclusive
    /// vault lock. v1/v2 files first walk the existing v2/v3 chain, then
    /// convert to v4 in the same transaction.
    fn unlock_migrate_legacy(
        &self,
        raw: &[u8],
        passphrase: &SecretString,
    ) -> Result<Zeroizing<[u8; DK_LEN]>, CoreError> {
        match detect_vault_version(raw) {
            1 => {
                log::info!("migrating vault from v1 to v4");
                let mut v2 = migrate_v1_to_v2(raw, passphrase)?;
                v2.passphrase_policy_checked = true;
                let (v3, dk) = migrate_v2_to_v3(&v2, passphrase)?;
                self.migrate_v3_and_write(&v3, &dk)?;
                Ok(dk)
            }
            2 => {
                let v2: VaultFileV2 = serde_json::from_slice(raw)
                    .map_err(|e| CoreError::Serialization(format!("parsing vault: {e}")))?;
                // Verify passphrase against the first v2 entry before migrating
                // (so we don't write garbage if the password is wrong).
                if let Some(first) = v2.entries.values().next() {
                    let _ = decrypt_entry(first, passphrase)?;
                }
                if !v2.passphrase_policy_checked {
                    ensure_passphrase_strength(passphrase.expose_secret())?;
                }
                log::info!("migrating vault from v2 to v4");
                let (v3, dk) = migrate_v2_to_v3(&v2, passphrase)?;
                self.migrate_v3_and_write(&v3, &dk)?;
                Ok(dk)
            }
            // A concurrent process migrated the vault between the unlocked
            // read and lock acquisition: take the steady-state path.
            3 => {
                let (current, dk) = Self::open_v3_file(raw, passphrase)?;
                self.migrate_v3_and_write(&current, &dk)?;
                Ok(dk)
            }
            4 => {
                let (current, dk) = Self::open_v4_file(raw, passphrase)?;
                self.finish_v4_unlock_locked(current, &dk)?;
                Ok(dk)
            }
            other => Err(CoreError::Secret(format!(
                "unsupported vault format version {other}"
            ))),
        }
    }

    /// Lock the vault: destroy the session file.
    ///
    /// # Errors
    ///
    /// Returns an error if the session file cannot be removed.
    pub fn lock(&self) -> Result<(), CoreError> {
        VaultSession::destroy(&self.vault_path)
    }

    /// Check vault status.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure.
    pub fn status(&self) -> Result<VaultStatus, CoreError> {
        let exists = self.vault_path.exists();
        let session = if exists {
            VaultSession::load(&self.vault_path)?
        } else {
            None
        };

        Ok(VaultStatus {
            vault_path: self.vault_path.clone(),
            exists,
            unlocked: session.is_some(),
            expires_at: session.as_ref().map(|s| s.expires_at),
            remaining_secs: session.as_ref().map(VaultSession::remaining_secs),
        })
    }

    /// Load the data key, or return an error if locked.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault is locked.
    pub fn require_session_pub(&self) -> Result<Zeroizing<[u8; DK_LEN]>, CoreError> {
        self.require_session()
    }

    /// Load the data key from the active session, or error if locked.
    fn require_session(&self) -> Result<Zeroizing<[u8; DK_LEN]>, CoreError> {
        let session = VaultSession::load(&self.vault_path)?.ok_or_else(|| {
            CoreError::Secret(format!(
                "vault is locked ({}). Run 'kyz vault unlock' first.",
                self.vault_path.display()
            ))
        })?;
        Ok(session.dk)
    }

    /// Write the v3 vault file without acquiring the vault lock.
    ///
    /// Only for use inside an already-held exclusive lock transaction
    /// (see [`VaultStore::unlock_to_dk`]); re-locking from the same process
    /// would self-deadlock. Uses the atomic same-directory-replace path.
    fn write_vault_file_unlocked(&self, vault: &VaultFileV3) -> Result<(), CoreError> {
        let json = serde_json::to_string_pretty(vault)
            .map_err(|e| CoreError::Serialization(format!("serializing vault: {e}")))?;
        crate::atomic::write_atomic(&self.vault_path, json.as_bytes())
    }

    /// Write the v4 vault file without acquiring the vault lock:
    /// finalize (canonicalize + MAC), serialize pretty, atomic replace.
    ///
    /// Same locking contract as [`Self::write_vault_file_unlocked`]: only
    /// call inside an already-held exclusive lock transaction.
    fn write_v4_unlocked(
        &self,
        vault: &mut VaultFileV4,
        dk: &Zeroizing<[u8; DK_LEN]>,
    ) -> Result<(), CoreError> {
        vault.finalize(dk)?;
        let bytes = vault.to_bytes_pretty()?;
        crate::atomic::write_atomic(&self.vault_path, &bytes)
    }

    /// Migrate a decrypted v3 vault to v4 and persist it, setting the
    /// passphrase-policy flag (migration implies the passphrase was just
    /// verified against the v3 file).
    fn migrate_v3_and_write(
        &self,
        v3: &VaultFileV3,
        dk: &Zeroizing<[u8; DK_LEN]>,
    ) -> Result<(), CoreError> {
        let mut v4 = vault_v4::migrate_v3_to_v4(v3, dk)?;
        v4.passphrase_policy_checked = true;
        self.write_v4_unlocked(&mut v4, dk)
    }

    /// Unlock the vault into memory without persisting any session state.
    ///
    /// Returns an [`UnlockedVault`] whose data key lives only in process
    /// memory. Unlike [`VaultStore::unlock`], this never calls
    /// [`VaultSession::save`], never writes to the OS keyring, and never
    /// creates a session file. Any vault migration (v1/v2 → v3, passphrase
    /// policy update) happens inside a single exclusive file-lock
    /// transaction before the handle is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault doesn't exist, the passphrase is wrong
    /// (the error text never contains the passphrase), or migration fails.
    pub fn unlock_in_memory(&self, passphrase: &SecretString) -> Result<UnlockedVault, CoreError> {
        let dk = self.unlock_to_dk(passphrase)?;
        Ok(UnlockedVault {
            dk,
            vault_path: self.vault_path.clone(),
        })
    }
}

/// An unlocked vault whose data key (DK) resides only in memory.
///
/// The DK is private: there is no accessor for the raw key bytes, and
/// decryption stays encapsulated in `kyz-core`. The handle holds **no
/// plaintext cache** — every [`UnlockedVault::get`] /
/// [`UnlockedVault::resolve_fields`] call re-reads the latest `vault.json`
/// under the shared vault lock, so secret updates made by the CLI while the
/// daemon is alive are visible on the next resolve.
///
/// Dropping the handle zeroizes the DK.
pub struct UnlockedVault {
    /// The unwrapped data key. Never exposed; zeroized on drop.
    dk: Zeroizing<[u8; DK_LEN]>,
    /// Path of the backing vault file.
    vault_path: PathBuf,
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Zeroizing's derived Debug prints the key contents; never do that.
        f.debug_struct("UnlockedVault")
            .field("dk", &"[REDACTED]")
            .field("vault_path", &self.vault_path)
            .finish()
    }
}

impl UnlockedVault {
    /// The vault file path backing this handle.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Decrypt and return a full secret entry, reading the latest vault file.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be read, the entry is missing,
    /// or decryption fails.
    pub fn get(&self, service: &str, key: &str) -> Result<SecretEntry, CoreError> {
        let contents = read_contents_at(&self.vault_path)?;
        get_entry_from(&contents, &self.dk, service, key)
    }

    /// Decrypt only the requested fields of an entry.
    ///
    /// Fails closed: if any requested field does not exist in the entry, the
    /// whole call returns an error instead of returning a partial map. An
    /// empty `fields` slice yields an empty map (there is no implicit
    /// "all fields" mode).
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be read, the entry is missing,
    /// a requested field is missing, or decryption fails.
    pub fn resolve_fields(
        &self,
        service: &str,
        key: &str,
        fields: &[String],
    ) -> Result<BTreeMap<String, SecretString>, CoreError> {
        let entry = self.get(service, key)?;
        let mut resolved = BTreeMap::new();
        for field in fields {
            let value = entry.fields.get(field).ok_or_else(|| {
                CoreError::SecretNotFound(format!(
                    "field '{field}' not found in secret '{service}/{key}'"
                ))
            })?;
            resolved.insert(field.clone(), value.clone());
        }
        Ok(resolved)
    }
}

/// Vault contents parsed from disk, version-dispatched.
#[derive(Debug, Clone)]
pub enum VaultContents {
    /// Legacy v3 file (last-writer-wins entries). `set`/`delete` upgrade
    /// it to v4 inside their write transactions; rollback writes it back
    /// as v3 until one of those (or the next unlock) migrates it.
    V3(VaultFileV3),
    /// v4 file (per-entry operation logs).
    V4(VaultFileV4),
}

/// History of one entry, dispatched by the on-disk format.
#[derive(Debug, Clone)]
pub enum HistoryView {
    /// Legacy v3 entry: numbered archived versions, plaintext metadata
    /// only (the vault has not been migrated yet).
    V3 {
        /// The encrypted entry with its archived history.
        encrypted: EncryptedEntryV3,
    },
    /// v4 operation-log history (current/conflict/ancestor/tombstone).
    V4(Vec<HistoryItem>),
}

/// Read the vault file at `vault_path` under a shared (read) lock and
/// dispatch by detected version.
///
/// # Errors
///
/// Returns an error if the file is missing, unparsable, or older than v3.
fn read_contents_at(vault_path: &Path) -> Result<VaultContents, CoreError> {
    if !vault_path.exists() {
        return Err(CoreError::Secret(format!(
            "vault not found at {}",
            vault_path.display()
        )));
    }
    let _lock = VaultFileLock::shared(vault_path)?;
    read_contents_no_lock(vault_path)
}

/// Read and parse the vault file without taking any lock (the caller must
/// already hold a vault lock when the file may be written concurrently).
///
/// # Errors
///
/// Returns an error if the file is missing, unparsable, or of an
/// unsupported version.
fn read_contents_no_lock(vault_path: &Path) -> Result<VaultContents, CoreError> {
    let raw = fs::read(vault_path).map_err(CoreError::Io)?;
    match detect_vault_version(&raw) {
        3 => {
            let v3: VaultFileV3 = serde_json::from_slice(&raw)
                .map_err(|e| CoreError::Serialization(format!("parsing vault: {e}")))?;
            Ok(VaultContents::V3(v3))
        }
        4 => {
            let v4 = VaultFileV4::parse(&raw)?;
            Ok(VaultContents::V4(v4))
        }
        other => Err(CoreError::Secret(format!(
            "vault is v{other}; run 'kyz vault unlock' to migrate it"
        ))),
    }
}

/// Decrypt and return a full secret entry from already-parsed vault
/// contents. Shared by [`UnlockedVault::get`] and the `SecretStore` impl,
/// which differ only in where the session DK comes from.
fn get_entry_from(
    contents: &VaultContents,
    dk: &Zeroizing<[u8; DK_LEN]>,
    service: &str,
    key: &str,
) -> Result<SecretEntry, CoreError> {
    match contents {
        VaultContents::V3(vault) => {
            let encrypted = vault.get_encrypted(service, key).ok_or_else(|| {
                CoreError::SecretNotFound(format!(
                    "secret '{key}' not found in service '{service}'"
                ))
            })?;
            decrypt_entry_v3(encrypted, dk)
        }
        VaultContents::V4(vault) => {
            vault.verify_mac(dk)?;
            Ok(vault.decrypt_current(dk, service, key)?.to_entry())
        }
    }
}

/// FNV-1a 64-bit hash over raw bytes.
///
/// Shared with `kyz-daemon`'s state-dir-derived names so every
/// path-derived identifier in the workspace uses one hash definition.
#[must_use]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Derive the v4 history view from already-parsed contents. Shared by
/// [`VaultStore::history_v4`] and the v4 arm of [`VaultStore::history`].
///
/// # Errors
///
/// Returns an error if verification fails or the entry has no operations.
fn history_v4_from(
    vault: &VaultFileV4,
    dk: &Zeroizing<[u8; DK_LEN]>,
    service: &str,
    key: &str,
) -> Result<Vec<HistoryItem>, CoreError> {
    vault.verify_mac(dk)?;
    let ops = vault.ops(service, key).ok_or_else(|| {
        CoreError::SecretNotFound(format!("secret '{key}' not found in service '{service}'"))
    })?;
    vault_v4::history(ops)
}

/// Vault status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    /// Path to the vault file.
    pub vault_path: PathBuf,
    /// Whether the vault file exists.
    pub exists: bool,
    /// Whether the vault is currently unlocked.
    pub unlocked: bool,
    /// When the session expires (Unix timestamp), if unlocked.
    pub expires_at: Option<u64>,
    /// Seconds remaining until session expiry, if unlocked.
    pub remaining_secs: Option<u64>,
}

impl SecretStore for VaultStore {
    fn get(&self, service: &str, key: &str) -> Result<SecretEntry, CoreError> {
        let dk = self.require_session()?;
        let contents = read_contents_at(&self.vault_path)?;
        get_entry_from(&contents, &dk, service, key)
    }

    fn set(&self, service: &str, key: &str, entry: &SecretEntry) -> Result<(), CoreError> {
        self.set_with_options(service, key, entry, false)
    }

    fn set_recreating(
        &self,
        service: &str,
        key: &str,
        entry: &SecretEntry,
    ) -> Result<(), CoreError> {
        self.set_with_options(service, key, entry, true)
    }

    fn delete(&self, service: &str, key: &str) -> Result<(), CoreError> {
        let dk = self.require_session()?;
        let _lock = VaultFileLock::exclusive(&self.vault_path)?;
        // Writes upgrade a v3 file inside the same transaction (matching
        // `set`), so a successful delete always leaves a v4 vault behind.
        let mut vault = self.load_v4_for_write(&dk)?;
        // Deleting a non-existent (never-written or already tombstoned)
        // entry keeps the historical CLI semantics and generates no
        // operation — and no write, so a failed delete leaves the file
        // untouched.
        if !matches!(vault.projection(service, key)?, Projection::Visible { .. }) {
            return Err(CoreError::SecretNotFound(format!(
                "secret '{key}' not found in service '{service}'"
            )));
        }
        Self::append_local_delete(&mut vault, service, key)?;
        self.write_v4_unlocked(&mut vault, &dk)
    }

    fn list(&self, service: &str) -> Result<Vec<SecretSummary>, CoreError> {
        let dk = self.require_session()?;
        match read_contents_at(&self.vault_path)? {
            VaultContents::V3(vault) => Ok(vault.summaries(service)),
            VaultContents::V4(vault) => {
                vault.verify_mac(&dk)?;
                let mut out = Vec::new();
                for (ck, meta) in vault.visible_metas()? {
                    // Compound keys split at the first `/` after both
                    // parts were percent-escaped, so services or keys
                    // containing `/` (possible in library-created v3
                    // vaults) are attributed correctly.
                    let Some((svc, key)) = VaultFileV4::split_compound_key(&ck) else {
                        continue;
                    };
                    if svc != service {
                        continue;
                    }
                    out.push(SecretSummary {
                        key,
                        service: svc,
                        field_names: meta.field_names,
                        tags: meta.tags,
                        updated_at: meta.updated_at,
                    });
                }
                Ok(out)
            }
        }
    }

    fn list_services(&self) -> Result<Vec<String>, CoreError> {
        let dk = self.require_session()?;
        match read_contents_at(&self.vault_path)? {
            VaultContents::V3(vault) => Ok(vault.services()),
            VaultContents::V4(vault) => {
                vault.verify_mac(&dk)?;
                let mut svcs: Vec<String> = vault
                    .visible_metas()?
                    .into_iter()
                    .filter_map(|(ck, _)| VaultFileV4::split_compound_key(&ck).map(|(svc, _)| svc))
                    .collect();
                svcs.sort();
                svcs.dedup();
                Ok(svcs)
            }
        }
    }
}

impl VaultStore {
    /// Store or update an entry, optionally allowing an explicit rebuild
    /// of a deleted entry.
    ///
    /// v4 `set` re-reads the file under the exclusive vault lock and bases
    /// the new snapshot on the current projection:
    ///
    /// - entry visible: the passed fields overlay the current snapshot
    ///   (v3 CLI semantics) and tags are unioned;
    /// - entry deleted: without `recreate` the call fails rather than
    ///   silently resurrecting; with `recreate` the passed entry becomes
    ///   the complete new snapshot, parented on the observed delete.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is locked, the vault fails
    /// verification, or a deleted entry is targeted without `recreate`.
    pub fn set_with_options(
        &self,
        service: &str,
        key: &str,
        entry: &SecretEntry,
        recreate: bool,
    ) -> Result<(), CoreError> {
        let dk = self.require_session()?;
        let _lock = VaultFileLock::exclusive(&self.vault_path)?;
        let mut vault = self.load_v4_for_write(&dk)?;

        // One causal walk serves both the overlay base and the new op's
        // parents: when the projection is visible the frontier is exactly
        // {current} ∪ conflicts (a frontier delete would have hidden it).
        let (snapshot, parents) = match vault.projection(service, key)? {
            Projection::Visible { current, conflicts } => {
                let current_snapshot = vault.decrypt_current(&dk, service, key)?;
                let mut fields = current_snapshot.fields;
                for (name, value) in &entry.fields {
                    fields.insert(name.clone(), value.expose_secret().to_string());
                }
                let mut tags = current_snapshot.tags;
                tags.extend(entry.tags.iter().cloned());
                let snapshot = SnapshotPlain {
                    service: service.to_string(),
                    key: key.to_string(),
                    fields,
                    tags,
                    created_at: current_snapshot.created_at,
                    updated_at: now_unix(),
                };
                let mut parents = conflicts;
                parents.push(current);
                (snapshot, parents)
            }
            Projection::Hidden => {
                if vault.ops(service, key).is_some() && !recreate {
                    return Err(CoreError::Secret(format!(
                        "secret '{key}' in service '{service}' was deleted; re-run with --yes to recreate it from exactly the fields you provide (previous values are not recoverable)"
                    )));
                }
                let mut stored = entry.clone();
                stored.service = service.to_string();
                stored.key = key.to_string();
                stored.updated_at = now_unix();
                // The rebuild must be parented on the observed frontier,
                // tombstone included, so it wins over the delete.
                let parents = vault
                    .frontier_of(service, key)?
                    .map_or_else(Vec::new, |f| f.into_iter().collect());
                (SnapshotPlain::from_entry(&stored), parents)
            }
        };

        Self::append_local_put(&mut vault, &snapshot, parents, &dk)?;
        self.write_v4_unlocked(&mut vault, &dk)
    }

    /// Load the vault as v4 for a write transaction. A v3 file is upgraded
    /// inside the caller's exclusive-lock transaction first, so every new
    /// write produces the v4 format. Files read from disk as v4 are
    /// MAC-verified before being returned; freshly migrated files carry no
    /// MAC yet and are trusted as local output.
    fn load_v4_for_write(&self, dk: &Zeroizing<[u8; DK_LEN]>) -> Result<VaultFileV4, CoreError> {
        match read_contents_no_lock(&self.vault_path)? {
            VaultContents::V4(vault) => {
                vault.verify_mac(dk)?;
                Ok(vault)
            }
            VaultContents::V3(v3) => Ok(vault_v4::migrate_v3_to_v4(&v3, dk)?),
        }
    }

    /// Mint a fresh operation id and HLC for a local write and append a
    /// put with the given causal parents.
    fn append_local_put(
        vault: &mut VaultFileV4,
        snapshot: &SnapshotPlain,
        parents: Vec<OpId>,
        dk: &Zeroizing<[u8; DK_LEN]>,
    ) -> Result<(), CoreError> {
        let id = allocate_op_id(vault)?;
        let changed_at = Hlc::tick(Some(vault.max_hlc()));
        vault.append_put(snapshot, id, parents, changed_at, dk)
    }

    /// Append a delete (tombstone) with a fresh local id over the current
    /// frontier.
    fn append_local_delete(
        vault: &mut VaultFileV4,
        service: &str,
        key: &str,
    ) -> Result<(), CoreError> {
        let id = allocate_op_id(vault)?;
        let changed_at = Hlc::tick(Some(vault.max_hlc()));
        let parents: Vec<OpId> = vault
            .frontier_of(service, key)?
            .map_or_else(Vec::new, |f| f.into_iter().collect());
        vault.append_delete(service, key, id, parents, changed_at);
        Ok(())
    }

    /// Read the vault contents (public wrapper, shared lock).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn read_contents_pub(&self) -> Result<VaultContents, CoreError> {
        read_contents_at(&self.vault_path)
    }

    /// Derive the v4 history view for one entry (session-authenticated).
    ///
    /// # Errors
    ///
    /// Returns an error if the session is locked, the vault is not v4
    /// (run unlock to migrate), verification fails, or the entry has no
    /// operations.
    pub fn history_v4(&self, service: &str, key: &str) -> Result<Vec<HistoryItem>, CoreError> {
        let dk = self.require_session()?;
        match read_contents_at(&self.vault_path)? {
            VaultContents::V3(_) => Err(CoreError::Secret(
                "vault is still v3; run 'kyz vault unlock' to migrate it to v4".to_string(),
            )),
            VaultContents::V4(vault) => history_v4_from(&vault, &dk, service, key),
        }
    }

    /// History of one entry, dispatched by the on-disk format.
    ///
    /// Version dispatch lives here (like `get`/`set`/`delete`) so callers
    /// never need to sniff the format themselves. v4 vaults require an
    /// unlocked session (the view is MAC-verified); legacy v3 vaults are
    /// read without one, matching the pre-v4 CLI behavior.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry is missing, the session is locked
    /// (v4 only), or verification fails.
    pub fn history(&self, service: &str, key: &str) -> Result<HistoryView, CoreError> {
        match read_contents_at(&self.vault_path)? {
            VaultContents::V3(vault) => {
                let encrypted = vault.get_encrypted(service, key).ok_or_else(|| {
                    CoreError::SecretNotFound(format!(
                        "secret '{key}' not found in service '{service}'"
                    ))
                })?;
                Ok(HistoryView::V3 {
                    encrypted: encrypted.clone(),
                })
            }
            VaultContents::V4(vault) => {
                let dk = self.require_session()?;
                Ok(HistoryView::V4(history_v4_from(&vault, &dk, service, key)?))
            }
        }
    }

    /// Roll back (or explicitly rebuild) an entry from a historical v4
    /// snapshot.
    ///
    /// `target` is either an operation id in `actor:counter` form or a
    /// 1-based sequence number counting from the oldest operation
    /// (matching the v3 version numbering, so a literal `--to N` selects
    /// the same snapshot before and after migration). The rollback is a
    /// fresh put whose parents are the current frontier — when the entry
    /// is currently deleted this acts as the explicit post-delete rebuild.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is locked, the target cannot be
    /// resolved, or its ciphertext was pruned.
    pub fn rollback_v4(&self, service: &str, key: &str, target: &str) -> Result<(), CoreError> {
        let dk = self.require_session()?;
        let _lock = VaultFileLock::exclusive(&self.vault_path)?;
        let mut vault = self.load_v4_for_write(&dk)?;
        rollback_v4_locked(&mut vault, &dk, service, key, target)?;
        self.write_v4_unlocked(&mut vault, &dk)
    }

    /// Roll back an entry to a historical version, dispatched by the
    /// on-disk format inside one exclusive-lock transaction (like `set`).
    ///
    /// v4 vaults: `target` follows [`Self::rollback_v4`]. Legacy v3
    /// vaults: `target` is the archived version number (also counted
    /// from the oldest, so a literal `--to N` keeps its meaning across
    /// migration) and the file is written back as v3 — the one v3 write
    /// that does not upgrade; the next unlock/set/delete migrates it.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is locked, `target` cannot be
    /// resolved, or the target ciphertext is gone.
    pub fn rollback(
        &self,
        service: &str,
        key: &str,
        target: &str,
        retention: u32,
    ) -> Result<(), CoreError> {
        let dk = self.require_session()?;
        let _lock = VaultFileLock::exclusive(&self.vault_path)?;
        match read_contents_no_lock(&self.vault_path)? {
            VaultContents::V3(mut vault) => {
                let version: u32 = target.parse().map_err(|_| {
                    CoreError::Secret(
                        "v3 vaults accept numeric versions only; unlock first to migrate to v4"
                            .to_string(),
                    )
                })?;
                vault.rollback_with_retention(service, key, version, &dk, retention)?;
                self.write_vault_file_unlocked(&vault)
            }
            VaultContents::V4(mut vault) => {
                vault.verify_mac(&dk)?;
                rollback_v4_locked(&mut vault, &dk, service, key, target)?;
                self.write_v4_unlocked(&mut vault, &dk)
            }
        }
    }

    /// Merge operations from the v4 vault file at `source_path` into this
    /// vault.
    ///
    /// Transaction shape (design §7): the source is read and fully
    /// verified (version, same-origin, MAC, per-blob AEAD) from a byte
    /// snapshot **before** the target's exclusive lock is taken — no
    /// concurrent `get`/`list`/daemon resolve is blocked by the O(source
    /// size) verification. Only then is the lock acquired, the target
    /// re-read and verified, the operation sets unioned, canonicalized,
    /// and — unless `dry_run` or the merge changed nothing — atomically
    /// written back. The source file is never modified.
    ///
    /// `allow_legacy_resurrections` gates entries the merge would
    /// introduce that exist only as pre-v4 operations in the source and
    /// are absent from the target: v3-era deletions leave no tombstone,
    /// so those entries may be secrets deleted before migration. Unless
    /// allowed, such a merge fails without writing.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is locked, the source or target is
    /// not a verified v4 replica of this vault, the merge violates
    /// integrity rules, or a legacy resurrection is not allowed.
    pub fn merge_vault_from(
        &self,
        source_path: &Path,
        dry_run: bool,
        allow_legacy_resurrections: bool,
    ) -> Result<MergeReport, CoreError> {
        let dk = self.require_session()?;

        // 1. Source byte snapshot + structural validation (read-only, no
        //    locks; the file may keep changing underneath — the merge uses
        //    exactly these verified bytes).
        let raw = fs::read(source_path).map_err(CoreError::Io)?;
        let version = detect_vault_version(&raw);
        if version != 4 {
            return Err(CoreError::Secret(format!(
                "source {} is a v{version} vault; merge only accepts v4 — unlock the source copy first to migrate it",
                source_path.display()
            )));
        }
        let source = VaultFileV4::parse(&raw)?;
        let source_digest = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(&raw))
        };

        // 2. Same-origin gate on an unlocked target peek, so an
        //    independent vault fails with a clear message before any
        //    source crypto. Re-checked on the locked re-read below.
        let peek_raw = fs::read(&self.vault_path).map_err(CoreError::Io)?;
        if detect_vault_version(&peek_raw) != 4 {
            return Err(CoreError::Secret(
                "target vault is not v4; run 'kyz vault unlock' to migrate it to v4 before merging"
                    .to_string(),
            ));
        }
        vault_v4::ensure_same_origin(&VaultFileV4::parse(&peek_raw)?, &source)?;

        // 3. Full source verification with the session DK, before the
        //    target lock: MAC over all headers and ciphertext, then AEAD
        //    on every blob.
        source.verify_mac(&dk)?;
        for (ck, ops) in &source.entries {
            for op in ops {
                source.decrypt_op_at(&dk, ck, op)?;
            }
        }

        // 4. Target under its exclusive lock, re-read from disk.
        let _lock = VaultFileLock::exclusive(&self.vault_path)?;
        let raw_target = fs::read(&self.vault_path).map_err(CoreError::Io)?;
        let target_version = detect_vault_version(&raw_target);
        if target_version != 4 {
            return Err(CoreError::Secret(format!(
                "target vault is v{target_version}; run 'kyz vault unlock' to migrate it to v4 before merging"
            )));
        }
        let mut target = VaultFileV4::parse(&raw_target)?;
        target.verify_mac(&dk)?;
        vault_v4::ensure_same_origin(&target, &source)?;

        // 5. Union + canonicalize + report.
        let mut report = vault_v4::merge_ops(&mut target, &source, &dk)?;
        report.source_digest = source_digest;

        // 6. Legacy resurrection gate: refuse the write unless the caller
        //    explicitly accepts entries that may have been deleted in v3.
        if !dry_run && !allow_legacy_resurrections && !report.legacy_resurrections.is_empty() {
            return Err(CoreError::Secret(format!(
                "merge would re-introduce {} entrie(s) that exist only in the source's pre-v4 history and are absent here: [{}]. v3-era deletions leave no tombstone, so these may be secrets deleted before migration; re-run with --yes to accept them",
                report.legacy_resurrections.len(),
                report.legacy_resurrections.join(", ")
            )));
        }

        // 7. Write back (never in dry-run; never when nothing changed).
        if !dry_run && report.changed {
            self.write_v4_unlocked(&mut target, &dk)?;
        }
        Ok(report)
    }
}

/// Draw the next counter for this machine's actor on this vault, floored
/// by the largest counter already present in the file (so a lost
/// actor-state file can never re-issue ids).
///
/// A v4 write must not hard-fail just because the global state directory
/// is unusable (read-only home, stripped service account): in that case an
/// ephemeral in-process actor takes over, whose random 16-byte id keeps
/// op-id collisions negligible.
fn allocate_op_id(vault: &VaultFileV4) -> Result<OpId, CoreError> {
    let ephemeral_actor =
        || ActorState::ephemeral().map_err(|e| CoreError::Secret(format!("ephemeral actor: {e}")));
    let mut actor = match crate::paths::default_state_dir() {
        Ok(dir) => match ActorState::load_or_init(&dir) {
            Ok(state) => state,
            Err(e) => {
                log::warn!(
                    "actor state at {} unusable ({e}); using an ephemeral actor id for this process",
                    dir.display()
                );
                ephemeral_actor()?
            }
        },
        Err(e) => {
            log::warn!(
                "cannot determine state dir ({e}); using an ephemeral actor id for this process"
            );
            ephemeral_actor()?
        }
    };
    let floor = vault.max_counter_of(actor.actor_id());
    let counter = actor.next_counter(&vault.vault_id, floor)?;
    OpId::new(actor.actor_id(), counter)
}

/// Resolve a rollback target: an `actor:counter` op id, or a 1-based
/// sequence number counting from the **oldest** operation (matching the
/// v3 version numbering, so a literal `--to N` selects the same snapshot
/// before and after migration; sequence numbers stay stable as new ops
/// append). Sequence `0` is out of range, matching v3's rejection of
/// version 0.
fn resolve_rollback_target<'a>(target: &str, items: &'a [HistoryItem]) -> Option<&'a HistoryItem> {
    if target.contains(':') {
        let id = OpId::parse(target).ok()?;
        items.iter().find(|item| item.op_id == id)
    } else {
        let seq: usize = target.parse().ok()?;
        // `items` is newest-first; sequence 1 is the oldest entry.
        let idx = items.len().checked_sub(seq)?;
        items.get(idx)
    }
}

/// Core of [`VaultStore::rollback_v4`] (also the v4 arm of
/// [`VaultStore::rollback`]): resolve `target` against the entry's
/// history and append the restoring put. The caller holds the exclusive
/// vault lock, has MAC-verified `vault`, and writes the file.
///
/// # Errors
///
/// Returns an error if the target cannot be resolved or its ciphertext
/// was pruned.
fn rollback_v4_locked(
    vault: &mut VaultFileV4,
    dk: &Zeroizing<[u8; DK_LEN]>,
    service: &str,
    key: &str,
    target: &str,
) -> Result<(), CoreError> {
    if !target.contains(':') && target.parse::<usize>().is_err() {
        return Err(CoreError::Secret(format!(
            "invalid rollback target '{target}': expected <seq> or <actor:counter>"
        )));
    }
    let ck = VaultFileV4::compound_key(service, key);
    let ops = vault.ops(service, key).ok_or_else(|| {
        CoreError::SecretNotFound(format!("secret '{key}' not found in service '{service}'"))
    })?;
    let items = vault_v4::history(ops)?;
    let item = resolve_rollback_target(target, &items).ok_or_else(|| {
        CoreError::Secret(format!(
            "no history version '{target}' for '{service}/{key}'"
        ))
    })?;
    if item.kind != vault_v4::OpKind::Put {
        return Err(CoreError::Secret(format!(
            "history version '{target}' of '{service}/{key}' is a deletion, not a snapshot"
        )));
    }
    let op = ops
        .iter()
        .find(|op| op.id == item.op_id)
        .ok_or_else(|| CoreError::Secret(format!("op {} missing", item.op_id)))?;
    let Some(snapshot) = vault.decrypt_op_at(dk, &ck, op)? else {
        return Err(CoreError::Secret(format!(
            "history version '{target}' of '{service}/{key}' no longer has ciphertext (pruned after a delete)"
        )));
    };

    // The rollback is a fresh put parented on the entry's current frontier
    // (tombstone included when the entry is deleted). The restored
    // snapshot gets a new `updated_at`, matching v3 rollback: consumers
    // keying change detection on it must see the rollback.
    let parents: Vec<OpId> = vault
        .frontier_of(service, key)?
        .map_or_else(Vec::new, |f| f.into_iter().collect());
    let mut snapshot = snapshot;
    snapshot.updated_at = now_unix();
    VaultStore::append_local_put(vault, &snapshot, parents, dk)
}

/// OS keyring backend using the `keyring` crate.
///
/// Stores each secret entry as a JSON blob in the platform-native credential
/// store. Maintains a key index per service for enumeration.
///
/// Note: Requires a desktop session (D-Bus + Secret Service on Linux,
/// Keychain on macOS, Credential Manager on Windows).
#[derive(Debug, Clone, Copy)]
pub struct KeyringStore;

/// Reserved key name for the index.
const INDEX_KEY: &str = "__kyz_index__";

impl KeyringStore {
    /// Create a new keyring store instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Load the key index for a service.
    ///
    /// Handles both legacy `BTreeMap<String, ()>` format and current
    /// `BTreeSet<String>` format transparently.
    fn load_index(service: &str) -> Result<BTreeSet<String>, CoreError> {
        let entry = keyring::Entry::new(service, INDEX_KEY)
            .map_err(|e| CoreError::Secret(format!("failed to create index entry: {e}")))?;
        match entry.get_password() {
            Ok(json) => {
                // Try new format (array) first, fall back to legacy (object with null values)
                if let Ok(set) = serde_json::from_str::<BTreeSet<String>>(&json) {
                    return Ok(set);
                }
                // Legacy format: {"key": null, ...} → extract keys
                let map: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_str(&json)
                        .map_err(|e| CoreError::Secret(format!("corrupted key index: {e}")))?;
                Ok(map.keys().cloned().collect())
            }
            Err(keyring::Error::NoEntry) => Ok(BTreeSet::new()),
            Err(e) => Err(CoreError::Secret(format!("failed to read key index: {e}"))),
        }
    }

    /// Save the key index for a service.
    fn save_index(service: &str, index: &BTreeSet<String>) -> Result<(), CoreError> {
        let entry = keyring::Entry::new(service, INDEX_KEY)
            .map_err(|e| CoreError::Secret(format!("failed to create index entry: {e}")))?;
        let json = serde_json::to_string(index)
            .map_err(|e| CoreError::Secret(format!("failed to serialize key index: {e}")))?;
        entry
            .set_password(&json)
            .map_err(|e| CoreError::Secret(format!("failed to write key index: {e}")))
    }
}

impl Default for KeyringStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for KeyringStore {
    fn get(&self, service: &str, key: &str) -> Result<SecretEntry, CoreError> {
        let entry = keyring::Entry::new(service, key)
            .map_err(|e| CoreError::Secret(format!("failed to create keyring entry: {e}")))?;
        let json = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => CoreError::SecretNotFound(format!(
                "secret '{key}' not found in service '{service}'"
            )),
            other => CoreError::Secret(format!("keyring error: {other}")),
        })?;

        // Try parsing as SecretEntry JSON first
        if let Ok(parsed) = serde_json::from_str::<SecretEntry>(&json) {
            return Ok(parsed);
        }

        // Fallback: treat as raw string value (legacy single-value format)
        Ok(SecretEntry::single(service, key, &json))
    }

    fn set(&self, service: &str, key: &str, secret: &SecretEntry) -> Result<(), CoreError> {
        let entry = keyring::Entry::new(service, key)
            .map_err(|e| CoreError::Secret(format!("failed to create keyring entry: {e}")))?;
        let json = serde_json::to_string(secret)
            .map_err(|e| CoreError::Secret(format!("failed to serialize entry: {e}")))?;
        entry
            .set_password(&json)
            .map_err(|e| CoreError::Secret(format!("failed to set secret: {e}")))?;

        let mut index = Self::load_index(service)?;
        index.insert(key.to_string());
        Self::save_index(service, &index)?;

        Ok(())
    }

    fn delete(&self, service: &str, key: &str) -> Result<(), CoreError> {
        let entry = keyring::Entry::new(service, key)
            .map_err(|e| CoreError::Secret(format!("failed to create keyring entry: {e}")))?;
        entry.delete_credential().map_err(|e| match e {
            keyring::Error::NoEntry => CoreError::SecretNotFound(format!(
                "secret '{key}' not found in service '{service}'"
            )),
            other => CoreError::Secret(format!("failed to delete secret: {other}")),
        })?;

        let mut index = Self::load_index(service)?;
        index.remove(key);
        Self::save_index(service, &index)?;

        Ok(())
    }

    fn list(&self, service: &str) -> Result<Vec<SecretSummary>, CoreError> {
        let index = Self::load_index(service)?;
        Ok(index
            .iter()
            .map(|key| SecretSummary {
                key: key.clone(),
                service: service.to_string(),
                field_names: Vec::new(), // Can't know without fetching each entry
                tags: BTreeSet::new(),
                updated_at: 0,
            })
            .collect())
    }

    fn list_services(&self) -> Result<Vec<String>, CoreError> {
        // Keyring doesn't support cross-service enumeration
        Err(CoreError::Secret(
            "keyring backend does not support listing services".to_string(),
        ))
    }
}

mod secret_fields_serde {
    use std::collections::BTreeMap;

    use secrecy::SecretString;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(
        fields: &BTreeMap<String, SecretString>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let plain: BTreeMap<&str, &str> = fields
            .iter()
            .map(|(k, v)| (k.as_str(), secrecy::ExposeSecret::expose_secret(v)))
            .collect();
        plain.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<String, SecretString>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let plain = BTreeMap::<String, String>::deserialize(deserializer)?;
        Ok(plain
            .into_iter()
            .map(|(k, v)| (k, SecretString::from(v)))
            .collect())
    }
}

/// Advisory file lock for vault operations.
///
/// Uses platform-native locking: `flock` on Unix, `LockFileEx` on Windows.
/// The lock is released when the guard is dropped. Also guards the
/// actor-state file (same sidecar `.json.lock` convention) through
/// [`VaultFileLock::exclusive`].
pub(crate) struct VaultFileLock {
    _file: fs::File,
}

impl VaultFileLock {
    /// Acquire a shared (read) lock. Multiple readers can hold this simultaneously.
    fn shared(vault_path: &Path) -> Result<Self, CoreError> {
        let lock_path = vault_path.with_extension("json.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(CoreError::Io)?;

        Self::flock_shared(&file, &lock_path)?;
        Ok(Self { _file: file })
    }

    /// Acquire an exclusive (write) lock. Only one writer at a time.
    /// Also guards the actor-state file, which shares the sidecar
    /// `.json.lock` convention.
    pub(crate) fn exclusive(vault_path: &Path) -> Result<Self, CoreError> {
        let lock_path = vault_path.with_extension("json.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(CoreError::Io)?;

        Self::flock_exclusive(&file, &lock_path)?;
        Ok(Self { _file: file })
    }

    fn flock_shared(file: &fs::File, lock_path: &Path) -> Result<(), CoreError> {
        fs2::FileExt::lock_shared(file).map_err(|e| {
            CoreError::Secret(format!(
                "failed to acquire shared lock on {}: {e}",
                lock_path.display()
            ))
        })
    }

    fn flock_exclusive(file: &fs::File, lock_path: &Path) -> Result<(), CoreError> {
        fs2::FileExt::lock_exclusive(file).map_err(|e| {
            CoreError::Secret(format!(
                "failed to acquire exclusive lock on {}: {e}",
                lock_path.display()
            ))
        })
    }
}

const MIN_PASSPHRASE_LEN: usize = 16;
const PASS_PHRASE_POLICY_ENV_BYPASS: &str = "KYZ_VAULT_PASSWORD";

fn should_skip_passphrase_policy() -> bool {
    std::env::var_os(PASS_PHRASE_POLICY_ENV_BYPASS).is_some()
}

fn passphrase_strength_error_details(passphrase: &str) -> Option<String> {
    if passphrase.chars().count() >= MIN_PASSPHRASE_LEN {
        return None;
    }

    let entropy = zxcvbn::zxcvbn(passphrase, &[]);
    if entropy.score() >= zxcvbn::Score::Three {
        None
    } else {
        Some(format!(
            "passphrase too weak: {} chars, zxcvbn score {}",
            passphrase.chars().count(),
            u8::from(entropy.score())
        ))
    }
}

fn ensure_passphrase_strength(passphrase: &str) -> Result<(), CoreError> {
    if should_skip_passphrase_policy() {
        return Ok(());
    }

    if let Some(details) = passphrase_strength_error_details(passphrase) {
        return Err(CoreError::Secret(format!(
            "Weak vault passphrase rejected ({details}). Use at least {MIN_PASSPHRASE_LEN} characters OR a passphrase with zxcvbn score >= 3. Set {PASS_PHRASE_POLICY_ENV_BYPASS} in CI/automation to bypass this check."
        )));
    }

    Ok(())
}

/// Get the vault file path for a named environment.
///
/// # Errors
///
/// Returns an error if the data directory cannot be determined.
pub fn env_vault_path(env_name: &str) -> Result<PathBuf, CoreError> {
    let data_dir = crate::paths::default_data_dir()
        .map_err(|e| CoreError::Path(format!("cannot determine data dir: {e}")))?;
    Ok(data_dir.join(ENVS_DIR).join(env_name).join(VAULT_FILENAME))
}

/// List all named environments that have vault files.
///
/// # Errors
///
/// Returns an error if the data directory cannot be determined or read.
pub fn list_environments() -> Result<Vec<String>, CoreError> {
    let data_dir = crate::paths::default_data_dir()
        .map_err(|e| CoreError::Path(format!("cannot determine data dir: {e}")))?;
    let envs_dir = data_dir.join(ENVS_DIR);
    if !envs_dir.exists() {
        return Ok(Vec::new());
    }

    let mut envs = Vec::new();
    let entries = fs::read_dir(&envs_dir).map_err(CoreError::Io)?;
    for entry in entries {
        let entry = entry.map_err(CoreError::Io)?;
        let path = entry.path();
        if path.is_dir()
            && path.join(VAULT_FILENAME).exists()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            envs.push(name.to_string());
        }
    }
    envs.sort();
    Ok(envs)
}

/// Get the central vault file path.
///
/// # Errors
///
/// Returns an error if the data directory cannot be determined.
pub fn central_vault_path() -> Result<PathBuf, CoreError> {
    let data_dir = crate::paths::default_data_dir()
        .map_err(|e| CoreError::Path(format!("cannot determine data dir: {e}")))?;
    Ok(data_dir.join(VAULT_FILENAME))
}

/// Get the workspace vault path for a given directory.
#[must_use]
pub fn workspace_vault_path(workspace_dir: &Path) -> PathBuf {
    workspace_dir.join(WORKSPACE_VAULT_DIR).join(VAULT_FILENAME)
}

/// Current Unix timestamp in seconds.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Simple deterministic hash for path-to-filename mapping.
fn simple_hash(input: &str) -> String {
    format!("{:016x}", fnv1a_64(input.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("kyz-{label}-{}-{nanos}.json", std::process::id()))
    }

    /// OS keyrings do not reliably serialize concurrent access from
    /// multiple threads (the keyring crate calls this out for Windows in
    /// particular): parallel tests issuing concurrent writes/deletes can
    /// lose a delete. Tests that touch the keyring hold this lock so they
    /// run one at a time.
    static KEYRING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Acquire [`KEYRING_TEST_LOCK`] for the lifetime of the test.
    fn keyring_guard() -> std::sync::MutexGuard<'static, ()> {
        KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // v4-write tests stay off the developer's real actor-state directory
    // via the shared test-util hook.
    use crate::paths::isolate_state_dir;

    #[test]
    fn test_encrypt_decrypt_entry_roundtrip() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "username".to_string(),
            SecretString::from("alice".to_string()),
        );
        fields.insert(
            "password".to_string(),
            SecretString::from("s3cr3t".to_string()),
        );
        let entry = SecretEntry::new("svc", "db", fields.clone());

        let passphrase = SecretString::from("a-very-strong-passphrase-123".to_string());
        let encrypted = encrypt_entry(&entry, &passphrase)
            .map_err(|e| format!("encrypt failed: {e}"))
            .expect("entry encrypt/decrypt roundtrip should succeed");
        let decrypted = decrypt_entry(&encrypted, &passphrase)
            .map_err(|e| format!("decrypt failed: {e}"))
            .expect("entry encrypt/decrypt roundtrip should succeed");

        assert_eq!(decrypted.service, "svc");
        assert_eq!(decrypted.key, "db");
        assert_eq!(decrypted.field("username"), Some("alice"));
        assert_eq!(decrypted.field("password"), Some("s3cr3t"));
    }

    #[test]
    fn test_vault_store_crud_roundtrip() {
        let _keyring = keyring_guard();
        isolate_state_dir().expect("isolate state dir");
        let vault_path = temp_vault_path("crud");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";

        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");
        store
            .unlock(passphrase, 60)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("vault unlock should succeed");

        let entry = SecretEntry::single("app", "api-key", "token-123");
        store
            .set("app", "api-key", &entry)
            .map_err(|e| format!("set failed: {e}"))
            .expect("vault set should succeed");

        let fetched = store
            .get("app", "api-key")
            .map_err(|e| format!("get failed: {e}"))
            .expect("vault get should succeed");
        assert_eq!(fetched.value(), Some("token-123"));

        let summaries = store
            .list("app")
            .map_err(|e| format!("list failed: {e}"))
            .expect("vault list should succeed");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].key, "api-key");

        store
            .delete("app", "api-key")
            .map_err(|e| format!("delete failed: {e}"))
            .expect("vault delete should succeed");
        let missing = store.get("app", "api-key");
        assert!(missing.is_err());

        let _ = store.lock();
        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn v3_unlock_with_policy_flag_skips_the_vault_lock() {
        let vault_path = temp_vault_path("v3-nolock");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";
        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");
        // `init` already flags the policy as checked; start from a clean
        // slate so a created lock file cannot mask the assertion.
        let _ = std::fs::remove_file(vault_path.with_extension("json.lock"));

        store
            .unlock_in_memory(&SecretString::from(passphrase.to_string()))
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("vault unlock should succeed");

        assert!(
            !vault_path.with_extension("json.lock").exists(),
            "steady-state v3 unlock must not serialize on the vault lock"
        );
        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_secret_entry_and_vaultdata_merge_behavior() {
        let mut first = SecretEntry::single("svc", "name", "v1");
        first.add_tag("prod");

        let mut second_fields = BTreeMap::new();
        second_fields.insert("token".to_string(), SecretString::from("abc".to_string()));
        let second = SecretEntry::new("svc", "name", second_fields);

        let mut data = VaultData::new();
        data.set(first);
        data.set(second);

        let merged = data.get("svc", "name").expect("merged entry should exist");
        assert_eq!(merged.value(), Some("v1"));
        assert_eq!(merged.field("token"), Some("abc"));
        assert!(merged.has_tag("prod"));
    }

    #[test]
    fn test_vault_history_on_update() {
        let _keyring = keyring_guard();
        isolate_state_dir().expect("isolate state dir");
        let vault_path = temp_vault_path("history");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";

        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");
        store
            .unlock(passphrase, 60)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("vault unlock should succeed");

        // First set — one op, current, no ancestors.
        store
            .set("app", "key", &SecretEntry::single("app", "key", "value-1"))
            .map_err(|e| format!("set failed: {e}"))
            .expect("first set should succeed");

        let items = store
            .history_v4("app", "key")
            .map_err(|e| format!("history failed: {e}"))
            .expect("history should succeed");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].role, vault_v4::HistoryRole::Current);

        // Second set — v4 archives nothing physically; the previous
        // version becomes a causal ancestor visible in history.
        store
            .set("app", "key", &SecretEntry::single("app", "key", "value-2"))
            .map_err(|e| format!("set failed: {e}"))
            .expect("second set should succeed");

        let items = store
            .history_v4("app", "key")
            .map_err(|e| format!("history failed: {e}"))
            .expect("history should succeed");
        assert_eq!(items.len(), 2, "both versions stay in the op log");
        assert_eq!(items[0].role, vault_v4::HistoryRole::Current);
        assert_eq!(items[1].role, vault_v4::HistoryRole::Ancestor);

        let fetched = store
            .get("app", "key")
            .map_err(|e| format!("get failed: {e}"))
            .expect("get should succeed");
        assert_eq!(fetched.value(), Some("value-2"));

        let _ = store.lock();
        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_vault_rollback() {
        let _keyring = keyring_guard();
        isolate_state_dir().expect("isolate state dir");
        let vault_path = temp_vault_path("rollback");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";

        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");
        store
            .unlock(passphrase, 60)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("vault unlock should succeed");

        for v in ["v1", "v2", "v3"] {
            store
                .set("app", "key", &SecretEntry::single("app", "key", v))
                .map_err(|e| format!("set failed: {e}"))
                .expect("set should succeed");
        }
        let fetched = store
            .get("app", "key")
            .map_err(|e| format!("get failed: {e}"))
            .expect("get should succeed");
        assert_eq!(fetched.value(), Some("v3"));

        // Rollback by sequence number counting from the oldest: v1 is #1.
        store
            .rollback_v4("app", "key", "1")
            .map_err(|e| format!("rollback failed: {e}"))
            .expect("rollback should succeed");

        let fetched = store
            .get("app", "key")
            .map_err(|e| format!("get failed: {e}"))
            .expect("get should succeed");
        assert_eq!(fetched.value(), Some("v1"));

        // Rollback is a new write: the log keeps every version.
        let items = store
            .history_v4("app", "key")
            .map_err(|e| format!("history failed: {e}"))
            .expect("history should succeed");
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].role, vault_v4::HistoryRole::Current);

        // The same rollback also works by stable op id.
        let target = items[1].op_id.to_string();
        store
            .rollback_v4("app", "key", &target)
            .map_err(|e| format!("rollback failed: {e}"))
            .expect("rollback by op id should succeed");
        let items = store
            .history_v4("app", "key")
            .map_err(|e| format!("history failed: {e}"))
            .expect("history should succeed");
        assert_eq!(items.len(), 5);

        let _ = store.lock();
        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_history_retention_limit() {
        let _keyring = keyring_guard();
        isolate_state_dir().expect("isolate state dir");
        let vault_path = temp_vault_path("retention");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";

        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");
        store
            .unlock(passphrase, 60)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("vault unlock should succeed");

        // In v4, retention limits history display only — the operation
        // log is never physically trimmed, because old replicas may
        // re-deliver pruned versions.
        for i in 0..5 {
            let entry = SecretEntry::single("app", "key", &format!("v{i}"));
            store
                .set("app", "key", &entry)
                .map_err(|e| format!("set failed: {e}"))
                .expect("set should succeed");
        }

        let items = store
            .history_v4("app", "key")
            .map_err(|e| format!("history failed: {e}"))
            .expect("history should succeed");
        assert_eq!(items.len(), 5, "v4 keeps every operation");
        assert_eq!(items[0].role, vault_v4::HistoryRole::Current);

        let _ = store.lock();
        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_passphrase_strength_rejected_on_init() {
        let vault_path = temp_vault_path("weak-init");
        let store = VaultStore::new(vault_path.clone());

        let result = store.init("weak", false);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(err.to_string().contains("Weak vault passphrase rejected"));
        }

        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_first_unlock_marks_policy_checked() {
        let _keyring = keyring_guard();
        let vault_path = temp_vault_path("policy-checked");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";

        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");
        store
            .unlock(passphrase, 60)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("first unlock should succeed");

        let raw = std::fs::read(&vault_path)
            .map_err(|e| format!("read vault failed: {e}"))
            .expect("vault file should be readable");
        let parsed: VaultFileV2 = serde_json::from_slice(&raw)
            .map_err(|e| format!("parse vault failed: {e}"))
            .expect("vault should parse as v2 json");
        assert!(parsed.passphrase_policy_checked);

        let _ = store.lock();
        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_unlock_in_memory_resolves_without_session_or_keyring() {
        let _keyring = keyring_guard();
        isolate_state_dir().expect("isolate state dir");
        let vault_path = temp_vault_path("in-memory");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";

        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");
        // Create the secret through a normal CLI-style session, then lock it
        // again so only the in-memory handle remains.
        store
            .unlock(passphrase, 60)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("unlock should succeed");
        store
            .set(
                "app",
                "api-key",
                &SecretEntry::single("app", "api-key", "token-123"),
            )
            .map_err(|e| format!("set failed: {e}"))
            .expect("set should succeed");
        store
            .lock()
            .map_err(|e| format!("lock failed: {e}"))
            .expect("lock should succeed");

        let secret = SecretString::from(passphrase.to_string());
        let uv = store
            .unlock_in_memory(&secret)
            .map_err(|e| format!("unlock_in_memory failed: {e}"))
            .expect("in-memory unlock should succeed");

        let entry = uv
            .get("app", "api-key")
            .map_err(|e| format!("get failed: {e}"))
            .expect("get should succeed");
        assert_eq!(entry.value(), Some("token-123"));

        let fields = vec!["value".to_string()];
        let resolved = uv
            .resolve_fields("app", "api-key", &fields)
            .map_err(|e| format!("resolve_fields failed: {e}"))
            .expect("resolve_fields should succeed");
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved
                .get("value")
                .map(secrecy::ExposeSecret::expose_secret),
            Some("token-123")
        );

        let session_file = VaultSession::session_file_for(&vault_path).expect("session file path");
        assert!(
            !session_file.exists(),
            "in-memory unlock must not create a session file"
        );

        // No keyring entry was written (best effort: some CI environments have
        // no keyring at all, in which case only the file check applies).
        let keyring_user = VaultSession::keyring_user(&vault_path);
        if let Ok(entry) = keyring::Entry::new(SESSION_KEYRING_SERVICE, &keyring_user)
            && let Ok(stored) = entry.get_password()
        {
            panic!("in-memory unlock must not write the DK to the keyring: {stored}");
        }

        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_unlock_in_memory_wrong_passphrase_error_has_no_secret() {
        let vault_path = temp_vault_path("in-memory-wrong");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";
        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");

        let wrong = SecretString::from("definitely-the-wrong-passphrase".to_string());
        let err = store
            .unlock_in_memory(&wrong)
            .expect_err("wrong passphrase should fail");
        let text = err.to_string();
        assert!(!text.contains("definitely-the-wrong-passphrase"));

        let secret = SecretString::from(passphrase.to_string());
        let uv = store
            .unlock_in_memory(&secret)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("unlock with right passphrase should succeed");
        let debug = format!("{uv:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(passphrase));

        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_unlock_in_memory_sees_cli_updates_in_real_time() {
        let _keyring = keyring_guard();
        isolate_state_dir().expect("isolate state dir");
        let vault_path = temp_vault_path("in-memory-realtime");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";

        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");
        store
            .unlock(passphrase, 60)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("unlock should succeed");
        store
            .set("app", "key", &SecretEntry::single("app", "key", "v1"))
            .map_err(|e| format!("set failed: {e}"))
            .expect("set should succeed");

        let secret = SecretString::from(passphrase.to_string());
        let uv = store
            .unlock_in_memory(&secret)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("in-memory unlock should succeed");
        assert_eq!(uv.get("app", "key").expect("get v1").value(), Some("v1"));

        store
            .set("app", "key", &SecretEntry::single("app", "key", "v2"))
            .map_err(|e| format!("set failed: {e}"))
            .expect("set should succeed");
        assert_eq!(uv.get("app", "key").expect("get v2").value(), Some("v2"));

        let _ = store.lock();
        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_unlock_in_memory_missing_field_fails_closed() {
        let _keyring = keyring_guard();
        isolate_state_dir().expect("isolate state dir");
        let vault_path = temp_vault_path("in-memory-fields");
        let store = VaultStore::new(vault_path.clone());
        let passphrase = "a-very-strong-passphrase-123";
        store
            .init(passphrase, false)
            .map_err(|e| format!("init failed: {e}"))
            .expect("vault init should succeed");
        store
            .unlock(passphrase, 60)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("unlock should succeed");
        store
            .set("app", "key", &SecretEntry::single("app", "key", "v1"))
            .map_err(|e| format!("set failed: {e}"))
            .expect("set should succeed");
        let _ = store.lock();

        let secret = SecretString::from(passphrase.to_string());
        let uv = store
            .unlock_in_memory(&secret)
            .map_err(|e| format!("unlock failed: {e}"))
            .expect("in-memory unlock should succeed");

        let missing = vec!["nope".to_string()];
        assert!(uv.resolve_fields("app", "key", &missing).is_err());

        let empty: Vec<String> = Vec::new();
        let resolved = uv
            .resolve_fields("app", "key", &empty)
            .expect("empty field list should resolve to empty map");
        assert!(resolved.is_empty());

        let _ = std::fs::remove_file(&vault_path);
    }

    #[test]
    fn test_migration_runs_inside_single_exclusive_lock_transaction() {
        let vault_path = temp_vault_path("migration-lock");
        let passphrase = "a-very-strong-passphrase-123";

        // Craft a v2 vault (per-entry scrypt-age) directly on disk.
        let secret = SecretString::from(passphrase.to_string());
        let mut v2 = VaultFileV2::new();
        v2.passphrase_policy_checked = true;
        let plain = SecretEntry::single("app", "key", "v2-value");
        let encrypted = encrypt_entry(&plain, &secret).expect("encrypt entry");
        v2.entries
            .insert(VaultFileV2::compound_key("app", "key"), encrypted);
        let v2_json = serde_json::to_string_pretty(&v2).expect("serialize v2");
        std::fs::write(&vault_path, v2_json).expect("write v2 vault");

        // Hold the exclusive vault lock, then start an in-memory unlock that
        // must migrate v2 -> v3. It has to block until we release.
        let guard = VaultFileLock::exclusive(&vault_path).expect("hold exclusive lock");

        let store = VaultStore::new(vault_path.clone());
        let unlock_thread = std::thread::spawn(move || {
            store
                .unlock_in_memory(&secret)
                .expect("in-memory unlock with migration should succeed")
        });

        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !unlock_thread.is_finished(),
            "unlock_in_memory must block while another writer holds the vault lock"
        );

        drop(guard);
        let uv = unlock_thread
            .join()
            .expect("unlock thread should not panic");

        let raw = std::fs::read(&vault_path).expect("read migrated vault");
        assert_eq!(detect_vault_version(&raw), 4, "vault should now be v4");
        assert_eq!(uv.get("app", "key").expect("get").value(), Some("v2-value"));

        let _ = std::fs::remove_file(&vault_path);
    }
}
