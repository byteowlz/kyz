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

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default service name used when none is specified.
pub const DEFAULT_SERVICE: &str = "kyz";

/// Default session timeout in seconds (30 minutes).
pub const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 1800;

/// Vault filename.
pub const VAULT_FILENAME: &str = "vault.json";

/// Workspace vault directory name.
pub const WORKSPACE_VAULT_DIR: &str = ".kyz";

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// A stored secret entry with multiple named fields.
///
/// Each entry belongs to a service namespace and has a key (name).
/// Fields hold the actual secret data (username, password, url, notes, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// The key (name) of the secret.
    pub key: String,
    /// The service namespace this secret belongs to.
    pub service: String,
    /// Named fields containing the secret data.
    pub fields: BTreeMap<String, String>,
    /// Unix timestamp when the entry was created.
    pub created_at: u64,
    /// Unix timestamp when the entry was last modified.
    pub updated_at: u64,
}

impl SecretEntry {
    /// Create a new entry with the given service, key, and fields.
    #[must_use]
    pub fn new(service: &str, key: &str, fields: BTreeMap<String, String>) -> Self {
        let now = now_unix();
        Self {
            key: key.to_string(),
            service: service.to_string(),
            fields,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new entry with a single "value" field (backwards compat).
    #[must_use]
    pub fn single(service: &str, key: &str, value: &str) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("value".to_string(), value.to_string());
        Self::new(service, key, fields)
    }

    /// Get a specific field value.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    /// Get the "value" field (convenience for single-value entries).
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.field("value")
    }

    /// Set a field, updating the modification timestamp.
    pub fn set_field(&mut self, name: &str, value: &str) {
        self.fields.insert(name.to_string(), value.to_string());
        self.updated_at = now_unix();
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
    /// Unix timestamp when last modified.
    pub updated_at: u64,
}

impl From<&SecretEntry> for SecretSummary {
    fn from(entry: &SecretEntry) -> Self {
        Self {
            key: entry.key.clone(),
            service: entry.service.clone(),
            field_names: entry.fields.keys().cloned().collect(),
            updated_at: entry.updated_at,
        }
    }
}

// ---------------------------------------------------------------------------
// SecretStore trait
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Vault file format
// ---------------------------------------------------------------------------

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
            .filter(|e| e.service == service || Self::compound_key(&e.service, &e.key).starts_with(&prefix))
            .collect()
    }

    /// List all distinct service names.
    #[must_use]
    pub fn services(&self) -> Vec<String> {
        let mut svcs: Vec<String> = self
            .entries
            .values()
            .map(|e| e.service.clone())
            .collect();
        svcs.sort();
        svcs.dedup();
        svcs
    }
}

// ---------------------------------------------------------------------------
// Vault encryption / decryption (age passphrase-based)
// ---------------------------------------------------------------------------

/// Encrypt vault data with a passphrase using age (scrypt KDF + ChaCha20-Poly1305).
///
/// # Errors
///
/// Returns an error if serialization or encryption fails.
pub fn encrypt_vault(data: &VaultData, passphrase: &str) -> Result<Vec<u8>, CoreError> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| CoreError::Serialization(format!("serializing vault: {e}")))?;

    let encryptor = age::Encryptor::with_user_passphrase(secrecy::SecretString::from(passphrase.to_string()));
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
pub fn decrypt_vault(encrypted: &[u8], passphrase: &str) -> Result<VaultData, CoreError> {
    let decryptor = age::Decryptor::new(encrypted)
        .map_err(|e| CoreError::Secret(format!("reading encrypted vault: {e}")))?;

    if !decryptor.is_scrypt() {
        return Err(CoreError::Secret("vault is not passphrase-encrypted".to_string()));
    }

    let identity = age::scrypt::Identity::new(secrecy::SecretString::from(passphrase.to_string()));

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

// ---------------------------------------------------------------------------
// Session file management
// ---------------------------------------------------------------------------

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

/// A vault session tracks an unlocked vault's passphrase via the OS keyring.
///
/// The passphrase is stored in the platform-native credential store:
/// - **macOS**: Keychain (file-backed, works over SSH)
/// - **Linux**: kernel keyutils (in-memory, works headless, cleared on reboot)
/// - **Windows**: Credential Manager
///
/// A companion session file at `$XDG_RUNTIME_DIR/kyz/session-<hash>` holds
/// only non-sensitive metadata (expiry timestamp, vault path).
///
/// If the OS keyring is unavailable, falls back to an age-encrypted session
/// file with a machine-bound key.
#[derive(Debug, Clone)]
pub struct VaultSession {
    /// The vault passphrase (in memory only).
    pub passphrase: String,
    /// Unix timestamp when this session expires.
    pub expires_at: u64,
    /// Path to the vault file this session unlocks.
    pub vault_path: PathBuf,
}

/// Keyring service name for vault session passphrases.
const SESSION_KEYRING_SERVICE: &str = "kyz-session";

impl VaultSession {
    /// Create a new session.
    #[must_use]
    pub fn new(passphrase: &str, vault_path: &Path, timeout_secs: u64) -> Self {
        Self {
            passphrase: passphrase.to_string(),
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
        // Use $USER to scope the directory per-user, preventing cross-user access
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
        // Hash the vault path to create a unique session file per vault
        let hash = simple_hash(&vault_path.to_string_lossy());
        Ok(dir.join(format!("session-{hash}")))
    }

    /// Derive the keyring username for a given vault path.
    ///
    /// Each vault gets a unique keyring entry keyed by a hash of the vault
    /// path, so multiple vaults can have independent sessions.
    fn keyring_user(vault_path: &Path) -> String {
        let hash = simple_hash(&vault_path.to_string_lossy());
        format!("vault-{hash}")
    }

    /// Store the passphrase in the OS keyring.
    fn keyring_store(vault_path: &Path, passphrase: &str) -> Result<(), CoreError> {
        let user = Self::keyring_user(vault_path);
        let entry = keyring::Entry::new(SESSION_KEYRING_SERVICE, &user)
            .map_err(|e| CoreError::Secret(format!("creating keyring entry: {e}")))?;
        entry
            .set_password(passphrase)
            .map_err(|e| CoreError::Secret(format!("storing passphrase in keyring: {e}")))?;
        Ok(())
    }

    /// Retrieve the passphrase from the OS keyring.
    fn keyring_load(vault_path: &Path) -> Result<Option<String>, CoreError> {
        let user = Self::keyring_user(vault_path);
        let entry = keyring::Entry::new(SESSION_KEYRING_SERVICE, &user)
            .map_err(|e| CoreError::Secret(format!("creating keyring entry: {e}")))?;
        match entry.get_password() {
            Ok(pass) => Ok(Some(pass)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CoreError::Secret(format!(
                "reading passphrase from keyring: {e}"
            ))),
        }
    }

    /// Remove the passphrase from the OS keyring.
    fn keyring_delete(vault_path: &Path) -> Result<(), CoreError> {
        let user = Self::keyring_user(vault_path);
        let entry = keyring::Entry::new(SESSION_KEYRING_SERVICE, &user)
            .map_err(|e| CoreError::Secret(format!("creating keyring entry: {e}")))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CoreError::Secret(format!(
                "removing passphrase from keyring: {e}"
            ))),
        }
    }

    /// Derive a machine-bound session encryption key (fallback only).
    ///
    /// Used when the OS keyring is unavailable. The key is derived from the
    /// vault path, the current user, and the hostname.
    fn fallback_encryption_key(vault_path: &Path) -> String {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| String::from("unknown"));

        let hostname = hostname::get()
            .map_or_else(|_| String::from("localhost"), |h| h.to_string_lossy().to_string());

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

    /// Write the session to disk and store the passphrase in the OS keyring.
    ///
    /// The passphrase is stored in the platform-native credential store. Only
    /// non-sensitive metadata (expiry, vault path) is written to the session
    /// file. If the keyring is unavailable, falls back to an age-encrypted
    /// session file.
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

        // Try OS keyring first (passphrase never touches disk)
        let keyring_ok = Self::keyring_store(&self.vault_path, &self.passphrase).is_ok();

        if keyring_ok {
            // Keyring succeeded: write only metadata to the session file
            let meta = SessionMeta {
                expires_at: self.expires_at,
                vault_path: self.vault_path.clone(),
            };
            let json = serde_json::to_string(&meta)
                .map_err(|e| CoreError::Serialization(format!("serializing session meta: {e}")))?;
            fs::write(&path, json.as_bytes()).map_err(CoreError::Io)?;
        } else {
            // Keyring unavailable: fall back to age-encrypted session file
            log::debug!("OS keyring unavailable, falling back to encrypted session file");
            let full = FallbackSession {
                passphrase: self.passphrase.clone(),
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
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(CoreError::Io)?;
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
    fn load_keyring_session(
        vault_path: &Path,
        raw: &[u8],
    ) -> Result<Option<Self>, CoreError> {
        // Metadata files are valid UTF-8 JSON; encrypted files are binary
        let Ok(text) = std::str::from_utf8(raw) else {
            return Ok(None);
        };
        let Ok(meta) = serde_json::from_str::<SessionMeta>(text) else {
            return Ok(None);
        };

        // We have valid metadata; now get the passphrase from the keyring
        let Some(passphrase) = Self::keyring_load(vault_path)? else {
            // Keyring entry gone (reboot on Linux keyutils, manual clear, etc.)
            // Clean up the orphaned metadata file
            let path = Self::session_file_for(vault_path)?;
            let _ = fs::remove_file(&path);
            return Ok(None);
        };

        Ok(Some(Self {
            passphrase,
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
        Some(Self {
            passphrase: fb.passphrase,
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
        // Remove keyring entry (ignore errors -- may not exist)
        let _ = Self::keyring_delete(vault_path);

        // Remove session file
        let path = Self::session_file_for(vault_path)?;
        if path.exists() {
            fs::remove_file(&path).map_err(CoreError::Io)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fallback session (age-encrypted file when keyring is unavailable)
// ---------------------------------------------------------------------------

/// Full session data for the encrypted-file fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FallbackSession {
    /// The vault passphrase.
    passphrase: String,
    /// Unix timestamp when this session expires.
    expires_at: u64,
    /// Path to the vault file this session unlocks.
    vault_path: PathBuf,
}

/// Encrypt session data with a passphrase using age.
fn encrypt_session_data(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, CoreError> {
    let encryptor =
        age::Encryptor::with_user_passphrase(secrecy::SecretString::from(passphrase.to_string()));
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| CoreError::Secret(format!("creating session encryptor: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| CoreError::Secret(format!("encrypting session data: {e}")))?;
    writer
        .finish()
        .map_err(|e| CoreError::Secret(format!("finalizing session encryption: {e}")))?;
    Ok(encrypted)
}

/// Decrypt session data with a passphrase using age.
fn decrypt_session_data(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, CoreError> {
    let decryptor = age::Decryptor::new(encrypted)
        .map_err(|e| CoreError::Secret(format!("reading encrypted session: {e}")))?;

    if !decryptor.is_scrypt() {
        return Err(CoreError::Secret(
            "session file is not passphrase-encrypted".to_string(),
        ));
    }

    let identity =
        age::scrypt::Identity::new(secrecy::SecretString::from(passphrase.to_string()));

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| CoreError::Secret(format!("session decryption failed: {e}")))?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| CoreError::Secret(format!("reading decrypted session: {e}")))?;

    Ok(decrypted)
}

// ---------------------------------------------------------------------------
// VaultStore backend
// ---------------------------------------------------------------------------

/// File-based vault backend using age encryption.
///
/// Secrets are stored in an age-encrypted JSON file. The vault must be
/// unlocked (session file present) before any operations.
///
/// Vault location resolution order:
/// 1. Explicit path (if provided)
/// 2. Workspace vault: `<cwd>/.kyz/vault.json`
/// 3. Central vault: `$XDG_DATA_HOME/kyz/vault.json`
#[derive(Debug, Clone)]
pub struct VaultStore {
    /// Path to the vault file.
    vault_path: PathBuf,
}

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

    /// Resolve vault path: explicit > workspace > central.
    ///
    /// # Errors
    ///
    /// Returns an error if no vault can be found or paths fail to resolve.
    pub fn resolve(explicit: Option<&Path>) -> Result<Self, CoreError> {
        if let Some(p) = explicit {
            return Ok(Self::new(p.to_path_buf()));
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
    /// Creates an empty encrypted vault file. Fails if one already exists
    /// (use `force` to overwrite).
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists and force is false, or on I/O failure.
    pub fn init(&self, passphrase: &str, force: bool) -> Result<(), CoreError> {
        if self.vault_path.exists() && !force {
            return Err(CoreError::Secret(format!(
                "vault already exists at {} (use --force to overwrite)",
                self.vault_path.display()
            )));
        }

        if let Some(parent) = self.vault_path.parent() {
            fs::create_dir_all(parent)
                .map_err(CoreError::Io)?;
        }

        let data = VaultData::new();
        let encrypted = encrypt_vault(&data, passphrase)?;
        fs::write(&self.vault_path, &encrypted)
            .map_err(CoreError::Io)?;

        // Set vault file permissions to 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&self.vault_path, fs::Permissions::from_mode(0o600))
                .map_err(CoreError::Io)?;
        }

        Ok(())
    }

    /// Unlock the vault: verify passphrase and create a session file.
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

        // Verify passphrase by attempting to decrypt
        let encrypted = fs::read(&self.vault_path)
            .map_err(CoreError::Io)?;
        let _data = decrypt_vault(&encrypted, passphrase)?;

        // Create session
        let session = VaultSession::new(passphrase, &self.vault_path, timeout_secs);
        session.save()
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

    /// Load the session passphrase, or return an error if locked.
    fn require_session(&self) -> Result<String, CoreError> {
        let session = VaultSession::load(&self.vault_path)?
            .ok_or_else(|| CoreError::Secret(
                "vault is locked. Run 'kyz unlock' first.".to_string()
            ))?;
        Ok(session.passphrase)
    }

    /// Read and decrypt the vault data.
    fn read_data(&self) -> Result<VaultData, CoreError> {
        let passphrase = self.require_session()?;
        if !self.vault_path.exists() {
            return Ok(VaultData::new());
        }
        let encrypted = fs::read(&self.vault_path)
            .map_err(CoreError::Io)?;
        decrypt_vault(&encrypted, &passphrase)
    }

    /// Encrypt and write the vault data.
    fn write_data(&self, data: &VaultData) -> Result<(), CoreError> {
        let passphrase = self.require_session()?;
        let encrypted = encrypt_vault(data, &passphrase)?;
        fs::write(&self.vault_path, &encrypted)
            .map_err(CoreError::Io)?;
        Ok(())
    }
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
        let data = self.read_data()?;
        data.get(service, key)
            .cloned()
            .ok_or_else(|| CoreError::SecretNotFound(
                format!("secret '{key}' not found in service '{service}'")
            ))
    }

    fn set(&self, service: &str, key: &str, entry: &SecretEntry) -> Result<(), CoreError> {
        let mut data = self.read_data()?;
        // Ensure the entry has the correct service/key
        let mut stored = entry.clone();
        stored.service = service.to_string();
        stored.key = key.to_string();
        data.set(stored);
        self.write_data(&data)
    }

    fn delete(&self, service: &str, key: &str) -> Result<(), CoreError> {
        let mut data = self.read_data()?;
        if !data.remove(service, key) {
            return Err(CoreError::SecretNotFound(
                format!("secret '{key}' not found in service '{service}'")
            ));
        }
        self.write_data(&data)
    }

    fn list(&self, service: &str) -> Result<Vec<SecretSummary>, CoreError> {
        let data = self.read_data()?;
        Ok(data
            .list_service(service)
            .iter()
            .map(|e| SecretSummary::from(*e))
            .collect())
    }

    fn list_services(&self) -> Result<Vec<String>, CoreError> {
        let data = self.read_data()?;
        Ok(data.services())
    }
}

// ---------------------------------------------------------------------------
// KeyringStore backend (kept for desktop use)
// ---------------------------------------------------------------------------

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
    fn load_index(service: &str) -> Result<BTreeSet<String>, CoreError> {
        let entry = keyring::Entry::new(service, INDEX_KEY)
            .map_err(|e| CoreError::Secret(format!("failed to create index entry: {e}")))?;
        match entry.get_password() {
            Ok(json) => serde_json::from_str(&json)
                .map_err(|e| CoreError::Secret(format!("corrupted key index: {e}"))),
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
            keyring::Error::NoEntry => {
                CoreError::SecretNotFound(format!("secret '{key}' not found in service '{service}'"))
            }
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
            keyring::Error::NoEntry => {
                CoreError::SecretNotFound(format!("secret '{key}' not found in service '{service}'"))
            }
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Simple deterministic hash for path-to-filename mapping.
fn simple_hash(input: &str) -> String {
    // FNV-1a 64-bit
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}
