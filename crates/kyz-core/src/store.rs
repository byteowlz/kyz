//! Secret store abstraction and OS keyring backend.
//!
//! Provides a [`SecretStore`] trait for CRUD operations on secrets,
//! and a [`KeyringStore`] implementation backed by the OS keyring
//! (gnome-keyring on Linux, macOS Keychain, Windows Credential Manager).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Default service name used when none is specified.
pub const DEFAULT_SERVICE: &str = "kyz";

/// A stored secret entry with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// The key (name) of the secret.
    pub key: String,
    /// The service namespace this secret belongs to.
    pub service: String,
}

/// Trait for secret store backends.
///
/// Implementations must provide CRUD operations for secrets
/// organized by service namespace and key name.
pub trait SecretStore: fmt::Debug + Send + Sync {
    /// Retrieve a secret value by key.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret is not found or the backend fails.
    fn get(&self, service: &str, key: &str) -> Result<String, CoreError>;

    /// Store or update a secret value.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to persist the secret.
    fn set(&self, service: &str, key: &str, value: &str) -> Result<(), CoreError>;

    /// Remove a secret by key.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret is not found or the backend fails.
    fn delete(&self, service: &str, key: &str) -> Result<(), CoreError>;

    /// List all known secret keys for a given service.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to enumerate secrets.
    fn list(&self, service: &str) -> Result<Vec<SecretEntry>, CoreError>;
}

/// OS keyring backend using the `keyring` crate.
///
/// Secrets are stored in the platform-native credential store:
/// - Linux: Secret Service (gnome-keyring / KWallet)
/// - macOS: Keychain
/// - Windows: Credential Manager
///
/// The keyring crate does not support enumeration, so we maintain a
/// metadata index stored as a JSON blob under a reserved key per service.
#[derive(Debug, Clone, Copy)]
pub struct KeyringStore;

/// Reserved key name used to store the index of known keys per service.
const INDEX_KEY: &str = "__kyz_index__";

impl KeyringStore {
    /// Create a new keyring store instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Load the key index for a service from the keyring.
    fn load_index(&self, service: &str) -> Result<BTreeMap<String, ()>, CoreError> {
        let entry = keyring::Entry::new(service, INDEX_KEY)
            .map_err(|e| CoreError::Secret(format!("failed to create index entry: {e}")))?;
        match entry.get_password() {
            Ok(json) => serde_json::from_str(&json)
                .map_err(|e| CoreError::Secret(format!("corrupted key index: {e}"))),
            Err(keyring::Error::NoEntry) => Ok(BTreeMap::new()),
            Err(e) => Err(CoreError::Secret(format!("failed to read key index: {e}"))),
        }
    }

    /// Save the key index for a service to the keyring.
    fn save_index(&self, service: &str, index: &BTreeMap<String, ()>) -> Result<(), CoreError> {
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
    fn get(&self, service: &str, key: &str) -> Result<String, CoreError> {
        let entry = keyring::Entry::new(service, key)
            .map_err(|e| CoreError::Secret(format!("failed to create keyring entry: {e}")))?;
        entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => {
                CoreError::SecretNotFound(format!("secret '{key}' not found in service '{service}'"))
            }
            other => CoreError::Secret(format!("keyring error: {other}")),
        })
    }

    fn set(&self, service: &str, key: &str, value: &str) -> Result<(), CoreError> {
        let entry = keyring::Entry::new(service, key)
            .map_err(|e| CoreError::Secret(format!("failed to create keyring entry: {e}")))?;
        entry
            .set_password(value)
            .map_err(|e| CoreError::Secret(format!("failed to set secret: {e}")))?;

        // Update the index
        let mut index = self.load_index(service)?;
        index.insert(key.to_string(), ());
        self.save_index(service, &index)?;

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

        // Update the index
        let mut index = self.load_index(service)?;
        index.remove(key);
        self.save_index(service, &index)?;

        Ok(())
    }

    fn list(&self, service: &str) -> Result<Vec<SecretEntry>, CoreError> {
        let index = self.load_index(service)?;
        Ok(index
            .keys()
            .map(|key| SecretEntry {
                key: key.clone(),
                service: service.to_string(),
            })
            .collect())
    }
}
