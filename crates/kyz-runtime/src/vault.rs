//! Single-source vault facade.
//!
//! [`Vault`] is the library-level handle a consumer holds to one vault
//! source. It composes:
//!
//! - a [`kyz_core::SecretStore`] backend (file-backed or keyring),
//! - a [`crate::VaultSource`] describing provenance,
//! - a declared [`crate::UnlockMode`] that informs how
//!   [`Vault::unlock_state`] reports a locked vault.
//!
//! For multi-source lookups (workspace-first, personal-fallback, etc.)
//! compose several `Vault` instances in a [`crate::LayeredVault`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use kyz_core::store::{central_vault_path, workspace_vault_path};
use kyz_core::{
    KeyringStore, SecretEntry, SecretStore, SecretSummary, VaultStore, env_vault_path,
};
use secrecy::{ExposeSecret as _, SecretString};

use crate::error::{Error, Result};
use crate::reference::SecretRef;
use crate::source::{VaultKind, VaultSource};
use crate::unlock::{UnlockMode, UnlockState};

/// Minimum session timeout we will ever request from the core layer.
const DEFAULT_UNLOCK_TTL: Duration = Duration::from_mins(30);

/// Runtime view of a vault's current state.
#[derive(Debug, Clone)]
pub struct VaultStatus {
    /// The source this status describes.
    pub source: VaultSource,
    /// True if the underlying vault file / backend exists.
    pub exists: bool,
    /// Current unlock state.
    pub unlock: UnlockState,
}

#[derive(Debug)]
enum Backend {
    Vault(VaultStore),
    Keyring(KeyringStore),
}

impl Backend {
    fn store(&self) -> &dyn SecretStore {
        match self {
            Self::Vault(v) => v,
            Self::Keyring(k) => k,
        }
    }
}

/// A single vault source with declared unlock mode.
#[derive(Debug)]
pub struct Vault {
    backend: Backend,
    source: VaultSource,
    declared_mode: UnlockMode,
}

impl Vault {
    /// Open whichever vault the core layer resolves by default.
    ///
    /// Resolution order matches [`VaultStore::resolve`]: explicit >
    /// named environment > workspace > central. The returned [`Vault`]
    /// carries a best-effort [`VaultSource`] inferred from the resolved
    /// path.
    ///
    /// # Errors
    ///
    /// Returns an error if core vault resolution fails.
    pub fn open_default() -> Result<Self> {
        let store = VaultStore::resolve(None).map_err(Error::from)?;
        let path = store.vault_path().to_path_buf();
        let source = infer_source(&path);
        Ok(Self::from_vault_store(store, source))
    }

    /// Open a vault at an explicit path.
    #[must_use]
    pub fn open_path(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let store = VaultStore::new(path.clone());
        let source = VaultSource::new("custom", VaultKind::Custom, Some(path));
        Self::from_vault_store(store, source)
    }

    /// Open the workspace vault under the given directory.
    ///
    /// The resulting [`Vault`] will report
    /// [`UnlockState::Locked`]/`Unlocked` based on the session file
    /// living next to that path.
    #[must_use]
    pub fn open_workspace(workspace_dir: impl AsRef<Path>) -> Self {
        let path = workspace_vault_path(workspace_dir.as_ref());
        let source = VaultSource::workspace(path.clone());
        let store = VaultStore::new(path);
        Self::from_vault_store(store, source)
    }

    /// Open the personal / central vault.
    ///
    /// # Errors
    ///
    /// Returns an error if the XDG data directory cannot be resolved.
    pub fn open_personal() -> Result<Self> {
        let path = central_vault_path().map_err(Error::from)?;
        let source = VaultSource::personal(path.clone());
        let store = VaultStore::new(path);
        Ok(Self::from_vault_store(store, source))
    }

    /// Open a named-environment vault (e.g. `dev`, `staging`, `prod`).
    ///
    /// # Errors
    ///
    /// Returns an error if the environment path cannot be resolved.
    pub fn open_environment(env_name: &str) -> Result<Self> {
        let path = env_vault_path(env_name).map_err(Error::from)?;
        let source = VaultSource::environment(env_name.to_string(), path.clone());
        let store = VaultStore::new(path);
        Ok(Self::from_vault_store(store, source))
    }

    /// Open the OS keyring backend (no file path, no explicit unlock).
    #[must_use]
    pub fn open_keyring() -> Self {
        Self {
            backend: Backend::Keyring(KeyringStore::new()),
            source: VaultSource::keyring(),
            declared_mode: UnlockMode::Interactive,
        }
    }

    const fn from_vault_store(store: VaultStore, source: VaultSource) -> Self {
        Self {
            backend: Backend::Vault(store),
            source,
            declared_mode: UnlockMode::Interactive,
        }
    }

    /// Set the declared unlock mode (builder-style).
    ///
    /// The declared mode does not change how the core layer unlocks the
    /// vault — it only affects how [`Vault::unlock_state`] reports a
    /// locked vault (e.g. [`UnlockState::LockedRequestable`] vs
    /// [`UnlockState::Locked`]).
    #[must_use]
    pub const fn with_unlock_mode(mut self, mode: UnlockMode) -> Self {
        self.declared_mode = mode;
        self
    }

    /// The source descriptor for this vault.
    #[must_use]
    pub const fn source(&self) -> &VaultSource {
        &self.source
    }

    /// The declared unlock mode.
    #[must_use]
    pub const fn declared_unlock_mode(&self) -> UnlockMode {
        self.declared_mode
    }

    /// Current runtime status (existence + unlock state).
    ///
    /// # Errors
    ///
    /// Returns an error if the core layer cannot inspect the vault file.
    pub fn status(&self) -> Result<VaultStatus> {
        let unlock = self.unlock_state()?;
        let exists = match &self.backend {
            Backend::Vault(v) => v.vault_path().exists(),
            // OS keyring is always "present" from the client's perspective.
            Backend::Keyring(_) => true,
        };
        Ok(VaultStatus {
            source: self.source.clone(),
            exists,
            unlock,
        })
    }

    /// Report the unlock state.
    ///
    /// For the OS keyring backend this is always
    /// [`UnlockState::Unlocked`] with no expiry (the OS manages the
    /// session on our behalf).
    ///
    /// # Errors
    ///
    /// Returns an error if the core layer cannot inspect the vault file.
    pub fn unlock_state(&self) -> Result<UnlockState> {
        match &self.backend {
            Backend::Keyring(_) => Ok(UnlockState::Unlocked {
                mode: self.declared_mode,
                expires_at: 0,
                remaining_secs: u64::MAX,
            }),
            Backend::Vault(v) => {
                let status = v.status().map_err(Error::from)?;
                if !status.exists {
                    return Ok(self.locked_variant());
                }
                match (status.unlocked, status.expires_at, status.remaining_secs) {
                    (true, Some(expires_at), Some(remaining_secs)) => Ok(UnlockState::Unlocked {
                        mode: self.declared_mode,
                        expires_at,
                        remaining_secs,
                    }),
                    _ => Ok(self.locked_variant()),
                }
            }
        }
    }

    const fn locked_variant(&self) -> UnlockState {
        if matches!(self.declared_mode, UnlockMode::RemoteApproval) {
            UnlockState::LockedRequestable
        } else {
            UnlockState::Locked
        }
    }

    /// Override the inferred source.
    ///
    /// Useful for tests and for integrations that want to declare a
    /// non-default name or kind (for example, marking a custom path as
    /// the "prod-shared" source in a layered resolver).
    #[must_use]
    pub fn with_source(mut self, source: VaultSource) -> Self {
        self.source = source;
        self
    }

    /// Initialise a new vault file at this vault's path.
    ///
    /// Keyring-backed vaults are always "initialised"; this method is a
    /// no-op for them.
    ///
    /// # Errors
    ///
    /// Returns an error if the file already exists (unless `force`) or
    /// if initialisation fails.
    pub fn init(&self, passphrase: &SecretString, force: bool) -> Result<()> {
        match &self.backend {
            Backend::Keyring(_) => Ok(()),
            Backend::Vault(v) => v
                .init(passphrase.expose_secret(), force)
                .map_err(Error::from),
        }
    }

    /// Store an entry under the given ref.
    ///
    /// # Errors
    ///
    /// Returns an error on backend failure.
    pub fn set(&self, r: &SecretRef, entry: &SecretEntry) -> Result<()> {
        self.backend
            .store()
            .set(r.service(), r.key(), entry)
            .map_err(Error::from)
    }

    /// Delete an entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the entry doesn't exist.
    pub fn delete(&self, r: &SecretRef) -> Result<()> {
        self.backend
            .store()
            .delete(r.service(), r.key())
            .map_err(|e| Error::from_core(e, Some(r)))
    }

    /// Unlock a file-backed vault with an interactive passphrase.
    ///
    /// This is a no-op for keyring-backed vaults (they have no explicit
    /// session).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is keyring-only or the unlock
    /// call fails.
    pub fn unlock_interactive(
        &self,
        passphrase: &SecretString,
        ttl: Option<Duration>,
    ) -> Result<UnlockState> {
        match &self.backend {
            Backend::Keyring(_) => Err(Error::UnsupportedKind {
                expected: "file-backed vault",
                actual: "keyring".to_string(),
            }),
            Backend::Vault(v) => {
                let ttl_secs = ttl.unwrap_or(DEFAULT_UNLOCK_TTL).as_secs();
                v.unlock(passphrase.expose_secret(), ttl_secs)
                    .map_err(Error::from)?;
                self.unlock_state()
            }
        }
    }

    /// Tear down the unlock session, if any.
    ///
    /// No-op for keyring backends.
    ///
    /// # Errors
    ///
    /// Returns an error if the core layer fails to remove the session.
    pub fn lock(&self) -> Result<()> {
        match &self.backend {
            Backend::Keyring(_) => Ok(()),
            Backend::Vault(v) => v.lock().map_err(Error::from),
        }
    }

    /// List services that have at least one entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails.
    pub fn list_services(&self) -> Result<Vec<String>> {
        self.backend.store().list_services().map_err(Error::from)
    }

    /// List entry summaries in a given service.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails.
    pub fn list(&self, service: &str) -> Result<Vec<SecretSummary>> {
        self.backend.store().list(service).map_err(Error::from)
    }

    /// List entry summaries across all services.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails.
    pub fn list_all(&self) -> Result<Vec<SecretSummary>> {
        let services = self.list_services()?;
        let mut out = Vec::new();
        for svc in services {
            out.extend(self.list(&svc)?);
        }
        Ok(out)
    }

    /// Resolve a ref to its full entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists, or a
    /// backend error otherwise.
    pub fn get(&self, r: &SecretRef) -> Result<SecretEntry> {
        self.backend
            .store()
            .get(r.service(), r.key())
            .map_err(|e| Error::from_core(e, Some(r)))
    }

    /// Resolve a ref, returning `Ok(None)` for a clean miss.
    ///
    /// Useful for layered resolution where a miss on one source is not
    /// itself an error.
    ///
    /// # Errors
    ///
    /// Returns an error for backend failures other than not-found.
    pub fn try_get(&self, r: &SecretRef) -> Result<Option<SecretEntry>> {
        match self.get(r) {
            Ok(entry) => Ok(Some(entry)),
            Err(Error::NotFound { .. }) => Ok(None),
            Err(other) => Err(other),
        }
    }

    /// Fetch a single field of an entry.
    ///
    /// Returns [`Error::NotFound`] if the entry is missing; returns
    /// [`Error::UnsupportedKind`] if the entry lacks the requested
    /// field.
    ///
    /// # Errors
    ///
    /// See above.
    pub fn get_field(&self, r: &SecretRef, field: &str) -> Result<SecretString> {
        let entry = self.get(r)?;
        entry
            .field(field)
            .map(|s| SecretString::from(s.to_string()))
            .ok_or_else(|| Error::UnsupportedKind {
                expected: "entry with requested field",
                actual: format!("entry missing field '{field}'"),
            })
    }
}

fn infer_source(path: &Path) -> VaultSource {
    let path_str = path.to_string_lossy();
    if path_str.contains("/.kyz/") {
        VaultSource::workspace(path.to_path_buf())
    } else if let Some(name) = extract_env_name(path) {
        VaultSource::environment(name, path.to_path_buf())
    } else {
        VaultSource::personal(path.to_path_buf())
    }
}

fn extract_env_name(path: &Path) -> Option<String> {
    // $XDG_DATA_HOME/kyz/envs/<name>/vault.json
    let components: Vec<_> = path.components().collect();
    let len = components.len();
    if len < 3 {
        return None;
    }
    let envs_idx = components
        .iter()
        .position(|c| c.as_os_str() == std::ffi::OsStr::new("envs"))?;
    if envs_idx + 1 >= len {
        return None;
    }
    let name = components[envs_idx + 1].as_os_str().to_string_lossy();
    Some(name.into_owned())
}
