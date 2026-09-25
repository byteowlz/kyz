//! Per-machine actor identity and per-vault operation counters.
//!
//! v4 operation ids are `actor_id + counter`. The actor id identifies one
//! installation on one machine and never travels inside the vault; the
//! counter is tracked per `vault_id` so a vault copied between machines
//! cannot collide with the source machine's future ops.
//!
//! Both live in a state file under `$XDG_STATE_HOME/kyz/actor-state.json`,
//! guarded by an independent process lock (not the vault file lock) and
//! updated with an atomic replace. If the state file is lost or its actor
//! id is malformed, a fresh random actor id is generated — old ids are
//! never reused. When the state directory cannot be used at all (read-only
//! home, stripped service accounts), an in-process ephemeral actor takes
//! over: its random 16-byte id makes counter collisions negligible, at the
//! cost of one actor per process.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::store::VaultFileLock;
use crate::vault_v4::ACTOR_ID_LEN;

/// Name of the actor state file inside the state directory.
pub const ACTOR_STATE_FILE: &str = "actor-state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActorFile {
    actor_id: String,
    counters: BTreeMap<String, u64>,
}

/// A loaded (or freshly initialized) actor state.
#[derive(Debug, Clone)]
pub struct ActorState {
    /// State file path; `None` for an ephemeral (in-process only) actor.
    path: Option<PathBuf>,
    actor_id: String,
    counters: BTreeMap<String, u64>,
}

impl ActorState {
    /// Load the machine's actor state, creating it with a fresh random
    /// actor id on first use.
    ///
    /// A state file whose actor id is not 32 lowercase hex characters is
    /// treated as corrupt and replaced with a fresh identity, keeping
    /// writes working instead of failing every subsequent op id mint.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file cannot be read, parsed, or
    /// created.
    pub fn load_or_init(state_dir: &Path) -> Result<Self, CoreError> {
        fs::create_dir_all(state_dir).map_err(CoreError::Io)?;
        let path = state_dir.join(ACTOR_STATE_FILE);
        if path.exists()
            && let Ok(raw) = fs::read(&path)
            && let Ok(file) = serde_json::from_slice::<ActorFile>(&raw)
            && is_actor_id(&file.actor_id)
        {
            return Ok(Self {
                path: Some(path),
                actor_id: file.actor_id,
                counters: file.counters,
            });
        }
        // Missing, unreadable, or malformed state: generate a new identity
        // rather than fail. Old ids are never reused, so this is always safe.
        let actor_id = random_actor_id()?;
        let state = Self {
            path: Some(path),
            actor_id,
            counters: BTreeMap::new(),
        };
        state.persist()?;
        Ok(state)
    }

    /// An ephemeral actor that never touches disk: fresh random id,
    /// in-memory counters. Used when the state directory is unusable.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS RNG fails.
    pub fn ephemeral() -> Result<Self, CoreError> {
        Ok(Self {
            path: None,
            actor_id: random_actor_id()?,
            counters: BTreeMap::new(),
        })
    }

    /// This machine's actor id (hex).
    #[must_use]
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    /// Allocate the next counter for `vault_id`.
    ///
    /// Persistent actors run under the dedicated actor-state lock with a
    /// re-read, so two processes writing the same vault never draw the same
    /// counter. `floor` is the largest counter observed for this actor inside
    /// the current vault file; the allocated value is always greater than both
    /// it and the stored state, so a lost or rolled-back state file cannot
    /// re-issue ids either.
    ///
    /// # Errors
    ///
    /// Returns an error on lock or I/O failure.
    pub fn next_counter(&mut self, vault_id: &str, floor: u64) -> Result<u64, CoreError> {
        let Some(path) = &self.path else {
            // Ephemeral actor: single-process by construction, in-memory
            // monotonic counters suffice.
            let next = floor
                .max(self.counters.get(vault_id).copied().unwrap_or(0))
                .saturating_add(1);
            self.counters.insert(vault_id.to_string(), next);
            return Ok(next);
        };
        let _lock = VaultFileLock::exclusive(path)?;
        // Re-read: another process may have advanced the counter since.
        let mut current = Self::read_counters(path)?;
        let next = floor
            .max(current.remove(vault_id).unwrap_or(0))
            .saturating_add(1);
        current.insert(vault_id.to_string(), next);
        self.counters = current.clone();
        let file = ActorFile {
            actor_id: self.actor_id.clone(),
            counters: current,
        };
        let json = serde_json::to_vec(&file)
            .map_err(|e| CoreError::Serialization(format!("serializing actor state: {e}")))?;
        crate::atomic::write_atomic(path, &json)?;
        Ok(next)
    }

    fn read_counters(path: &Path) -> Result<BTreeMap<String, u64>, CoreError> {
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let raw = fs::read(path).map_err(|e| {
            CoreError::Io(std::io::Error::new(
                e.kind(),
                format!("{e} (actor state {})", path.display()),
            ))
        })?;
        let file: ActorFile = serde_json::from_slice(&raw).map_err(|e| {
            CoreError::Serialization(format!("parsing actor state {}: {e}", path.display()))
        })?;
        Ok(file.counters)
    }

    fn persist(&self) -> Result<(), CoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = ActorFile {
            actor_id: self.actor_id.clone(),
            counters: self.counters.clone(),
        };
        let json = serde_json::to_vec(&file)
            .map_err(|e| CoreError::Serialization(format!("serializing actor state: {e}")))?;
        crate::atomic::write_atomic(path, &json)
    }
}

fn random_actor_id() -> Result<String, CoreError> {
    let mut bytes = [0u8; ACTOR_ID_LEN];
    getrandom::fill(&mut bytes)
        .map_err(|e| CoreError::Secret(format!("getrandom actor id: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Whether `id` is a well-formed actor id (32 lowercase hex characters).
fn is_actor_id(id: &str) -> bool {
    crate::vault_v4::validate_hex_id("actor id", id, ACTOR_ID_LEN).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_state_counter_is_monotonic_and_floor_aware() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = ActorState::load_or_init(dir.path()).expect("load");
        let vault = "0123456789abcdef0123456789abcdef";

        assert_eq!(state.next_counter(vault, 0).expect("c1"), 1);
        assert_eq!(state.next_counter(vault, 0).expect("c2"), 2);
        // Floor from the vault file must never be re-issued.
        assert_eq!(state.next_counter(vault, 40).expect("c3"), 41);

        // A fresh process reading the same state continues the sequence.
        let mut reloaded = ActorState::load_or_init(dir.path()).expect("reload");
        assert_eq!(reloaded.actor_id(), state.actor_id());
        assert_eq!(reloaded.next_counter(vault, 0).expect("c4"), 42);

        // Separate vaults have independent counters.
        assert_eq!(
            state
                .next_counter("ffffffffffffffffffffffffffffffff", 0)
                .expect("o"),
            1
        );
    }

    #[test]
    fn lost_state_generates_new_actor_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = ActorState::load_or_init(dir.path()).expect("load");
        std::fs::remove_file(dir.path().join(ACTOR_STATE_FILE)).expect("remove");
        let second = ActorState::load_or_init(dir.path()).expect("reload");
        assert_ne!(first.actor_id(), second.actor_id());
    }

    #[test]
    fn malformed_actor_id_state_is_replaced_not_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(ACTOR_STATE_FILE);
        std::fs::write(
            &path,
            br#"{"actor_id":"NOT-HEX-BUT-RIGHT-LENGTH0000","counters":{}}"#,
        )
        .expect("write corrupt state");
        let state = ActorState::load_or_init(dir.path()).expect("load replaces bad state");
        assert!(is_actor_id(state.actor_id()));
        // The replacement is persisted: a reload keeps the new identity.
        let reloaded = ActorState::load_or_init(dir.path()).expect("reload");
        assert_eq!(reloaded.actor_id(), state.actor_id());
    }

    #[test]
    fn ephemeral_actor_counters_are_monotonic_without_disk() {
        let mut state = ActorState::ephemeral().expect("ephemeral");
        let vault = "0123456789abcdef0123456789abcdef";
        assert_eq!(state.next_counter(vault, 0).expect("c1"), 1);
        assert_eq!(state.next_counter(vault, 0).expect("c2"), 2);
        assert_eq!(state.next_counter(vault, 9).expect("c3"), 10);
        assert_eq!(
            state
                .next_counter("ffffffffffffffffffffffffffffffff", 0)
                .expect("o"),
            1
        );
    }
}
