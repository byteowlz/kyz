//! Vault format v4: entry-level multi-replica merging.
//!
//! v4 keeps the v3 crypto layering (scrypt KEK wraps a per-vault DK; field
//! blobs are XChaCha20-Poly1305 under the DK) and replaces the
//! last-writer-wins entry map with a per-entry operation log:
//!
//! - Every write is an **operation** with a globally unique id
//!   (`actor_id + monotonic counter`), the set of observed frontier ids
//!   (`parents`), a kind (`put`/`delete`), and an HLC `changed_at`.
//! - The current state of an entry is a pure projection of its operation
//!   set: compute the causal frontier, then apply **delete-wins** for
//!   concurrent delete/put, and pick the winner among concurrent puts by
//!   the total order `(changed_at, id)`. Losers stay visible in history.
//! - Merging replicas is a set union of operation logs followed by
//!   canonicalization, which is commutative, associative and idempotent;
//!   equal operation sets always serialize to identical bytes.
//! - All plaintext metadata that participates in merging, listing, or
//!   path decisions is covered by an HMAC-SHA256 over the canonical file
//!   body, keyed via domain-separated HKDF from the DK.
//!
//! Merge never re-encrypts: operations are copied verbatim. Puts whose
//! blob is not needed for any future projection — those a delete
//! causally superseded (the delete observed them) — have their ciphertext
//! pruned during canonicalization, but the operation header is kept
//! forever so causality and dedup stay stable. Puts merely concurrent
//! with a delete keep their blobs: a later put observing that delete
//! un-hides the entry, and the concurrent put may then be the winner.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::store::{SecretEntry, now_unix};
use crate::vault_v3::{DK_LEN, KdfParams};

type HmacSha256 = Hmac<Sha256>;

/// Byte length of an actor id (hex-encoded as 32 characters).
pub const ACTOR_ID_LEN: usize = 16;

/// Byte length of a vault id (hex-encoded as 32 characters).
pub const VAULT_ID_LEN: usize = 16;

/// Globally unique operation id: `actor_id + monotonic counter`.
///
/// The same actor must never reuse a counter. Ordering is by
/// `(actor, counter)` which gives a stable total order used for
/// canonical serialization and deterministic winner selection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OpId {
    /// Hex-encoded 16-byte actor id.
    pub actor: String,
    /// Monotonic per-actor counter.
    pub counter: u64,
}

impl OpId {
    /// Create an op id, validating the actor encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when `actor` is not 32 lowercase hex characters.
    pub fn new(actor: &str, counter: u64) -> Result<Self, CoreError> {
        let id = Self {
            actor: actor.to_string(),
            counter,
        };
        id.validate()?;
        Ok(id)
    }

    /// Validate the actor encoding (32 lowercase hex chars).
    ///
    /// # Errors
    ///
    /// Returns an error for malformed actor ids.
    pub fn validate(&self) -> Result<(), CoreError> {
        validate_hex_id("op id actor", &self.actor, ACTOR_ID_LEN)
    }

    /// Parse `actor:counter` (the display form used by the CLI).
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input.
    pub fn parse(text: &str) -> Result<Self, CoreError> {
        let (actor, counter) = text.split_once(':').ok_or_else(|| {
            CoreError::Secret(format!("invalid op id '{text}': expected actor:counter"))
        })?;
        let counter: u64 = counter
            .parse()
            .map_err(|e| CoreError::Secret(format!("invalid op id counter '{counter}': {e}")))?;
        Self::new(actor, counter)
    }
}

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.actor, self.counter)
    }
}

/// Hybrid logical clock timestamp used for display and deterministic
/// winner selection among concurrent puts. Never used to decide whether
/// two operations are concurrent — only the parent graph does that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc {
    /// Wall-clock seconds at issue time (unix epoch).
    pub phys: u64,
    /// Logical tick, incremented when the physical clock does not advance.
    pub logical: u32,
}

impl Hlc {
    /// The zero HLC (ordered before every real timestamp).
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            phys: 0,
            logical: 0,
        }
    }

    /// Issue the next timestamp after observing `prev_max` (the largest
    /// HLC already present in the vault). Monotonic even when the local
    /// wall clock drifts backwards.
    #[must_use]
    pub fn tick(prev_max: Option<Self>) -> Self {
        let now = now_unix();
        match prev_max {
            Some(prev) if prev.phys >= now => Self {
                phys: prev.phys,
                logical: prev.logical.saturating_add(1),
            },
            _ => Self {
                phys: now,
                logical: 0,
            },
        }
    }

    /// The greater of two timestamps.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }
}

/// Operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpKind {
    /// A full entry snapshot write.
    #[serde(rename = "put")]
    Put,
    /// A tombstone removing the entry.
    #[serde(rename = "delete")]
    Delete,
}

/// MAC-authenticated plaintext projection of a put snapshot, used for
/// listing without the DK. Verified against the decrypted snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryMeta {
    /// Tags at snapshot time (sorted).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<String>,
    /// Field names at snapshot time (sorted).
    pub field_names: Vec<String>,
    /// Entry creation timestamp preserved across rewrites.
    pub created_at: u64,
    /// Snapshot write timestamp.
    pub updated_at: u64,
}

/// A single entry operation.
///
/// Headers are plaintext and MAC-authenticated; `blob` is the AEAD
/// ciphertext of the full snapshot (`None` for deletes and for pruned
/// puts whose ciphertext is no longer reachable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    /// Unique operation id.
    pub id: OpId,
    /// Frontier ids observed at write time (causal parents).
    #[serde(default)]
    pub parents: Vec<OpId>,
    /// Put or delete.
    pub kind: OpKind,
    /// HLC timestamp for display and deterministic selection.
    pub changed_at: Hlc,
    /// Plaintext metadata projection (put only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<EntryMeta>,
    /// Base64 `nonce(24) || ct || tag` of the snapshot (put only; `None`
    /// once pruned by canonicalization).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

impl Op {
    /// Compare all header fields except the blob ciphertext. Parent order
    /// is not semantic (canonical files sort it), so parents are compared
    /// order-insensitively. Two legitimate replicas of the same operation
    /// (e.g. both migrated from the same v3 data with independent random
    /// nonces) are equal here.
    #[must_use]
    pub fn header_eq(&self, other: &Self) -> bool {
        if self.id != other.id
            || self.kind != other.kind
            || self.changed_at != other.changed_at
            || self.meta != other.meta
        {
            return false;
        }
        let mut a = self.parents.clone();
        let mut b = other.parents.clone();
        a.sort();
        b.sort();
        a == b
    }
}

/// The complete plaintext entry snapshot encrypted inside a put blob.
/// Related fields (username, password, api key, …) always travel together.
#[derive(Clone, Serialize, Deserialize)]
pub struct SnapshotPlain {
    /// Service namespace.
    pub service: String,
    /// Entry key.
    pub key: String,
    /// Secret field values.
    pub fields: BTreeMap<String, String>,
    /// Tags.
    #[serde(default)]
    pub tags: BTreeSet<String>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Last-modified timestamp.
    pub updated_at: u64,
}

impl SnapshotPlain {
    /// Build a snapshot from a [`SecretEntry`].
    #[must_use]
    pub fn from_entry(entry: &SecretEntry) -> Self {
        Self {
            service: entry.service.clone(),
            key: entry.key.clone(),
            fields: entry
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), v.expose_secret().to_string()))
                .collect(),
            tags: entry.tags.clone(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }

    /// Convert back into a [`SecretEntry`].
    #[must_use]
    pub fn to_entry(&self) -> SecretEntry {
        SecretEntry {
            key: self.key.clone(),
            service: self.service.clone(),
            fields: self
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), SecretString::from(v.clone())))
                .collect(),
            tags: self.tags.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Canonical JSON bytes (BTreeMap/BTreeSet ordering makes this stable).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

impl fmt::Debug for SnapshotPlain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted: BTreeMap<&String, &str> =
            self.fields.keys().map(|k| (k, "[REDACTED]")).collect();
        f.debug_struct("SnapshotPlain")
            .field("service", &self.service)
            .field("key", &self.key)
            .field("fields", &redacted)
            .field("tags", &self.tags)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Vault file format v4: entry operation logs plus an authenticating MAC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFileV4 {
    /// Schema version. Always 4.
    pub version: u32,
    /// Stable vault identity (shared by all replicas of one vault).
    pub vault_id: String,
    /// KDF parameters (unchanged from v3).
    pub kdf: KdfParams,
    /// DK wrapped under the passphrase KEK (unchanged from v3).
    pub wrapped_dk: String,
    /// Whether passphrase strength policy has already been checked.
    #[serde(default = "default_true")]
    pub passphrase_policy_checked: bool,
    /// Operation logs per `"service/key"`, each sorted by op id.
    #[serde(default)]
    pub entries: BTreeMap<String, Vec<Op>>,
    /// Hex HMAC-SHA256 over the canonical serialization of everything else.
    #[serde(default)]
    pub mac: String,
}

const fn default_true() -> bool {
    true
}

/// HKDF info string for the file MAC key.
const MAC_KEY_INFO: &[u8] = b"kyz-vault-v4-mac-v1";
/// HKDF salt for the file MAC key.
const MAC_KEY_SALT: &[u8] = b"kyz-vault-v4";

/// Derive the 32-byte file MAC key from the DK via domain-separated
/// HKDF-SHA256.
#[must_use]
pub fn derive_mac_key(dk: &[u8; DK_LEN]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(MAC_KEY_SALT), dk);
    let mut key = Zeroizing::new([0u8; 32]);
    // HKDF expand only fails when the output exceeds the hash limit;
    // 32 bytes for SHA-256 never does.
    let _ = hk.expand(MAC_KEY_INFO, key.as_mut_slice());
    key
}

/// AAD binding: canonical JSON of the op header plus the compound
/// `service/key` position. Binding the full compound key (rather than
/// splitting it back into service and key) keeps the binding unambiguous
/// even when a service name itself contains `/`.
///
/// The AAD is computed from the canonical header form (parents sorted), so
/// canonicalization's parent re-ordering can never invalidate the binding.
#[derive(Serialize)]
struct OpAad<'a> {
    entry: &'a str,
    id: &'a OpId,
    parents: &'a [OpId],
    kind: &'a OpKind,
    changed_at: &'a Hlc,
}

fn op_aad_bytes(entry: &str, op: &Op) -> Vec<u8> {
    let mut parents = op.parents.clone();
    parents.sort();
    serde_json::to_vec(&OpAad {
        entry,
        id: &op.id,
        parents: &parents,
        kind: &op.kind,
        changed_at: &op.changed_at,
    })
    .unwrap_or_default()
}

fn ops_by_id(ops: &[Op]) -> BTreeMap<&OpId, &Op> {
    ops.iter().map(|op| (&op.id, op)).collect()
}

/// Collect every ancestor id of `start` (transitive parents closure).
///
/// Cycles are detected because any cycle through `start` must revisit it.
fn collect_ancestors(
    by_id: &BTreeMap<&OpId, &Op>,
    start: &OpId,
    out: &mut BTreeSet<OpId>,
) -> Result<(), CoreError> {
    let start_op = by_id
        .get(start)
        .ok_or_else(|| CoreError::Secret(format!("op {start} referenced but not present")))?;
    let mut stack: Vec<OpId> = start_op.parents.clone();
    let mut visited: BTreeSet<OpId> = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if id == *start {
            return Err(CoreError::Secret(format!(
                "causality cycle detected at op {start}"
            )));
        }
        if !visited.insert(id.clone()) {
            continue;
        }
        let op = by_id.get(&id).ok_or_else(|| {
            CoreError::Secret(format!("parent op {id} referenced but not present"))
        })?;
        stack.extend(op.parents.iter().cloned());
    }
    out.extend(visited);
    Ok(())
}

/// Whether the op parent graph is acyclic (Kahn peeling): repeatedly
/// remove ops whose parents have all been removed; an acyclic graph
/// empties completely, a cycle leaves its members stuck.
fn parents_form_acyclic_graph(ops: &[Op]) -> bool {
    // Duplicate op ids break the edge-count invariant below (their parent
    // edges can decrement a counter another copy already consumed, which
    // underflows); such sets bail to the per-op ancestor walk, which is
    // duplicate-tolerant. `validate_structure` tolerates equal-content
    // duplicates, so they genuinely reach this function.
    let mut unique: BTreeSet<&OpId> = BTreeSet::new();
    for op in ops {
        if !unique.insert(&op.id) {
            return false;
        }
    }
    // Remaining unresolved-parent count per op.
    let mut remaining: BTreeMap<&OpId, usize> =
        ops.iter().map(|op| (&op.id, op.parents.len())).collect();
    // Reverse edges: which ops list each id as a parent.
    let mut children: BTreeMap<&OpId, Vec<&OpId>> = BTreeMap::new();
    for op in ops {
        for parent in &op.parents {
            children.entry(parent).or_default().push(&op.id);
        }
    }
    let mut ready: Vec<&OpId> = remaining
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(id, _)| *id)
        .collect();
    let mut peeled = 0usize;
    while let Some(id) = ready.pop() {
        peeled += 1;
        if let Some(kids) = children.get(id) {
            for kid in kids {
                if let Some(n) = remaining.get_mut(*kid) {
                    *n -= 1;
                    if *n == 0 {
                        ready.push(*kid);
                    }
                }
            }
        }
    }
    peeled == ops.len()
}

/// The causal frontier: ids of operations that are not an ancestor of any
/// other operation in the set (the maximal elements of the DAG).
///
/// Fast path: in an acyclic set where every parent resolves, the dominated
/// set is exactly the union of direct parent ids — every transitive
/// ancestor is reached through one direct parent edge — so a single
/// O(ops + parents) pass replaces an ancestor walk per op. Corrupt shapes
/// (dangling parents, cycles) fall back to the per-op ancestor walk so the
/// reported error is unchanged.
///
/// # Errors
///
/// Returns an error on unresolvable parents or causality cycles.
pub fn frontier(ops: &[Op]) -> Result<BTreeSet<OpId>, CoreError> {
    let by_id = ops_by_id(ops);
    let mut dominated: BTreeSet<OpId> = BTreeSet::new();
    let mut resolvable = true;
    'scan: for op in ops {
        for parent in &op.parents {
            if !by_id.contains_key(parent) {
                resolvable = false;
                break 'scan;
            }
            dominated.insert(parent.clone());
        }
    }
    if resolvable && parents_form_acyclic_graph(ops) {
        return Ok(ops
            .iter()
            .map(|op| op.id.clone())
            .filter(|id| !dominated.contains(id))
            .collect());
    }
    let mut dominated: BTreeSet<OpId> = BTreeSet::new();
    for op in ops {
        collect_ancestors(&by_id, &op.id, &mut dominated)?;
    }
    Ok(ops
        .iter()
        .map(|op| op.id.clone())
        .filter(|id| !dominated.contains(id))
        .collect())
}

/// Projected state of one entry's operation log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Projection {
    /// The entry is externally absent: the frontier contains a delete
    /// (concurrent delete-wins), or the log has no visible puts.
    Hidden,
    /// The entry is externally visible.
    Visible {
        /// Winner snapshot op, chosen by the total order `(changed_at, id)`.
        current: OpId,
        /// Concurrent frontier puts that lost the selection; visible in
        /// history as conflict versions.
        conflicts: Vec<OpId>,
    },
}

/// The winning put among concurrent frontier puts: greatest
/// `(changed_at, id)`. Shared by [`project`] and [`history`] so the two
/// can never disagree about which version is current.
fn winner_put<'a>(puts: impl Iterator<Item = &'a Op>) -> Option<&'a Op> {
    puts.max_by(|a, b| (a.changed_at, &a.id).cmp(&(b.changed_at, &b.id)))
}

/// Project one entry's operation log to its externally visible state.
///
/// Rules (see the v4 design):
/// 1. any delete in the frontier hides the entry (delete-wins);
/// 2. otherwise the winner is the frontier put with the greatest
///    `(changed_at, id)`; the remaining frontier puts are conflicts.
///
/// # Errors
///
/// Returns an error on unresolvable parents or causality cycles.
pub fn project(ops: &[Op]) -> Result<Projection, CoreError> {
    if ops.is_empty() {
        return Ok(Projection::Hidden);
    }
    let frontier_ids = frontier(ops)?;
    let by_id = ops_by_id(ops);
    let mut frontier_puts: Vec<&Op> = Vec::new();
    for id in &frontier_ids {
        let op = by_id
            .get(id)
            .ok_or_else(|| CoreError::Secret(format!("op {id} referenced but not present")))?;
        match op.kind {
            OpKind::Delete => return Ok(Projection::Hidden),
            OpKind::Put => frontier_puts.push(op),
        }
    }
    // frontier is non-empty whenever ops is non-empty and un-cycled.
    let Some(current) = winner_put(frontier_puts.iter().copied()).map(|op| op.id.clone()) else {
        return Ok(Projection::Hidden);
    };
    let conflicts = frontier_puts
        .iter()
        .filter(|op| op.id != current)
        .map(|op| op.id.clone())
        .collect();
    Ok(Projection::Visible { current, conflicts })
}

pub(crate) fn validate_hex_id(label: &str, id: &str, len: usize) -> Result<(), CoreError> {
    if id.len() != len * 2
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CoreError::Secret(format!(
            "invalid {label} '{id}': want {len} lowercase-hex bytes"
        )));
    }
    Ok(())
}

impl VaultFileV4 {
    /// Current schema version.
    pub const CURRENT_VERSION: u32 = 4;

    /// Percent-escape `/` and `%` so a compound key splits unambiguously
    /// at the first `/` even when the service name itself contains one
    /// (library-created v3 vaults never validated service characters, so
    /// migrated data can carry them).
    fn escape_key_part(part: &str) -> String {
        let mut out = String::with_capacity(part.len());
        for c in part.chars() {
            match c {
                '/' => out.push_str("%2F"),
                '%' => out.push_str("%25"),
                _ => out.push(c),
            }
        }
        out
    }

    /// Inverse of [`Self::escape_key_part`]. Unknown `%` escapes are kept
    /// literally; compound keys are MAC-covered, so any genuine corruption
    /// is caught by verification rather than here.
    fn unescape_key_part(part: &str) -> String {
        let mut out = String::with_capacity(part.len());
        let mut rest = part;
        while let Some(idx) = rest.find('%') {
            out.push_str(&rest[..idx]);
            let after = &rest[idx + 1..];
            if let Some(tail) = after
                .strip_prefix("2F")
                .or_else(|| after.strip_prefix("2f"))
            {
                out.push('/');
                rest = tail;
            } else if let Some(tail) = after.strip_prefix("25") {
                out.push('%');
                rest = tail;
            } else {
                out.push('%');
                rest = after;
            }
        }
        out.push_str(rest);
        out
    }

    /// Build a compound key from service and entry key. Both parts are
    /// percent-escaped (see [`Self::escape_key_part`]), so the key splits
    /// at the first `/` regardless of `/` inside either part.
    #[must_use]
    pub fn compound_key(service: &str, key: &str) -> String {
        format!(
            "{}/{}",
            Self::escape_key_part(service),
            Self::escape_key_part(key)
        )
    }

    /// Split a compound key into its `(service, key)` parts (inverse of
    /// [`Self::compound_key`], unescaping both parts; `None` when it
    /// carries no service segment).
    #[must_use]
    pub fn split_compound_key(ck: &str) -> Option<(String, String)> {
        ck.split_once('/')
            .map(|(svc, key)| (Self::unescape_key_part(svc), Self::unescape_key_part(key)))
    }

    /// Assemble a v4 file from existing identity parts (used by `create`
    /// and by the v3 migration; the MAC is not yet computed).
    #[must_use]
    pub fn new_unfinalized(vault_id: &str, kdf: KdfParams, wrapped_dk: &str) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            vault_id: vault_id.to_string(),
            kdf,
            wrapped_dk: wrapped_dk.to_string(),
            passphrase_policy_checked: true,
            entries: BTreeMap::new(),
            mac: String::new(),
        }
    }

    /// Structural validation without the DK: header fields, op id encodings,
    /// parent resolution, duplicate-id content equality, and cycle-freedom
    /// (cycles surface through the frontier computation).
    ///
    /// # Errors
    ///
    /// Returns an error describing the first violation found.
    pub fn validate_structure(&self) -> Result<(), CoreError> {
        if self.version != Self::CURRENT_VERSION {
            return Err(CoreError::Secret(format!(
                "unsupported vault format version {}",
                self.version
            )));
        }
        validate_hex_id("vault_id", &self.vault_id, VAULT_ID_LEN)?;
        self.kdf.validate_params()?;
        for (ck, ops) in &self.entries {
            let mut seen: BTreeMap<OpId, &Op> = BTreeMap::new();
            for op in ops {
                op.id.validate()?;
                if let Some(prev) = seen.get(&op.id) {
                    if !prev.header_eq(op) || prev.blob != op.blob {
                        return Err(CoreError::Secret(format!(
                            "duplicate op id {} with different content in entry '{ck}'",
                            op.id
                        )));
                    }
                } else {
                    seen.insert(op.id.clone(), op);
                }
                let mut parents: BTreeSet<&OpId> = BTreeSet::new();
                for parent in &op.parents {
                    if !parents.insert(parent) {
                        return Err(CoreError::Secret(format!(
                            "duplicate parent {} on op {}",
                            parent, op.id
                        )));
                    }
                }
                match op.kind {
                    OpKind::Delete => {
                        if op.meta.is_some() || op.blob.is_some() {
                            return Err(CoreError::Secret(format!(
                                "delete op {} must not carry metadata or a blob",
                                op.id
                            )));
                        }
                    }
                    OpKind::Put => {
                        if op.meta.is_none() {
                            return Err(CoreError::Secret(format!(
                                "put op {} is missing its metadata projection",
                                op.id
                            )));
                        }
                    }
                }
            }
            // Parent resolution against the full op set: ids sort by
            // actor/counter, not causality, so a parent may legitimately
            // appear later in the list. The graph walk below then rejects
            // unresolvable parents and cycles.
            let all_ids: BTreeSet<&OpId> = ops.iter().map(|op| &op.id).collect();
            for op in ops {
                for parent in &op.parents {
                    if !all_ids.contains(&parent) {
                        return Err(CoreError::Secret(format!(
                            "op {} in entry '{ck}' references unknown parent {parent}",
                            op.id
                        )));
                    }
                }
            }
            frontier(ops)?;
        }
        Ok(())
    }

    /// Canonical MAC body: the file serialized compactly with an empty
    /// `mac` field. Field order is fixed by the struct definition and all
    /// maps are ordered, so this is byte-stable for equal op sets.
    fn mac_body_bytes(&self) -> Result<Vec<u8>, CoreError> {
        // Borrowed mirror of `VaultFileV4` (same field order) so the MAC
        // body serializes without cloning the whole file; only the `mac`
        // field is substituted. Keep the field list in sync with
        // `VaultFileV4`.
        #[derive(Serialize)]
        struct MacBody<'a> {
            version: u32,
            vault_id: &'a str,
            kdf: &'a KdfParams,
            wrapped_dk: &'a str,
            passphrase_policy_checked: bool,
            entries: &'a BTreeMap<String, Vec<Op>>,
            mac: &'a str,
        }
        let body = MacBody {
            version: self.version,
            vault_id: &self.vault_id,
            kdf: &self.kdf,
            wrapped_dk: &self.wrapped_dk,
            passphrase_policy_checked: self.passphrase_policy_checked,
            entries: &self.entries,
            mac: "",
        };
        serde_json::to_vec(&body)
            .map_err(|e| CoreError::Serialization(format!("serializing MAC body: {e}")))
    }

    /// Compute the hex HMAC-SHA256 over the canonical body, keyed via
    /// HKDF from the DK.
    ///
    /// # Errors
    ///
    /// Returns an error on serialization failure.
    pub fn compute_mac(&self, dk: &[u8; DK_LEN]) -> Result<String, CoreError> {
        let bytes = self.mac_body_bytes()?;
        let key = derive_mac_key(dk);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_slice())
            .map_err(|e| CoreError::Secret(format!("MAC init: {e}")))?;
        <HmacSha256 as Mac>::update(&mut mac, &bytes);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Verify the file MAC against the DK (constant-time tag comparison).
    ///
    /// # Errors
    ///
    /// Returns an error when the MAC is malformed or does not match.
    pub fn verify_mac(&self, dk: &[u8; DK_LEN]) -> Result<(), CoreError> {
        let bytes = self.mac_body_bytes()?;
        let decoded = hex::decode(&self.mac)
            .ok()
            .ok_or_else(|| CoreError::Secret("vault MAC is not valid hex".to_string()))?;
        let key = derive_mac_key(dk);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_slice())
            .map_err(|e| CoreError::Secret(format!("MAC init: {e}")))?;
        <HmacSha256 as Mac>::update(&mut mac, &bytes);
        mac.verify_slice(&decoded).map_err(|_| {
            CoreError::Secret(
                "vault MAC verification failed (vault corrupt, tampered, or wrong key)".to_string(),
            )
        })
    }

    /// Canonicalize in place: sort each op log by id, sort parents, and
    /// prune put blobs that can never be reached again.
    ///
    /// A put blob is pruned when a delete causally superseded the put (the
    /// put is an ancestor of the delete). Op sets only ever grow by union,
    /// so a dominated put can never re-enter the frontier in any future
    /// merged state — its blob is unreachable from every projection.
    ///
    /// Puts merely concurrent with a delete are **not** pruned, even though
    /// the delete currently hides the entry: delete-wins only applies while
    /// the delete is in the frontier, and a later put observing that delete
    /// (an explicit rebuild) un-hides the entry, after which a concurrent
    /// put can win the projection. Headers are always kept so causality
    /// and dedup stay stable across replicas.
    ///
    /// # Errors
    ///
    /// Returns an error on graph violations (cycles, unresolvable parents).
    pub fn canonicalize(&mut self) -> Result<(), CoreError> {
        for ops in self.entries.values_mut() {
            // Pass 1 (immutable): ancestor sets and prune decisions. With no
            // deletes nothing can be pruned, and every in-crate input has
            // already been graph-validated by `parse`/`validate_structure`,
            // so the ancestor pass is skipped entirely.
            let to_prune: BTreeSet<OpId> = {
                if ops.iter().all(|op| op.kind != OpKind::Delete) {
                    BTreeSet::new()
                } else {
                    let by_id = ops_by_id(ops);
                    // Every op a delete dominates (directly or transitively):
                    // these puts are permanently out of the frontier.
                    let mut shadowed: BTreeSet<OpId> = BTreeSet::new();
                    for op in &*ops {
                        if op.kind == OpKind::Delete {
                            collect_ancestors(&by_id, &op.id, &mut shadowed)?;
                        }
                    }
                    ops.iter()
                        .filter(|op| {
                            op.kind == OpKind::Put && op.blob.is_some() && shadowed.contains(&op.id)
                        })
                        .map(|op| op.id.clone())
                        .collect()
                }
            };
            // Pass 2 (mutable): apply pruning and canonical ordering.
            for op in ops.iter_mut() {
                if to_prune.contains(&op.id) {
                    op.blob = None;
                }
                op.parents.sort();
            }
            ops.sort_by(|a, b| a.id.cmp(&b.id));
            ops.dedup_by(|a, b| a.id == b.id);
        }
        self.entries.retain(|_, ops| !ops.is_empty());
        Ok(())
    }

    /// Finalize for writing: canonicalize, then compute and set the MAC.
    ///
    /// # Errors
    ///
    /// Returns an error on graph violations or serialization failure.
    pub fn finalize(&mut self, dk: &[u8; DK_LEN]) -> Result<(), CoreError> {
        self.canonicalize()?;
        self.mac = self.compute_mac(dk)?;
        Ok(())
    }

    /// Serialize canonically (compact JSON, deterministic field order).
    ///
    /// # Errors
    ///
    /// Returns an error on serialization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CoreError> {
        serde_json::to_vec(self)
            .map_err(|e| CoreError::Serialization(format!("serializing vault: {e}")))
    }

    /// Serialize for disk (pretty JSON). The MAC is computed over the
    /// compact body, so both forms authenticate the same content.
    ///
    /// # Errors
    ///
    /// Returns an error on serialization failure.
    pub fn to_bytes_pretty(&self) -> Result<Vec<u8>, CoreError> {
        serde_json::to_string_pretty(self)
            .map(String::into_bytes)
            .map_err(|e| CoreError::Serialization(format!("serializing vault: {e}")))
    }

    /// Parse and structurally validate v4 bytes (no MAC check).
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not a valid v4 file.
    pub fn parse(raw: &[u8]) -> Result<Self, CoreError> {
        let file: Self = serde_json::from_slice(raw)
            .map_err(|e| CoreError::Serialization(format!("parsing v4 vault: {e}")))?;
        file.validate_structure()?;
        Ok(file)
    }

    /// The entry operation log for `service/key`, if any.
    #[must_use]
    pub fn ops(&self, service: &str, key: &str) -> Option<&[Op]> {
        self.entries
            .get(&Self::compound_key(service, key))
            .map(Vec::as_slice)
    }

    /// Project one entry.
    ///
    /// # Errors
    ///
    /// Returns an error on graph violations.
    pub fn projection(&self, service: &str, key: &str) -> Result<Projection, CoreError> {
        self.ops(service, key)
            .map_or_else(|| Ok(Projection::Hidden), project)
    }

    /// Largest counter used by `actor` anywhere in this file (0 if none).
    /// Local writes bump the actor state to at least this value so a lost
    /// state file can never re-issue a counter.
    #[must_use]
    pub fn max_counter_of(&self, actor: &str) -> u64 {
        self.entries
            .values()
            .flatten()
            .filter(|op| op.id.actor == actor)
            .map(|op| op.id.counter)
            .max()
            .unwrap_or(0)
    }

    /// The largest HLC in the file (observed before issuing new timestamps).
    #[must_use]
    pub fn max_hlc(&self) -> Hlc {
        self.entries
            .values()
            .flatten()
            .map(|op| op.changed_at)
            .fold(Hlc::zero(), Hlc::max)
    }

    /// Whether two files are replicas of the same vault (same identity and
    /// key material). Independent vaults never merge.
    #[must_use]
    pub fn same_origin_as(&self, other: &Self) -> bool {
        self.vault_id == other.vault_id
            && self.kdf == other.kdf
            && self.wrapped_dk == other.wrapped_dk
    }

    /// Append a put operation: encrypts the full snapshot under the DK with
    /// the op header and entry position bound as AAD, and records the
    /// metadata projection. The entry position comes from the snapshot
    /// itself.
    ///
    /// # Errors
    ///
    /// Returns an error on encryption failure.
    pub fn append_put(
        &mut self,
        snapshot: &SnapshotPlain,
        id: OpId,
        parents: Vec<OpId>,
        changed_at: Hlc,
        dk: &[u8; DK_LEN],
    ) -> Result<(), CoreError> {
        let meta = EntryMeta {
            tags: snapshot.tags.clone(),
            field_names: snapshot.fields.keys().cloned().collect(),
            created_at: snapshot.created_at,
            updated_at: snapshot.updated_at,
        };
        let mut op = Op {
            id,
            parents,
            kind: OpKind::Put,
            changed_at,
            meta: Some(meta),
            blob: None,
        };
        let ck = Self::compound_key(&snapshot.service, &snapshot.key);
        op.blob = Some(crate::vault_v3::aead_encrypt_b64(
            dk,
            &snapshot.canonical_bytes(),
            &op_aad_bytes(&ck, &op),
        )?);
        self.entries.entry(ck).or_default().push(op);
        Ok(())
    }

    /// Append a delete (tombstone) operation.
    pub fn append_delete(
        &mut self,
        service: &str,
        key: &str,
        id: OpId,
        parents: Vec<OpId>,
        changed_at: Hlc,
    ) {
        let op = Op {
            id,
            parents,
            kind: OpKind::Delete,
            changed_at,
            meta: None,
            blob: None,
        };
        self.entries
            .entry(Self::compound_key(service, key))
            .or_default()
            .push(op);
    }

    /// Decrypt the snapshot of a specific put op at one entry position.
    /// Verifies the AAD binding and that the metadata projection matches
    /// the decrypted snapshot.
    ///
    /// Returns `None` when the op has no blob (delete or pruned put).
    ///
    /// # Errors
    ///
    /// Returns an error when decryption fails or the projection disagrees
    /// with the snapshot (tampered metadata).
    pub fn decrypt_op_at(
        &self,
        dk: &[u8; DK_LEN],
        entry: &str,
        op: &Op,
    ) -> Result<Option<SnapshotPlain>, CoreError> {
        let Some(blob) = &op.blob else {
            return Ok(None);
        };
        let plain = crate::vault_v3::aead_decrypt_b64(dk, blob, &op_aad_bytes(entry, op))?;
        let snapshot: SnapshotPlain = serde_json::from_slice(&plain)
            .map_err(|e| CoreError::Serialization(format!("parsing decrypted snapshot: {e}")))?;
        if Self::compound_key(&snapshot.service, &snapshot.key) != entry {
            return Err(CoreError::Secret(format!(
                "snapshot identity mismatch for op {} (expected '{entry}')",
                op.id
            )));
        }
        if let Some(meta) = &op.meta {
            let field_names: Vec<&String> = snapshot.fields.keys().collect();
            let meta_names: Vec<&String> = meta.field_names.iter().collect();
            if meta_names != field_names
                || meta.tags != snapshot.tags
                || meta.created_at != snapshot.created_at
                || meta.updated_at != snapshot.updated_at
            {
                return Err(CoreError::Secret(format!(
                    "metadata projection mismatch for op {} (tampered header)",
                    op.id
                )));
            }
        }
        Ok(Some(snapshot))
    }

    /// Decrypt the snapshot of a specific put op of one entry.
    ///
    /// Returns `None` when the op has no blob (delete or pruned put).
    ///
    /// # Errors
    ///
    /// See [`Self::decrypt_op_at`].
    pub fn decrypt_op(
        &self,
        dk: &[u8; DK_LEN],
        service: &str,
        key: &str,
        op: &Op,
    ) -> Result<Option<SnapshotPlain>, CoreError> {
        self.decrypt_op_at(dk, &Self::compound_key(service, key), op)
    }

    /// Decrypt the currently-winning snapshot of an entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the entry is hidden, the winner blob was
    /// pruned, or decryption fails.
    pub fn decrypt_current(
        &self,
        dk: &[u8; DK_LEN],
        service: &str,
        key: &str,
    ) -> Result<SnapshotPlain, CoreError> {
        let ops = self.ops(service, key).ok_or_else(|| {
            CoreError::SecretNotFound(format!("secret '{key}' not found in service '{service}'"))
        })?;
        match project(ops)? {
            Projection::Hidden => Err(CoreError::SecretNotFound(format!(
                "secret '{key}' not found in service '{service}'"
            ))),
            Projection::Visible { current, .. } => {
                let op = ops
                    .iter()
                    .find(|op| op.id == current)
                    .ok_or_else(|| CoreError::Secret(format!("op {current} missing")))?;
                self.decrypt_op(dk, service, key, op)?.ok_or_else(|| {
                    CoreError::Secret(format!(
                        "current snapshot of '{service}/{key}' has no ciphertext (pruned)"
                    ))
                })
            }
        }
    }

    /// Frontier ids of one entry (`None` when the entry has no ops).
    ///
    /// # Errors
    ///
    /// Returns an error on graph violations.
    pub fn frontier_of(
        &self,
        service: &str,
        key: &str,
    ) -> Result<Option<BTreeSet<OpId>>, CoreError> {
        self.ops(service, key)
            .map_or(Ok(None), |ops| frontier(ops).map(Some))
    }

    /// Visible-entry metadata projections (list without secret values).
    /// Order follows the entry map (service/key sort).
    ///
    /// # Errors
    ///
    /// Returns an error on graph violations.
    pub fn visible_metas(&self) -> Result<Vec<(String, EntryMeta)>, CoreError> {
        let mut out = Vec::new();
        for (ck, ops) in &self.entries {
            if let Projection::Visible { current, .. } = project(ops)?
                && let Some(op) = ops.iter().find(|op| op.id == current)
                && let Some(meta) = &op.meta
            {
                out.push((ck.clone(), meta.clone()));
            }
        }
        Ok(out)
    }
}

/// Role of an operation in the history listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HistoryRole {
    /// The currently winning snapshot.
    Current,
    /// A concurrent loser; full snapshot preserved, rollback-able.
    Conflict,
    /// Causally superseded ancestor snapshot.
    Ancestor,
    /// A delete tombstone.
    Tombstone,
}

/// One history item, identified by its stable op id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryItem {
    /// Stable operation id.
    pub op_id: OpId,
    /// HLC timestamp of the write.
    pub changed_at: Hlc,
    /// Put or delete.
    pub kind: OpKind,
    /// Current / conflict / ancestor / tombstone.
    pub role: HistoryRole,
    /// Field names at snapshot time.
    pub field_names: Vec<String>,
    /// Tags at snapshot time.
    pub tags: BTreeSet<String>,
    /// Whether the snapshot ciphertext is still present (rollback-able).
    pub has_blob: bool,
}

/// Derive the history view for one entry.
///
/// Every operation is listed newest first by `(changed_at, id)`, with the
/// winning frontier put marked current, other frontier puts marked
/// conflict, dominated puts marked ancestor, and deletes marked tombstone.
///
/// # Errors
///
/// Returns an error on graph violations.
pub fn history(ops: &[Op]) -> Result<Vec<HistoryItem>, CoreError> {
    if ops.is_empty() {
        return Ok(Vec::new());
    }
    let frontier_ids = frontier(ops)?;
    // Winner among frontier puts: greatest (changed_at, id).
    let winner: Option<OpId> = winner_put(
        ops.iter()
            .filter(|op| op.kind == OpKind::Put && frontier_ids.contains(&op.id)),
    )
    .map(|op| op.id.clone());
    let mut items: Vec<HistoryItem> = ops
        .iter()
        .map(|op| {
            let role = match op.kind {
                OpKind::Delete => HistoryRole::Tombstone,
                OpKind::Put if Some(&op.id) == winner.as_ref() => HistoryRole::Current,
                OpKind::Put if frontier_ids.contains(&op.id) => HistoryRole::Conflict,
                OpKind::Put => HistoryRole::Ancestor,
            };
            HistoryItem {
                op_id: op.id.clone(),
                changed_at: op.changed_at,
                kind: op.kind,
                role,
                field_names: op
                    .meta
                    .as_ref()
                    .map_or_else(Vec::new, |m| m.field_names.clone()),
                tags: op
                    .meta
                    .as_ref()
                    .map_or_else(BTreeSet::new, |m| m.tags.clone()),
                has_blob: op.blob.is_some(),
            }
        })
        .collect();
    items.sort_by(|a, b| (b.changed_at, &b.op_id).cmp(&(a.changed_at, &a.op_id)));
    Ok(items)
}

/// Per-entry conflict reported by a merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryConflict {
    /// `service/key` of the conflicted entry.
    pub entry: String,
    /// Winner op id (deterministic).
    pub kept: OpId,
    /// Winner snapshot `updated_at` (display).
    pub kept_updated_at: u64,
    /// Losing concurrent versions, visible in history.
    pub losing: Vec<OpId>,
}

/// Structured merge report. Never contains secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeReport {
    /// Operations copied from the source.
    pub ops_added: usize,
    /// Source ops whose id was already present in the target.
    pub ops_already_present: usize,
    /// Entries that became visible and were not before.
    pub new_entries: Vec<String>,
    /// Entries present in the source only as pre-v4 (legacy) operations
    /// and entirely absent from the target. v3-era deletions leave no
    /// tombstone, so these may be secrets that were deleted before one of
    /// the two sides migrated — indistinguishable from post-fork v3
    /// creations. Callers must gate the write on this list (the CLI asks
    /// for `--yes`).
    pub legacy_resurrections: Vec<String>,
    /// Entries whose winning snapshot changed.
    pub updated_entries: Vec<String>,
    /// Entries that were visible and are now hidden (delete won).
    pub deleted_entries: Vec<String>,
    /// Entries with concurrent losing versions after the merge.
    pub conflicts: Vec<EntryConflict>,
    /// SHA-256 hex digest of the verified source file bytes.
    pub source_digest: String,
    /// Source vault id.
    pub source_vault_id: String,
    /// Total operations in the source file.
    pub source_ops: usize,
    /// Whether the merged file differs from the target (would be written).
    pub changed: bool,
}

fn projection_states(file: &VaultFileV4) -> Result<BTreeMap<String, Projection>, CoreError> {
    let mut out = BTreeMap::new();
    for (ck, ops) in &file.entries {
        out.insert(ck.clone(), project(ops)?);
    }
    Ok(out)
}

/// Gate for merges: `source` must be a replica of `target` (same identity
/// and key material); independent vaults can never merge.
///
/// # Errors
///
/// Returns an error naming both vault ids when the origins differ.
pub(crate) fn ensure_same_origin(
    target: &VaultFileV4,
    source: &VaultFileV4,
) -> Result<(), CoreError> {
    if !target.same_origin_as(source) {
        return Err(CoreError::Secret(format!(
            "source vault {} is not a replica of target vault {} (independent vaults cannot be merged)",
            source.vault_id, target.vault_id
        )));
    }
    Ok(())
}

/// Merge the union of `source` operations into `target` in place.
///
/// Verification is the caller's job: both files must already be
/// structurally valid and MAC-verified. This function checks same-origin,
/// unions the operation logs and canonicalizes the target so pruning and
/// ordering are applied deterministically. The MAC is not recomputed here.
///
/// Duplicate op ids are expected from independent migrations of the same
/// pre-v4 data: headers must match exactly, and differing ciphertexts
/// must decrypt to identical plaintexts (nonce-independent equality);
/// otherwise the input is rejected. The surviving ciphertext variant is
/// chosen bytewise-smallest so every replica converges on the same bytes.
///
/// # Errors
///
/// Returns an error when the files are not replicas of the same vault, a
/// blob cannot be decrypted under `dk`, or an op id arrives with genuinely
/// different content.
pub fn merge_ops(
    target: &mut VaultFileV4,
    source: &VaultFileV4,
    dk: &[u8; DK_LEN],
) -> Result<MergeReport, CoreError> {
    ensure_same_origin(target, source)?;
    let before = projection_states(target)?;
    let before_file = target.clone();

    // Candidate v3-era resurrections: entries the target has never seen,
    // contributed exclusively by legacy (pre-migration) operations. The
    // target side of a legacy entry can only be absent when this side
    // deleted it in v3 (no tombstone) or never had it — undecidable from
    // the data, so it is reported for the caller to gate on.
    let legacy_actor = legacy_actor_id(&target.vault_id);
    let mut legacy_resurrections: Vec<String> = Vec::new();

    let mut ops_added = 0usize;
    let mut ops_already_present = 0usize;
    let mut source_ops = 0usize;
    for (ck, src_ops) in &source.entries {
        source_ops += src_ops.len();
        if !target.entries.contains_key(ck) && src_ops.iter().all(|op| op.id.actor == legacy_actor)
        {
            legacy_resurrections.push(ck.clone());
        }
        let dst = target.entries.entry(ck.clone()).or_default();
        // Position index so duplicate detection is a lookup instead of a
        // linear scan over the target log per source op; appended ops
        // extend it in place.
        let mut positions: BTreeMap<OpId, usize> = dst
            .iter()
            .enumerate()
            .map(|(i, op)| (op.id.clone(), i))
            .collect();
        for src in src_ops {
            if let Some(&pos) = positions.get(&src.id) {
                let existing = &mut dst[pos];
                if !existing.header_eq(src) {
                    return Err(CoreError::Secret(format!(
                        "op {} arrived twice with different headers in entry '{ck}'",
                        src.id
                    )));
                }
                match (&existing.blob, &src.blob) {
                    (Some(a), Some(b)) if a != b => {
                        // Same id and headers, different ciphertext: both
                        // must decrypt to the same plaintext (independent
                        // nonces) or the input is hostile.
                        let aad = op_aad_bytes(ck, existing);
                        let plain_a = crate::vault_v3::aead_decrypt_b64(dk, a, &aad)?;
                        let plain_b = crate::vault_v3::aead_decrypt_b64(dk, b, &aad)?;
                        if plain_a != plain_b {
                            return Err(CoreError::Secret(format!(
                                "op {} arrived twice with different content in entry '{ck}'",
                                src.id
                            )));
                        }
                        if b < a {
                            existing.blob.clone_from(&src.blob);
                        }
                    }
                    (None, Some(b)) => {
                        // Restore a pruned variant; still refuse inputs
                        // that cannot be decrypted under the session DK.
                        let aad = op_aad_bytes(ck, existing);
                        crate::vault_v3::aead_decrypt_b64(dk, b, &aad)?;
                        existing.blob.clone_from(&src.blob);
                    }
                    _ => {}
                }
                ops_already_present += 1;
            } else {
                positions.insert(src.id.clone(), dst.len());
                dst.push(src.clone());
                ops_added += 1;
            }
        }
    }

    target.canonicalize()?;
    let after = projection_states(target)?;
    // The write decision cannot rely on `ops_added` alone: a re-delivered
    // op can still change bytes (e.g. restoring a blob variant an earlier
    // canonicalization pruned on another replica).
    let changed = {
        let mut before_body = before_file;
        before_body.mac = String::new();
        let mut after_body = target.clone();
        after_body.mac = String::new();
        before_body != after_body
    };

    let report = build_merge_report(
        target,
        &before,
        &after,
        MergeReport {
            ops_added,
            ops_already_present,
            new_entries: Vec::new(),
            legacy_resurrections,
            updated_entries: Vec::new(),
            deleted_entries: Vec::new(),
            conflicts: Vec::new(),
            source_digest: String::new(),
            source_vault_id: source.vault_id.clone(),
            source_ops,
            changed,
        },
    );
    Ok(report)
}

/// Diff the pre/post projections of a merged target and fill in the
/// per-entry sections of the report.
fn build_merge_report(
    target: &VaultFileV4,
    before: &BTreeMap<String, Projection>,
    after: &BTreeMap<String, Projection>,
    mut report: MergeReport,
) -> MergeReport {
    let mut all_keys: BTreeSet<String> = before.keys().cloned().collect();
    all_keys.extend(after.keys().cloned());
    for ck in &all_keys {
        let prior = before.get(ck).cloned();
        let post = after.get(ck);
        match (prior, post) {
            (
                Some(Projection::Visible { current: old, .. }),
                Some(Projection::Visible { current: new, .. }),
            ) => {
                if old != *new {
                    report.updated_entries.push(ck.clone());
                }
            }
            (None | Some(Projection::Hidden), Some(Projection::Visible { .. })) => {
                report.new_entries.push(ck.clone());
            }
            (Some(Projection::Visible { .. }), None | Some(Projection::Hidden)) => {
                report.deleted_entries.push(ck.clone());
            }
            (None | Some(Projection::Hidden), None | Some(Projection::Hidden)) => {}
        }
        if let Some(Projection::Visible { current, conflicts }) = post
            && !conflicts.is_empty()
            && let Some(ops) = target.entries.get(ck)
            && let Some(winner) = ops.iter().find(|op| op.id == *current)
        {
            report.conflicts.push(EntryConflict {
                entry: ck.clone(),
                kept: current.clone(),
                kept_updated_at: winner.meta.as_ref().map_or(0, |m| m.updated_at),
                losing: conflicts.clone(),
            });
        }
    }
    report
}

/// Deterministically derive the vault id from the shared key material.
///
/// Both `kdf` params and `wrapped_dk` are identical across replicas of one
/// v3 vault (they never change after creation), so forked v3 copies that
/// migrate independently derive the same v4 identity.
#[must_use]
pub fn derive_vault_id(kdf: &KdfParams, wrapped_dk: &str) -> String {
    let material = format!(
        "{}|{}|{}|{}|{}|{}",
        kdf.algo, kdf.log_n, kdf.r, kdf.p, kdf.salt_b64, wrapped_dk
    );
    let digest = Sha256::digest(material.as_bytes());
    hex::encode(&digest[..VAULT_ID_LEN])
}

/// Length-prefixed canonical encoding used to derive legacy op counters.
/// Locked by fixture tests: any change here invalidates migrated vaults.
fn legacy_feed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Derive the deterministic counter for a legacy snapshot op. Inputs are
/// only pre-migration data: vault id, entry identity, legacy timestamp,
/// the snapshot's position in the oldest→newest chain, and the canonical
/// plaintext snapshot — never the random ciphertext, the migrating
/// machine's actor id, or the migration time.
///
/// The chain position disambiguates two snapshots with identical content
/// and timestamp (e.g. v3 `set A; set B; set A` inside one unix second):
/// without it they would mint the *same* op id, and canonicalization's
/// `dedup_by` would drop the current version's op, silently projecting
/// the superseded value.
fn legacy_op_counter(
    vault_id: &str,
    service: &str,
    key: &str,
    ts: u64,
    occurrence: u64,
    plain: &[u8],
) -> u64 {
    let ts_bytes = ts.to_le_bytes();
    let occ_bytes = occurrence.to_le_bytes();
    let body = legacy_feed(&[
        b"kyz-v4-legacy-op-v2",
        vault_id.as_bytes(),
        service.as_bytes(),
        key.as_bytes(),
        &ts_bytes,
        &occ_bytes,
        plain,
    ]);
    let digest = Sha256::digest(&body);
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(counter)
}

/// Derive the synthetic actor id used by all migrated (legacy) ops of one
/// vault, so they never collide with any real machine's actor id.
fn legacy_actor_id(vault_id: &str) -> String {
    let digest = Sha256::digest(legacy_feed(&[b"kyz-v4-legacy-actor", vault_id.as_bytes()]));
    hex::encode(&digest[..ACTOR_ID_LEN])
}

/// Deterministic HLC for a legacy op: physical time from the legacy
/// timestamp, logical component derived from the stable op id.
fn legacy_hlc(ts: u64, op_id: &OpId) -> Hlc {
    let digest = Sha256::digest(op_id.to_string().as_bytes());
    let mut logical = [0u8; 4];
    logical.copy_from_slice(&digest[..4]);
    Hlc {
        phys: ts,
        logical: u32::from_be_bytes(logical),
    }
}

/// Migrate a decrypted v3 vault into v4.
///
/// Each v3 entry becomes a causal chain of put operations: its history
/// snapshots (oldest → newest) followed by the current snapshot, each
/// parented on the snapshot it was archived in favor of. Operation ids,
/// parents and timestamps are derived deterministically from pre-migration
/// data, so two replicas migrating the same (or a forked) v3 file at
/// different times and on different machines produce identical ids for
/// identical snapshots — common history deduplicates on merge and forked
/// snapshots surface as concurrent conflict versions.
///
/// The `kdf`, `wrapped_dk`, DK and policy flag are preserved; the caller
/// finalizes (MAC) and writes the result.
///
/// # Errors
///
/// Returns an error when a v3 blob cannot be decrypted under `dk` (wrong
/// key or corrupt vault).
pub fn migrate_v3_to_v4(
    v3: &crate::vault_v3::VaultFileV3,
    dk: &[u8; DK_LEN],
) -> Result<VaultFileV4, CoreError> {
    let vault_id = derive_vault_id(&v3.kdf, &v3.wrapped_dk);
    let actor = legacy_actor_id(&vault_id);
    let mut v4 = VaultFileV4::new_unfinalized(&vault_id, v3.kdf.clone(), &v3.wrapped_dk);
    v4.passphrase_policy_checked = v3.passphrase_policy_checked;

    for entry in v3.entries.values() {
        let service = entry.service.as_str();
        let key = entry.key.as_str();

        // Build the causal chain oldest → newest: reversed history then
        // the current snapshot. Each snapshot's parents point at the next
        // newer version (the one that observed it).
        let mut chain: Vec<(SnapshotPlain, u64)> = Vec::with_capacity(entry.history.len() + 1);
        for h in entry.history.iter().rev() {
            let plain =
                crate::vault_v3::aead_decrypt_b64(dk, &h.fields_blob, &[]).map_err(|_| {
                    CoreError::Secret(
                        "v3 blob decrypt failed (wrong key or corrupt vault)".to_string(),
                    )
                })?;
            let fields: BTreeMap<String, String> = serde_json::from_slice(&plain)
                .map_err(|e| CoreError::Serialization(format!("parsing v3 history fields: {e}")))?;
            chain.push((
                SnapshotPlain {
                    service: service.to_string(),
                    key: key.to_string(),
                    fields,
                    // v3 history stores only fields and times; old tags
                    // cannot be recovered and are honestly recorded as
                    // absent rather than guessed from the current entry.
                    tags: BTreeSet::new(),
                    created_at: entry.created_at,
                    updated_at: h.archived_at,
                },
                h.archived_at,
            ));
        }
        let current = crate::vault_v3::decrypt_entry_v3(entry, dk)?;
        chain.push((SnapshotPlain::from_entry(&current), entry.updated_at));

        // Causality: a newer version's writer observed the version it
        // replaced, so each op's parents point at the *older* snapshot it
        // superseded; the oldest snapshot has no parents. The chain
        // position feeds the id derivation so identical (content, ts)
        // snapshots never collide on one op id.
        let mut ids: Vec<OpId> = Vec::with_capacity(chain.len());
        for (idx, (snapshot, ts)) in chain.iter().enumerate() {
            let counter = legacy_op_counter(
                &vault_id,
                service,
                key,
                *ts,
                idx as u64,
                &snapshot.canonical_bytes(),
            );
            ids.push(OpId::new(&actor, counter)?);
        }
        for (idx, (snapshot, ts)) in chain.iter().enumerate() {
            let parents: Vec<OpId> = if idx == 0 {
                Vec::new()
            } else {
                vec![ids[idx - 1].clone()]
            };
            v4.append_put(
                snapshot,
                ids[idx].clone(),
                parents,
                legacy_hlc(*ts, &ids[idx]),
                dk,
            )?;
        }
    }
    Ok(v4)
}

impl VaultFileV4 {
    /// Create a brand new v4 vault with a fresh random DK and vault id.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS RNG or scrypt fails.
    pub fn create(passphrase: &SecretString) -> Result<(Self, Zeroizing<[u8; DK_LEN]>), CoreError> {
        let kdf = KdfParams::with_random_salt()?;
        let kek = crate::vault_v3::derive_kek(passphrase, &kdf)?;
        let dk = crate::vault_v3::generate_dk()?;
        let wrapped_dk = crate::vault_v3::aead_encrypt_b64(&kek, &*dk, &[])?;
        let mut raw = [0u8; VAULT_ID_LEN];
        getrandom::fill(&mut raw)
            .map_err(|e| CoreError::Secret(format!("getrandom vault id: {e}")))?;
        let mut file = Self::new_unfinalized(&hex::encode(raw), kdf, &wrapped_dk);
        file.passphrase_policy_checked = false;
        Ok((file, dk))
    }

    /// Unwrap the data key using the passphrase (one scrypt).
    ///
    /// # Errors
    ///
    /// Returns an error if the passphrase is wrong or the file is corrupt.
    pub fn unwrap_dk(
        &self,
        passphrase: &SecretString,
    ) -> Result<Zeroizing<[u8; DK_LEN]>, CoreError> {
        crate::vault_v3::unwrap_dk_from(&self.kdf, &self.wrapped_dk, passphrase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SecretEntry;
    use crate::vault_v3::{EncryptedEntryV3, HistoryEntryV3, VaultFileV3, encrypt_entry_v3};

    /// Deterministic xorshift64* PRNG so property tests are reproducible.
    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n.max(1) as u64) as usize
        }
        fn chance(&mut self, pct: u64) -> bool {
            self.next_u64() % 100 < pct
        }
    }

    const DK: [u8; DK_LEN] = [7u8; DK_LEN];
    const VAULT: &str = "0123456789abcdef0123456789abcdef";

    fn test_kdf() -> KdfParams {
        KdfParams {
            algo: "scrypt".to_string(),
            log_n: 15,
            r: 8,
            p: 1,
            salt_b64: "c2FsdHNhbHRzYWx0c2FsdA==".to_string(),
        }
    }

    fn test_file() -> VaultFileV4 {
        VaultFileV4::new_unfinalized(VAULT, test_kdf(), "wrapped-dk-placeholder")
    }

    fn snap(service: &str, key: &str, value: &str) -> SnapshotPlain {
        let mut fields = BTreeMap::new();
        fields.insert("value".to_string(), value.to_string());
        SnapshotPlain {
            service: service.to_string(),
            key: key.to_string(),
            fields,
            tags: BTreeSet::new(),
            created_at: 100,
            updated_at: 200,
        }
    }

    fn op_id(actor_num: u8, counter: u64) -> OpId {
        OpId::new(&format!("{actor_num:032x}"), counter).expect("valid actor hex")
    }

    /// Append a put with explicit causal fields (bypasses HLC/actor logic).
    fn put_op(
        file: &mut VaultFileV4,
        service: &str,
        key: &str,
        value: &str,
        id: OpId,
        parents: Vec<OpId>,
        phys: u64,
    ) {
        let mut snapshot = snap(service, key, value);
        snapshot.updated_at = phys;
        file.append_put(&snapshot, id, parents, Hlc { phys, logical: 0 }, &DK)
            .expect("append_put");
    }

    fn delete_op(
        file: &mut VaultFileV4,
        service: &str,
        key: &str,
        id: OpId,
        parents: Vec<OpId>,
        phys: u64,
    ) {
        file.append_delete(service, key, id, parents, Hlc { phys, logical: 0 });
    }

    fn ops_of<'a>(file: &'a VaultFileV4, key: &str) -> &'a [Op] {
        file.ops("svc", key).expect("entry present")
    }

    #[test]
    fn op_id_roundtrip_and_validation() {
        let id = OpId::new("0123456789abcdef0123456789abcdef", 42).expect("valid");
        assert_eq!(OpId::parse(&id.to_string()).expect("parse"), id);
        assert!(OpId::new("XYZ", 1).is_err());
        assert!(OpId::new("0123456789ABCDEF0123456789ABCDEF", 1).is_err());
        assert!(OpId::parse("no-counter").is_err());
    }

    #[test]
    fn hlc_tick_is_monotonic_even_with_backward_clock() {
        let a = Hlc::tick(None);
        assert_eq!(a.logical, 0);
        // A previously observed future physical time forces logical ticks.
        let future = Hlc {
            phys: a.phys + 500,
            logical: 3,
        };
        let b = Hlc::tick(Some(future));
        assert_eq!(
            b,
            Hlc {
                phys: a.phys + 500,
                logical: 4
            }
        );
        assert!(b > a);
        let c = Hlc::tick(Some(b));
        assert!(c > b);
    }

    #[test]
    fn frontier_of_linear_chain_is_last_op() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        put_op(
            &mut file,
            "svc",
            "k",
            "v2",
            op_id(1, 2),
            vec![op_id(1, 1)],
            11,
        );
        put_op(
            &mut file,
            "svc",
            "k",
            "v3",
            op_id(1, 3),
            vec![op_id(1, 2)],
            12,
        );
        let f = frontier(ops_of(&file, "k")).expect("frontier");
        assert_eq!(f, BTreeSet::from([op_id(1, 3)]));
    }

    #[test]
    fn frontier_of_diamond_has_two_maxima() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "base", op_id(1, 1), vec![], 10);
        put_op(
            &mut file,
            "svc",
            "k",
            "left",
            op_id(1, 2),
            vec![op_id(1, 1)],
            11,
        );
        put_op(
            &mut file,
            "svc",
            "k",
            "right",
            op_id(2, 1),
            vec![op_id(1, 1)],
            12,
        );
        let f = frontier(ops_of(&file, "k")).expect("frontier");
        assert_eq!(f, BTreeSet::from([op_id(1, 2), op_id(2, 1)]));
    }

    #[test]
    fn cycle_is_detected() {
        // Two ops parenting each other.
        let ops = vec![
            Op {
                id: op_id(1, 1),
                parents: vec![op_id(1, 2)],
                kind: OpKind::Put,
                changed_at: Hlc::zero(),
                meta: None,
                blob: None,
            },
            Op {
                id: op_id(1, 2),
                parents: vec![op_id(1, 1)],
                kind: OpKind::Put,
                changed_at: Hlc::zero(),
                meta: None,
                blob: None,
            },
        ];
        assert!(frontier(&ops).is_err());
    }

    #[test]
    fn unresolvable_parent_is_rejected() {
        let ops = vec![Op {
            id: op_id(1, 1),
            parents: vec![op_id(9, 9)],
            kind: OpKind::Put,
            changed_at: Hlc::zero(),
            meta: None,
            blob: None,
        }];
        assert!(frontier(&ops).is_err());
    }

    #[test]
    fn concurrent_delete_wins_over_newer_put() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        // Concurrent: machine 2 never observed v1; its put is NEWER by HLC.
        put_op(&mut file, "svc", "k", "v2", op_id(2, 1), vec![], 20);
        delete_op(&mut file, "svc", "k", op_id(3, 1), vec![], 19);
        assert_eq!(
            file.projection("svc", "k").expect("proj"),
            Projection::Hidden
        );
    }

    #[test]
    fn concurrent_puts_keep_both_versions_with_deterministic_winner() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "older", op_id(1, 1), vec![], 10);
        put_op(&mut file, "svc", "k", "newer", op_id(2, 1), vec![], 20);
        // Winner: greater (changed_at, id).
        assert_eq!(
            file.projection("svc", "k").expect("proj"),
            Projection::Visible {
                current: op_id(2, 1),
                conflicts: vec![op_id(1, 1)]
            }
        );
        // HLC tie: greater id wins.
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "a", op_id(1, 1), vec![], 10);
        put_op(&mut file, "svc", "k", "b", op_id(2, 1), vec![], 10);
        assert_eq!(
            file.projection("svc", "k").expect("proj"),
            Projection::Visible {
                current: op_id(2, 1),
                conflicts: vec![op_id(1, 1)]
            }
        );
    }

    #[test]
    fn put_observing_delete_revives_entry() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        delete_op(&mut file, "svc", "k", op_id(2, 1), vec![op_id(1, 1)], 11);
        assert_eq!(
            file.projection("svc", "k").expect("proj"),
            Projection::Hidden
        );
        // Explicit re-create: observed the delete, so causally later.
        put_op(
            &mut file,
            "svc",
            "k",
            "v2",
            op_id(1, 2),
            vec![op_id(2, 1)],
            12,
        );
        assert_eq!(
            file.projection("svc", "k").expect("proj"),
            Projection::Visible {
                current: op_id(1, 2),
                conflicts: vec![]
            }
        );
    }

    #[test]
    fn delete_observed_then_merged_remote_delete_still_wins() {
        // Machine A deletes, then re-creates without seeing machine B's
        // concurrent delete: after merging B, the delete wins again.
        let mut a = test_file();
        put_op(&mut a, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        delete_op(&mut a, "svc", "k", op_id(1, 2), vec![op_id(1, 1)], 11);
        put_op(&mut a, "svc", "k", "v2", op_id(1, 3), vec![op_id(1, 2)], 12);

        let mut b = test_file();
        put_op(&mut b, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        delete_op(&mut b, "svc", "k", op_id(2, 1), vec![op_id(1, 1)], 11);

        merge_ops(&mut a, &b, &DK).expect("merge");
        assert_eq!(a.projection("svc", "k").expect("proj"), Projection::Hidden);
    }

    #[test]
    fn canonicalize_prunes_only_puts_a_delete_causally_supersedes() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        delete_op(&mut file, "svc", "k", op_id(2, 1), vec![op_id(1, 1)], 11);
        put_op(
            &mut file,
            "svc",
            "k",
            "v2",
            op_id(1, 2),
            vec![op_id(2, 1)],
            12,
        );
        file.canonicalize().expect("canonicalize");

        let ops = ops_of(&file, "k");
        let v1 = ops.iter().find(|o| o.id == op_id(1, 1)).expect("v1");
        let del = ops.iter().find(|o| o.id == op_id(2, 1)).expect("delete");
        let v2 = ops.iter().find(|o| o.id == op_id(1, 2)).expect("v2");
        // v1's blob pruned (the delete observed it); header kept.
        assert!(v1.blob.is_none());
        assert_eq!(v1.kind, OpKind::Put);
        // The delete header stays forever.
        assert_eq!(del.kind, OpKind::Delete);
        // The explicit rebuild observed the delete: blob kept.
        assert!(v2.blob.is_some());
    }

    #[test]
    fn canonicalize_keeps_concurrent_put_blobs_across_a_delete() {
        // Regression: a put merely concurrent with a delete must keep its
        // blob. A later put observing the delete un-hides the entry, and
        // the concurrent put may then win the projection — pruning it
        // would lose the plaintext permanently.
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        delete_op(&mut file, "svc", "k", op_id(2, 1), vec![], 19);
        put_op(&mut file, "svc", "k", "conc", op_id(3, 1), vec![], 20);
        file.canonicalize().expect("canonicalize");
        let ops = ops_of(&file, "k");
        // v1 is concurrent with the delete too (parents=[]), so it also
        // keeps its blob under the causal-supersession rule.
        assert!(
            ops.iter()
                .all(|o| o.blob.is_some() || o.kind == OpKind::Delete)
        );

        // The rebuild that observes the delete un-hides the entry; the
        // concurrent put (higher HLC) wins and must stay decryptable.
        put_op(
            &mut file,
            "svc",
            "k",
            "rebuild",
            op_id(1, 2),
            vec![op_id(2, 1)],
            12,
        );
        file.canonicalize().expect("canonicalize");
        let Projection::Visible { current, .. } = file.projection("svc", "k").expect("proj") else {
            panic!("entry must be visible after the rebuild");
        };
        assert_eq!(current, op_id(3, 1), "concurrent put with higher HLC wins");
        let snapshot = file.decrypt_current(&DK, "svc", "k").expect("decrypt");
        assert_eq!(
            snapshot.fields.get("value").map(String::as_str),
            Some("conc")
        );
    }

    #[test]
    fn merge_keeps_forked_put_blob_across_delete_and_rebuild() {
        // The exact data-loss shape from review: A writes P1, deletes it,
        // and rebuilds after observing the delete; B forked before the
        // delete and writes P3 on top of P1 with a later HLC. After the
        // merge the frontier is {P2, P3} with no delete, so P3 wins — its
        // blob must have survived A's canonicalization despite A's delete.
        let mut a = test_file();
        put_op(&mut a, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        delete_op(&mut a, "svc", "k", op_id(1, 2), vec![op_id(1, 1)], 11);
        put_op(
            &mut a,
            "svc",
            "k",
            "rebuild",
            op_id(1, 3),
            vec![op_id(1, 2)],
            12,
        );
        a.canonicalize().expect("canonicalize a");

        let mut b = test_file();
        put_op(&mut b, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        put_op(
            &mut b,
            "svc",
            "k",
            "fork-write",
            op_id(2, 1),
            vec![op_id(1, 1)],
            30,
        );
        b.canonicalize().expect("canonicalize b");

        merge_ops(&mut a, &b, &DK).expect("merge");
        let Projection::Visible { current, .. } = a.projection("svc", "k").expect("proj") else {
            panic!("entry must be visible: the rebuild dominates the delete");
        };
        assert_eq!(current, op_id(2, 1), "fork write with later HLC wins");
        let snapshot = a.decrypt_current(&DK, "svc", "k").expect("decrypt");
        assert_eq!(
            snapshot.fields.get("value").map(String::as_str),
            Some("fork-write")
        );
    }

    #[test]
    fn canonicalize_sorts_ops_and_parents() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(2, 5), vec![], 10);
        put_op(&mut file, "svc", "k", "v2", op_id(1, 1), vec![], 10);
        // Reverse-sorted parents.
        put_op(
            &mut file,
            "svc",
            "k",
            "v3",
            op_id(1, 2),
            vec![op_id(2, 5), op_id(1, 1)],
            11,
        );
        file.canonicalize().expect("canonicalize");
        let ops = ops_of(&file, "k");
        assert!(ops.windows(2).all(|w| w[0].id < w[1].id));
        let v3_op = ops.iter().find(|o| o.id == op_id(1, 2)).expect("v3");
        assert_eq!(v3_op.parents, vec![op_id(1, 1), op_id(2, 5)]);
    }

    #[test]
    fn validation_rejects_duplicate_id_with_different_content() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        let mut evil = file.clone();
        put_op(&mut evil, "svc", "k", "DIFFERENT", op_id(1, 1), vec![], 10);
        assert!(evil.validate_structure().is_err());
        // Identical duplicate is tolerated (dedup happens on canonicalize/merge).
        let dup = file.entries.get("svc/k").expect("entry")[0].clone();
        file.entries.get_mut("svc/k").expect("entry").push(dup);
        assert!(file.validate_structure().is_ok());
    }

    #[test]
    fn put_decrypt_roundtrip_and_meta_consistency() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "hunter2", op_id(1, 1), vec![], 10);
        let snapshot = file.decrypt_current(&DK, "svc", "k").expect("decrypt");
        assert_eq!(
            snapshot.fields.get("value").map(String::as_str),
            Some("hunter2")
        );

        // Tampered metadata projection must be caught on decrypt.
        let mut evil = file.clone();
        evil.entries.get_mut("svc/k").expect("entry")[0]
            .meta
            .as_mut()
            .expect("meta")
            .field_names
            .push("injected".to_string());
        assert!(evil.decrypt_current(&DK, "svc", "k").is_err());
    }

    #[test]
    fn aad_rejects_moved_blob() {
        // A blob decrypted under a different header (here: different key name)
        // must fail: service/key is bound as AAD.
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "secret", op_id(1, 1), vec![], 10);
        let mut moved = file.clone();
        let op = moved.entries.get_mut("svc/k").expect("entry").remove(0);
        moved.entries.insert("svc/other".to_string(), vec![op]);
        assert!(moved.validate_structure().is_ok());
        assert!(moved.decrypt_current(&DK, "svc", "other").is_err());
    }

    #[test]
    fn mac_covers_headers_and_ciphertext() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        file.finalize(&DK).expect("finalize");
        assert!(file.verify_mac(&DK).is_ok());

        // Wrong DK fails.
        let wrong = [9u8; DK_LEN];
        assert!(file.verify_mac(&wrong).is_err());

        // Tamper: tags in the metadata projection.
        let mut evil = file.clone();
        evil.entries.get_mut("svc/k").expect("entry")[0]
            .meta
            .as_mut()
            .expect("meta")
            .tags
            .insert("t".to_string());
        assert!(evil.verify_mac(&DK).is_err());

        // Tamper: blob ciphertext.
        let mut evil = file.clone();
        let blob = evil.entries.get_mut("svc/k").expect("entry")[0]
            .blob
            .as_mut()
            .expect("blob");
        blob.insert(0, 'A');
        assert!(evil.verify_mac(&DK).is_err());

        // Tamper: parents.
        let mut evil = file.clone();
        evil.entries.get_mut("svc/k").expect("entry")[0]
            .parents
            .push(op_id(9, 9));
        assert!(evil.verify_mac(&DK).is_err());

        // Tamper: HLC.
        let mut evil = file.clone();
        evil.entries.get_mut("svc/k").expect("entry")[0]
            .changed_at
            .phys += 1;
        assert!(evil.verify_mac(&DK).is_err());
    }

    #[test]
    fn mac_body_matches_legacy_clone_serialization() {
        // The borrowed `MacBody` mirror must serialize byte-identically to
        // the old clone-and-clear-mac approach; any field-order or type
        // drift here would invalidate every existing on-disk MAC.
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        put_op(&mut file, "svc", "other", "v2", op_id(2, 1), vec![], 12);
        delete_op(&mut file, "svc", "k", op_id(3, 1), vec![op_id(1, 1)], 13);
        file.canonicalize().expect("canonicalize");

        let mut legacy = file.clone();
        legacy.mac = String::new();
        let legacy_bytes = serde_json::to_vec(&legacy).expect("legacy serialize");
        assert_eq!(file.mac_body_bytes().expect("mac body"), legacy_bytes);
    }

    #[test]
    fn parse_rejects_bad_versions_and_ids() {
        let mut file = test_file();
        file.finalize(&DK).expect("finalize");
        let bytes = file.canonical_bytes().expect("bytes");
        let parsed = VaultFileV4::parse(&bytes).expect("parse");
        assert_eq!(parsed, file);

        let mut bad = file.clone();
        bad.version = 3;
        assert!(VaultFileV4::parse(&bad.canonical_bytes().expect("bytes")).is_err());

        let mut bad = file.clone();
        bad.vault_id = "nothex".to_string();
        assert!(VaultFileV4::parse(&bad.canonical_bytes().expect("bytes")).is_err());
    }

    fn finalized_bytes(file: &mut VaultFileV4) -> Vec<u8> {
        file.finalize(&DK).expect("finalize");
        file.canonical_bytes().expect("bytes")
    }

    #[test]
    fn merge_is_commutative_idempotent_and_byte_stable() {
        let mut a = test_file();
        put_op(&mut a, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        put_op(&mut a, "svc", "k", "a2", op_id(1, 2), vec![op_id(1, 1)], 11);

        let mut b = test_file();
        put_op(&mut b, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        put_op(&mut b, "svc", "k", "b2", op_id(2, 7), vec![op_id(1, 1)], 12);
        put_op(&mut b, "svc", "other", "x", op_id(2, 8), vec![], 12);

        let mut ab = a.clone();
        let report = merge_ops(&mut ab, &b, &DK).expect("merge");
        assert_eq!(report.ops_added, 2);
        assert_eq!(report.updated_entries, vec!["svc/k".to_string()]);
        assert_eq!(report.new_entries, vec!["svc/other".to_string()]);
        assert_eq!(report.conflicts.len(), 1);
        assert!(report.changed);

        let mut ba = b.clone();
        merge_ops(&mut ba, &a, &DK).expect("merge");

        // Commutativity: identical canonical bytes.
        assert_eq!(finalized_bytes(&mut ab), finalized_bytes(&mut ba));

        // Idempotency: re-merging adds nothing and reports no change.
        let report2 = merge_ops(&mut ab, &b, &DK).expect("merge");
        assert_eq!(report2.ops_added, 0);
        assert_eq!(report2.ops_already_present, 3);
        assert!(!report2.changed);
        let bytes_before = ab.canonical_bytes().expect("bytes");
        merge_ops(&mut ab, &b, &DK).expect("merge");
        assert_eq!(ab.canonical_bytes().expect("bytes"), bytes_before);
    }

    #[test]
    fn merge_is_associative() {
        let mut a = test_file();
        put_op(&mut a, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        let mut b = test_file();
        put_op(&mut b, "svc", "k", "v2", op_id(2, 1), vec![], 10);
        let mut c = test_file();
        put_op(&mut c, "svc", "k", "v3", op_id(3, 1), vec![], 10);

        let mut left = a.clone();
        merge_ops(&mut left, &b, &DK).expect("merge");
        merge_ops(&mut left, &c, &DK).expect("merge");

        let mut right = c.clone();
        merge_ops(&mut right, &b, &DK).expect("merge");
        merge_ops(&mut right, &a, &DK).expect("merge");

        assert_eq!(finalized_bytes(&mut left), finalized_bytes(&mut right));
    }

    #[test]
    fn merge_rejects_independent_vaults_and_duplicate_id_conflicts() {
        let mut a = test_file();
        put_op(&mut a, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        let mut other = test_file();
        other.vault_id = "ffffffffffffffffffffffffffffffff".to_string();
        put_op(&mut other, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        assert!(merge_ops(&mut a, &other, &DK).is_err());

        let mut b = test_file();
        put_op(
            &mut b,
            "svc",
            "k",
            "SAME-ID-DIFFERENT-SNAPSHOT",
            op_id(1, 1),
            vec![],
            10,
        );
        assert!(merge_ops(&mut a, &b, &DK).is_err());
    }

    #[test]
    fn merge_prefers_blobful_variant_and_converges() {
        // Two replicas migrated from the same data carry equal headers but
        // independent random nonces: merge keeps one deterministically.
        let mut a = test_file();
        put_op(&mut a, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        let mut b = test_file();
        put_op(&mut b, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        assert_ne!(
            ops_of(&a, "k")[0].blob,
            ops_of(&b, "k")[0].blob,
            "random nonces should differ"
        );

        let mut ab = a.clone();
        merge_ops(&mut ab, &b, &DK).expect("merge");
        let mut ba = b.clone();
        merge_ops(&mut ba, &a, &DK).expect("merge");
        assert_eq!(finalized_bytes(&mut ab), finalized_bytes(&mut ba));
    }

    /// Build one master op DAG for an entry, then split it into three
    /// replica files (assignment + parent closure so each file is valid).
    fn random_replicas(seed: u64) -> Vec<VaultFileV4> {
        let mut rng = Rng::new(seed);
        let actors: [u8; 3] = [1, 2, 3];
        let mut counters: BTreeMap<u8, u64> = BTreeMap::new();
        let mut master = test_file();
        let mut created: Vec<OpId> = Vec::new();
        let op_count = 6 + rng.below(10);

        for step in 0..op_count {
            let actor = actors[rng.below(3)];
            let counter = counters.entry(actor).or_insert(0);
            *counter += 1;
            let id = op_id(actor, *counter);
            // Parents: mostly the current frontier, occasionally a subset
            // (creating concurrency), occasionally nothing.
            let parents: Vec<OpId> = if created.is_empty() || rng.chance(15) {
                vec![]
            } else if rng.chance(70) {
                frontier(&master.entries["svc/k"])
                    .unwrap_or_default()
                    .into_iter()
                    .collect()
            } else {
                created.iter().filter(|_| rng.chance(30)).cloned().collect()
            };
            let phys = 1000 + step as u64;
            if rng.chance(25) {
                master.append_delete("svc", "k", id.clone(), parents, Hlc { phys, logical: 0 });
            } else {
                let mut s = snap("svc", "k", &format!("v{step}"));
                s.updated_at = phys;
                master
                    .append_put(
                        &s,
                        id.clone(),
                        parents,
                        Hlc {
                            phys,
                            logical: rng.below(4) as u32,
                        },
                        &DK,
                    )
                    .expect("append");
            }
            created.push(id);
        }

        // Split: each op goes to a random non-empty subset of replicas;
        // then close each replica over missing parents.
        let all_ops = master.entries["svc/k"].clone();
        let mut replicas: Vec<VaultFileV4> = Vec::new();
        for slot in 0..3 {
            let mut file = test_file();
            let mut ids: BTreeSet<OpId> = BTreeSet::new();
            for op in &all_ops {
                if rng.chance(55) || (slot == 0 && op.id == all_ops[0].id) {
                    ids.insert(op.id.clone());
                }
            }
            if ids.is_empty() {
                ids.insert(all_ops[0].id.clone());
            }
            loop {
                let mut added = false;
                for op in &all_ops {
                    if ids.contains(&op.id) {
                        for p in &op.parents {
                            if ids.insert(p.clone()) {
                                added = true;
                            }
                        }
                    }
                }
                if !added {
                    break;
                }
            }
            file.entries.insert(
                "svc/k".to_string(),
                all_ops
                    .iter()
                    .filter(|op| ids.contains(&op.id))
                    .cloned()
                    .collect(),
            );
            replicas.push(file);
        }
        replicas
    }

    #[test]
    fn random_dag_merges_converge_in_any_order() {
        for seed in 1..=40 {
            let replicas = random_replicas(seed);

            // All six merge orders must produce identical canonical bytes
            // and identical projections.
            let orders: [[usize; 3]; 6] = [
                [0, 1, 2],
                [0, 2, 1],
                [1, 0, 2],
                [1, 2, 0],
                [2, 0, 1],
                [2, 1, 0],
            ];
            let mut reference_bytes: Option<Vec<u8>> = None;
            let mut reference_proj: Option<Projection> = None;
            for order in &orders {
                let mut merged = replicas[order[0]].clone();
                merge_ops(&mut merged, &replicas[order[1]], &DK).expect("merge 1");
                merge_ops(&mut merged, &replicas[order[2]], &DK).expect("merge 2");
                let bytes = finalized_bytes(&mut merged);
                let proj = merged.projection("svc", "k").expect("proj");
                if let Some(want) = &reference_bytes {
                    assert_eq!(&bytes, want, "seed {seed}: merge order {order:?} diverged");
                    assert_eq!(&proj, reference_proj.as_ref().expect("proj"), "seed {seed}");
                } else {
                    reference_bytes = Some(bytes);
                    reference_proj = Some(proj);
                }
            }

            // Merging the union into any single replica reports convergence:
            // re-merging everything changes nothing.
            let mut merged = replicas[0].clone();
            merge_ops(&mut merged, &replicas[1], &DK).expect("merge");
            merge_ops(&mut merged, &replicas[2], &DK).expect("merge");
            for source in &replicas {
                let report = merge_ops(&mut merged, source, &DK).expect("re-merge");
                assert!(!report.changed, "seed {seed}: re-merge changed bytes");
            }
            assert!(merged.validate_structure().is_ok());
        }
    }

    #[test]
    fn frontier_tolerates_duplicate_ids_without_underflow() {
        // Two equal-content ops sharing one id plus a child parenting that
        // id: the fast path's edge accounting must not underflow; it bails
        // to the duplicate-tolerant ancestor walk instead.
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        let dup = file.entries["svc/k"][0].clone();
        file.entries.get_mut("svc/k").expect("entry").push(dup);
        assert!(file.validate_structure().is_ok());
        let f = frontier(ops_of(&file, "k")).expect("frontier");
        assert_eq!(f, BTreeSet::from([op_id(1, 1)]));
    }

    #[test]
    fn compound_key_escapes_slashes_in_both_parts() {
        // Service names containing `/` (possible in library-created v3
        // vaults) must round-trip through the compound key and split back
        // to the exact parts — list/list_services and get then agree.
        for (service, key) in [
            ("team/api", "token"),
            ("svc", "path/like/key"),
            ("a/b", "c/d"),
            ("100%", "%2F"),
            ("plain", "plain"),
        ] {
            let ck = VaultFileV4::compound_key(service, key);
            assert_eq!(
                VaultFileV4::split_compound_key(&ck),
                Some((service.to_string(), key.to_string())),
                "roundtrip failed for {service}/{key}"
            );
        }
        assert_eq!(VaultFileV4::split_compound_key("no-service"), None);
    }

    #[test]
    fn entries_with_slash_in_service_survive_migration_and_split() {
        // The v3 entry map is keyed by the raw "service/key" string, but
        // migration reads the structured fields: the escaped v4 compound
        // key must split back to the original service and key.
        let dk = DK;
        let entry =
            encrypt_entry_v3(&SecretEntry::single("team/api", "token", "x"), &dk).expect("enc");
        let mut entries = BTreeMap::new();
        entries.insert("team/api/token".to_string(), entry);
        let v3 = VaultFileV3 {
            version: 3,
            kdf: test_kdf(),
            wrapped_dk: "wrapped-dk-placeholder".to_string(),
            passphrase_policy_checked: true,
            entries,
        };
        let v4 = migrate_v3_to_v4(&v3, &dk).expect("migrate");
        let ck = VaultFileV4::compound_key("team/api", "token");
        assert!(
            v4.entries.contains_key(&ck),
            "entry must live under the escaped key {ck}, got {:?}",
            v4.entries.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            VaultFileV4::split_compound_key(&ck),
            Some(("team/api".to_string(), "token".to_string()))
        );
        assert!(v4.ops("team/api", "token").is_some());
        let snapshot = v4
            .decrypt_current(&dk, "team/api", "token")
            .expect("decrypt");
        assert_eq!(snapshot.fields.get("value").map(String::as_str), Some("x"));
    }

    #[test]
    fn history_marks_current_conflict_ancestor_tombstone() {
        let mut file = test_file();
        put_op(&mut file, "svc", "k", "v1", op_id(1, 1), vec![], 10);
        put_op(
            &mut file,
            "svc",
            "k",
            "v2",
            op_id(1, 2),
            vec![op_id(1, 1)],
            11,
        );
        put_op(&mut file, "svc", "k", "side", op_id(2, 1), vec![], 12);
        delete_op(&mut file, "svc", "k", op_id(3, 1), vec![], 5);
        let items = history(ops_of(&file, "k")).expect("history");
        let by_id = |id: &OpId| items.iter().find(|i| &i.op_id == id).expect("item");
        assert_eq!(by_id(&op_id(2, 1)).role, HistoryRole::Current);
        assert_eq!(by_id(&op_id(1, 2)).role, HistoryRole::Conflict);
        assert_eq!(by_id(&op_id(1, 1)).role, HistoryRole::Ancestor);
        assert_eq!(by_id(&op_id(3, 1)).role, HistoryRole::Tombstone);
        // Newest first.
        assert!(
            items
                .windows(2)
                .all(|w| (w[0].changed_at, &w[0].op_id) > (w[1].changed_at, &w[1].op_id))
        );
    }

    fn v3_with_history() -> (VaultFileV3, [u8; DK_LEN]) {
        let dk = DK;
        let mut entry = encrypt_entry_v3(&SecretEntry::single("svc", "k", "current-value"), &dk)
            .expect("encrypt");
        // v3 stores history newest-first: history[0] is the most recent
        // prior version (archived at 66), history[1] the oldest (55).
        entry.history = vec![
            HistoryEntryV3 {
                version: 2,
                archived_at: 66,
                field_names: vec!["value".to_string()],
                fields_blob: crate::vault_v3::aead_encrypt_b64(
                    &dk,
                    br#"{"value":"mid-value"}"#,
                    &[],
                )
                .expect("wrap"),
            },
            HistoryEntryV3 {
                version: 1,
                archived_at: 55,
                field_names: vec!["value".to_string()],
                fields_blob: crate::vault_v3::aead_encrypt_b64(
                    &dk,
                    br#"{"value":"old-value"}"#,
                    &[],
                )
                .expect("wrap"),
            },
        ];
        let mut entries = BTreeMap::new();
        entries.insert("svc/k".to_string(), entry);
        let mut v3 = VaultFileV3 {
            version: 3,
            kdf: test_kdf(),
            wrapped_dk: "wrapped-dk-placeholder".to_string(),
            passphrase_policy_checked: true,
            entries,
        };
        v3.entries.insert("svc/second".to_string(), {
            let e: EncryptedEntryV3 =
                encrypt_entry_v3(&SecretEntry::single("svc", "second", "x"), &dk).expect("encrypt");
            e
        });
        (v3, dk)
    }

    #[test]
    fn migration_is_deterministic_across_machines_and_times() {
        let (v3, dk) = v3_with_history();
        let first = migrate_v3_to_v4(&v3, &dk).expect("migrate");
        let second = migrate_v3_to_v4(&v3, &dk).expect("migrate again");
        // Identical logical operations (ids, parents, HLCs); blobs use
        // random nonces so compare headers + the ability to decrypt both.
        assert_eq!(first.entries.len(), second.entries.len());
        for (ck, ops) in &first.entries {
            let other = second.entries.get(ck).expect("same entry");
            assert_eq!(ops.len(), other.len());
            for (a, b) in ops.iter().zip(other.iter()) {
                assert!(a.header_eq(b), "entry {ck}: op headers diverged");
                assert_eq!(a.parents, b.parents);
                assert_eq!(a.changed_at, b.changed_at);
            }
        }
        assert_eq!(first.vault_id, second.vault_id);
        // History chain: oldest → current, each parented on the newer one.
        let ops = first.ops("svc", "k").expect("ops");
        assert_eq!(ops.len(), 3);
        let oldest = ops
            .iter()
            .find(|o| o.parents.is_empty())
            .expect("oldest (only the oldest snapshot has no parents)");
        let hist = ops
            .iter()
            .find(|o| !o.parents.is_empty() && o.parents[0] == oldest.id)
            .expect("mid");
        let current = ops
            .iter()
            .find(|o| !o.parents.is_empty() && o.parents[0] == hist.id)
            .expect("current");
        assert_eq!(oldest.changed_at.phys, 55);
        assert_eq!(hist.changed_at.phys, 66);
        assert!(current.blob.is_some());
        // Snapshots decrypt and match the v3 values.
        let dec = first
            .decrypt_op(&dk, "svc", "k", current)
            .expect("decrypt")
            .expect("blob");
        assert_eq!(
            dec.fields.get("value").map(String::as_str),
            Some("current-value")
        );
        let dec = first
            .decrypt_op(&dk, "svc", "k", oldest)
            .expect("d")
            .expect("b");
        assert_eq!(
            dec.fields.get("value").map(String::as_str),
            Some("old-value")
        );
        // Projection picks the current version.
        assert_eq!(
            first.projection("svc", "k").expect("proj"),
            Projection::Visible {
                current: current.id.clone(),
                conflicts: vec![]
            }
        );
    }

    #[test]
    fn migration_same_second_same_content_snapshots_stay_distinct() {
        // Regression: v3 `set A; set B; set A` inside one unix second. The
        // archived first A (history[1], archived_at=T) and the current A
        // (updated_at=T) have identical canonical bytes and timestamps;
        // their op ids must still differ, or canonicalization's dedup
        // drops the current version's op and `kyz get` silently returns
        // the superseded B.
        let dk = DK;
        let mut current = SecretEntry::single("svc", "k", "A");
        current.created_at = 400;
        current.updated_at = 500;
        let mut entry = encrypt_entry_v3(&current, &dk).expect("encrypt");
        entry.history = vec![
            HistoryEntryV3 {
                version: 2,
                archived_at: 500,
                field_names: vec!["value".to_string()],
                fields_blob: crate::vault_v3::aead_encrypt_b64(&dk, br#"{"value":"B"}"#, &[])
                    .expect("wrap B"),
            },
            HistoryEntryV3 {
                version: 1,
                archived_at: 500,
                field_names: vec!["value".to_string()],
                fields_blob: crate::vault_v3::aead_encrypt_b64(&dk, br#"{"value":"A"}"#, &[])
                    .expect("wrap A"),
            },
        ];
        let mut entries = BTreeMap::new();
        entries.insert("svc/k".to_string(), entry);
        let v3 = VaultFileV3 {
            version: 3,
            kdf: test_kdf(),
            wrapped_dk: "wrapped-dk-placeholder".to_string(),
            passphrase_policy_checked: true,
            entries,
        };

        let mut v4 = migrate_v3_to_v4(&v3, &dk).expect("migrate");
        v4.finalize(&dk).expect("finalize");
        v4.validate_structure().expect("valid after canonicalize");

        let ops = v4.ops("svc", "k").expect("ops");
        assert_eq!(ops.len(), 3, "all three snapshots must survive");
        let mut ids: BTreeSet<OpId> = BTreeSet::new();
        for op in ops {
            assert!(ids.insert(op.id.clone()), "duplicate op id {}", op.id);
        }
        let snapshot = v4.decrypt_current(&dk, "svc", "k").expect("decrypt");
        assert_eq!(
            snapshot.fields.get("value").map(String::as_str),
            Some("A"),
            "the current version must win, not the superseded B"
        );
    }

    #[test]
    fn migrated_forks_dedup_history_and_conflict_on_divergence() {
        let (v3, dk) = v3_with_history();

        // Fork: machine B edited the current value before migrating.
        let mut v3_fork = v3.clone();
        let edited = encrypt_entry_v3(&SecretEntry::single("svc", "k", "forked-value"), &dk)
            .expect("encrypt");
        v3_fork.entries.insert("svc/k".to_string(), {
            let mut e = edited;
            e.history = v3.entries["svc/k"].history.clone();
            e
        });

        let mut a = migrate_v3_to_v4(&v3, &dk).expect("migrate a");
        let b = migrate_v3_to_v4(&v3_fork, &dk).expect("migrate b");

        let report = merge_ops(&mut a, &b, &DK).expect("merge");
        // Common history (2 snapshots) deduped; forked currents conflict.
        assert!(report.ops_added >= 1);
        assert!(report.ops_already_present >= 2);
        assert_eq!(report.conflicts.len(), 1);
        let proj = a.projection("svc", "k").expect("proj");
        let Projection::Visible { current, conflicts } = proj else {
            panic!("expected visible");
        };
        assert_eq!(conflicts.len(), 1);
        // Winner is deterministic: higher (changed_at, id).
        let ops = a.ops("svc", "k").expect("ops");
        let winner = ops.iter().find(|o| o.id == current).expect("winner");
        let loser_id = conflicts[0].clone();
        let loser = ops.iter().find(|o| o.id == loser_id).expect("loser");
        assert!(
            (winner.changed_at, &winner.id) > (loser.changed_at, &loser.id),
            "winner must order above loser"
        );
    }

    #[test]
    fn stale_v3_migration_does_not_override_newer_v4_writes() {
        let (v3, dk) = v3_with_history();
        let mut live = migrate_v3_to_v4(&v3, &dk).expect("migrate");
        live.finalize(&dk).expect("finalize");

        // Machine A writes a fresh v4 op on top of the migrated frontier.
        let legacy_frontier = live.frontier_of("svc", "k").expect("f").expect("some");
        let fresh_id = op_id(7, 1);
        put_op(
            &mut live,
            "svc",
            "k",
            "fresh-v4-write",
            fresh_id.clone(),
            legacy_frontier.iter().cloned().collect(),
            9_999_999,
        );
        live.finalize(&dk).expect("finalize");

        // The stale v3 copy migrates much later; its legacy timestamps are
        // all older than the fresh write and it never observed the write.
        // Its ops are all already present (deterministic ids); the first
        // merge may still swap an equivalent ciphertext variant (nonce
        // convergence), so only logical contributions are asserted here.
        let stale = migrate_v3_to_v4(&v3, &dk).expect("stale migrate");
        let report = merge_ops(&mut live, &stale, &dk).expect("merge");
        assert_eq!(
            report.ops_added, 0,
            "stale migration contributes nothing new"
        );
        // Convergence: nothing changes on any further merge.
        let report = merge_ops(&mut live, &stale, &dk).expect("re-merge");
        assert!(!report.changed, "converged file must not change again");

        let Projection::Visible { current, .. } = live.projection("svc", "k").expect("proj") else {
            panic!("entry must stay visible");
        };
        assert_eq!(current, fresh_id, "fresh v4 write must remain current");
    }

    #[test]
    fn legacy_id_encoding_is_locked_by_fixture() {
        // Independent reimplementation of the locked canonical encodings:
        // any change to derive_vault_id / legacy op id derivation must
        // invalidate migrated vaults and must be caught here.
        use sha2::Digest as _;

        let kdf = test_kdf();
        let wrapped = "wrapped-dk-placeholder";
        let material = format!(
            "{}|{}|{}|{}|{}|{}",
            kdf.algo, kdf.log_n, kdf.r, kdf.p, kdf.salt_b64, wrapped
        );
        let expect_vault = {
            let d = Sha256::digest(material.as_bytes());
            hex::encode(&d[..VAULT_ID_LEN])
        };
        assert_eq!(derive_vault_id(&kdf, wrapped), expect_vault);

        let vault_id = expect_vault;
        let mut feed = Vec::new();
        for part in [
            b"kyz-v4-legacy-op-v2" as &[u8],
            vault_id.as_bytes(),
            b"svc",
            b"k",
            &55u64.to_le_bytes(),
            &0u64.to_le_bytes(),
            br#"{"service":"svc","key":"k","fields":{"value":"old-value"},"tags":[],"created_at":100,"updated_at":55}"#,
        ] {
            feed.extend_from_slice(&(part.len() as u64).to_le_bytes());
            feed.extend_from_slice(part);
        }
        let d = Sha256::digest(&feed);
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&d[..8]);
        let expect_counter = u64::from_le_bytes(counter);

        let snapshot = SnapshotPlain {
            service: "svc".to_string(),
            key: "k".to_string(),
            fields: BTreeMap::from([("value".to_string(), "old-value".to_string())]),
            tags: BTreeSet::new(),
            created_at: 100,
            updated_at: 55,
        };
        assert_eq!(
            legacy_op_counter(&vault_id, "svc", "k", 55, 0, &snapshot.canonical_bytes()),
            expect_counter,
        );
        // Distinct inputs derive distinct counters: timestamp, chain
        // position, and content each disambiguate.
        assert_ne!(
            legacy_op_counter(&vault_id, "svc", "k", 55, 0, &snapshot.canonical_bytes()),
            legacy_op_counter(&vault_id, "svc", "k", 66, 0, &snapshot.canonical_bytes()),
        );
        assert_ne!(
            legacy_op_counter(&vault_id, "svc", "k", 55, 0, &snapshot.canonical_bytes()),
            legacy_op_counter(&vault_id, "svc", "k", 55, 1, &snapshot.canonical_bytes()),
            "identical (content, ts) snapshots at different chain positions must not collide"
        );
    }

    #[test]
    fn create_and_unlock_roundtrip() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let (mut file, dk) = VaultFileV4::create(&pass).expect("create");
        assert_eq!(file.version, 4);
        assert!(!file.passphrase_policy_checked);
        file.finalize(&dk).expect("finalize");
        let unwrapped = file.unwrap_dk(&pass).expect("unwrap");
        assert_eq!(*unwrapped, *dk);
        let wrong = SecretString::from("incorrect horse battery staple".to_string());
        assert!(file.unwrap_dk(&wrong).is_err());
    }
}
