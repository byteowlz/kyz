//! One-time local secret submission and JIT grant validation primitives.
//!
//! This module provides the policy/state layer used by local IPC integrations
//! (Pi/TUI) and runner-side grant enforcement.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Metadata about the producer of a one-time submission.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginMetadata {
    /// Optional human-readable source, e.g. `pi-tui`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Optional process identifier as string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
    /// Optional host identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// One-time submission payload accepted over local IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeSecretSubmission {
    /// Caller-provided id used for replay protection.
    pub request_id: String,
    /// Target service namespace.
    pub service: String,
    /// Secret key in the target service.
    pub key: String,
    /// Secret value/envelope.
    pub value: String,
    /// Absolute expiry timestamp (unix seconds).
    pub expires_at: u64,
    /// Origin details for auditing.
    #[serde(default)]
    pub origin: OriginMetadata,
}

/// Stored one-time secret payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSubmission {
    /// Target service namespace.
    pub service: String,
    /// Secret key in the target service.
    pub key: String,
    /// Secret value/envelope.
    pub value: String,
    /// Absolute expiry timestamp (unix seconds).
    pub expires_at: u64,
    /// Origin metadata.
    pub origin: OriginMetadata,
}

/// Denial reason for submission/consumption decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionReason {
    /// JSON payload was malformed.
    Malformed,
    /// Request id has already been seen.
    Replayed,
    /// Payload or grant expired.
    Expired,
    /// Request/grant was not found.
    NotFound,
    /// Scope command/workspace mismatch.
    OutOfScope,
    /// Grant exhausted its use count.
    UseCountExceeded,
}

/// In-memory replay-protected one-time submission store.
#[derive(Debug, Default)]
pub struct OneTimeSubmissionStore {
    submissions: BTreeMap<String, StoredSubmission>,
    seen_ids: BTreeSet<String>,
}

impl OneTimeSubmissionStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse and submit a JSON payload.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionReason::Malformed`] when parsing fails or required
    /// fields are empty. Returns [`DecisionReason::Replayed`] for duplicate ids
    /// and [`DecisionReason::Expired`] for expired submissions.
    pub fn submit_json(&mut self, payload: &str, now_unix: u64) -> Result<(), DecisionReason> {
        let parsed = serde_json::from_str::<OneTimeSecretSubmission>(payload)
            .map_err(|_| DecisionReason::Malformed)?;
        self.submit(parsed, now_unix)
    }

    /// Submit an already parsed payload.
    ///
    /// # Errors
    ///
    /// Returns malformed/replayed/expired reasons when validation fails.
    pub fn submit(
        &mut self,
        payload: OneTimeSecretSubmission,
        now_unix: u64,
    ) -> Result<(), DecisionReason> {
        if payload.request_id.is_empty()
            || payload.service.is_empty()
            || payload.key.is_empty()
            || payload.value.is_empty()
        {
            return Err(DecisionReason::Malformed);
        }
        if payload.expires_at <= now_unix {
            return Err(DecisionReason::Expired);
        }
        if self.seen_ids.contains(&payload.request_id) {
            return Err(DecisionReason::Replayed);
        }

        self.seen_ids.insert(payload.request_id.clone());
        self.submissions.insert(
            payload.request_id,
            StoredSubmission {
                service: payload.service,
                key: payload.key,
                value: payload.value,
                expires_at: payload.expires_at,
                origin: payload.origin,
            },
        );
        Ok(())
    }

    /// Resolve and consume a one-time submission by request id.
    ///
    /// # Errors
    ///
    /// Returns not-found or expired if resolution fails.
    pub fn resolve_once(
        &mut self,
        request_id: &str,
        now_unix: u64,
    ) -> Result<StoredSubmission, DecisionReason> {
        let Some(entry) = self.submissions.remove(request_id) else {
            return Err(DecisionReason::NotFound);
        };
        if entry.expires_at <= now_unix {
            return Err(DecisionReason::Expired);
        }
        Ok(entry)
    }
}

/// Constraints embedded into a brokered JIT grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantScope {
    /// Allowed secret references (`service/key` or `service/key:field`).
    pub secret_refs: Vec<String>,
    /// Allowed command basenames. Empty means unrestricted.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Allowed workspace roots. Empty means unrestricted.
    #[serde(default)]
    pub workspaces: Vec<String>,
}

/// Brokered JIT grant token metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JitGrant {
    /// Opaque grant token.
    pub token: String,
    /// Scope and policy constraints.
    pub scope: GrantScope,
    /// Absolute expiry timestamp (unix seconds).
    pub expires_at: u64,
    /// Remaining number of allowed uses.
    pub use_count: u32,
}

/// Runtime context of a grant consumer call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantUseContext<'a> {
    /// Secret reference being requested.
    pub secret_ref: &'a str,
    /// Command basename being executed.
    pub command: &'a str,
    /// Workspace identifier/path.
    pub workspace: &'a str,
}

/// In-memory grant registry with scope + TTL + `use_count` enforcement.
#[derive(Debug, Default)]
pub struct GrantStore {
    grants: BTreeMap<String, JitGrant>,
}

impl GrantStore {
    /// Create an empty grant registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert/replace a grant token.
    pub fn insert(&mut self, grant: JitGrant) {
        self.grants.insert(grant.token.clone(), grant);
    }

    /// Validate and consume one grant usage.
    ///
    /// # Errors
    ///
    /// Returns explicit denial reasons for not-found, expired, exhausted or
    /// out-of-scope usage.
    pub fn validate_and_consume(
        &mut self,
        token: &str,
        ctx: &GrantUseContext<'_>,
        now_unix: u64,
    ) -> Result<(), DecisionReason> {
        let Some(grant) = self.grants.get_mut(token) else {
            return Err(DecisionReason::NotFound);
        };

        if grant.expires_at <= now_unix {
            return Err(DecisionReason::Expired);
        }
        if grant.use_count == 0 {
            return Err(DecisionReason::UseCountExceeded);
        }

        if !grant.scope.secret_refs.iter().any(|s| s == ctx.secret_ref) {
            return Err(DecisionReason::OutOfScope);
        }

        if !grant.scope.commands.is_empty()
            && !grant.scope.commands.iter().any(|c| c == ctx.command)
        {
            return Err(DecisionReason::OutOfScope);
        }

        if !grant.scope.workspaces.is_empty()
            && !grant.scope.workspaces.iter().any(|w| w == ctx.workspace)
        {
            return Err(DecisionReason::OutOfScope);
        }

        grant.use_count -= 1;
        Ok(())
    }
}

/// Current unix timestamp in seconds.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_happy_path_and_one_time_resolution() {
        let mut store = OneTimeSubmissionStore::new();
        let now = 100;
        let payload = OneTimeSecretSubmission {
            request_id: "req-1".to_string(),
            service: "svc".to_string(),
            key: "api".to_string(),
            value: "secret-value".to_string(),
            expires_at: 200,
            origin: OriginMetadata {
                source: Some("pi-tui".to_string()),
                process_id: None,
                host: None,
            },
        };

        assert_eq!(store.submit(payload, now), Ok(()));
        let resolved = store.resolve_once("req-1", now);
        assert!(resolved.is_ok());
        let second = store.resolve_once("req-1", now);
        assert_eq!(second, Err(DecisionReason::NotFound));
    }

    #[test]
    fn submission_replay_is_rejected() {
        let mut store = OneTimeSubmissionStore::new();
        let now = 100;
        let payload = OneTimeSecretSubmission {
            request_id: "req-1".to_string(),
            service: "svc".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            expires_at: 200,
            origin: OriginMetadata::default(),
        };

        assert_eq!(store.submit(payload.clone(), now), Ok(()));
        assert_eq!(store.submit(payload, now), Err(DecisionReason::Replayed));
    }

    #[test]
    fn submission_expiry_and_malformed_are_rejected() {
        let mut store = OneTimeSubmissionStore::new();
        let now = 100;

        let expired = OneTimeSecretSubmission {
            request_id: "req-1".to_string(),
            service: "svc".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            expires_at: 100,
            origin: OriginMetadata::default(),
        };
        assert_eq!(store.submit(expired, now), Err(DecisionReason::Expired));

        let malformed_json = "{\"request_id\":\"x\",\"service\":1}";
        assert_eq!(
            store.submit_json(malformed_json, now),
            Err(DecisionReason::Malformed)
        );
    }

    #[test]
    fn grant_scope_violation_is_rejected() {
        let mut grants = GrantStore::new();
        grants.insert(JitGrant {
            token: "tok".to_string(),
            scope: GrantScope {
                secret_refs: vec!["svc/key".to_string()],
                commands: vec!["curl".to_string()],
                workspaces: vec!["/ws/project".to_string()],
            },
            expires_at: 200,
            use_count: 1,
        });

        let bad_cmd = GrantUseContext {
            secret_ref: "svc/key",
            command: "bash",
            workspace: "/ws/project",
        };
        assert_eq!(
            grants.validate_and_consume("tok", &bad_cmd, 100),
            Err(DecisionReason::OutOfScope)
        );

        let ok_ctx = GrantUseContext {
            secret_ref: "svc/key",
            command: "curl",
            workspace: "/ws/project",
        };
        assert_eq!(grants.validate_and_consume("tok", &ok_ctx, 100), Ok(()));

        let exhausted = grants.validate_and_consume("tok", &ok_ctx, 100);
        assert_eq!(exhausted, Err(DecisionReason::UseCountExceeded));
    }
}
