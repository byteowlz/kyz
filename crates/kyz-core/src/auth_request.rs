//! Auth request model for headless agent authentication.
//!
//! Provides the data model and in-memory store for managing authentication
//! requests from headless agents that need vault secrets but cannot prompt
//! for a passphrase interactively.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique identifier for an auth request.
pub type AuthRequestId = String;

/// Status of an authentication request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequestStatus {
    /// Waiting for human approval.
    Pending,
    /// Approved by a human (secrets delivered).
    Approved,
    /// Denied by a human.
    Denied,
    /// Expired without action.
    Expired,
}

/// A request from a headless agent for vault secret access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Unique request identifier.
    pub id: AuthRequestId,
    /// Human-readable label identifying the requester (e.g. "ci-deploy", "agent-session-xyz").
    pub requester: String,
    /// Requested secret scopes: list of `"service/key"` or `"service/key:field"` references.
    pub scopes: Vec<String>,
    /// Optional reason/justification from the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Current status.
    pub status: AuthRequestStatus,
    /// Unix timestamp when the request was created.
    pub created_at: u64,
    /// Unix timestamp when the request expires if not acted on.
    pub expires_at: u64,
    /// Unix timestamp when the request was resolved (approved/denied), if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<u64>,
    /// Who denied the request, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_by: Option<String>,
    /// Denial reason, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
}

/// Parameters for creating a new auth request.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateAuthRequest {
    /// Human-readable label identifying the requester.
    pub requester: String,
    /// Requested secret scopes.
    pub scopes: Vec<String>,
    /// Optional reason/justification.
    #[serde(default)]
    pub reason: Option<String>,
    /// TTL in seconds (default: 300 = 5 minutes).
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

const fn default_ttl() -> u64 {
    300
}

/// Parameters for denying a request.
#[derive(Debug, Clone, Deserialize)]
pub struct DenyAuthRequest {
    /// Who is denying (optional identifier).
    #[serde(default)]
    pub denied_by: Option<String>,
    /// Reason for denial.
    #[serde(default)]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

/// Thread-safe in-memory store for auth requests.
#[derive(Debug, Clone)]
pub struct AuthRequestStore {
    requests: Arc<RwLock<BTreeMap<AuthRequestId, AuthRequest>>>,
}

impl AuthRequestStore {
    /// Create a new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Create a new auth request and return it.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn create(&self, params: &CreateAuthRequest) -> Result<AuthRequest, String> {
        let now = now_unix();
        let id = generate_request_id();
        let request = AuthRequest {
            id: id.clone(),
            requester: params.requester.clone(),
            scopes: params.scopes.clone(),
            reason: params.reason.clone(),
            status: AuthRequestStatus::Pending,
            created_at: now,
            expires_at: now + params.ttl_seconds,
            resolved_at: None,
            denied_by: None,
            deny_reason: None,
        };

        self.requests
            .write()
            .map_err(|e| format!("lock poisoned: {e}"))?
            .insert(id, request.clone());
        Ok(request)
    }

    /// Get a request by ID, marking it expired if past its TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn get(&self, id: &str) -> Result<Option<AuthRequest>, String> {
        let mut store = self
            .requests
            .write()
            .map_err(|e| format!("lock poisoned: {e}"))?;

        let Some(request) = store.get_mut(id) else {
            return Ok(None);
        };

        // Auto-expire
        let now = now_unix();
        if request.status == AuthRequestStatus::Pending && now >= request.expires_at {
            request.status = AuthRequestStatus::Expired;
            request.resolved_at = Some(now);
        }

        let result = request.clone();
        drop(store);
        Ok(Some(result))
    }

    /// List all requests, optionally filtered by status.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn list(
        &self,
        status_filter: Option<AuthRequestStatus>,
    ) -> Result<Vec<AuthRequest>, String> {
        let mut store = self
            .requests
            .write()
            .map_err(|e| format!("lock poisoned: {e}"))?;

        let now = now_unix();

        // Auto-expire pending requests
        for req in store.values_mut() {
            if req.status == AuthRequestStatus::Pending && now >= req.expires_at {
                req.status = AuthRequestStatus::Expired;
                req.resolved_at = Some(now);
            }
        }

        let results: Vec<AuthRequest> = store
            .values()
            .filter(|r| status_filter.is_none_or(|s| r.status == s))
            .cloned()
            .collect();

        drop(store);
        Ok(results)
    }

    /// Deny a request.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is not found, not pending, or the lock is poisoned.
    pub fn deny(&self, id: &str, params: &DenyAuthRequest) -> Result<AuthRequest, String> {
        let mut store = self
            .requests
            .write()
            .map_err(|e| format!("lock poisoned: {e}"))?;

        let request = store
            .get_mut(id)
            .ok_or_else(|| format!("request '{id}' not found"))?;

        // Auto-expire check
        let now = now_unix();
        if request.status == AuthRequestStatus::Pending && now >= request.expires_at {
            request.status = AuthRequestStatus::Expired;
            request.resolved_at = Some(now);
        }

        if request.status != AuthRequestStatus::Pending {
            return Err(format!(
                "request '{id}' is not pending (status: {:?})",
                request.status
            ));
        }

        request.status = AuthRequestStatus::Denied;
        request.resolved_at = Some(now);
        request.denied_by.clone_from(&params.denied_by);
        request.deny_reason.clone_from(&params.reason);

        let result = request.clone();
        drop(store);
        Ok(result)
    }

    /// Mark a request as approved (called by the approval flow).
    ///
    /// # Errors
    ///
    /// Returns an error if the request is not found or not pending.
    pub fn approve(&self, id: &str) -> Result<AuthRequest, String> {
        let mut store = self
            .requests
            .write()
            .map_err(|e| format!("lock poisoned: {e}"))?;

        let request = store
            .get_mut(id)
            .ok_or_else(|| format!("request '{id}' not found"))?;

        let now = now_unix();
        if request.status == AuthRequestStatus::Pending && now >= request.expires_at {
            request.status = AuthRequestStatus::Expired;
            request.resolved_at = Some(now);
        }

        if request.status != AuthRequestStatus::Pending {
            return Err(format!(
                "request '{id}' is not pending (status: {:?})",
                request.status
            ));
        }

        request.status = AuthRequestStatus::Approved;
        request.resolved_at = Some(now);

        let result = request.clone();
        drop(store);
        Ok(result)
    }

    /// Remove expired and resolved requests older than `max_age_secs`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn cleanup(&self, max_age_secs: u64) -> Result<usize, String> {
        let mut store = self
            .requests
            .write()
            .map_err(|e| format!("lock poisoned: {e}"))?;

        let cutoff = now_unix().saturating_sub(max_age_secs);
        let before = store.len();
        store.retain(|_, r| {
            // Keep pending requests (even old ones, they'll auto-expire on access)
            if r.status == AuthRequestStatus::Pending {
                return true;
            }
            // Keep resolved requests that are recent enough
            r.resolved_at.unwrap_or(r.created_at) > cutoff
        });

        Ok(before - store.len())
    }
}

impl Default for AuthRequestStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_request_id() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 12];
    getrandom::fill(&mut bytes).unwrap_or_default();
    let mut s = String::with_capacity(28);
    let _ = write!(s, "ar-");
    for b in &bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> CreateAuthRequest {
        CreateAuthRequest {
            requester: "test-agent".to_string(),
            scopes: vec!["kyz/api-key".to_string()],
            reason: Some("need deploy key".to_string()),
            ttl_seconds: 60,
        }
    }

    #[test]
    fn test_create_and_get() {
        let store = AuthRequestStore::new();
        let req = store.create(&test_params()).expect("create");
        assert_eq!(req.status, AuthRequestStatus::Pending);
        assert_eq!(req.requester, "test-agent");

        let fetched = store.get(&req.id).expect("get").expect("found");
        assert_eq!(fetched.id, req.id);
    }

    #[test]
    fn test_deny() {
        let store = AuthRequestStore::new();
        let req = store.create(&test_params()).expect("create");

        let denied = store
            .deny(
                &req.id,
                &DenyAuthRequest {
                    denied_by: Some("admin".to_string()),
                    reason: Some("not authorized".to_string()),
                },
            )
            .expect("deny");

        assert_eq!(denied.status, AuthRequestStatus::Denied);
        assert_eq!(denied.denied_by.as_deref(), Some("admin"));
    }

    #[test]
    fn test_approve() {
        let store = AuthRequestStore::new();
        let req = store.create(&test_params()).expect("create");

        let approved = store.approve(&req.id).expect("approve");
        assert_eq!(approved.status, AuthRequestStatus::Approved);
        assert!(approved.resolved_at.is_some());
    }

    #[test]
    fn test_cannot_deny_twice() {
        let store = AuthRequestStore::new();
        let req = store.create(&test_params()).expect("create");
        let deny_params = DenyAuthRequest {
            denied_by: None,
            reason: None,
        };
        store.deny(&req.id, &deny_params).expect("first deny");
        assert!(store.deny(&req.id, &deny_params).is_err());
    }

    #[test]
    fn test_list_with_filter() {
        let store = AuthRequestStore::new();
        store.create(&test_params()).expect("create 1");
        let req2 = store.create(&test_params()).expect("create 2");
        store
            .deny(
                &req2.id,
                &DenyAuthRequest {
                    denied_by: None,
                    reason: None,
                },
            )
            .expect("deny");

        let pending = store.list(Some(AuthRequestStatus::Pending)).expect("list");
        assert_eq!(pending.len(), 1);

        let denied = store.list(Some(AuthRequestStatus::Denied)).expect("list");
        assert_eq!(denied.len(), 1);

        let all = store.list(None).expect("list all");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_cleanup() {
        let store = AuthRequestStore::new();
        let req = store.create(&test_params()).expect("create");
        store
            .deny(
                &req.id,
                &DenyAuthRequest {
                    denied_by: None,
                    reason: None,
                },
            )
            .expect("deny");

        // Cleanup with 0 max_age removes all resolved
        let removed = store.cleanup(0).expect("cleanup");
        assert_eq!(removed, 1);
    }
}
