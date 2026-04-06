//! Integration tests for the auth request store.

use kyz_core::auth_request::{
    AuthRequestStatus, AuthRequestStore, CreateAuthRequest, DenyAuthRequest,
};

fn test_params() -> CreateAuthRequest {
    CreateAuthRequest {
        requester: "test-agent".to_string(),
        scopes: vec!["github/token".to_string()],
        reason: Some("testing".to_string()),
        ttl_seconds: 300,
    }
}

#[test]
fn create_and_retrieve() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");
    assert!(!req.id.is_empty());
    assert_eq!(req.requester, "test-agent");
    assert_eq!(req.status, AuthRequestStatus::Pending);

    let fetched = store.get(&req.id).expect("get").expect("found");
    assert_eq!(fetched.id, req.id);
    assert_eq!(fetched.requester, "test-agent");
    assert_eq!(fetched.scopes, vec!["github/token"]);
}

#[test]
fn deny_request() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");

    let deny = DenyAuthRequest {
        denied_by: None,
        reason: Some("not authorized".to_string()),
    };
    store.deny(&req.id, &deny).expect("deny");

    let fetched = store.get(&req.id).expect("get").expect("found");
    assert_eq!(fetched.status, AuthRequestStatus::Denied);
    assert_eq!(fetched.deny_reason.as_deref(), Some("not authorized"));
}

#[test]
fn approve_request() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");
    store.approve(&req.id).expect("approve");

    let fetched = store.get(&req.id).expect("get").expect("found");
    assert_eq!(fetched.status, AuthRequestStatus::Approved);
    assert!(fetched.resolved_at.is_some());
}

#[test]
fn cannot_approve_already_denied() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");

    let deny = DenyAuthRequest {
        denied_by: None,
        reason: None,
    };
    store.deny(&req.id, &deny).expect("deny");

    let result = store.approve(&req.id);
    assert!(result.is_err());
}

#[test]
fn cannot_deny_already_approved() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");
    store.approve(&req.id).expect("approve");

    let deny = DenyAuthRequest {
        denied_by: None,
        reason: None,
    };
    let result = store.deny(&req.id, &deny);
    assert!(result.is_err());
}

#[test]
fn cannot_deny_twice() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");

    let deny = DenyAuthRequest {
        denied_by: None,
        reason: None,
    };
    store.deny(&req.id, &deny).expect("first deny");
    let result = store.deny(&req.id, &deny);
    assert!(result.is_err());
}

#[test]
fn list_with_status_filter() {
    let store = AuthRequestStore::new();
    let r1 = store.create(&test_params()).expect("create 1");
    let r2 = store.create(&test_params()).expect("create 2");
    let _r3 = store.create(&test_params()).expect("create 3");

    store.approve(&r1.id).expect("approve");
    store
        .deny(
            &r2.id,
            &DenyAuthRequest {
                denied_by: None,
                reason: None,
            },
        )
        .expect("deny");

    let pending = store
        .list(Some(AuthRequestStatus::Pending))
        .expect("list pending");
    assert_eq!(pending.len(), 1);

    let approved = store
        .list(Some(AuthRequestStatus::Approved))
        .expect("list approved");
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0].id, r1.id);

    let all = store.list(None).expect("list all");
    assert_eq!(all.len(), 3);
}

#[test]
fn cleanup_removes_resolved_requests() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");

    // Approve it (moves to resolved state)
    store.approve(&req.id).expect("approve");

    // cleanup(0) should remove all resolved requests (cutoff = now)
    let removed = store.cleanup(0).expect("cleanup");
    assert_eq!(removed, 1);

    // Should be gone
    let fetched = store.get(&req.id).expect("get");
    assert!(fetched.is_none());
}

#[test]
fn cleanup_keeps_recent_resolved() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");
    store.approve(&req.id).expect("approve");

    // cleanup with large max_age should keep it
    let removed = store.cleanup(3600).expect("cleanup");
    assert_eq!(removed, 0);

    let fetched = store.get(&req.id).expect("get");
    assert!(fetched.is_some());
}

#[test]
fn get_nonexistent_returns_none() {
    let store = AuthRequestStore::new();
    let fetched = store.get("nonexistent-id").expect("get");
    assert!(fetched.is_none());
}

#[test]
fn subscribe_receives_events() {
    let store = AuthRequestStore::new();
    let mut rx = store.subscribe();

    let req = store.create(&test_params()).expect("create");
    store.approve(&req.id).expect("approve");

    let mut found_approval = false;
    while let Ok(event) = rx.try_recv() {
        if event.status == AuthRequestStatus::Approved {
            found_approval = true;
        }
    }
    assert!(found_approval);
}

#[test]
fn stash_and_pickup_secrets() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");
    store.approve(&req.id).expect("approve");

    let mut secrets = std::collections::BTreeMap::new();
    let mut scope_secrets = std::collections::BTreeMap::new();
    scope_secrets.insert("value".to_string(), "ghp_abc123".to_string());
    secrets.insert("github/token".to_string(), scope_secrets);

    store.stash_secrets(&req.id, secrets).expect("stash");

    // First pickup succeeds
    let picked = store.pickup_secrets(&req.id).expect("pickup");
    assert!(picked.is_some());
    let picked = picked.expect("some");
    assert!(picked.contains_key("github/token"));

    // Second pickup returns None (one-time)
    let second = store.pickup_secrets(&req.id).expect("pickup again");
    assert!(second.is_none());
}

#[test]
fn multiple_requests_independent() {
    let store = AuthRequestStore::new();
    let r1 = store.create(&test_params()).expect("create 1");
    let r2 = store.create(&test_params()).expect("create 2");

    store.approve(&r1.id).expect("approve r1");

    let r1_status = store.get(&r1.id).expect("get").expect("found");
    let r2_status = store.get(&r2.id).expect("get").expect("found");

    assert_eq!(r1_status.status, AuthRequestStatus::Approved);
    assert_eq!(r2_status.status, AuthRequestStatus::Pending);
}

#[test]
fn auto_expire_on_get() {
    let store = AuthRequestStore::new();
    let params = CreateAuthRequest {
        requester: "test".to_string(),
        scopes: vec!["scope".to_string()],
        reason: None,
        ttl_seconds: 0,
    };
    let req = store.create(&params).expect("create");

    std::thread::sleep(std::time::Duration::from_millis(10));

    let fetched = store.get(&req.id).expect("get").expect("found");
    assert_eq!(fetched.status, AuthRequestStatus::Expired);
}

#[test]
fn deny_with_reason_and_identity() {
    let store = AuthRequestStore::new();
    let req = store.create(&test_params()).expect("create");

    let deny = DenyAuthRequest {
        denied_by: Some("admin@example.com".to_string()),
        reason: Some("security audit failed".to_string()),
    };
    store.deny(&req.id, &deny).expect("deny");

    let fetched = store.get(&req.id).expect("get").expect("found");
    assert_eq!(fetched.status, AuthRequestStatus::Denied);
    assert_eq!(fetched.denied_by.as_deref(), Some("admin@example.com"));
    assert_eq!(
        fetched.deny_reason.as_deref(),
        Some("security audit failed")
    );
}

#[test]
fn request_scopes_preserved() {
    let store = AuthRequestStore::new();
    let params = CreateAuthRequest {
        requester: "agent".to_string(),
        scopes: vec![
            "github/token".to_string(),
            "aws/key:access_key".to_string(),
            "db/prod:password".to_string(),
        ],
        reason: Some("deploy".to_string()),
        ttl_seconds: 300,
    };
    let req = store.create(&params).expect("create");
    assert_eq!(req.scopes.len(), 3);
    assert!(req.scopes.contains(&"aws/key:access_key".to_string()));
}
