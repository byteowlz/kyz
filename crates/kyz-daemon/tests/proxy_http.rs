#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::panic_in_result_fn,
        reason = "tests assert outcomes: expect/unwrap/panic are the failure mechanism"
    )
)]
#![cfg_attr(
    test,
    allow(
        clippy::significant_drop_tightening,
        reason = "each test holds its daemon (and the serialization lock) until the explicit shutdown call"
    )
)]
//! End-to-end HTTP credential proxy integration tests.
//!
//! Covers: token authentication, routing
//! (host normalization, wildcards, path prefixes, methods), bidirectional
//! hop-by-hop sanitization, credential strip-before-inject (including
//! duplicate headers), fail-closed injection, redirect pass-through,
//! upstream error mapping, body/concurrency limits, live credential
//! updates, reload validation, audit hygiene, and secret-leak canaries.

mod common;
#[path = "proxy_http/support.rs"]
mod support;

use std::fmt::Write as _;
use std::time::Duration;

use common::Fixture;
use support::{
    ProxyFixture, RecordedRequest, ScriptedResponse, send_http, send_http_chunked,
    send_http_stalled_body, send_http_untimed, spawn_tls_garbage_listener,
};

/// Marker environment variable selecting child mode for the env-proxy
/// re-exec test.
const CHILD_MODE_ENV: &str = "KYZ_PROXY_TEST_CHILD_MODE";

/// Read the audit log once at least `min_count` occurrences of `needle`
/// have been written. Audit events land on the daemon's writer thread, so
/// the file can lag the HTTP response by a moment.
async fn audit_log_with(paths: &kyz_daemon::DaemonPaths, needle: &str, min_count: usize) -> String {
    let path = paths.audit_log_path();
    for _ in 0..200 {
        if let Ok(content) = std::fs::read_to_string(&path)
            && content.matches(needle).count() >= min_count
        {
            return content;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    std::fs::read_to_string(&path).expect("audit log")
}

/// One `[[proxy.rules]]` block: token credential bound to the fixture
/// vault secret (`app/api:token`), injected into `X-Api-Key`, with a
/// per-rule static `X-Rule` marker for routing assertions.
fn rule_toml(
    name: &str,
    host: &str,
    prefix: Option<&str>,
    upstream: &str,
    methods: Option<&str>,
) -> String {
    let mut block = format!(
        "[[proxy.rules]]\nname = \"{name}\"\nhost = \"{host}\"\nupstream = \"{upstream}\"\n"
    );
    if let Some(prefix) = prefix {
        writeln!(block, "path_prefix = \"{prefix}\"").expect("infallible string write");
    }
    if let Some(methods) = methods {
        writeln!(block, "methods = [{methods}]").expect("infallible string write");
    }
    write!(
        block,
        "[[proxy.rules.credentials]]\nalias = \"app\"\nservice = \"app\"\nkey = \
         \"api\"\nfields = [\"token\"]\n\n[proxy.rules.headers]\n\"X-Api-Key\" = \
         \"{{{{app.token}}}}\"\n\n[proxy.rules.static_headers]\n\"X-Rule\" = \"{name}\"\n"
    )
    .expect("infallible string write");
    block
}

#[tokio::test]
async fn routes_hosts_prefixes_and_methods() {
    let pf = ProxyFixture::new();
    let upstream = pf.mock.url.as_str();
    // `wild` lives on its own domain: a wildcard with default methods must
    // not rescue method-forbidden requests aimed at the restricted
    // `api.example.com` rules.
    let rules = [
        rule_toml("wild", "*.wildcard.test", None, upstream, None),
        rule_toml("v1", "api.example.com", Some("/v1/"), upstream, None),
        rule_toml(
            "root",
            "api.example.com",
            Some("/"),
            upstream,
            Some("\"GET\", \"POST\""),
        ),
    ]
    .join("\n");
    pf.write_config_with(&rules, "");
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;
    let token = pf.proxy_token();
    let auth = vec![("X-Kyz-Proxy-Token".to_string(), token)];

    // Exact host beats wildcard; longer prefix beats shorter; prefixes
    // end on segment boundaries.
    for (target, expected_rule) in [
        ("/v1/items", "v1"),
        ("/health", "root"),
        ("/v10/items", "root"),
    ] {
        pf.mock.clear_requests();
        let response = send_http(addr, "GET", "api.example.com", target, &auth, b"")
            .await
            .unwrap();
        assert_eq!(response.status, 200, "target {target}");
        let requests = pf.mock.wait_for_requests(1).await;
        assert_eq!(
            last_header(&requests, "x-rule"),
            expected_rule,
            "target {target} routed wrongly"
        );
    }

    // Host normalization: case and legal port are stripped for matching.
    for host in ["API.EXAMPLE.COM", "api.example.com:8477"] {
        let response = send_http(addr, "GET", host, "/v1/x", &auth, b"")
            .await
            .unwrap();
        assert_eq!(response.status, 200, "host {host}");
    }

    // Wildcard matches one label only.
    pf.mock.clear_requests();
    let response = send_http(addr, "GET", "api.wildcard.test", "/x", &auth, b"")
        .await
        .unwrap();
    assert_eq!(
        response.status, 200,
        "single-label host matches the wildcard"
    );
    let requests = pf.mock.wait_for_requests(1).await;
    assert_eq!(last_header(&requests, "x-rule"), "wild");
    let response = send_http(addr, "GET", "a.b.wildcard.test", "/x", &auth, b"")
        .await
        .unwrap();
    assert_eq!(
        response.status, 404,
        "two-label host must not match *.wildcard.test"
    );
    let response = send_http(addr, "GET", "wildcard.test", "/x", &auth, b"")
        .await
        .unwrap();
    assert_eq!(
        response.status, 404,
        "bare domain must not match *.wildcard.test"
    );

    // Method not allowed by the matching rule → 405; unknown host → 404;
    // CONNECT/TRACE never allowed.
    let response = send_http(addr, "DELETE", "api.example.com", "/x", &auth, b"")
        .await
        .unwrap();
    assert_eq!(response.status, 405);
    let response = send_http(addr, "GET", "unknown.test", "/x", &auth, b"")
        .await
        .unwrap();
    assert_eq!(response.status, 404);
    let response = send_http(addr, "TRACE", "api.example.com", "/x", &auth, b"")
        .await
        .unwrap();
    assert_eq!(response.status, 405, "TRACE must always be rejected");
    let response = send_http(addr, "CONNECT", "api.example.com:443", "/x", &auth, b"")
        .await
        .unwrap();
    assert_eq!(response.status, 405, "CONNECT must always be rejected");

    daemon.shutdown().await;
    pf.mock.stop();
}

fn last_header(requests: &[RecordedRequest], name: &str) -> String {
    requests
        .last()
        .expect("at least one recorded request")
        .header_values(name)
        .first()
        .expect("header present")
        .to_string()
}

#[tokio::test]
async fn strips_hostile_headers_and_injects_credentials() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    pf.mock.push_response(ScriptedResponse {
        status: 200,
        headers: vec![
            ("Connection".to_string(), "keep-alive".to_string()),
            ("Keep-Alive".to_string(), "timeout=5".to_string()),
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Proxy-Authenticate".to_string(), "Basic".to_string()),
            ("Trailer".to_string(), "X-Some-Trailer".to_string()),
            ("X-Custom".to_string(), "end-to-end".to_string()),
            ("Content-Type".to_string(), "text/plain".to_string()),
        ],
        body: b"ok".to_vec(),
        delay: None,
    });

    let headers = vec![
        ("X-Kyz-Proxy-Token".to_string(), pf.proxy_token()),
        (
            "Authorization".to_string(),
            "Bearer client-secret".to_string(),
        ),
        (
            "Authorization".to_string(),
            "Bearer duplicate-secret".to_string(),
        ),
        ("X-Api-Key".to_string(), "client-key".to_string()),
        (
            "Proxy-Authorization".to_string(),
            "Basic client".to_string(),
        ),
        ("Keep-Alive".to_string(), "timeout=1".to_string()),
        ("Connection".to_string(), "X-Nominated".to_string()),
        ("X-Nominated".to_string(), "must-vanish".to_string()),
        ("Upgrade".to_string(), "websocket".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    // The body is chunked-framed: the client's `Transfer-Encoding` must be
    // consumed by kyz re-framing, never forwarded.
    let response = send_http_chunked(
        addr,
        "POST",
        "api.sophify.com",
        "/v1/items?a=secret-query",
        &headers,
        b"{}",
    )
    .await
    .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
    // Response-side hop-by-hop stripping: the upstream's scripted values
    // never reach the client, and framing headers are regenerated. (The
    // transport may add its own `Connection: close` for our close-framed
    // request; that is local framing, not a forwarded header.)
    assert!(!response.header_values("connection").contains(&"keep-alive"));
    assert!(response.header_values("keep-alive").is_empty());
    assert!(response.header_values("transfer-encoding").is_empty());
    assert!(response.header_values("proxy-authenticate").is_empty());
    assert!(response.header_values("trailer").is_empty());
    // End-to-end headers pass through untouched.
    assert_eq!(response.header_values("x-custom"), vec!["end-to-end"]);
    assert_eq!(response.header_values("content-type"), vec!["text/plain"]);
    assert_eq!(response.header_values("content-length"), vec!["2"]);

    let requests = pf.mock.wait_for_requests(1).await;
    let recorded = requests.last().expect("recorded request");
    assert_eq!(recorded.method, "POST");
    // Strip-before-inject: the injected value is the vault secret; the
    // client's values (including duplicates) never made it upstream.
    let api_keys = recorded.header_values("x-api-key");
    assert_eq!(api_keys, vec![pf.fixture.secret_value.as_str()]);
    assert!(recorded.header_values("authorization").is_empty());
    assert!(recorded.header_values("proxy-authorization").is_empty());
    assert!(recorded.header_values("keep-alive").is_empty());
    assert!(recorded.header_values("connection").is_empty());
    assert!(recorded.header_values("x-nominated").is_empty());
    assert!(recorded.header_values("upgrade").is_empty());
    assert!(recorded.header_values("transfer-encoding").is_empty());
    assert!(recorded.header_values("x-kyz-proxy-token").is_empty());
    // Static headers flow; query and body pass through untouched.
    assert_eq!(recorded.header_values("x-rule"), vec!["sophify"]);
    assert_eq!(recorded.target, "/v1/items?a=secret-query");
    assert_eq!(recorded.body, b"{}");

    daemon.shutdown().await;
    // Canary: the vault value, passphrase, and proxy token never
    // reached daemon.log/audit.log (or any state file).
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn token_authentication_gate() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    let missing = send_http(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await
        .unwrap();
    assert_eq!(missing.status, 401, "missing token → 401");

    let wrong = vec![("X-Kyz-Proxy-Token".to_string(), "deadbeef".to_string())];
    let wrong = send_http(addr, "GET", "api.sophify.com", "/x", &wrong, b"")
        .await
        .unwrap();
    assert_eq!(wrong.status, 403, "wrong token → 403");

    let duplicated = vec![
        ("X-Kyz-Proxy-Token".to_string(), pf.proxy_token()),
        ("X-Kyz-Proxy-Token".to_string(), pf.proxy_token()),
    ];
    let duplicated = send_http(addr, "GET", "api.sophify.com", "/x", &duplicated, b"")
        .await
        .unwrap();
    assert_eq!(duplicated.status, 403, "duplicated token → 403");

    // Correct token passes and the token is invisible upstream.
    let ok = pf
        .send(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(ok.status, 200);
    let requests = pf.mock.wait_for_requests(1).await;
    let recorded = requests.last().expect("recorded");
    assert!(recorded.header_values("x-kyz-proxy-token").is_empty());

    // Auth failures never reach the upstream.
    assert_eq!(
        pf.mock.requests().len(),
        1,
        "only the authorized request reached the upstream"
    );

    // Audit records the rejections (typed reason, no secrets).
    let audit = audit_log_with(&pf.fixture.daemon_paths(), "auth_rejected", 3).await;
    assert_eq!(audit.matches("auth_rejected").count(), 3);

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn auth_none_mode_allows_unauthenticated_loopback() {
    let pf = ProxyFixture::new();
    let rules = rule_toml("open", "api.sophify.com", None, &pf.mock.url, None);
    // Flip [proxy] auth to "none" (explicit user opt-in).
    pf.write_config_raw("127.0.0.1:0", "none", &rules, "");
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    let response = send_http(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await
        .unwrap();
    assert_eq!(response.status, 200, "auth=none requires no token");

    daemon.shutdown().await;
    pf.mock.stop();
}

#[tokio::test]
async fn redirects_are_passed_through_without_following() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    pf.mock.push_response(ScriptedResponse::with_headers(
        302,
        vec![(
            "Location".to_string(),
            "https://evil.example/steal".to_string(),
        )],
    ));

    let response = pf
        .send(addr, "GET", "api.sophify.com", "/v1/items", &[], b"")
        .await;
    assert_eq!(response.status, 302, "redirect returns verbatim");
    assert_eq!(
        response.header_values("location"),
        vec!["https://evil.example/steal"]
    );

    let requests = pf.mock.wait_for_requests(1).await;
    assert_eq!(
        requests.len(),
        1,
        "kyz must not follow the redirect to another origin"
    );
    // The credential stayed on the configured upstream request only.
    let recorded = requests.last().expect("recorded");
    assert_eq!(
        recorded.header_values("x-api-key"),
        vec![pf.fixture.secret_value.as_str()]
    );

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn fail_closed_injection_makes_no_upstream_request() {
    let pf = ProxyFixture::new();
    // The rule references a secret that does not exist in the fixture
    // vault (load-time validation cannot see vault contents).
    let rules = format!(
        "[[proxy.rules]]\nname = \"broken\"\nhost = \"api.sophify.com\"\nupstream = \
         \"{}\"\n\n[[proxy.rules.credentials]]\nalias = \"gone\"\nservice = \
         \"gone\"\nkey = \"none\"\nfields = [\"token\"]\n\n[proxy.rules.headers]\n\"X-Api-Key\" = \
         \"{{{{gone.token}}}}\"\n",
        pf.mock.url
    );
    pf.write_config(&rules);
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    let response = pf
        .send(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(response.status, 500, "missing secret → fail closed 500");
    assert!(pf.mock.requests().is_empty(), "no partial injection");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(pf.mock.requests().is_empty(), "still no upstream request");

    let audit = audit_log_with(&pf.fixture.daemon_paths(), "missing_secret", 1).await;
    assert!(audit.contains("proxy_inject_error"), "audit: {audit}");
    assert!(audit.contains("missing_secret"), "audit: {audit}");

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn empty_credential_value_fails_closed() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    // `kyz set` to an empty value; next request must fail closed.
    pf.update_vault_secret("");
    let response = pf
        .send(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(response.status, 500, "empty field → fail closed 500");
    assert!(pf.mock.requests().is_empty());

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn credential_updates_apply_on_the_next_request() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    let first = pf
        .send(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(first.status, 200);
    let requests = pf.mock.wait_for_requests(1).await;
    assert_eq!(last_header(&requests, "x-api-key"), pf.fixture.secret_value);

    // `kyz set` while the daemon lives: the very next request uses the new
    // value (live vault read, no plaintext caching).
    let rotated = format!("KYZ_TEST_SECRET_rotated_{}", std::process::id());
    pf.update_vault_secret(&rotated);
    let second = pf
        .send(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(second.status, 200);
    let requests = pf.mock.wait_for_requests(2).await;
    assert_eq!(last_header(&requests, "x-api-key"), rotated);

    daemon.shutdown().await;
    // The rotated value is just as secret as the original.
    let mut fixture_owned = pf.fixture;
    fixture_owned.secret_value = rotated;
    fixture_owned.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn upstream_error_mapping() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    // Upstream 4xx/5xx pass through verbatim.
    pf.mock.push_response(ScriptedResponse::status(404));
    let response = pf
        .send(addr, "GET", "api.sophify.com", "/missing", &[], b"")
        .await;
    assert_eq!(response.status, 404);
    pf.mock
        .push_response(ScriptedResponse::with_body(503, b"overloaded"));
    let response = pf
        .send(addr, "GET", "api.sophify.com", "/missing", &[], b"")
        .await;
    assert_eq!(response.status, 503);
    assert_eq!(response.body, b"overloaded");

    // TLS failure → 502 (a rule pointing at a non-TLS endpoint).
    let garbage = spawn_tls_garbage_listener();
    let rules = rule_toml(
        "tls",
        "tls.sophify.com",
        None,
        &format!("https://{garbage}"),
        None,
    );
    pf.write_config(&format!(
        "{}\n{}",
        rule_toml("sophify", "api.sophify.com", None, &pf.mock.url, None),
        rules
    ));
    let reload = kyz_daemon::ipc::send_request(
        &pf.fixture.daemon_paths(),
        &pf.fixture.ipc_token(),
        kyz_daemon::ipc::IpcRequestKind::Reload,
    )
    .await
    .expect("reload");
    assert!(
        reload.ok,
        "reload with extra rule: {}",
        reload.error_message()
    );

    let response = pf
        .send(addr, "GET", "tls.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(response.status, 502, "TLS failure → 502");

    // DNS failure → 502.
    let dns_rules = rule_toml(
        "dns",
        "dns.sophify.com",
        None,
        "https://nonexistent-host.invalid",
        None,
    );
    pf.write_config(&format!(
        "{}\n{}",
        rule_toml("sophify", "api.sophify.com", None, &pf.mock.url, None),
        dns_rules
    ));
    let reload = kyz_daemon::ipc::send_request(
        &pf.fixture.daemon_paths(),
        &pf.fixture.ipc_token(),
        kyz_daemon::ipc::IpcRequestKind::Reload,
    )
    .await
    .expect("reload");
    assert!(reload.ok);
    let response = pf
        .send(addr, "GET", "dns.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(response.status, 502, "DNS failure → 502");

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn upstream_timeout_maps_to_504() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    // 1s upstream timeout; the mock delays 3s.
    let daemon = pf.start_with(1, u64::MAX).await;
    let addr = pf.proxy_addr().await;

    pf.mock
        .push_response(ScriptedResponse::status(200).delayed(Duration::from_secs(3)));
    let started = std::time::Instant::now();
    let response = pf
        .send(addr, "GET", "api.sophify.com", "/slow", &[], b"")
        .await;
    assert_eq!(response.status, 504, "upstream timeout → 504");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "timeout must be bounded"
    );

    let audit = audit_log_with(&pf.fixture.daemon_paths(), "\"status\":504", 1).await;
    assert!(audit.contains("504"));

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn body_and_concurrency_limits() {
    let pf = ProxyFixture::new();
    pf.write_config_with(
        &rule_toml("sophify", "api.sophify.com", None, &pf.mock.url, None),
        "request_body_limit_bytes = 16\n",
    );
    // Response limit of 8 bytes (client fixed at startup).
    let daemon = pf.start_with(30, 8).await;
    let addr = pf.proxy_addr().await;

    // Request body over the limit → 413 (and no upstream request).
    let response = pf
        .send(addr, "POST", "api.sophify.com", "/big", &[], &[42u8; 17])
        .await;
    assert_eq!(response.status, 413);
    assert!(pf.mock.requests().is_empty(), "413 must not forward");

    // Exactly at the limit passes.
    let response = pf
        .send(addr, "POST", "api.sophify.com", "/ok", &[], &[42u8; 16])
        .await;
    assert_eq!(response.status, 200);

    // Response body over the limit → 502.
    pf.mock
        .push_response(ScriptedResponse::with_body(200, &[1u8; 9]));
    let response = pf
        .send(addr, "GET", "api.sophify.com", "/huge", &[], b"")
        .await;
    assert_eq!(response.status, 502, "response body over limit → 502");

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn max_in_flight_rejects_excess_requests() {
    let pf = ProxyFixture::new();
    pf.write_config_with(
        &rule_toml("sophify", "api.sophify.com", None, &pf.mock.url, None),
        "max_in_flight = 1\n",
    );
    let daemon = pf.start().await;
    pf.mock
        .push_response(ScriptedResponse::status(200).delayed(Duration::from_millis(1200)));
    let addr = pf.proxy_addr().await;
    let first_addr = addr;
    let first_token = pf.proxy_token();
    let first = tokio::spawn(async move {
        let headers = vec![("X-Kyz-Proxy-Token".to_string(), first_token)];
        send_http(first_addr, "GET", "api.sophify.com", "/slow", &headers, b"")
            .await
            .expect("first request")
    });
    // Let the first request occupy the single slot.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second = pf
        .send(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(second.status, 503, "max_in_flight excess → 503");

    let first = first.await.expect("first task").status;
    assert_eq!(first, 200, "the in-flight request itself succeeds");

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn reload_swaps_rules_and_rejects_ambiguity() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;
    let paths = pf.fixture.daemon_paths();
    let ipc_token = pf.fixture.ipc_token();

    // Valid reload: a second rule extends routing immediately.
    pf.write_config(&format!(
        "{}\n{}",
        rule_toml("sophify", "api.sophify.com", None, &pf.mock.url, None),
        rule_toml("mirror", "mirror.sophify.com", None, &pf.mock.url, None),
    ));
    let reload =
        kyz_daemon::ipc::send_request(&paths, &ipc_token, kyz_daemon::ipc::IpcRequestKind::Reload)
            .await
            .expect("reload request");
    assert!(reload.ok, "valid reload: {}", reload.error_message());
    let response = pf
        .send(addr, "GET", "mirror.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(response.status, 200, "new rule serves after reload");
    let requests = pf.mock.wait_for_requests(1).await;
    assert_eq!(last_header(&requests, "x-rule"), "mirror");

    // Ambiguous config is rejected; the active snapshot keeps serving.
    pf.write_config(&format!(
        "{}\n{}",
        rule_toml("a", "api.sophify.com", None, &pf.mock.url, None),
        rule_toml("b", "api.sophify.com", None, &pf.mock.url, None),
    ));
    let reload =
        kyz_daemon::ipc::send_request(&paths, &ipc_token, kyz_daemon::ipc::IpcRequestKind::Reload)
            .await
            .expect("reload request");
    assert!(!reload.ok, "ambiguous config must be rejected");
    let response = pf
        .send(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(response.status, 200, "previous snapshot still active");
    let requests = pf.mock.wait_for_requests(2).await;
    assert_eq!(
        last_header(&requests, "x-rule"),
        "sophify",
        "the pre-reload snapshot still routes api.sophify.com"
    );

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

/// Reload cannot change proxy settings that are fixed at proxy startup —
/// most importantly `proxy.auth`: a none→token flip that only swapped the
/// snapshot would report the new mode while the running proxy keeps
/// serving unauthenticated (fail open). Such reloads must be rejected with
/// the active snapshot untouched.
#[tokio::test]
async fn reload_rejects_startup_fixed_proxy_changes() {
    let pf = ProxyFixture::new();
    let rules = rule_toml("sophify", "api.sophify.com", None, &pf.mock.url, None);
    pf.write_config_raw("127.0.0.1:0", "none", &rules, "");
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;
    let paths = pf.fixture.daemon_paths();
    let ipc_token = pf.fixture.ipc_token();

    // none -> token is rejected and named in the error.
    pf.write_config_raw("127.0.0.1:0", "token", &rules, "");
    let reload =
        kyz_daemon::ipc::send_request(&paths, &ipc_token, kyz_daemon::ipc::IpcRequestKind::Reload)
            .await
            .expect("reload request");
    assert!(!reload.ok, "auth flip must be rejected");
    assert!(
        reload.error_message().contains("proxy.auth"),
        "error should name the fixed field: {}",
        reload.error_message()
    );

    // The active snapshot is unchanged: unauthenticated requests still serve.
    let response = send_http(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    // A rule-only reload still applies live.
    let extended = format!(
        "{rules}\n{}",
        rule_toml("mirror", "mirror.sophify.com", None, &pf.mock.url, None)
    );
    pf.write_config_raw("127.0.0.1:0", "none", &extended, "");
    let reload =
        kyz_daemon::ipc::send_request(&paths, &ipc_token, kyz_daemon::ipc::IpcRequestKind::Reload)
            .await
            .expect("reload request");
    assert!(reload.ok, "rule-only reload: {}", reload.error_message());
    let response = send_http(addr, "GET", "mirror.sophify.com", "/x", &[], b"")
        .await
        .unwrap();
    assert_eq!(response.status, 200, "new rule serves after reload");

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

/// A client that declares a body but stalls mid-write must hit the
/// body-read deadline (408) and release its in-flight permit — never pin
/// the concurrency budget forever. Uses a paused runtime so the daemon's
/// deadline fires without wall-clock waiting.
#[tokio::test(start_paused = true)]
async fn stalled_request_body_times_out_and_frees_the_permit() {
    let pf = ProxyFixture::new();
    pf.write_config_with(
        &rule_toml("sophify", "api.sophify.com", None, &pf.mock.url, None),
        "max_in_flight = 1\n",
    );
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;
    let token = pf.proxy_token();

    // Declare 1024 body bytes, write one, and stall: the deadline (not the
    // client) ends this request.
    let response =
        send_http_stalled_body(addr, "api.sophify.com", "/slow-upload", &token, 1024, b"x")
            .await
            .unwrap();
    assert_eq!(response.status, 408, "stalled body must hit the deadline");

    // The single in-flight permit was freed: the next request serves.
    let response = send_http_untimed(addr, "GET", "api.sophify.com", "/x", &token, b"")
        .await
        .unwrap();
    assert_eq!(response.status, 200, "permit must be released after 408");

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

/// A proxy bind failure after the management task started must tear that
/// task down: the retry against the same state dir starts cleanly instead
/// of failing on a stale pipe/socket instance.
#[tokio::test]
async fn proxy_bind_failure_allows_retry_on_same_state_dir() {
    let pf = ProxyFixture::new();
    let rules = rule_toml("sophify", "api.sophify.com", None, &pf.mock.url, None);
    // Occupy the port so `daemon.listen` cannot bind.
    let squatter = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("squatter bind");
    let taken = squatter.local_addr().expect("squatter addr").port();
    pf.write_config_raw(&format!("127.0.0.1:{taken}"), "token", &rules, "");

    let guard = common::daemon_test_lock().await;
    let error = kyz_daemon::run_daemon_with_upstream(
        pf.fixture.options(None),
        pf.test_client(30, u64::MAX),
    )
    .await
    .expect_err("occupied port must fail startup");
    assert!(
        error.to_string().contains("binding proxy listener"),
        "expected bind failure, got: {error}"
    );
    drop(guard);
    drop(squatter);

    // Same state dir, free port: the retry must start (and serve), proving
    // the failed attempt released the pipe instance, runtime files, and
    // instance lock.
    pf.write_config_raw("127.0.0.1:0", "token", &rules, "");
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;
    let response = pf
        .send(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(response.status, 200);

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

/// RFC 7230 §6.1: headers nominated by the upstream's `Connection` value
/// are hop-by-hop and must not reach the local client — symmetric with the
/// request direction.
#[tokio::test]
async fn response_connection_nominated_headers_are_stripped() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    pf.mock.push_response(ScriptedResponse::with_headers(
        200,
        vec![
            ("Connection".to_string(), "X-Upstream-Internal".to_string()),
            ("X-Upstream-Internal".to_string(), "hop-state".to_string()),
            ("X-Keep".to_string(), "end-to-end".to_string()),
        ],
    ));
    let response = pf
        .send(addr, "GET", "api.sophify.com", "/x", &[], b"")
        .await;
    assert_eq!(response.status, 200);
    assert!(
        response.header_values("x-upstream-internal").is_empty(),
        "connection-nominated headers must not reach the client"
    );
    assert_eq!(response.header_values("x-keep"), vec!["end-to-end"]);

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

#[tokio::test]
async fn non_loopback_listen_fails_startup() {
    let pf = ProxyFixture::new();
    let rules = rule_toml("sophify", "api.sophify.com", None, &pf.mock.url, None);
    pf.write_config_raw("0.0.0.0:8477", "token", &rules, "");
    let guard = common::daemon_test_lock().await;
    let error = kyz_daemon::run_daemon_with_upstream(
        pf.fixture.options(None),
        pf.test_client(30, u64::MAX),
    )
    .await
    .expect_err("non-loopback listen must fail closed");
    assert!(
        error.to_string().contains("loopback"),
        "expected loopback rejection, got: {error}"
    );
    drop(guard);
    pf.mock.stop();
}

/// Without `daemon.listen` the daemon stays proxy-less (management IPC
/// only) and reports no bound proxy address.
#[tokio::test]
async fn daemon_without_listen_runs_proxyless() {
    let fixture = Fixture::new();
    let daemon = fixture.start(None).await;
    let response = kyz_daemon::ipc::send_request(
        &fixture.daemon_paths(),
        &fixture.ipc_token(),
        kyz_daemon::ipc::IpcRequestKind::Status,
    )
    .await
    .expect("status request");
    assert!(response.ok, "status failed: {}", response.error_message());
    assert!(
        response.result.expect("status payload")["proxy_listen"].is_null(),
        "no proxy listener expected without daemon.listen"
    );
    fixture.assert_no_session_artifacts();
    daemon.shutdown().await;
}

#[tokio::test]
async fn audit_records_forward_without_path_or_query() {
    let pf = ProxyFixture::new();
    pf.write_config(&rule_toml(
        "sophify",
        "api.sophify.com",
        None,
        &pf.mock.url,
        None,
    ));
    let daemon = pf.start().await;
    let addr = pf.proxy_addr().await;

    let response = pf
        .send(
            addr,
            "GET",
            "api.sophify.com",
            "/v1/items?api_key=super-secret",
            &[],
            b"",
        )
        .await;
    assert_eq!(response.status, 200);

    let audit = audit_log_with(&pf.fixture.daemon_paths(), "\"op\":\"proxy_forward\"", 1).await;
    let forward_lines: Vec<&str> = audit
        .lines()
        .filter(|line| line.contains("\"op\":\"proxy_forward\""))
        .collect();
    assert_eq!(forward_lines.len(), 1);
    let event: serde_json::Value = serde_json::from_str(forward_lines[0]).expect("audit json");
    assert_eq!(event["rule"], "sophify");
    assert_eq!(event["method"], "GET");
    assert_eq!(event["upstream_host"], "127.0.0.1");
    assert_eq!(event["status"], 200);
    // Neither path nor query (name or value) may appear anywhere.
    assert!(!audit.contains("/v1/items"), "path must not be audited");
    assert!(
        !audit.contains("api_key"),
        "query names must not be audited"
    );
    assert!(!audit.contains("super-secret"));
    // The field whitelist holds.
    for key in event.as_object().expect("audit object").keys() {
        assert!(
            [
                "ts",
                "op",
                "rule",
                "method",
                "upstream_host",
                "status",
                "duration_ms",
                "grant",
                "reason"
            ]
            .contains(&key.as_str()),
            "unexpected audit field {key}"
        );
    }

    daemon.shutdown().await;
    pf.fixture.assert_no_secret_leaks();
    pf.mock.stop();
}

/// The daemon's upstream client must ignore `HTTP_PROXY` /
/// `HTTPS_PROXY` / `ALL_PROXY` and always connect directly.
///
/// Env vars cannot be mutated in-process (edition-2024 `set_var` is
/// unsafe, forbidden workspace-wide), so the test re-executes itself as a
/// child with the variables pointing at a local decoy and asserts the
/// child's direct request succeeds while the decoy sees zero connections.
#[test]
fn env_proxy_variables_are_ignored() {
    if std::env::var_os(CHILD_MODE_ENV).is_some() {
        child_direct_request();
        return;
    }
    let decoy = DecoyProxy::spawn();
    let exe = std::env::current_exe().expect("test binary path");
    let output = std::process::Command::new(exe)
        .args(["--exact", "--nocapture", "env_proxy_variables_are_ignored"])
        .env(CHILD_MODE_ENV, "1")
        .env("HTTP_PROXY", decoy.url())
        .env("HTTPS_PROXY", decoy.url())
        .env("ALL_PROXY", decoy.url())
        .output()
        .expect("run child test");
    assert!(
        output.status.success(),
        "child direct-request test failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        decoy.connections(),
        0,
        "env proxy decoy must never be contacted"
    );
}

/// Child half of [`env_proxy_variables_are_ignored`]: request the mock
/// upstream through the hardened client while the parent-injected proxy
/// env vars are set. Panics (failing the child) on any deviation.
fn child_direct_request() {
    let mock = support::MockUpstream::start();
    let client = kyz_daemon::UpstreamClient::with_root_certs(
        Duration::from_secs(15),
        u64::MAX,
        &mock.ca_pem,
    );
    let request = kyz_daemon::UpstreamRequest {
        method: "GET".to_string(),
        url: format!("{}/direct", mock.url),
        headers: Vec::new(),
        body: bytes::Bytes::new(),
    };
    let response = client.execute(request).expect("direct request succeeds");
    assert_eq!(response.status, 200);
    let requests = mock.requests();
    assert_eq!(requests.len(), 1, "mock upstream saw the request");
    assert_eq!(requests[0].target, "/direct");
    mock.stop();
}

/// Local decoy that counts TCP connections and never speaks HTTP.
struct DecoyProxy {
    addr: std::net::SocketAddr,
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl DecoyProxy {
    fn spawn() -> Self {
        use std::io::Read as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("decoy bind");
        let addr = listener.local_addr().expect("decoy addr");
        let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&connections);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                counter.fetch_add(1, std::sync::atomic::Ordering::Release);
                let mut sink = [0u8; 64];
                let _ = stream.read(&mut sink);
            }
        });
        Self { addr, connections }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::Acquire)
    }
}
