//! HTTP credential proxy: loopback listener → controlled HTTPS upstream.
//!
//! Local applications send plain HTTP to the daemon's `daemon.listen`
//! address; requests are authenticated with the per-daemon proxy token,
//! routed against the rule set from the active snapshot, sanitized
//! (hop-by-hop headers both directions), stripped of client credentials,
//! injected with vault-resolved credentials, and forwarded to the rule's
//! fixed HTTPS upstream. No MITM, no CONNECT, no forward-proxy mode.
//!
//! Ordering is fixed: hop-by-hop sanitize → credential strip →
//! static headers → credential inject. Injection is fail closed:
//! any resolve/decrypt/render failure rejects the upstream request with
//! 500 and an audit `proxy_inject_error` — never a partial injection.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body as AxumBody, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use secrecy::ExposeSecret;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};

use kyz_core::config::AppConfig;
use kyz_core::proxy_config::{
    HOP_BY_HOP_HEADERS, PROXY_TOKEN_HEADER, RuleMatch, match_rule, normalize_host, render_template,
    upstream_host,
};
use kyz_core::{CoreError, ProxyAuthMode, ProxyRuleConfig};

use crate::audit::{AuditEvent, AuditReason, AuditSink};
use crate::lifecycle::DaemonState;
use crate::upstream::{UpstreamClient, UpstreamError, UpstreamRequest};
use crate::{DaemonError, Result};

/// Deadline for reading one request body from a (possibly slow or stalled)
/// local client. Without it, a client that never finishes writing would pin
/// its in-flight permit forever and starve every other request; loopback
/// makes this generous relative to actual transfer times.
pub(crate) const REQUEST_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared proxy state, fixed at startup (the rule set itself is read from
/// the active snapshot per request, so reloads apply immediately).
pub struct ProxyShared {
    /// Daemon state: snapshot holder, vault access, audit sink.
    pub state: Arc<DaemonState>,
    /// Expected proxy token; `None` when `proxy.auth = "none"`.
    auth_token: Option<String>,
    /// Hardened HTTPS upstream client.
    client: UpstreamClient,
    /// Concurrency cap (`daemon.max_in_flight`), fixed at startup.
    in_flight: Arc<Semaphore>,
}

impl std::fmt::Debug for ProxyShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyShared")
            .field("state", &"<daemon state>")
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "<redacted>"),
            )
            .field("client", &self.client)
            .field("in_flight", &self.in_flight.available_permits())
            .finish_non_exhaustive()
    }
}

impl ProxyShared {
    /// Build the shared state from the daemon state and its active
    /// snapshot, constructing the production upstream client. Integration
    /// tests may substitute a client that trusts their own mock CA
    /// instead (test seam).
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Config`] when token authentication is
    /// configured but no proxy token is available (fail closed).
    pub(crate) fn with_client(
        state: Arc<DaemonState>,
        client_override: Option<UpstreamClient>,
    ) -> Result<Self> {
        let snapshot = state.snapshots.current()?;
        let auth_token = match snapshot.config.proxy.auth {
            ProxyAuthMode::Token => Some(state.proxy_token().ok_or_else(|| {
                DaemonError::Config("proxy token missing for auth = \"token\"".to_string())
            })?),
            ProxyAuthMode::None => None,
        };
        let timeout_secs = snapshot
            .config
            .runtime
            .timeout
            .unwrap_or(crate::upstream::DEFAULT_UPSTREAM_TIMEOUT_SECS)
            .max(1);
        let client = client_override.unwrap_or_else(|| {
            UpstreamClient::new(
                Duration::from_secs(timeout_secs),
                snapshot.config.daemon.response_body_limit_bytes,
            )
        });
        Ok(Self {
            client,
            state,
            auth_token,
            in_flight: Arc::new(Semaphore::new(snapshot.config.daemon.max_in_flight.max(1))),
        })
    }

    /// Full request pipeline: auth → concurrency → route → body limit →
    /// sanitize → strip → static → inject → forward → respond.
    async fn handle(self: &Arc<Self>, request: Request) -> Response {
        let started = Instant::now();
        let method = request.method().as_str().to_ascii_uppercase();
        let audit = &self.state.audit;

        // Authentication runs before anything else touches routing or the
        // vault. Missing token → 401; wrong (or duplicated) token
        // → 403.
        if let Some(expected) = &self.auth_token
            && let Some(denied) = auth_gate(audit, request.headers(), expected, &method)
        {
            return denied;
        }

        // Concurrency cap: over-limit requests are rejected, never queued.
        let Ok(_permit) = self.in_flight.clone().try_acquire_owned() else {
            return deny_response(audit, None, Some(&method), AuditReason::Overloaded, 503);
        };

        if self.state.is_shutting_down() {
            return empty_status(503);
        }
        let Ok(snapshot) = self.state.snapshots.current() else {
            return empty_status(500);
        };

        // Host comes from the request itself: absolute-form authority,
        // then the Host header. Forwarded/X-Forwarded-Host are never
        // consulted.
        let (host_raw, path, query) = request_target(&request);
        let Ok(host) = normalize_host(&host_raw) else {
            return deny_response(audit, None, Some(&method), AuditReason::NoRoute, 404);
        };

        let rule = match route_rule(audit, &snapshot.config.proxy.rules, &host, &path, &method) {
            Ok(rule) => rule,
            Err(denied) => return *denied,
        };

        let (parts, body) = request.into_parts();
        // The read is deadline-bounded while the in-flight permit is held:
        // a stalled client must release its permit, not pin it forever.
        let body_read = tokio::time::timeout(
            REQUEST_BODY_READ_TIMEOUT,
            read_request_body(body, snapshot.config.daemon.request_body_limit_bytes),
        );
        let body_bytes = match body_read.await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(BodyReadError::TooLarge)) => {
                return deny_response(
                    audit,
                    Some(&rule.name),
                    Some(&method),
                    AuditReason::RequestTooLarge,
                    413,
                );
            }
            Ok(Err(BodyReadError::Incomplete)) => {
                return deny_response(
                    audit,
                    Some(&rule.name),
                    Some(&method),
                    AuditReason::RequestIncomplete,
                    400,
                );
            }
            Err(_stalled) => {
                return deny_response(
                    audit,
                    Some(&rule.name),
                    Some(&method),
                    AuditReason::Timeout,
                    408,
                );
            }
        };

        // Fixed order: sanitize → strip → static → inject.
        let mut forward_headers = sanitize_request_headers(&parts.headers, &rule.strip);
        for (name, value) in &rule.static_headers {
            replace_header(&mut forward_headers, name, value);
        }

        // Credential resolution and template rendering run on the blocking
        // pool (vault reads + AEAD decrypts); any failure fails closed
        // before an upstream request exists.
        let inject_state = Arc::clone(&self.state);
        let inject_rule = rule.clone();
        let injected =
            tokio::task::spawn_blocking(move || resolve_credentials(&inject_state, &inject_rule))
                .await;
        let injected = match injected {
            Ok(Ok(headers)) => headers,
            Ok(Err(failure)) => {
                audit.emit(&AuditEvent::proxy_inject_error(&rule.name, failure.reason));
                return empty_status(500);
            }
            Err(join) => {
                log::error!("credential resolve task failed: {join}");
                audit.emit(&AuditEvent::proxy_inject_error(
                    &rule.name,
                    AuditReason::InjectFailed,
                ));
                return empty_status(500);
            }
        };
        for (name, value) in injected {
            replace_header(&mut forward_headers, &name, &value);
        }

        let upstream_request = UpstreamRequest {
            method,
            url: join_upstream(&rule.upstream, &path, query.as_deref()),
            headers: forward_headers,
            body: body_bytes,
        };
        // Same parsing (and host rules) as load-time upstream validation;
        // only a corrupt snapshot can fail, and the audit field then just
        // comes out empty.
        let audit_upstream_host = upstream_host(&rule.upstream).unwrap_or_default();
        self.forward(upstream_request, &rule.name, &audit_upstream_host, started)
            .await
    }

    /// Execute the upstream call and map the outcome onto the client
    /// response.
    async fn forward(
        &self,
        request: UpstreamRequest,
        rule: &str,
        upstream_host: &str,
        started: Instant,
    ) -> Response {
        let audit = &self.state.audit;
        let audit_method = request.method.clone();
        let client = self.client.clone();
        let outcome = tokio::task::spawn_blocking(move || client.execute(request))
            .await
            .unwrap_or_else(|join| {
                Err(UpstreamError::Transport(format!(
                    "upstream task failed: {join}"
                )))
            });

        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match outcome {
            Ok(upstream) => {
                let status =
                    StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::BAD_GATEWAY);
                let clean_headers = sanitize_response_headers(&upstream.headers);
                let mut builder = Response::builder().status(status);
                for (name, value) in &clean_headers {
                    builder = builder.header(name.clone(), value.clone());
                }
                audit.emit(&AuditEvent::proxy_forward(
                    rule,
                    &audit_method,
                    upstream_host,
                    status.as_u16(),
                    duration_ms,
                ));
                builder
                    .body(AxumBody::from(upstream.body))
                    .unwrap_or_else(|_| Response::new(AxumBody::empty()))
            }
            Err(error) => {
                // The typed audit reason intentionally stays coarse; the
                // run log carries the diagnostic detail (URL-free by
                // construction — see `map_ureq_error`).
                log::warn!("rule '{rule}' upstream call to {upstream_host} failed: {error}");
                let (status, reason) = match error {
                    UpstreamError::Timeout => (504, Some(AuditReason::Timeout)),
                    UpstreamError::ResponseLimit => (502, Some(AuditReason::ResponseTooLarge)),
                    UpstreamError::Connect | UpstreamError::Transport(_) => (502, None),
                };
                audit.emit(&AuditEvent::proxy_forward_with_reason(
                    rule,
                    &audit_method,
                    upstream_host,
                    status,
                    duration_ms,
                    reason,
                ));
                empty_status(status)
            }
        }
    }
}

/// Proxy settings that are fixed at proxy startup: the running proxy state
/// was built from them, so a reload that changes any of them cannot apply
/// and is rejected outright instead of half-applying. Most importantly
/// `proxy.auth`: swapping the snapshot while `ProxyShared::auth_token`
/// keeps its startup value would leave the proxy authenticated (or open)
/// per the *old* mode while `status` reports the new one.
pub(crate) fn reload_runtime_compat(
    active: &AppConfig,
    candidate: &AppConfig,
) -> std::result::Result<(), String> {
    let mut fixed: Vec<&str> = Vec::new();
    if active.proxy.auth != candidate.proxy.auth {
        fixed.push("proxy.auth");
    }
    if active.daemon.listen != candidate.daemon.listen {
        fixed.push("daemon.listen");
    }
    if active.daemon.max_in_flight != candidate.daemon.max_in_flight {
        fixed.push("daemon.max_in_flight");
    }
    if active.daemon.response_body_limit_bytes != candidate.daemon.response_body_limit_bytes {
        fixed.push("daemon.response_body_limit_bytes");
    }
    if active.runtime.timeout != candidate.runtime.timeout {
        fixed.push("runtime.timeout");
    }
    if fixed.is_empty() {
        return Ok(());
    }
    Err(format!(
        "reload cannot apply changes to {} (fixed at proxy startup); restart the daemon to change them",
        fixed.join(", ")
    ))
}

/// Bound proxy listener. Created by [`bind`], driven by [`serve`].
#[derive(Debug)]
pub struct ProxyEndpoint {
    listener: TcpListener,
    /// Actual bound address (useful when configured as `127.0.0.1:0`).
    pub local_addr: SocketAddr,
}

/// Bind the proxy listener when `daemon.listen` is configured.
///
/// Fail closed: the address must parse and must be loopback — a non-
/// loopback TCP listener is rejected even with token authentication
/// configured. Emits the security warning for
/// `proxy.auth = "none"` (which requires an explicit user opt-in; the
/// default is `token`).
///
/// Returns `Ok(None)` when the daemon runs without the proxy.
///
/// # Errors
///
/// Returns an error when the configured listener is invalid, non-
/// loopback, or cannot be bound.
pub async fn bind(state: &DaemonState) -> Result<Option<ProxyEndpoint>> {
    let snapshot = state.snapshots.current()?;
    let Some(listen) = snapshot.config.daemon.listen.clone() else {
        return Ok(None);
    };
    let addr: SocketAddr = listen.parse().map_err(|_| {
        DaemonError::Config(format!(
            "daemon.listen '{listen}' is not a valid socket address"
        ))
    })?;
    if !addr.ip().is_loopback() {
        return Err(DaemonError::Config(format!(
            "daemon.listen '{listen}' must be a loopback address (non-loopback TCP is rejected)"
        )));
    }
    if snapshot.config.proxy.auth == ProxyAuthMode::None {
        log::warn!(
            "security warning: proxy auth is disabled (proxy.auth = \"none\"); \
             every local process can use the credential proxy on {listen}"
        );
    }
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| DaemonError::Internal(format!("binding proxy listener {listen}: {e}")))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| DaemonError::Internal(format!("resolving proxy listener address: {e}")))?;
    log::info!("credential proxy listening on {local_addr}");
    Ok(Some(ProxyEndpoint {
        listener,
        local_addr,
    }))
}

/// Serve the proxy until `shutdown` fires.
///
/// # Errors
///
/// Returns an error when the server loop fails irrecoverably.
pub async fn serve(
    endpoint: ProxyEndpoint,
    shared: Arc<ProxyShared>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if *shutdown.borrow_and_update() {
        return Ok(());
    }
    let app = Router::new().fallback(proxy_handler).with_state(shared);
    axum::serve(endpoint.listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
        .map_err(|e| DaemonError::Internal(format!("proxy server stopped: {e}")))
}

async fn proxy_handler(State(shared): State<Arc<ProxyShared>>, request: Request) -> Response {
    shared.handle(request).await
}

/// Token gate: `None` lets the request through; a `Some(response)`
/// is the rejection. Missing token → 401; wrong, duplicated, or
/// non-UTF-8 token → 403.
fn auth_gate(
    audit: &AuditSink,
    headers: &HeaderMap,
    expected: &str,
    method: &str,
) -> Option<Response> {
    let rejected = |status: u16| {
        Some(deny_response(
            audit,
            None,
            Some(method),
            AuditReason::AuthRejected,
            status,
        ))
    };
    match single_header_value(headers, PROXY_TOKEN_HEADER) {
        TokenHeader::Missing => rejected(401),
        TokenHeader::Invalid => rejected(403),
        TokenHeader::Present(candidate) => {
            if crate::lifecycle::token_matches(&candidate, expected) {
                None
            } else {
                rejected(403)
            }
        }
    }
}

/// Route against the rule set; `Err(response)` is the boxed 404/405/500
/// denial. Returns a borrow of the winning rule inside `rules`.
fn route_rule<'a>(
    audit: &AuditSink,
    rules: &'a [ProxyRuleConfig],
    host: &str,
    path: &str,
    method: &str,
) -> std::result::Result<&'a ProxyRuleConfig, Box<Response>> {
    match match_rule(rules, host, path, method) {
        RuleMatch::Matched(rule) => Ok(rule),
        RuleMatch::Ambiguous(_) => Err(Box::new(deny_response(
            // Impossible with a validated snapshot (load-time ambiguity
            // rejection), but fail closed anyway.
            audit,
            None,
            Some(method),
            AuditReason::AmbiguousRoute,
            500,
        ))),
        // Host+path covered but the method is not (CONNECT/TRACE always
        // land here): 405, not 404.
        RuleMatch::MethodNotAllowed => Err(Box::new(deny_response(
            audit,
            None,
            Some(method),
            AuditReason::MethodForbidden,
            405,
        ))),
        RuleMatch::NoMatch => Err(Box::new(deny_response(
            audit,
            None,
            Some(method),
            AuditReason::NoRoute,
            404,
        ))),
    }
}

/// Why a request body could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyReadError {
    /// The body exceeded the configured limit.
    TooLarge,
    /// The client hung up or sent malformed framing mid-body.
    Incomplete,
}

/// Read the request body, enforcing `limit` strictly: `to_bytes` reads at
/// most `limit+1` bytes, so a mid-read failure means the client hung up or
/// sent malformed framing (not an oversize body).
async fn read_request_body(
    body: AxumBody,
    limit: u64,
) -> std::result::Result<Bytes, BodyReadError> {
    let capped = usize::try_from(limit.saturating_add(1)).unwrap_or(usize::MAX);
    let bytes = axum::body::to_bytes(body, capped)
        .await
        .map_err(|_| BodyReadError::Incomplete)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(BodyReadError::TooLarge);
    }
    Ok(bytes)
}

/// Body-less response with the given raw status code.
fn empty_status(status: u16) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Response::builder()
        .status(code)
        .body(AxumBody::empty())
        .unwrap_or_else(|_| Response::new(AxumBody::empty()))
}

/// Emit a `proxy_deny` audit event and build the denial response.
fn deny_response(
    audit: &AuditSink,
    rule: Option<&str>,
    method: Option<&str>,
    reason: AuditReason,
    status: u16,
) -> Response {
    audit.emit(&AuditEvent::proxy_deny(rule, method, reason));
    empty_status(status)
}

/// What the `X-Kyz-Proxy-Token` header carried.
enum TokenHeader {
    /// Header absent.
    Missing,
    /// Header present but unusable (repeated or non-UTF-8).
    Invalid,
    /// One usable value.
    Present(String),
}

/// Extract the single value of a header.
fn single_header_value(headers: &HeaderMap, name: &str) -> TokenHeader {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return TokenHeader::Missing;
    };
    if values.next().is_some() {
        return TokenHeader::Invalid;
    }
    first.to_str().map_or(TokenHeader::Invalid, |value| {
        TokenHeader::Present(value.to_string())
    })
}

/// Request target decomposition: (host, path, query).
///
/// Absolute-form request targets (`GET http://host/path`) expose the
/// authority from the URI; origin-form requests fall back to the `Host`
/// header (HTTP/1) — hyper maps HTTP/2 `:authority` onto the URI
/// authority, which the first branch already covers.
fn request_target(request: &Request) -> (String, String, Option<String>) {
    let uri = request.uri();
    if let Some(authority) = uri.authority() {
        return (
            authority.as_str().to_string(),
            uri.path().to_string(),
            uri.query().map(String::from),
        );
    }
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (host, uri.path().to_string(), uri.query().map(String::from))
}

/// Header names nominated as hop-by-hop by `Connection` values:
/// `Connection` lists its tokens comma-separated, and each nominated name
/// is dropped alongside the static hop-by-hop set.
fn connection_nominated(headers: &HeaderMap) -> Vec<String> {
    let mut nominated = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        let Ok(text) = value.to_str() else { continue };
        for token in text.split(',') {
            let token = token.trim().to_ascii_lowercase();
            if !token.is_empty() {
                nominated.push(token);
            }
        }
    }
    nominated
}

/// Sanitize client request headers for forwarding.
///
/// Drops hop-by-hop headers (including `Connection`-nominated ones), the
/// proxy token, `Host` (the upstream URL's fixed authority decides the
/// destination), `Content-Length` (kyz re-frames the request), and
/// every occurrence of the rule's credential strip set. Non-UTF-8 header
/// values cannot be represented in the sanitized pipeline and are
/// dropped.
fn sanitize_request_headers(headers: &HeaderMap, strip: &[String]) -> Vec<(String, String)> {
    let strip: Vec<String> = strip.iter().map(|s| s.to_ascii_lowercase()).collect();
    let connection_nominated = connection_nominated(headers);
    let mut out = Vec::new();
    for (name, value) in headers {
        let name = name.as_str();
        if HOP_BY_HOP_HEADERS.contains(&name)
            || connection_nominated.iter().any(|n| n == name)
            || name == PROXY_TOKEN_HEADER
            || name == "host"
            || name == "content-length"
            || strip.iter().any(|s| s == name)
        {
            continue;
        }
        if let Ok(value) = value.to_str() {
            out.push((name.to_string(), value.to_string()));
        }
    }
    out
}

/// Sanitize upstream response headers for the client: hop-by-hop
/// removal — including headers the upstream's `Connection` nominations
/// mark hop-by-hop, symmetric with the request direction (RFC 7230 §6.1);
/// kyz regenerates the client response framing, so `Content-Length` is
/// dropped too.
fn sanitize_response_headers(headers: &HeaderMap) -> HeaderMap {
    let connection_nominated = connection_nominated(headers);
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if !HOP_BY_HOP_HEADERS.contains(&name.as_str())
            && !connection_nominated.iter().any(|n| n == name.as_str())
            && name != "content-length"
        {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Replace every occurrence of `name` with the single `value`.
///
/// Injection is replace-style: a client-supplied duplicate cannot
/// survive next to the injected value.
fn replace_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
    headers.push((name.to_string(), value.to_string()));
}

/// Join the rule's fixed upstream base with the client path and query.
/// The upstream authority alone decides the destination.
fn join_upstream(upstream: &str, path: &str, query: Option<&str>) -> String {
    let base = upstream.trim_end_matches('/');
    match query {
        Some(query) if !query.is_empty() => format!("{base}{path}?{query}"),
        _ => format!("{base}{path}"),
    }
}

/// Runtime credential-injection failure. The reason is a typed
/// audit category — never free text, so no secret material can be
/// interpolated into an audit line.
#[derive(Debug, Clone)]
struct InjectFailure {
    reason: AuditReason,
}

/// Resolve every credential of a rule and render its header templates.
///
/// Fields resolve live through the in-memory vault (`kyz set` updates are
/// visible on the next request). Any missing secret/field, empty
/// field, decrypt failure, vault read failure, or invalid rendered header
/// value fails the whole injection — there is no partial inject.
fn resolve_credentials(
    state: &DaemonState,
    rule: &ProxyRuleConfig,
) -> std::result::Result<Vec<(String, String)>, InjectFailure> {
    let inject_failed = || InjectFailure {
        reason: AuditReason::InjectFailed,
    };

    let mut values: BTreeMap<(String, String), String> = BTreeMap::new();
    for credential in &rule.credentials {
        let resolved = state
            .resolve_fields(&credential.service, &credential.key, &credential.fields)
            .map_err(|e| InjectFailure {
                reason: classify_core_error(&e),
            })?;
        for field in &credential.fields {
            let value = resolved.get(field).ok_or_else(inject_failed)?;
            if value.expose_secret().is_empty() {
                return Err(inject_failed());
            }
            values.insert(
                (credential.alias.clone(), field.clone()),
                value.expose_secret().to_string(),
            );
        }
    }

    let mut rendered = Vec::new();
    for (header_name, template) in &rule.headers {
        let value = render_template(template, |alias, field| {
            values.get(&(alias.to_string(), field.to_string())).cloned()
        })
        .map_err(|_| InjectFailure {
            reason: AuditReason::MissingSecret,
        })?;
        if HeaderValue::from_str(&value).is_err() {
            return Err(inject_failed());
        }
        rendered.push((header_name.clone(), value));
    }
    Ok(rendered)
}

const fn classify_core_error(error: &CoreError) -> AuditReason {
    match error {
        CoreError::SecretNotFound(_) => AuditReason::MissingSecret,
        _ => AuditReason::InjectFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_sanitizer_strips_everything_hostile() {
        let mut headers = HeaderMap::new();
        headers.append("host", HeaderValue::from_static("api.example.com"));
        headers.append("authorization", HeaderValue::from_static("Bearer client"));
        headers.append(
            "authorization",
            HeaderValue::from_static("Bearer duplicate"),
        );
        headers.append("x-kyz-proxy-token", HeaderValue::from_static("secret"));
        headers.append("connection", HeaderValue::from_static("x-nominated"));
        headers.append("x-nominated", HeaderValue::from_static("gone"));
        headers.append("content-type", HeaderValue::from_static("application/json"));
        headers.append("x-keep", HeaderValue::from_static("yes"));

        let strip = vec!["Authorization".to_string(), "X-Api-Key".to_string()];
        let out = sanitize_request_headers(&headers, &strip);
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["content-type", "x-keep"]);
        assert_eq!(out[0].1, "application/json");
    }

    #[test]
    fn response_sanitizer_drops_hop_by_hop_and_length() {
        let mut headers = HeaderMap::new();
        headers.append("connection", HeaderValue::from_static("close"));
        headers.append("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.append("content-length", HeaderValue::from_static("42"));
        headers.append("content-type", HeaderValue::from_static("application/json"));
        headers.append("trailer", HeaderValue::from_static("X-Some-Trailer"));
        headers.append("x-custom", HeaderValue::from_static("end-to-end"));

        let out = sanitize_response_headers(&headers);
        let mut names: Vec<&str> = out.keys().map(axum::http::HeaderName::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["content-type", "x-custom"]);
        assert_eq!(
            out.get("content-type"),
            Some(&HeaderValue::from_static("application/json"))
        );
    }

    #[test]
    fn response_sanitizer_drops_connection_nominated_headers() {
        // RFC 7230 §6.1: headers named by the upstream's `Connection` value
        // are hop-by-hop and must not reach the local client — symmetric
        // with the request direction.
        let mut headers = HeaderMap::new();
        headers.append(
            "connection",
            HeaderValue::from_static("X-Upstream-Internal"),
        );
        headers.append("x-upstream-internal", HeaderValue::from_static("hop-state"));
        headers.append("x-keep", HeaderValue::from_static("end-to-end"));

        let out = sanitize_response_headers(&headers);
        assert!(out.get("x-upstream-internal").is_none());
        assert_eq!(
            out.get("x-keep"),
            Some(&HeaderValue::from_static("end-to-end"))
        );
    }

    #[test]
    fn replace_header_removes_duplicates() {
        let mut headers = vec![
            ("X-Api-Key".to_string(), "client-value".to_string()),
            ("x-api-key".to_string(), "duplicate".to_string()),
            ("Other".to_string(), "v".to_string()),
        ];
        replace_header(&mut headers, "X-Api-Key", "injected");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], ("Other".to_string(), "v".to_string()));
        assert_eq!(
            headers[1],
            ("X-Api-Key".to_string(), "injected".to_string())
        );
    }

    #[test]
    fn join_upstream_appends_path_and_query() {
        assert_eq!(
            join_upstream("https://api.example.com", "/v1/items", None),
            "https://api.example.com/v1/items"
        );
        assert_eq!(
            join_upstream("https://api.example.com/", "/v1/items", Some("a=1&b=2")),
            "https://api.example.com/v1/items?a=1&b=2"
        );
        assert_eq!(
            join_upstream("https://api.example.com/base", "/x", Some("")),
            "https://api.example.com/base/x"
        );
    }

    #[test]
    fn single_header_value_classifies_presence() {
        let mut headers = HeaderMap::new();
        headers.append("x-a", HeaderValue::from_static("1"));
        assert!(matches!(
            single_header_value(&headers, "x-a"),
            TokenHeader::Present(value) if value == "1"
        ));
        assert!(matches!(
            single_header_value(&headers, "x-b"),
            TokenHeader::Missing
        ));
        headers.append("x-a", HeaderValue::from_static("2"));
        assert!(matches!(
            single_header_value(&headers, "x-a"),
            TokenHeader::Invalid
        ));
    }
}
