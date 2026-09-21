//! Dedicated HTTPS upstream client for the credential proxy.
//!
//! The agent is built once per daemon and deliberately deviates from every
//! `ureq` default that would be unsafe for a credential proxy:
//!
//! - redirects disabled (`max_redirects = 0`): a credential proxy must
//!   never follow a redirect and carry injected auth headers to another
//!   origin — 301/302/303/307/308 are returned to the client verbatim;
//! - `http_status_as_error = false`: upstream 4xx/5xx pass through as
//!   responses, not errors;
//! - `https_only`: belt-and-suspenders behind the rule-level `https://`
//!   validation;
//! - `proxy = None`: `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` environment
//!   variables are never inherited (`ureq` reads them by default);
//! - certificate validation left enabled (rustls `WebPki` roots);
//! - a bounded global request timeout.
//!
//! All calls are synchronous (`ureq` is blocking); proxy handlers wrap
//! them in `tokio::task::spawn_blocking`.

use std::io::Read as _;
use std::time::Duration;

use bytes::Bytes;
use ureq::tls::{RootCerts, TlsConfig};

/// Default upstream request timeout (seconds) when the config carries
/// none.
pub const DEFAULT_UPSTREAM_TIMEOUT_SECS: u64 = 60;

/// Error kinds mapped to client-facing statuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    /// Any configured timeout fired (DNS, connect, response, body).
    Timeout,
    /// DNS resolution, TCP connect, or TLS failure.
    Connect,
    /// Upstream response body exceeded the configured limit.
    ResponseLimit,
    /// Any other transport failure while talking to the upstream.
    Transport(String),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "upstream timed out"),
            Self::Connect => write!(f, "upstream DNS/connect/TLS failed"),
            Self::ResponseLimit => write!(f, "upstream response exceeded the size limit"),
            Self::Transport(reason) => write!(f, "upstream transport failed: {reason}"),
        }
    }
}

/// One sanitized, credential-injected request ready for the upstream.
#[derive(Debug, Clone)]
pub struct UpstreamRequest {
    /// Uppercase HTTP method (never `CONNECT`/`TRACE`; those are rejected
    /// at the routing layer).
    pub method: String,
    /// Absolute URL built from the rule's fixed `upstream` plus the client
    /// path and query.
    pub url: String,
    /// Header list after hop-by-hop sanitization and credential injection.
    pub headers: Vec<(String, String)>,
    /// Request body (possibly empty). Cheap to clone: the bytes are
    /// reference-counted straight from the client's read buffer.
    pub body: Bytes,
}

/// One upstream response, already bounded by the response body limit.
#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    /// Upstream status code.
    pub status: u16,
    /// Response headers as received (hop-by-hop headers are stripped
    /// later, when the client response is assembled).
    pub headers: ureq::http::HeaderMap,
    /// Response body bytes (empty when the upstream sent none).
    pub body: Vec<u8>,
}

/// The daemon's upstream client.
#[derive(Debug, Clone)]
pub struct UpstreamClient {
    agent: ureq::Agent,
    response_limit: u64,
}

impl UpstreamClient {
    /// Build the production client: system roots, bounded timeout.
    #[must_use]
    pub fn new(timeout: Duration, response_limit: u64) -> Self {
        Self::build(timeout, response_limit, None)
    }

    /// Test seam: identical hardening, but trusting only
    /// the provided PEM CA certificate instead of system roots. Never
    /// exposed through user configuration.
    #[doc(hidden)]
    #[must_use]
    pub fn with_root_certs(timeout: Duration, response_limit: u64, ca_pem: &str) -> Self {
        // The seam trusts exactly the mock CA: a single anchor is all it
        // needs, and an unparseable PEM yields an empty root set (fail
        // closed) rather than falling back to system roots.
        let root_certs = ureq::tls::Certificate::from_pem(ca_pem.as_bytes()).map_or_else(
            |_| RootCerts::from(Vec::new()),
            |cert| RootCerts::from(vec![cert]),
        );
        Self::build(timeout, response_limit, Some(root_certs))
    }

    fn build(timeout: Duration, response_limit: u64, roots: Option<RootCerts>) -> Self {
        let mut tls = TlsConfig::builder();
        if let Some(roots) = roots {
            tls = tls.root_certs(roots);
        }
        let config = ureq::config::Config::builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .https_only(true)
            // ureq's default config inherits HTTP(S)_PROXY/ALL_PROXY from
            // the environment; the daemon's upstream traffic must always
            // be direct.
            .proxy(None)
            .timeout_global(Some(timeout.max(Duration::from_secs(1))))
            .tls_config(tls.build())
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            response_limit,
        }
    }

    /// Whether the agent resolved any proxy from the environment.
    ///
    /// Always `false` by construction; tests assert this so a regression
    /// to ureq's default env inheritance cannot land silently.
    #[doc(hidden)]
    #[must_use]
    pub fn agent_uses_no_proxy(&self) -> bool {
        self.agent.config().proxy().is_none()
    }

    /// Execute one request synchronously, consuming it.
    ///
    /// Redirect responses are returned as normal [`UpstreamResponse`]
    /// values (`max_redirects = 0` disables following).
    ///
    /// # Errors
    ///
    /// Returns [`UpstreamError`] mapped to client statuses: timeouts →
    /// [`UpstreamError::Timeout`], DNS/connect/TLS →
    /// [`UpstreamError::Connect`], oversized response bodies →
    /// [`UpstreamError::ResponseLimit`].
    pub fn execute(&self, request: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
        let build_err =
            |e: ureq::http::Error| UpstreamError::Transport(format!("building request: {e}"));
        let UpstreamRequest {
            method,
            url,
            headers,
            body,
        } = request;
        let mut builder = ureq::http::Request::builder().method(method.as_str());
        for (name, value) in &headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        // An empty body would still produce a `Content-Length: 0`
        // frame on body-less methods; `()` keeps them truly bodiless.
        let response = if body.is_empty() {
            let http_request = builder.uri(url.as_str()).body(()).map_err(build_err)?;
            self.agent.run(http_request)
        } else {
            // `&[u8]` hands ureq the body without another copy.
            let http_request = builder
                .uri(url.as_str())
                .body(body.as_ref())
                .map_err(build_err)?;
            self.agent.run(http_request)
        }
        .map_err(|e| map_ureq_error(&e))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = read_body_bounded(response.into_body(), self.response_limit)?;
        Ok(UpstreamResponse {
            status,
            headers,
            body,
        })
    }
}

/// Read a response body, failing once it exceeds `limit` bytes.
fn read_body_bounded(mut body: ureq::Body, limit: u64) -> Result<Vec<u8>, UpstreamError> {
    let mut buf = Vec::new();
    let mut reader = body.as_reader();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|e| map_ureq_error(&ureq::Error::Io(e)))?;
        if read == 0 {
            return Ok(buf);
        }
        if u64::try_from(buf.len() + read).map_or(true, |total| total > limit) {
            return Err(UpstreamError::ResponseLimit);
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// Map a `ureq` error onto the client-facing categories.
///
/// The reasons carried by [`UpstreamError::Transport`] are URL-free: the
/// joined URL embeds the client's path and query, which must not leak into
/// logs, so the variants whose `Display` embeds the URL are replaced with
/// fixed text here.
fn map_ureq_error(error: &ureq::Error) -> UpstreamError {
    match error {
        ureq::Error::Timeout(_) => UpstreamError::Timeout,
        ureq::Error::HostNotFound
        | ureq::Error::Tls(_)
        | ureq::Error::Rustls(_)
        | ureq::Error::ConnectionFailed => UpstreamError::Connect,
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => UpstreamError::Timeout,
        // These embed the full URL in their `Display`.
        ureq::Error::BadUri(_) => {
            UpstreamError::Transport("upstream URL is not a valid URI".to_string())
        }
        ureq::Error::RequireHttpsOnly(_) => {
            UpstreamError::Transport("upstream URL is not https".to_string())
        }
        _ => UpstreamError::Transport(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_agent_never_uses_a_proxy() {
        let client = UpstreamClient::new(Duration::from_secs(DEFAULT_UPSTREAM_TIMEOUT_SECS), 1024);
        assert!(
            client.agent_uses_no_proxy(),
            "upstream agent must not resolve env proxies"
        );
    }

    #[test]
    fn test_seam_agent_also_direct() {
        let client = UpstreamClient::with_root_certs(
            Duration::from_secs(DEFAULT_UPSTREAM_TIMEOUT_SECS),
            1024,
            "",
        );
        assert!(client.agent_uses_no_proxy());
    }

    #[test]
    fn errors_render_without_leaking_urls() {
        assert_eq!(UpstreamError::Timeout.to_string(), "upstream timed out");
        assert!(UpstreamError::Connect.to_string().contains("TLS"));
    }
}
