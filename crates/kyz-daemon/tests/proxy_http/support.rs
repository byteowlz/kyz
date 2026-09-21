//! Test doubles for the HTTP credential proxy: a scripted HTTPS mock
//! upstream with a self-signed CA, a byte-level raw HTTP/1.1 client for
//! driving the proxy with full control over request bytes (duplicate
//! headers, hostile `Connection` tokens, oversized bodies), and a
//! `ProxyFixture` wiring everything to the shared daemon fixture.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use secrecy::SecretString;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, ReadHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::common::{FIXTURE_PASSPHRASE, Fixture};
use kyz_core::store::SecretEntry;
use kyz_daemon::upstream::UpstreamClient;

/// One request captured by the mock upstream.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// Uppercase HTTP method.
    pub method: String,
    /// Request target exactly as received (path + query).
    pub target: String,
    /// Header pairs as received (names lowercased; duplicates preserved).
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// All values of a header (case-insensitive).
    #[must_use]
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// A scripted upstream response.
#[derive(Debug, Clone)]
pub struct ScriptedResponse {
    /// HTTP status code.
    pub status: u16,
    /// Extra response headers.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// Delay before responding (timeout tests).
    pub delay: Option<Duration>,
}

impl ScriptedResponse {
    /// A plain `status` response with an empty body.
    #[must_use]
    pub const fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            delay: None,
        }
    }

    /// A `status` response with extra headers.
    #[must_use]
    pub const fn with_headers(status: u16, headers: Vec<(String, String)>) -> Self {
        Self {
            status,
            headers,
            body: Vec::new(),
            delay: None,
        }
    }

    /// A `status` response with a body.
    #[must_use]
    pub fn with_body(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
            delay: None,
        }
    }

    /// Delay this response.
    #[must_use]
    pub const fn delayed(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

/// Cap on any single mock connection, so a broken test fails instead of
/// hanging.
const CONN_TIMEOUT: Duration = Duration::from_secs(15);

/// A single-threaded tokio runtime handle for the mock server thread.
struct MockRuntime {
    thread: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl MockRuntime {
    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for MockRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// Scripted HTTPS mock upstream trusted by the daemon under test via
/// [`kyz_daemon::UpstreamClient::with_root_certs`].
pub struct MockUpstream {
    /// Base URL for rule `upstream` values (`https://127.0.0.1:port`).
    pub url: String,
    /// CA certificate (PEM) the daemon's test client must trust.
    pub ca_pem: String,
    recorded: Arc<Mutex<Vec<RecordedRequest>>>,
    script: Arc<Mutex<VecDeque<ScriptedResponse>>>,
    runtime: MockRuntime,
}

impl MockUpstream {
    /// Start the mock on an OS-assigned loopback port with a fresh
    /// self-signed CA for `127.0.0.1`.
    pub fn start() -> Self {
        let (cert_pem, server_config) = self_signed_config();
        let recorded: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let script: Arc<Mutex<VecDeque<ScriptedResponse>>> = Arc::new(Mutex::new(VecDeque::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let (addr_tx, addr_rx) = std::sync::mpsc::channel::<SocketAddr>();
        let thread_recorded = Arc::clone(&recorded);
        let thread_script = Arc::clone(&script);
        let thread_stop = Arc::clone(&stop);
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let thread = std::thread::Builder::new()
            .name("mock-upstream".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("mock runtime");
                runtime.block_on(async move {
                    let listener = tokio::net::TcpListener::bind(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        0,
                    ))
                    .await
                    .expect("mock bind");
                    addr_tx
                        .send(listener.local_addr().expect("mock local addr"))
                        .expect("mock addr channel");
                    loop {
                        if thread_stop.load(Ordering::Acquire) {
                            break;
                        }
                        let accepted =
                            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                                .await;
                        let Ok(Ok((stream, _))) = accepted else {
                            continue;
                        };
                        let acceptor = acceptor.clone();
                        let recorded = Arc::clone(&thread_recorded);
                        let script = Arc::clone(&thread_script);
                        tokio::spawn(async move {
                            let Ok(Ok(tls)) =
                                tokio::time::timeout(CONN_TIMEOUT, acceptor.accept(stream)).await
                            else {
                                return;
                            };
                            let (mut reader, mut writer) = tokio::io::split(tls);
                            if let Some(response) = serve_one(&mut reader, &recorded, &script).await
                            {
                                if let Some(delay) = response.delay {
                                    tokio::time::sleep(delay).await;
                                }
                                let _ = writer.write_all(&encode_response(&response)).await;
                                let _ = writer.shutdown().await;
                            }
                        });
                    }
                });
            })
            .expect("spawn mock upstream thread");

        let addr = addr_rx.recv().expect("mock upstream address");
        Self {
            url: format!("https://{addr}"),
            ca_pem: cert_pem,
            recorded,
            script,
            runtime: MockRuntime {
                thread: Some(thread),
                stop,
            },
        }
    }

    /// Queue a scripted response (served in FIFO order; an empty queue
    /// answers `200` with an empty body).
    pub fn push_response(&self, response: ScriptedResponse) {
        if let Ok(mut script) = self.script.lock() {
            script.push_back(response);
        }
    }

    /// All requests recorded so far.
    #[must_use]
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.recorded.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Drop all recorded requests.
    pub fn clear_requests(&self) {
        if let Ok(mut recorded) = self.recorded.lock() {
            recorded.clear();
        }
    }

    /// Wait until at least `count` requests have been recorded.
    pub async fn wait_for_requests(&self, count: usize) -> Vec<RecordedRequest> {
        for _ in 0..200 {
            if let Ok(recorded) = self.recorded.lock()
                && recorded.len() >= count
            {
                return recorded.clone();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.requests()
    }

    /// Stop the mock server thread.
    pub fn stop(self) {
        self.runtime.stop();
    }
}

/// Read exactly one HTTP/1.1 request (headers + Content-Length body),
/// record it, and return the scripted response for it.
async fn serve_one(
    reader: &mut ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    recorded: &Arc<Mutex<Vec<RecordedRequest>>>,
    script: &Arc<Mutex<VecDeque<ScriptedResponse>>>,
) -> Option<ScriptedResponse> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        let read = tokio::time::timeout(CONN_TIMEOUT, reader.read(&mut chunk))
            .await
            .ok()
            .and_then(Result::ok)?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let split = buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator found above");
    let head = String::from_utf8_lossy(&buffer[..split]).into_owned();
    let mut rest = buffer[split + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let request_line = lines.next()?.to_string();
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_ascii_uppercase();
    let target = parts.next()?.to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let content_length = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    while rest.len() < content_length {
        let read = tokio::time::timeout(CONN_TIMEOUT, reader.read(&mut chunk))
            .await
            .ok()
            .and_then(Result::ok)?;
        if read == 0 {
            break;
        }
        rest.extend_from_slice(&chunk[..read]);
    }
    let body = rest[..content_length.min(rest.len())].to_vec();

    if let Ok(mut recorded) = recorded.lock() {
        recorded.push(RecordedRequest {
            method,
            target,
            headers,
            body,
        });
    }
    Some(
        script
            .lock()
            .ok()
            .and_then(|mut queue| queue.pop_front())
            .unwrap_or_else(|| ScriptedResponse::status(200)),
    )
}

/// Generate a self-signed cert for `127.0.0.1` and the matching rustls
/// server config.
fn self_signed_config() -> (String, rustls::ServerConfig) {
    let mut params = rcgen::CertificateParams::default();
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let key_pair = rcgen::KeyPair::generate().expect("generate mock key");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");
    let cert_pem = cert.pem();
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("rustls protocol versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
    )
    .expect("mock server cert");
    (cert_pem, server_config)
}

/// Minimal HTTP/1.1 response encoder (`Connection: close`, explicit
/// `Content-Length`, or chunked framing when the script asks for
/// `Transfer-Encoding: chunked`). Scripted `Connection` headers are
/// emitted verbatim (connection-nomination tests rely on them); the mock
/// additionally appends its own `Connection: close`, which owns the actual
/// connection lifecycle.
fn encode_response(response: &ScriptedResponse) -> Vec<u8> {
    let reason = reason_phrase(response.status);
    let chunked = response.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked")
    });
    let mut head = format!("HTTP/1.1 {} {}\r\n", response.status, reason);
    for (name, value) in &response.headers {
        write!(head, "{name}: {value}\r\n").expect("infallible string write");
    }
    let body = if chunked {
        let mut framed = format!("{:x}\r\n", response.body.len()).into_bytes();
        framed.extend_from_slice(&response.body);
        framed.extend_from_slice(b"\r\n0\r\n\r\n");
        framed
    } else {
        write!(head, "Content-Length: {}\r\n", response.body.len())
            .expect("infallible string write");
        response.body.clone()
    };
    head.push_str("Connection: close\r\n\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&body);
    bytes
}

const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

/// A parsed HTTP/1.1 response from the proxy.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Header pairs (names lowercased; duplicates preserved).
    pub headers: Vec<(String, String)>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// All values of a header (case-insensitive).
    #[must_use]
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// Send one raw HTTP/1.1 request to the proxy. The request always carries
/// `Connection: close`, so the response can be read to EOF.
///
/// `headers` are appended verbatim after the `Host` header (duplicates
/// allowed — that is the point).
pub async fn send_http(
    addr: SocketAddr,
    method: &str,
    host: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> std::io::Result<HttpResponse> {
    send_http_head(addr, method, host, target, headers, "", body).await
}

/// Like [`send_http`] but frames the body with `Transfer-Encoding:
/// chunked` (properly encoded) — for exercising the request-side
/// hop-by-hop handling of transfer framing.
pub async fn send_http_chunked(
    addr: SocketAddr,
    method: &str,
    host: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> std::io::Result<HttpResponse> {
    let chunked = format!("{:x}\r\n", body.len());
    let mut framed = chunked.into_bytes();
    framed.extend_from_slice(body);
    framed.extend_from_slice(b"\r\n0\r\n\r\n");
    send_http_head(
        addr,
        method,
        host,
        target,
        headers,
        "Transfer-Encoding: chunked\r\n",
        &framed,
    )
    .await
}

async fn send_http_head(
    addr: SocketAddr,
    method: &str,
    host: &str,
    target: &str,
    headers: &[(String, String)],
    extra_head: &str,
    body: &[u8],
) -> std::io::Result<HttpResponse> {
    let mut stream = tokio::time::timeout(CONN_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let mut request = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in headers {
        write!(request, "{name}: {value}\r\n").expect("infallible string write");
    }
    if !body.is_empty() && extra_head.is_empty() {
        write!(request, "Content-Length: {}\r\n", body.len()).expect("infallible string write");
    }
    request.push_str(extra_head);
    request.push_str("Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;

    let mut raw = Vec::new();
    tokio::time::timeout(CONN_TIMEOUT, stream.read_to_end(&mut raw))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "response timeout"))??;
    parse_response(&raw)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad response"))
}

/// Parse a full HTTP/1.1 response from buffered bytes.
fn parse_response(raw: &[u8]) -> Option<HttpResponse> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let status = status_line.split(' ').nth(1)?.parse::<u16>().ok()?;

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_string());
        if name == "content-length" {
            content_length = value.parse().ok();
        }
        headers.push((name, value));
    }
    let body_bytes = &raw[split + 4..];
    let body = content_length.map_or_else(
        || body_bytes.to_vec(),
        |length| body_bytes[..length.min(body_bytes.len())].to_vec(),
    );
    Some(HttpResponse {
        status,
        headers,
        body,
    })
}

/// Spawn a plain-TCP listener that speaks garbage TLS and immediately
/// closes — pointing an `https://` rule at it yields a TLS failure (502).
pub fn spawn_tls_garbage_listener() -> SocketAddr {
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("garbage bind");
    let addr = listener.local_addr().expect("garbage addr");
    std::thread::Builder::new()
        .name("tls-garbage".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                let _ = stream.write_all(b"not a tls record\r\n");
            }
        })
        .expect("spawn garbage listener");
    addr
}

/// Send one authorized request with a *partially written* body: the head
/// declares `Content-Length: declared` but only `written` bytes follow and
/// the connection stays open. Reads the response to EOF with no timeout
/// wrappers of its own — usable on `start_paused` runtimes, where the
/// daemon's body-read deadline is advanced by the runtime instead of real
/// time.
pub async fn send_http_stalled_body(
    addr: SocketAddr,
    host: &str,
    target: &str,
    token: &str,
    declared: usize,
    written: &[u8],
) -> std::io::Result<HttpResponse> {
    let mut stream = TcpStream::connect(addr).await?;
    let head = format!(
        "POST {target} HTTP/1.1\r\nHost: {host}\r\nX-Kyz-Proxy-Token: {token}\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(written).await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    parse_response(&raw)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad response"))
}

/// Send one authorized request without any timeout wrappers (for paused
/// runtimes; see [`send_http_stalled_body`]).
pub async fn send_http_untimed(
    addr: SocketAddr,
    method: &str,
    host: &str,
    target: &str,
    token: &str,
    body: &[u8],
) -> std::io::Result<HttpResponse> {
    let mut stream = TcpStream::connect(addr).await?;
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nX-Kyz-Proxy-Token: {token}\r\nConnection: close\r\n"
    );
    if !body.is_empty() {
        write!(head, "Content-Length: {}\r\n", body.len()).expect("infallible string write");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    parse_response(&raw)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad response"))
}

/// A proxy-enabled daemon fixture: shared vault fixture + scripted HTTPS
/// mock upstream + helpers for driving the running daemon.
pub struct ProxyFixture {
    /// The shared fixture (temp dirs, vault, config).
    pub fixture: Fixture,
    /// The scripted HTTPS upstream rules point at.
    pub mock: MockUpstream,
}

impl ProxyFixture {
    /// Create the fixture pair. The config file still carries the plain
    /// no-proxy default; call [`ProxyFixture::write_config`] with the
    /// scenario's rules before [`ProxyFixture::start`].
    pub fn new() -> Self {
        Self {
            fixture: Fixture::new(),
            mock: MockUpstream::start(),
        }
    }

    /// An upstream client trusting the mock's CA (test seam).
    #[must_use]
    pub fn test_client(&self, timeout_secs: u64, response_limit: u64) -> UpstreamClient {
        UpstreamClient::with_root_certs(
            Duration::from_secs(timeout_secs),
            response_limit,
            &self.mock.ca_pem,
        )
    }

    /// A standard proxy config: token auth, loopback listener on an
    /// OS-assigned port, and `rules_toml` appended under `[[proxy.rules]]`
    /// with `upstream` already pointing at the mock.
    pub fn write_config(&self, rules_toml: &str) {
        self.write_config_with(rules_toml, "");
    }

    /// Like [`ProxyFixture::write_config`] with extra raw `[daemon]`
    /// lines (limits, concurrency).
    pub fn write_config_with(&self, rules_toml: &str, extra: &str) {
        self.write_config_raw("127.0.0.1:0", "token", rules_toml, extra);
    }

    /// Full control over listener and proxy auth mode, for the startup
    /// fail-closed and auth opt-out scenarios. `upstream` in `rules_toml`
    /// still points at the mock.
    pub fn write_config_raw(&self, listen: &str, auth: &str, rules_toml: &str, extra: &str) {
        let config = format!(
            "profile = \"default\"\n\n[runtime]\ntimeout = 30\n\n[daemon]\nlisten = \
             \"{listen}\"\n{extra}timeout_secs = 0\n\n[proxy]\nauth = \"{auth}\"\n{rules_toml}\n"
        );
        std::fs::write(&self.fixture.config_path, config).expect("rewrite fixture config");
    }

    /// Start the daemon with the mock-CA upstream client.
    pub async fn start(&self) -> crate::common::GuardedDaemon {
        self.start_with(30, u64::MAX).await
    }

    /// Start with an explicit upstream timeout (seconds) and response
    /// body limit for limit tests.
    pub async fn start_with(
        &self,
        timeout_secs: u64,
        response_limit: u64,
    ) -> crate::common::GuardedDaemon {
        self.fixture
            .start_with_client(None, Some(self.test_client(timeout_secs, response_limit)))
            .await
    }

    /// The running daemon's proxy bearer token.
    pub fn proxy_token(&self) -> String {
        std::fs::read_to_string(self.fixture.daemon_paths().proxy_token_path())
            .expect("proxy token file")
            .trim()
            .to_string()
    }

    /// The proxy's actual bound address (queried over management IPC;
    /// needed because the config binds port 0).
    pub async fn proxy_addr(&self) -> SocketAddr {
        let response = kyz_daemon::ipc::send_request(
            &self.fixture.daemon_paths(),
            &self.fixture.ipc_token(),
            kyz_daemon::ipc::IpcRequestKind::Status,
        )
        .await
        .expect("status request");
        assert!(response.ok, "status failed: {}", response.error_message());
        let listen = response.result.expect("status payload")["proxy_listen"]
            .as_str()
            .expect("proxy_listen string")
            .to_string();
        listen.parse().expect("proxy_listen socket address")
    }

    /// Replace the fixture secret's token field in the on-disk vault,
    /// simulating `kyz set` while the daemon runs (live re-read).
    pub fn update_vault_secret(&self, new_value: &str) {
        let passphrase = SecretString::from(FIXTURE_PASSPHRASE.to_string());
        let raw = std::fs::read(&self.fixture.vault_path).expect("read vault");
        let mut vault: kyz_core::vault_v3::VaultFileV3 =
            serde_json::from_slice(&raw).expect("parse vault");
        let dk = vault.unwrap_dk(&passphrase).expect("unwrap dk");
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "token".to_string(),
            SecretString::from(new_value.to_string()),
        );
        vault
            .set_with_retention(&SecretEntry::new("app", "api", fields), &dk, 0)
            .expect("update secret");
        let serialized = serde_json::to_string_pretty(&vault).expect("serialize vault");
        std::fs::write(&self.fixture.vault_path, serialized).expect("write vault");
    }

    /// Send one authorized request through the proxy.
    pub async fn send(
        &self,
        addr: SocketAddr,
        method: &str,
        host: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> HttpResponse {
        let mut headers = headers.to_vec();
        headers.push(("X-Kyz-Proxy-Token".to_string(), self.proxy_token()));
        send_http(addr, method, host, target, &headers, body)
            .await
            .expect("proxy request")
    }
}
