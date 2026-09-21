//! Management IPC: Unix domain socket + Windows named pipe.
//!
//! Protocol: one JSON object per line (JSON Lines), each request carrying a
//! protocol version and the per-daemon IPC token:
//!
//! ```json
//! {"version":1,"type":"status","token":"<hex>"}
//! ```
//!
//! Responses are `{"ok":true,"result":{...}}` or `{"ok":false,"error":"..."}`
//! where the error text never contains secret material. A single message
//! larger than [`IPC_MAX_LINE_BYTES`] causes an immediate disconnect.
//!
//! Transport security: on Unix the socket lives in the 0700 state directory
//! with 0600 permissions. Windows named pipes cannot carry a custom DACL
//! without unsafe Win32 calls (forbidden workspace-wide), so the per-queue
//! token check provides the cross-user access control that the socket file
//! mode provides on Unix; the username-suffixed pipe name prevents
//! collisions between Windows sessions, and `first_pipe_instance` blocks
//! instance squatting.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::watch;

use crate::lifecycle::DaemonState;
use crate::state::DaemonPaths;
use crate::{DaemonError, Result};

/// Management IPC protocol version spoken by this daemon.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

/// Maximum size of a single IPC message; larger messages disconnect.
pub const IPC_MAX_LINE_BYTES: usize = 1024 * 1024;

/// Windows `ERROR_PIPE_BUSY` (all instances busy; retry).
#[cfg(windows)]
const ERROR_PIPE_BUSY: i32 = 231;

/// Windows `ERROR_FILE_NOT_FOUND` (pipe not created yet; retry briefly).
const ERROR_FILE_NOT_FOUND: i32 = 2;

/// Management request types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpcRequestKind {
    /// Report daemon status and the active snapshot summary.
    Status,
    /// Request a graceful shutdown.
    Stop,
    /// Re-validate the configuration and swap the active snapshot.
    Reload,
}

/// One management request line.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcRequest {
    /// Protocol version; must equal [`IPC_PROTOCOL_VERSION`].
    pub version: u32,
    /// Request type.
    #[serde(rename = "type")]
    pub kind: IpcRequestKind,
    /// Per-daemon IPC token.
    pub token: String,
}

/// One management response line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    /// Whether the request succeeded.
    pub ok: bool,
    /// Type-specific payload on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Human-readable failure reason (never contains secrets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl IpcResponse {
    /// Successful response carrying `result`.
    #[must_use]
    pub const fn ok(result: serde_json::Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    /// Failure response with `error`.
    #[must_use]
    pub fn err(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(error.into()),
        }
    }

    /// The failure text, defaulting when the daemon sent no reason.
    #[must_use]
    pub fn error_message(&self) -> &str {
        self.error.as_deref().unwrap_or("unknown error")
    }
}

/// Status payload for the `status` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    /// Daemon process id.
    pub pid: u32,
    /// Seconds since daemon start.
    pub uptime_secs: u64,
    /// Whether the in-memory vault is still unlocked.
    pub unlocked: bool,
    /// Seconds remaining before the lifecycle timeout, if one is set.
    pub timeout_remaining_secs: Option<u64>,
    /// Whether a shutdown has started.
    pub shutting_down: bool,
    /// Active configuration snapshot summary.
    pub snapshot: crate::config_snapshot::SnapshotSummary,
    /// Actual bound address of the credential proxy, if running. Differs
    /// from the configured `daemon.listen` when configured as port 0.
    pub proxy_listen: Option<String>,
}

/// Read one newline-terminated line, enforcing `cap` strictly: once the
/// pending line exceeds `cap` bytes the read aborts (caller disconnects).
async fn read_line_capped<R: AsyncRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 4096];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            if buf.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed mid-line",
            ));
        }
        for &byte in &chunk[..read] {
            if byte == b'\n' {
                buf.push(byte);
                return Ok(buf);
            }
            buf.push(byte);
            if buf.len() > cap {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "message exceeds the IPC size limit",
                ));
            }
        }
    }
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) -> Result<()> {
    let io_err = |e: std::io::Error| DaemonError::Ipc(format!("writing IPC response: {e}"));
    writer.write_all(line.as_bytes()).await.map_err(io_err)?;
    writer.write_all(b"\n").await.map_err(io_err)?;
    writer.flush().await.map_err(io_err)?;
    Ok(())
}

/// Bound management endpoint: a Unix domain socket or the first Windows
/// named-pipe instance. Created by [`bind`], driven by [`serve`].
#[derive(Debug)]
pub struct IpcEndpoint {
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    #[cfg(windows)]
    server: tokio::net::windows::named_pipe::NamedPipeServer,
    /// Pipe name, needed to create subsequent instances in [`serve`].
    #[cfg(windows)]
    name: String,
}

/// Create the management transport endpoint: the Unix socket (mode 0600)
/// or the first Windows pipe instance.
///
/// Binding synchronously lets the caller fail startup when the endpoint
/// cannot be created (socket path unbindable — e.g. over the Unix
/// `sun_path` limit — or the pipe instance taken) instead of leaving a
/// daemon that can never be managed.
///
/// # Errors
///
/// Returns [`DaemonError::Ipc`] when the endpoint cannot be created or
/// secured.
pub fn bind(state: &DaemonState) -> Result<IpcEndpoint> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        use tokio::net::UnixListener;

        let path = state.paths.socket_path();
        let listener = UnixListener::bind(&path)
            .map_err(|e| DaemonError::Ipc(format!("binding {}: {e}", path.display())))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| DaemonError::Ipc(format!("securing {}: {e}", path.display())))?;
        Ok(IpcEndpoint { listener })
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;

        let name = state.paths.pipe_name();
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .map_err(|e| DaemonError::Ipc(format!("creating pipe {name}: {e}")))?;
        Ok(IpcEndpoint { server, name })
    }
}

/// Accept management connections on a bound endpoint until `shutdown`
/// fires.
///
/// Active connections finish their current request before closing; a
/// connection that stays idle simply ends when the stream drops. Per-client
/// accept/connect errors are logged and skipped (a client that terminates
/// mid-connect must not tear the listener down).
///
/// # Errors
///
/// Returns an error when the accept loop fails irrecoverably (e.g. the
/// next pipe instance cannot be created).
pub async fn serve(
    endpoint: IpcEndpoint,
    state: Arc<DaemonState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    #[cfg(unix)]
    {
        serve_unix(endpoint.listener, state, &mut shutdown).await
    }
    #[cfg(windows)]
    {
        serve_windows(endpoint.server, endpoint.name, state, &mut shutdown).await
    }
}

#[cfg(unix)]
async fn serve_unix(
    listener: tokio::net::UnixListener,
    state: Arc<DaemonState>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, _addr) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                log::debug!("management IPC accept failed: {e}");
                continue;
            }
        };
        let state = Arc::clone(&state);
        let mut conn_shutdown = shutdown.clone();
        connections.spawn(async move {
            handle_connection(stream, &state, &mut conn_shutdown).await;
        });
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[cfg(windows)]
async fn serve_windows(
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    name: String,
    state: Arc<DaemonState>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut connections = tokio::task::JoinSet::new();
    loop {
        let connected = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            connected = server.connect() => connected,
        };
        if let Err(e) = connected {
            // Transient client failure (e.g. the peer terminated before
            // ConnectNamedPipe completed, ERROR_NO_DATA): recycle the
            // broken instance instead of tearing down the listener.
            log::debug!("management IPC connect failed: {e}");
            let _ = server.disconnect();
            continue;
        }

        // Prepare the next instance before handing this one off so a second
        // client can connect concurrently.
        let next = ServerOptions::new()
            .create(&name)
            .map_err(|e| DaemonError::Ipc(format!("creating pipe {name}: {e}")))?;

        let state = Arc::clone(&state);
        let mut conn_shutdown = shutdown.clone();
        connections.spawn(async move {
            handle_connection(server, &state, &mut conn_shutdown).await;
        });
        server = next;
    }
    drop(server);
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_connection<S>(stream: S, state: &DaemonState, shutdown: &mut watch::Receiver<bool>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut stream = stream;
    loop {
        let line = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            line = read_line_capped(&mut stream, IPC_MAX_LINE_BYTES) => line,
        };
        let raw = match line {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                // Over the size limit: disconnect immediately.
                break;
            }
            Err(_) => break,
        };
        let text = String::from_utf8_lossy(&raw).trim().to_string();
        let response = state.handle_request(&text);
        if write_line(
            &mut stream,
            &serde_json::to_string(&response).unwrap_or_default(),
        )
        .await
        .is_err()
        {
            break;
        }
    }
}

/// Send one request over a fresh connection and read the response.
///
/// `token` must match `state_dir/daemon/ipc.token`.
///
/// # Errors
///
/// Returns [`DaemonError::Io`] with `ErrorKind::NotFound` (Unix) or the
/// OS error for a missing pipe (Windows) when the daemon is not running.
pub async fn send_request(
    paths: &DaemonPaths,
    token: &str,
    kind: IpcRequestKind,
) -> Result<IpcResponse> {
    #[cfg(unix)]
    let mut stream = connect_unix(paths).await?;
    #[cfg(windows)]
    let mut stream = connect_windows(paths).await?;

    let request = IpcRequest {
        version: IPC_PROTOCOL_VERSION,
        kind,
        token: token.to_string(),
    };
    let serialized = serde_json::to_string(&request)
        .map_err(|e| DaemonError::Ipc(format!("serializing request: {e}")))?;
    write_line(&mut stream, &serialized).await?;

    let raw = read_line_capped(&mut stream, IPC_MAX_LINE_BYTES)
        .await
        .map_err(|e| DaemonError::Ipc(format!("reading IPC response: {e}")))?;
    let text = String::from_utf8_lossy(&raw).trim().to_string();
    serde_json::from_str(&text).map_err(|e| DaemonError::Ipc(format!("parsing IPC response: {e}")))
}

#[cfg(unix)]
async fn connect_unix(paths: &DaemonPaths) -> Result<tokio::net::UnixStream> {
    let path = paths.socket_path();
    tokio::net::UnixStream::connect(&path)
        .await
        .map_err(|e| DaemonError::Io(std::io::Error::new(e.kind(), format!("{}", path.display()))))
}

/// How long a client keeps retrying while the daemon has not created its
/// pipe yet (the startup race).
#[cfg(windows)]
const CONNECT_NOT_FOUND_BUDGET: std::time::Duration = std::time::Duration::from_millis(750);

/// How long a client keeps retrying while every pipe instance is busy
/// serving other clients.
///
/// Must tolerate the daemon's shutdown drain (in-flight connections
/// finishing, bounded by the proxy request deadlines): during a graceful
/// shutdown the pipe instances stop accepting but are only dropped after
/// the drain, so "busy" is the normal signal for "shutting down, retry".
#[cfg(windows)]
const CONNECT_BUSY_BUDGET: std::time::Duration = std::time::Duration::from_secs(6);

#[cfg(windows)]
async fn connect_windows(
    paths: &DaemonPaths,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let name = paths.pipe_name();
    // Distinct retry budgets per condition: a missing pipe (dead daemon)
    // must be reported quickly instead of burning a fixed 3s on every
    // management call, while an all-instances-busy pipe is still a live
    // daemon worth waiting for.
    let not_found_deadline = std::time::Instant::now() + CONNECT_NOT_FOUND_BUDGET;
    let busy_deadline = std::time::Instant::now() + CONNECT_BUSY_BUDGET;
    loop {
        match ClientOptions::new().open(&name) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                if std::time::Instant::now() > not_found_deadline {
                    return Err(DaemonError::Io(e));
                }
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                if std::time::Instant::now() > busy_deadline {
                    // All instances stayed busy: the daemon is running but
                    // saturated — do not misreport that as "not running".
                    return Err(DaemonError::Ipc(format!(
                        "pipe {name} stayed busy for more than {CONNECT_BUSY_BUDGET:?}"
                    )));
                }
            }
            Err(e) => return Err(DaemonError::Io(e)),
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Send one management request from a synchronous context (the CLI's
/// one-shot `status`/`reload`/`stop` commands).
///
/// Owns a single-threaded tokio runtime per call so callers never need a
/// tokio dependency of their own.
///
/// # Errors
///
/// Same conditions as [`send_request`].
pub fn send_request_blocking(
    paths: &DaemonPaths,
    token: &str,
    kind: IpcRequestKind,
) -> Result<IpcResponse> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| DaemonError::Internal(format!("creating tokio runtime: {e}")))?;
    runtime.block_on(send_request(paths, token, kind))
}

/// Whether an IPC error means "no daemon is listening".
#[must_use]
pub fn is_not_running(error: &DaemonError) -> bool {
    match error {
        DaemonError::Io(e) => {
            matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) || e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_deserializes_with_type_rename() {
        let request: IpcRequest =
            serde_json::from_str(r#"{"version":1,"type":"status","token":"t"}"#)
                .expect("parse request");
        assert_eq!(request.kind, IpcRequestKind::Status);
        assert_eq!(request.version, 1);
    }

    #[test]
    fn response_roundtrips() {
        let response = IpcResponse::ok(serde_json::json!({"pid": 42}));
        let text = serde_json::to_string(&response).expect("serialize");
        let parsed: IpcResponse = serde_json::from_str(&text).expect("parse");
        assert!(parsed.ok);
        assert_eq!(parsed.result.expect("result")["pid"], 42);
    }

    #[tokio::test]
    async fn line_capped_read_enforces_limit() {
        let big = [b'a'; 64];
        let mut reader = &big[..];
        let err = read_line_capped(&mut reader, 16)
            .await
            .expect_err("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn line_capped_read_returns_on_newline() {
        let data = b"{\"a\":1}\ntrailing-not-read";
        let mut reader = &data[..];
        let line = read_line_capped(&mut reader, 1024)
            .await
            .expect("must read");
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(line.trim_ascii_end(), b"{\"a\":1}");
    }

    #[tokio::test]
    async fn line_capped_read_reports_eof() {
        let data = b"partial";
        let mut reader = &data[..];
        let err = read_line_capped(&mut reader, 1024).await.expect_err("eof");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
