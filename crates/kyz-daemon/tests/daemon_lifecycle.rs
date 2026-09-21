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
//! End-to-end daemon lifecycle integration tests.
//!
//! Covers one-passphrase start without session or keyring artifacts, live
//! resolves, stop semantics, lifecycle timeout with full cleanup,
//! stale-lock recovery, atomic reload behavior, IPC protocol details, and
//! secret-leak canaries.

mod common;

use common::{CANARY_PREFIX, Fixture};
use kyz_daemon::ipc::{
    IPC_MAX_LINE_BYTES, IPC_PROTOCOL_VERSION, IpcRequestKind, is_not_running, send_request,
};
use secrecy::ExposeSecret as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fields(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

#[tokio::test]
async fn start_status_resolve_stop_restart_lifecycle() {
    let fixture = Fixture::new();
    let daemon = fixture.start(None).await;
    let paths = fixture.daemon_paths();

    let status = send_request(&paths, &fixture.ipc_token(), IpcRequestKind::Status)
        .await
        .expect("status request");
    assert!(status.ok, "status failed: {:?}", status.error);
    let result = status.result.expect("status result");
    assert_eq!(result["pid"], u64::from(std::process::id()));
    assert_eq!(result["unlocked"], true, "vault should be unlocked");

    let resolved = daemon
        .handle
        .state()
        .resolve_fields("app", "api", &fields(&["value"]))
        .expect("resolve while running");
    assert!(resolved["value"].expose_secret().starts_with(CANARY_PREFIX));

    fixture.assert_no_session_artifacts();

    // Stop over IPC; wait for the graceful shutdown to finish (and release
    // the test lock so the restart below can acquire it).
    let stop = send_request(&paths, &fixture.ipc_token(), IpcRequestKind::Stop)
        .await
        .expect("stop request");
    assert!(stop.ok, "stop failed: {:?}", stop.error);
    daemon.shutdown().await;

    assert!(!paths.pid_path().exists(), "pid file must be removed");
    assert!(
        !paths.ipc_token_path().exists(),
        "ipc token must be removed"
    );
    #[cfg(unix)]
    assert!(!paths.socket_path().exists(), "socket must be removed");

    // Restart requires the passphrase again (a new daemon boots fine).
    let daemon2 = fixture.start(None).await;
    let status2 = send_request(&paths, &fixture.ipc_token(), IpcRequestKind::Status)
        .await
        .expect("status after restart");
    assert!(status2.ok);
    daemon2.shutdown().await;

    fixture.assert_no_secret_leaks();
}

#[tokio::test]
async fn timeout_zero_keeps_daemon_alive() {
    let fixture = Fixture::new();
    let daemon = fixture.start(Some(0)).await;

    // 2 seconds must NOT terminate a timeout=0 daemon.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let status = send_request(
        &fixture.daemon_paths(),
        &fixture.ipc_token(),
        IpcRequestKind::Status,
    )
    .await
    .expect("status");
    assert!(status.ok);
    assert_eq!(status.result.expect("result")["shutting_down"], false);

    daemon.shutdown().await;
}

#[tokio::test]
async fn timeout_triggers_graceful_shutdown_and_cleanup() {
    let fixture = Fixture::new();
    let paths = fixture.daemon_paths();
    let daemon = fixture.start(Some(1)).await;
    let token = fixture.ipc_token();

    daemon.handle.wait().await.expect("timeout shutdown");

    assert!(!paths.pid_path().exists(), "pid removed after timeout");
    assert!(!paths.ipc_token_path().exists(), "token removed");
    #[cfg(unix)]
    assert!(!paths.socket_path().exists(), "socket removed");

    let gone = send_request(&paths, &token, IpcRequestKind::Status).await;
    assert!(
        gone.is_err() && is_not_running(gone.as_ref().unwrap_err()),
        "daemon must stop listening after timeout"
    );
}

#[tokio::test]
async fn second_instance_is_rejected_while_first_runs() {
    let fixture = Fixture::new();
    let daemon = fixture.start(None).await;

    let second = kyz_daemon::run_daemon(fixture.options(None)).await;
    assert!(
        second.is_err(),
        "second daemon on the same state dir must fail"
    );
    let error = second.expect_err("second daemon must fail");
    assert!(
        error.to_string().contains("already running"),
        "unexpected error: {error}"
    );

    daemon.shutdown().await;

    let third = fixture.start(None).await;
    third.shutdown().await;
}

#[tokio::test]
async fn reload_is_atomic_and_reports_validation_errors() {
    let fixture = Fixture::new();
    let daemon = fixture.start(None).await;
    let paths = fixture.daemon_paths();
    let token = fixture.ipc_token();

    let before = send_request(&paths, &token, IpcRequestKind::Status)
        .await
        .expect("status")
        .result
        .expect("result")["snapshot"]["hash"]
        .clone();

    // Invalid candidate: rejected with detail, active snapshot unchanged.
    std::fs::write(
        &fixture.config_path,
        "[[proxy.rules]]\nname = \"bad\"\nhost = \"a.*.b\"\nupstream = \"http://x\"\n",
    )
    .expect("write invalid config");
    let rejected = send_request(&paths, &token, IpcRequestKind::Reload)
        .await
        .expect("reload request");
    assert!(!rejected.ok, "invalid reload must fail");
    let detail = rejected.error.unwrap_or_default();
    assert!(
        detail.contains("wildcards") || detail.contains("https"),
        "error should include validation detail: {detail}"
    );

    let after_bad = send_request(&paths, &token, IpcRequestKind::Status)
        .await
        .expect("status")
        .result
        .expect("result")["snapshot"]["hash"]
        .clone();
    assert_eq!(before, after_bad, "active snapshot must be unchanged");

    // Valid candidate: swapped in, hash changes.
    std::fs::write(
        &fixture.config_path,
        "profile = \"default\"\n\n[daemon]\ntimeout_secs = 1234\n",
    )
    .expect("write valid config");
    let accepted = send_request(&paths, &token, IpcRequestKind::Reload)
        .await
        .expect("reload request");
    assert!(
        accepted.ok,
        "valid reload must succeed: {:?}",
        accepted.error
    );

    let after_good = send_request(&paths, &token, IpcRequestKind::Status)
        .await
        .expect("status")
        .result
        .expect("result")["snapshot"]["hash"]
        .clone();
    assert_ne!(before, after_good, "snapshot must change on valid reload");

    daemon.shutdown().await;
    fixture.assert_no_secret_leaks();
}

#[tokio::test]
async fn invalid_config_fails_startup_before_any_state() {
    let fixture = Fixture::new();
    std::fs::write(
        &fixture.config_path,
        "[[proxy.rules]]\nname = \"x\"\nhost = \"in valid\"\nupstream = \"https://ok\"\n",
    )
    .expect("write invalid config");

    let result = kyz_daemon::run_daemon(fixture.options(None)).await;
    assert!(result.is_err(), "invalid config must block startup");
    assert!(
        result
            .expect_err("must fail")
            .to_string()
            .contains("configuration")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn unbindable_socket_path_fails_startup_and_cleans_up() {
    let fixture = Fixture::new();
    // Bury the state dir deep enough that the socket path overflows the
    // Unix `sun_path` limit (108 bytes on Linux, 104 on macOS).
    let deep = fixture
        .state_dir
        .parent()
        .expect("state parent")
        .join("d".repeat(128))
        .join("state");
    let mut options = fixture.options(None);
    options.state_dir = deep.clone();

    let result = kyz_daemon::run_daemon(options).await;
    let error = result.expect_err("bind must fail startup");
    assert!(
        error.to_string().contains("binding"),
        "unexpected error: {error}"
    );

    // The failed start must not strand runtime files or hold the lock.
    let paths = kyz_daemon::DaemonPaths::new(&deep);
    assert!(!paths.pid_path().exists(), "pid must be cleaned");
    assert!(!paths.ipc_token_path().exists(), "token must be cleaned");
}

#[tokio::test]
async fn reload_recomputes_the_lifecycle_deadline() {
    let fixture = Fixture::new();
    // Config starts with timeout_secs = 0 (run until stopped)…
    let daemon = fixture.start(None).await;
    let paths = fixture.daemon_paths();
    let token = fixture.ipc_token();

    // …and a reload to timeout_secs = 1 must actually arm the timeout.
    std::fs::write(
        &fixture.config_path,
        "profile = \"default\"\n\n[daemon]\ntimeout_secs = 1\n",
    )
    .expect("write config");
    let reload = send_request(&paths, &token, IpcRequestKind::Reload)
        .await
        .expect("reload request");
    assert!(reload.ok, "reload failed: {:?}", reload.error);

    daemon
        .handle
        .wait()
        .await
        .expect("timeout shutdown after reload");
    assert!(!paths.pid_path().exists(), "pid removed after timeout");
}

#[tokio::test]
async fn multi_vault_declaration_is_rejected() {
    let fixture = Fixture::new();
    std::fs::write(
        &fixture.config_path,
        "[daemon]\ntimeout_secs = 0\nvaults = [\"a\", \"b\"]\n",
    )
    .expect("write multi-vault config");

    let result = kyz_daemon::run_daemon(fixture.options(None)).await;
    assert!(
        result.is_err(),
        "multi-vault declarations must fail loudly, not silently pick one"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn unix_state_files_have_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let daemon = fixture.start(None).await;
    let paths = fixture.daemon_paths();

    let dir_mode = |path: &std::path::Path| {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    };
    assert_eq!(dir_mode(&paths.dir), 0o700, "state dir must be 0700");
    assert_eq!(dir_mode(&paths.pid_path()), 0o600);
    assert_eq!(dir_mode(&paths.ipc_token_path()), 0o600);
    assert_eq!(dir_mode(&paths.audit_log_path()), 0o600);
    assert_eq!(dir_mode(&paths.daemon_log_path()), 0o600);
    #[cfg(unix)]
    assert_eq!(dir_mode(&paths.socket_path()), 0o600, "socket must be 0600");

    daemon.shutdown().await;
}

#[tokio::test]
async fn audit_log_records_lifecycle_events_without_secrets() {
    let fixture = Fixture::new();
    let daemon = fixture.start(None).await;
    daemon.handle.stop();
    daemon.handle.wait().await.expect("shutdown");

    let audit =
        std::fs::read_to_string(fixture.daemon_paths().audit_log_path()).expect("read audit log");
    let lines: Vec<&str> = audit.lines().filter(|l| !l.is_empty()).collect();
    assert!(lines.len() >= 2, "expected start+stop events, got: {audit}");
    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("audit json");
    assert_eq!(first["op"], "daemon_start");
    let last: serde_json::Value = serde_json::from_str(lines[lines.len() - 1]).expect("audit json");
    assert_eq!(last["op"], "daemon_stop");

    fixture.assert_no_secret_leaks();
}

/// Open a raw management connection (transport-per-platform).
async fn raw_connection(paths: &kyz_daemon::DaemonPaths) -> Box<dyn RawStream> {
    #[cfg(unix)]
    {
        let stream = tokio::net::UnixStream::connect(paths.socket_path())
            .await
            .expect("connect raw");
        Box::new(stream)
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        // The daemon's serve task may not have created its pipe instance
        // yet; retry briefly like the real client does.
        let mut stream = None;
        for _ in 0..150 {
            match ClientOptions::new().open(paths.pipe_name()) {
                Ok(client) => {
                    stream = Some(client);
                    break;
                }
                Err(e) if e.raw_os_error() == Some(2) => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => panic!("connect pipe: {e}"),
            }
        }
        Box::new(stream.expect("connect pipe"))
    }
}

/// Minimal transport-agnostic stream for protocol tests.
trait RawStream: Send {
    fn write<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>>;
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>;
}

#[cfg(unix)]
impl RawStream for tokio::net::UnixStream {
    fn write<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>> {
        Box::pin(AsyncWriteExt::write_all(self, buf))
    }
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>
    {
        Box::pin(AsyncReadExt::read(self, buf))
    }
}

#[cfg(windows)]
impl RawStream for tokio::net::windows::named_pipe::NamedPipeClient {
    fn write<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>> {
        Box::pin(AsyncWriteExt::write_all(self, buf))
    }
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>
    {
        Box::pin(AsyncReadExt::read(self, buf))
    }
}

async fn roundtrip(stream: &mut Box<dyn RawStream>, request: &str) -> Option<String> {
    let mut payload = request.as_bytes().to_vec();
    payload.push(b'\n');
    stream.write(&payload).await.expect("write request");
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.expect("read response");
        if read == 0 {
            return None; // disconnected
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.ends_with(b"\n") {
            return Some(String::from_utf8_lossy(&buffer).trim().to_string());
        }
    }
}

#[tokio::test]
async fn ipc_protocol_rejects_wrong_version_and_token() {
    let fixture = Fixture::new();
    let daemon = fixture.start(None).await;
    let paths = fixture.daemon_paths();
    let token = fixture.ipc_token();

    let mut stream = raw_connection(&paths).await;
    let bad_version = roundtrip(
        &mut stream,
        &format!(r#"{{"version":99,"type":"status","token":"{token}"}}"#),
    )
    .await
    .expect("response");
    let parsed: serde_json::Value = serde_json::from_str(&bad_version).expect("json");
    assert_eq!(parsed["ok"], false);
    assert!(parsed["error"].as_str().unwrap_or("").contains("version"));

    let wrong = send_request(&paths, "deadbeef", IpcRequestKind::Status)
        .await
        .expect("request");
    assert!(!wrong.ok);
    assert_eq!(wrong.error.as_deref(), Some("unauthorized"));

    let mut stream = raw_connection(&paths).await;
    let malformed = roundtrip(&mut stream, "not json at all")
        .await
        .expect("response");
    let parsed: serde_json::Value = serde_json::from_str(&malformed).expect("json");
    assert_eq!(parsed["ok"], false);

    let ok = send_request(&paths, &token, IpcRequestKind::Status)
        .await
        .expect("status");
    assert!(ok.ok);
    assert_eq!(
        ok.result.expect("result")["pid"],
        u64::from(std::process::id())
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn ipc_oversized_message_disconnects_immediately() {
    let fixture = Fixture::new();
    let daemon = fixture.start(None).await;
    let paths = fixture.daemon_paths();
    let token = fixture.ipc_token();

    let mut stream = raw_connection(&paths).await;
    // Send a valid prefix, then blow past the 1 MiB line limit with no
    // newline: the daemon must disconnect without allocating unboundedly.
    let mut payload =
        format!(r#"{{"version":{IPC_PROTOCOL_VERSION},"type":"status","token":"{token}","#)
            .into_bytes();
    payload.resize(IPC_MAX_LINE_BYTES + 1024, b'a');
    stream
        .write(&payload)
        .await
        .expect("write oversized payload");

    let mut chunk = [0u8; 256];
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut chunk))
        .await
        .expect("read should finish");
    // Clean EOF or a reset both prove the daemon dropped the connection:
    // on Unix, closing a socket with unread bytes in the receive queue
    // surfaces as ECONNRESET on the peer instead of EOF.
    let disconnected = match outcome {
        Ok(0) => true,
        Err(e) => e.kind() == std::io::ErrorKind::ConnectionReset,
        _ => false,
    };
    assert!(disconnected, "daemon must disconnect on oversized messages");

    daemon.shutdown().await;
}

#[tokio::test]
async fn stale_socket_and_pid_are_recovered_on_restart() {
    // Simulate crash leftovers: garbage pid + socket file in the state dir.
    let fixture = Fixture::new();
    let paths = fixture.daemon_paths();
    paths.ensure().expect("ensure state dir");
    std::fs::write(paths.pid_path(), "999999\n").expect("stale pid");
    #[cfg(unix)]
    std::fs::write(paths.socket_path(), b"stale").expect("stale socket");

    let daemon = fixture.start(None).await;

    let status = send_request(&paths, &fixture.ipc_token(), IpcRequestKind::Status)
        .await
        .expect("status");
    assert!(status.ok);
    assert_eq!(
        status.result.expect("result")["pid"],
        u64::from(std::process::id()),
        "stale pid must be overwritten"
    );

    daemon.shutdown().await;
}
