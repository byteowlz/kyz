//! Daemon lifecycle: startup sequence, runtime state, and the graceful
//! shutdown state machine.
//!
//! Startup order: load+validate config snapshot → install run log →
//! unlock vault in memory (one passphrase, no session) → acquire the
//! single-instance lock → clear stale socket/pid → write pid → write IPC
//! and proxy tokens → open audit sink → publish snapshot → audit
//! `daemon_start` (drained to disk before serving, so a running daemon
//! already owes its full set of state files) → bind the management
//! listener. The run log is installed before the unlock so migration
//! diagnostics cannot be lost, and the listener is bound synchronously so
//! a bind failure fails startup.
//!
//! Shutdown never calls `std::process::exit`: mark shutting down →
//! refuse new proxy/grant work → close the listener → wait for in-flight
//! requests → drop the [`UnlockedVault`] (zeroizing the DK) → flush the
//! audit sink → remove pid/socket/tokens → return normally. SIGTERM,
//! SIGINT, lifecycle timeout, and `kyz daemon stop` all follow this path.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use kyz_core::config::{LogLevel, MAX_TIMEOUT_SECS, ProxyAuthMode};
use kyz_core::store::{UnlockedVault, VaultStore};
use kyz_core::{CoreError, SecretEntry};

use crate::audit::{AuditEvent, AuditReason, AuditSink};
use crate::config_snapshot::{ConfigSnapshot, SnapshotState, reload_failure_reason};
use crate::instance::{self, InstanceGuard};
use crate::ipc::{IPC_PROTOCOL_VERSION, IpcRequest, IpcRequestKind, IpcResponse, StatusReport};
use crate::logging::{DaemonLogger, LogSinkGuard};
use crate::state::{DaemonPaths, write_secure_file};

use crate::{DaemonError, Result};

/// Floor for the shutdown drain budget when the daemon serves no proxy
/// requests. The actual budget additionally covers one in-flight proxy
/// request (see [`shutdown_drain_budget`]).
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Slack added on top of the per-request deadlines when draining shutdown.
const SHUTDOWN_DRAIN_SLACK: Duration = Duration::from_secs(5);

/// How long shutdown may wait for the serving tasks (and their in-flight
/// requests): at least as long as one worst-case in-flight proxy request
/// (body-read deadline + upstream deadline + slack), so a graceful stop
/// does not cancel requests whose audit events would then be lost.
fn shutdown_drain_budget(state: &DaemonState) -> Duration {
    let upstream_secs = state
        .snapshots
        .current()
        .ok()
        .and_then(|s| s.config.runtime.timeout)
        .unwrap_or(crate::upstream::DEFAULT_UPSTREAM_TIMEOUT_SECS)
        .max(1);
    SHUTDOWN_DRAIN_TIMEOUT.max(
        crate::proxy::REQUEST_BODY_READ_TIMEOUT
            + Duration::from_secs(upstream_secs)
            + SHUTDOWN_DRAIN_SLACK,
    )
}

/// Take the serving tasks and wait (bounded) for them to unwind, so their
/// listeners, pipe instances, and in-flight requests are settled before
/// the caller proceeds with teardown.
async fn drain_serving_tasks(state: &DaemonState, budget: Duration) {
    let ipc_task = state
        .ipc_task
        .lock()
        .ok()
        .and_then(|mut guard| guard.take());
    let proxy_task = state
        .proxy_task
        .lock()
        .ok()
        .and_then(|mut guard| guard.take());
    for task in [ipc_task, proxy_task].into_iter().flatten() {
        let _ = tokio::time::timeout(budget, task).await;
    }
}

/// Everything needed to boot a daemon.
#[derive(Debug)]
pub struct DaemonOptions {
    /// Vault file to unlock.
    pub vault_path: PathBuf,
    /// Vault passphrase (held as a secret; dropped after unlock).
    pub passphrase: SecretString,
    /// Configuration file (loaded, validated, snapshotted).
    pub config_path: PathBuf,
    /// Application state directory (`<...>/kyz`); the daemon owns the
    /// `daemon/` subdirectory.
    pub state_dir: PathBuf,
    /// `--timeout N` override for `daemon.timeout_secs`.
    pub timeout_override: Option<u64>,
}

/// Shared runtime state of a running daemon.
pub struct DaemonState {
    /// Resolved daemon-owned paths.
    pub paths: DaemonPaths,
    /// When the daemon started.
    pub started_at: Instant,
    /// Lifecycle deadline (`timeout_secs > 0`), if any. Swapped under the
    /// mutex when a reload recomputes the timeout.
    deadline: Mutex<Option<Instant>>,
    /// Notifies the supervision task that `deadline` changed (reload).
    deadline_tx: watch::Sender<Option<Instant>>,
    /// `--timeout` override for `daemon.timeout_secs`; stays authoritative
    /// across reloads for this daemon's lifetime.
    timeout_override: Option<u64>,
    /// Run-log sink registration; dropping it (at shutdown) deregisters.
    log_sink: LogSinkGuard,
    /// The in-memory unlocked vault. `None` once shutdown has dropped it.
    vault: Mutex<Option<UnlockedVault>>,
    /// Active configuration snapshot (atomic swap on reload).
    pub snapshots: SnapshotState,
    /// Structured audit sink.
    pub audit: AuditSink,
    /// Actual bound address of the credential proxy, once running.
    proxy_addr: Mutex<Option<SocketAddr>>,
    /// Expected management IPC token.
    ipc_token: String,
    /// Expected proxy bearer token (`None` when `proxy.auth = "none"`).
    proxy_token: Option<String>,
    shutting_down: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    guard: Mutex<Option<InstanceGuard>>,
    ipc_task: Mutex<Option<JoinHandle<()>>>,
    proxy_task: Mutex<Option<JoinHandle<()>>>,
}

impl DaemonState {
    /// Whether the vault is still available for resolves.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        !self.shutting_down.load(Ordering::Acquire) && self.vault.lock().is_ok_and(|v| v.is_some())
    }

    /// Whether a shutdown has started (new work must be refused).
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// Request a graceful shutdown (idempotent).
    pub fn request_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        let _ = self.shutdown_tx.send_replace(true);
    }

    /// (Re)compute the lifecycle deadline from a timeout in seconds.
    ///
    /// The value is capped at [`MAX_TIMEOUT_SECS`]: `Instant + Duration`
    /// panics on overflow, and anything that large is indistinguishable
    /// from "run until stopped" anyway.
    fn set_timeout(&self, timeout_secs: u64) {
        let capped = timeout_secs.min(MAX_TIMEOUT_SECS);
        let deadline = (capped > 0)
            .then(|| Instant::now().checked_add(Duration::from_secs(capped)))
            .flatten();
        if let Ok(mut guard) = self.deadline.lock() {
            *guard = deadline;
        }
        let _ = self.deadline_tx.send_replace(deadline);
    }

    /// Run `f` against the in-memory vault, refusing during shutdown and
    /// after the vault was dropped.
    fn with_vault<T>(
        &self,
        f: impl FnOnce(&UnlockedVault) -> std::result::Result<T, CoreError>,
    ) -> std::result::Result<T, CoreError> {
        if self.is_shutting_down() {
            return Err(CoreError::Secret(
                "daemon is shutting down; refusing new resolves".to_string(),
            ));
        }
        self.vault
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(f))
            .unwrap_or_else(|| Err(CoreError::Secret("vault is no longer unlocked".to_string())))
    }

    /// Resolve secret fields through the in-memory vault (process-internal
    /// path).
    ///
    /// Refused once shutdown has started or the vault was dropped.
    ///
    /// # Errors
    ///
    /// Forwards vault errors; refuses during shutdown.
    pub fn resolve_fields(
        &self,
        service: &str,
        key: &str,
        fields: &[String],
    ) -> std::result::Result<BTreeMap<String, SecretString>, CoreError> {
        self.with_vault(|vault| vault.resolve_fields(service, key, fields))
    }

    /// Decrypt a full entry through the in-memory vault.
    ///
    /// # Errors
    ///
    /// Forwards vault errors; refuses during shutdown.
    pub fn get(&self, service: &str, key: &str) -> std::result::Result<SecretEntry, CoreError> {
        self.with_vault(|vault| vault.get(service, key))
    }

    /// The proxy bearer token, when token authentication is enabled.
    #[must_use]
    pub fn proxy_token(&self) -> Option<String> {
        self.proxy_token.clone()
    }

    /// Build the `status` report.
    ///
    /// # Errors
    ///
    /// Returns an error when no snapshot is active.
    pub fn status_report(&self) -> Result<StatusReport> {
        let deadline = self.deadline.lock().ok().and_then(|guard| *guard);
        Ok(StatusReport {
            pid: std::process::id(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            unlocked: self.is_unlocked(),
            timeout_remaining_secs: deadline
                .map(|d| d.saturating_duration_since(Instant::now()).as_secs()),
            shutting_down: self.is_shutting_down(),
            snapshot: self.snapshots.current()?.summary(),
            proxy_listen: self
                .proxy_addr
                .lock()
                .ok()
                .and_then(|guard| *guard)
                .map(|addr| addr.to_string()),
        })
    }

    /// Handle one raw management IPC request line.
    ///
    /// Pure synchronous work; the `stop` request triggers the async
    /// shutdown through the watch channel.
    #[must_use]
    pub fn handle_request(&self, raw: &str) -> IpcResponse {
        let request: IpcRequest = match serde_json::from_str(raw) {
            Ok(request) => request,
            Err(_) => return IpcResponse::err("malformed request"),
        };
        if request.version != IPC_PROTOCOL_VERSION {
            return IpcResponse::err(format!(
                "unsupported protocol version {} (server speaks {IPC_PROTOCOL_VERSION})",
                request.version
            ));
        }
        if !token_matches(&request.token, &self.ipc_token) {
            return IpcResponse::err("unauthorized");
        }
        match request.kind {
            IpcRequestKind::Status => match self.status_report() {
                Ok(report) => IpcResponse::ok(
                    serde_json::to_value(&report).unwrap_or_else(|_| serde_json::json!({})),
                ),
                Err(e) => IpcResponse::err(e.to_string()),
            },
            IpcRequestKind::Reload => self.handle_reload(),
            IpcRequestKind::Stop => {
                self.request_shutdown();
                IpcResponse::ok(serde_json::json!({"stopping": true}))
            }
        }
    }

    fn handle_reload(&self) -> IpcResponse {
        let Ok(active) = self.snapshots.current() else {
            return IpcResponse::err("no active snapshot");
        };
        let path = active.file_path.clone();
        // Load and check the candidate completely before swapping. A
        // candidate that changes proxy settings fixed at startup is
        // rejected outright instead of half-applying — most importantly
        // `proxy.auth`, where a swapped snapshot would report the new mode
        // while the running proxy keeps authenticating per its startup
        // mode (a none→token flip would fail open).
        let candidate = match ConfigSnapshot::load(&path) {
            Ok(candidate) => candidate,
            Err(e) => {
                self.audit
                    .emit(&AuditEvent::daemon_reload(Some(reload_failure_reason(&e))));
                return IpcResponse::err(e.to_string());
            }
        };
        if let Err(e) = crate::proxy::reload_runtime_compat(&active.config, &candidate.config) {
            self.audit.emit(&AuditEvent::daemon_reload(Some(
                AuditReason::ConfigRejected,
            )));
            return IpcResponse::err(e);
        }
        let snapshot = self.snapshots.publish(candidate);
        // The snapshot swap alone leaves stale runtime state
        // behind: recompute the lifecycle deadline (the status
        // report would otherwise show the new `timeout_secs` next
        // to the old countdown) and re-apply `logging.level`.
        let timeout_secs = self
            .timeout_override
            .unwrap_or(snapshot.config.daemon.timeout_secs);
        self.set_timeout(timeout_secs);
        self.log_sink
            .set_level(log_level(snapshot.config.logging.level));
        self.audit.emit(&AuditEvent::daemon_reload(None));
        let summary = snapshot.summary();
        IpcResponse::ok(serde_json::to_value(&summary).unwrap_or_else(|_| serde_json::json!({})))
    }
}

impl std::fmt::Debug for DaemonState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let deadline = self.deadline.lock().ok().and_then(|guard| *guard);
        f.debug_struct("DaemonState")
            .field("paths", &self.paths)
            .field("started_at", &self.started_at)
            .field("deadline", &deadline)
            .field("timeout_override", &self.timeout_override)
            .field("vault", &self.is_unlocked())
            .field("snapshots", &self.snapshots)
            .field("audit", &"<sink>")
            .field("proxy_addr", &self.proxy_addr.lock().ok().and_then(|g| *g))
            .field("ipc_token", &"<redacted>")
            .field("proxy_token", &"<redacted>")
            .field("shutting_down", &self.is_shutting_down())
            .field("shutdown_tx", &"<watch>")
            .field("guard", &"<instance lock>")
            .field("ipc_task", &"<join handle>")
            .field("proxy_task", &"<join handle>")
            .finish_non_exhaustive()
    }
}

/// Constant-time token comparison (lengths are public).
pub(crate) fn token_matches(candidate: &str, expected: &str) -> bool {
    let (candidate, expected) = (candidate.as_bytes(), expected.as_bytes());
    candidate.len() == expected.len()
        && bool::from(subtle::ConstantTimeEq::ct_eq(candidate, expected))
}

/// Running daemon handle returned by [`run_daemon`].
#[derive(Debug)]
pub struct DaemonHandle {
    state: Arc<DaemonState>,
    supervise: JoinHandle<()>,
}

impl DaemonHandle {
    /// Shared daemon state (status queries, in-process resolves).
    #[must_use]
    pub const fn state(&self) -> &Arc<DaemonState> {
        &self.state
    }

    /// Request a graceful shutdown without waiting.
    pub fn stop(&self) {
        self.state.request_shutdown();
    }

    /// Wait for the daemon to shut down gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if the supervision task panicked.
    pub async fn wait(self) -> Result<()> {
        self.supervise
            .await
            .map_err(|e| DaemonError::Internal(format!("daemon task failed: {e}")))
    }
}

/// Boot the daemon: run the full startup sequence and spawn the
/// supervision task. Returns once the daemon is serving; the caller drives
/// termination via [`DaemonHandle::wait`].
///
/// # Errors
///
/// Returns errors for every startup failure (config invalid, unlock
/// failed, another instance running, state dir unusable).
pub async fn run_daemon(opts: DaemonOptions) -> Result<DaemonHandle> {
    run_daemon_inner(opts, None).await
}

/// Like [`run_daemon`], substituting the production upstream client.
///
/// Test seam so integration tests can trust their own
/// mock-CA HTTPS upstream; never part of user-facing configuration.
#[doc(hidden)]
pub async fn run_daemon_with_upstream(
    opts: DaemonOptions,
    test_upstream_client: crate::upstream::UpstreamClient,
) -> Result<DaemonHandle> {
    run_daemon_inner(opts, Some(test_upstream_client)).await
}

async fn run_daemon_inner(
    opts: DaemonOptions,
    test_upstream_client: Option<crate::upstream::UpstreamClient>,
) -> Result<DaemonHandle> {
    let snapshot = ConfigSnapshot::load(&opts.config_path)?;

    let paths = DaemonPaths::new(&opts.state_dir);
    paths.ensure()?;

    // Best effort; installed before the unlock so vault migration
    // diagnostics cannot be lost.
    let log_sink = DaemonLogger::install(
        &paths.daemon_log_path(),
        log_level(snapshot.config.logging.level),
    );
    install_panic_logging();

    let store = VaultStore::new(opts.vault_path.clone());
    let vault = store.unlock_in_memory(&opts.passphrase)?;

    // The lock is the single-instance authority; the pid file is metadata.
    let guard = InstanceGuard::acquire(&paths.lock_path())?;
    instance::clear_stale_files(&paths);
    instance::write_pid(&paths.pid_path(), std::process::id())?;

    let ipc_token = generate_token_hex()?;
    write_secure_file(&paths.ipc_token_path(), ipc_token.as_bytes())?;
    let proxy_token = match snapshot.config.proxy.auth {
        ProxyAuthMode::Token => {
            let token = generate_token_hex()?;
            write_secure_file(&paths.proxy_token_path(), token.as_bytes())?;
            Some(token)
        }
        ProxyAuthMode::None => None,
    };

    let audit = AuditSink::open(&paths.audit_log_path());

    let timeout_secs = opts
        .timeout_override
        .unwrap_or(snapshot.config.daemon.timeout_secs);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (deadline_tx, deadline_rx) = watch::channel(None);
    let state = Arc::new(DaemonState {
        paths,
        started_at: Instant::now(),
        deadline: Mutex::new(None),
        deadline_tx,
        timeout_override: opts.timeout_override,
        log_sink,
        vault: Mutex::new(Some(vault)),
        snapshots: SnapshotState::new(),
        audit,
        proxy_addr: Mutex::new(None),
        ipc_token,
        proxy_token,
        shutting_down: AtomicBool::new(false),
        shutdown_tx,
        guard: Mutex::new(Some(guard)),
        ipc_task: Mutex::new(None),
        proxy_task: Mutex::new(None),
    });
    state.set_timeout(timeout_secs);
    state.snapshots.publish(snapshot);
    state.audit.emit(&AuditEvent::daemon_start());
    // Drain barrier: the writer thread creates `audit.log` lazily on its
    // first write, so startup must block on the queued `daemon_start`
    // before serving — a running daemon owes the caller its full set of
    // state files with their restricted permissions.
    state.audit.flush();
    log::info!(
        "kyz daemon started (pid {}, timeout {}s)",
        std::process::id(),
        timeout_secs
    );

    // Bound synchronously so a bind failure fails startup instead of
    // stranding a daemon nobody can manage.
    let endpoint = match crate::ipc::bind(&state) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            undo_startup_runtime_files(&state);
            return Err(e);
        }
    };
    let ipc_state = Arc::clone(&state);
    let ipc_shutdown = shutdown_rx;
    let ipc_task = tokio::spawn(async move {
        if let Err(e) = crate::ipc::serve(endpoint, Arc::clone(&ipc_state), ipc_shutdown).await {
            // The management endpoint is gone; an unmanageable daemon
            // holding the instance lock helps nobody — shut down
            // gracefully so stop/status keep working until it exits.
            log::error!("management IPC server stopped: {e}");
            ipc_state.request_shutdown();
        }
    });
    *state
        .ipc_task
        .lock()
        .map_err(|_| DaemonError::Internal("ipc task lock poisoned".to_string()))? = Some(ipc_task);

    // The credential proxy binds only when `daemon.listen` is configured;
    // the same synchronous-failure rule applies. On failure the management
    // task spawned above must be torn down too — otherwise it keeps the
    // named-pipe first instance (blocking any retry against this state
    // dir) and answering status/stop with tokens that outlive the failed
    // startup, and the unlocked vault would stay in memory un-zeroized.
    if let Err(e) = spawn_proxy(&state, test_upstream_client).await {
        state.request_shutdown();
        drain_serving_tasks(&state, shutdown_drain_budget(&state)).await;
        if let Ok(mut guard) = state.vault.lock() {
            *guard = None;
        }
        undo_startup_runtime_files(&state);
        return Err(e);
    }

    let supervise_state = Arc::clone(&state);
    let supervise = tokio::spawn(async move {
        wait_for_trigger(&supervise_state, deadline_rx).await;
        graceful_shutdown(&supervise_state).await;
    });

    Ok(DaemonHandle { state, supervise })
}

/// Boot the daemon and block until it shuts down, for synchronous callers
/// (`kyz daemon start --foreground`). Owns the async runtime so callers
/// never need a tokio dependency of their own.
///
/// # Errors
///
/// Returns errors for every startup failure (config invalid, unlock
/// failed, another instance running, state dir unusable) and if the
/// supervision task panics.
pub fn run_blocking(opts: DaemonOptions) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| DaemonError::Internal(format!("creating tokio runtime: {e}")))?;
    runtime.block_on(async {
        let handle = run_daemon(opts).await?;
        handle.wait().await
    })
}

/// Wait until any shutdown trigger fires: lifecycle timeout, SIGINT,
/// SIGTERM (Unix), or an IPC `stop` request.
///
/// `deadline_rx` fires whenever a reload recomputes the timeout (including
/// disabling it), so the sleep is rebuilt instead of pinning the deadline
/// from startup.
async fn wait_for_trigger(state: &DaemonState, mut deadline_rx: watch::Receiver<Option<Instant>>) {
    // `subscribe()` starts at the *current* value, so a stop request that
    // raced ahead of this task must be observed explicitly, not via
    // `changed()`.
    let mut stop_watch = state.shutdown_tx.subscribe();
    if *stop_watch.borrow_and_update() || state.is_shutting_down() {
        return;
    }

    #[cfg(unix)]
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(signal) => Some(signal),
        Err(e) => {
            log::error!("cannot listen for SIGTERM: {e}");
            None
        }
    };

    loop {
        let deadline = state.deadline.lock().ok().and_then(|guard| *guard);
        let deadline_sleep = async {
            match deadline {
                Some(deadline) => {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                }
                None => std::future::pending().await,
            }
        };
        let sigterm_fut = async {
            #[cfg(unix)]
            match sigterm.as_mut() {
                Some(signal) => signal.recv().await,
                None => std::future::pending::<Option<()>>().await,
            };
            #[cfg(not(unix))]
            std::future::pending::<Option<()>>().await;
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => return,
            () = deadline_sleep => return,
            _ = stop_watch.changed() => return,
            () = sigterm_fut => return,
            // The reload path recomputed the deadline: rebuild the sleep.
            _ = deadline_rx.changed() => {},
        }
    }
}

/// Bind and spawn the credential proxy when `daemon.listen` is set.
///
/// Does nothing (and returns `Ok`) when the daemon runs proxy-less.
///
/// # Errors
///
/// Returns an error when the listener cannot be bound (non-loopback,
/// address in use) or the proxy shared state cannot be built.
async fn spawn_proxy(
    state: &Arc<DaemonState>,
    client_override: Option<crate::UpstreamClient>,
) -> Result<()> {
    let Some(endpoint) = crate::proxy::bind(state).await? else {
        return Ok(());
    };
    if let Ok(mut guard) = state.proxy_addr.lock() {
        *guard = Some(endpoint.local_addr);
    }
    let shared = Arc::new(crate::proxy::ProxyShared::with_client(
        Arc::clone(state),
        client_override,
    )?);
    let proxy_shutdown = state.shutdown_tx.subscribe();
    let proxy_state = Arc::clone(state);
    let task = tokio::spawn(async move {
        if let Err(e) = crate::proxy::serve(endpoint, shared, proxy_shutdown).await {
            log::error!("credential proxy stopped: {e}");
            proxy_state.request_shutdown();
        }
    });
    *state
        .proxy_task
        .lock()
        .map_err(|_| DaemonError::Internal("proxy task lock poisoned".to_string()))? = Some(task);
    Ok(())
}

/// Undo the runtime files written during a failed startup and release the
/// single-instance lock (releasing the guard drops the lock).
fn undo_startup_runtime_files(state: &DaemonState) {
    instance::clear_stale_files(&state.paths);
    if let Ok(mut guard) = state.guard.lock()
        && let Some(mut instance) = guard.take()
    {
        instance.release();
    }
    state.audit.flush();
}

/// Copy panics into the rotating run log (in addition to the previous
/// hook, e.g. stderr).
///
/// The background launcher hands the daemon inherited stdio handles into
/// `daemon.log`; after a rotation rename those handles write to the
/// rotated file, so without this hook late panic messages could miss the
/// active log entirely.
fn install_panic_logging() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let location = info
                .location()
                .map_or_else(|| "<unknown>".to_string(), std::string::ToString::to_string);
            log::error!("panic at {location}: {info}");
            previous_hook(info);
        }));
    });
}

/// Execute the graceful shutdown sequence. Never calls
/// `std::process::exit`.
async fn graceful_shutdown(state: &Arc<DaemonState>) {
    state.request_shutdown();
    state.audit.emit(&AuditEvent::daemon_stop());
    log::info!("kyz daemon shutting down");

    // Drain the serving tasks in turn (in-flight proxy requests are
    // additionally bounded by their body-read and upstream deadlines,
    // which the drain budget covers).
    drain_serving_tasks(state, shutdown_drain_budget(state)).await;

    if let Ok(mut guard) = state.vault.lock() {
        *guard = None;
    }
    state.audit.flush();

    instance::clear_stale_files(&state.paths);

    if let Ok(mut guard) = state.guard.lock()
        && let Some(mut instance) = guard.take()
    {
        instance.release();
    }
    log::info!("kyz daemon stopped");
    DaemonLogger::flush_global();
}

const fn log_level(level: LogLevel) -> log::LevelFilter {
    match level {
        LogLevel::Error => log::LevelFilter::Error,
        LogLevel::Warn => log::LevelFilter::Warn,
        LogLevel::Info => log::LevelFilter::Info,
        LogLevel::Debug => log::LevelFilter::Debug,
        LogLevel::Trace => log::LevelFilter::Trace,
    }
}

/// Generate a 64-hex-char random token.
fn generate_token_hex() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| DaemonError::Internal(format!("generating token: {e}")))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_is_exact() {
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abc", "abd"));
        assert!(!token_matches("abc", "abcd"));
        assert!(!token_matches("", "x"));
    }

    #[test]
    fn tokens_are_random_and_well_formed() {
        let first = generate_token_hex().expect("token");
        let second = generate_token_hex().expect("token");
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }
}
