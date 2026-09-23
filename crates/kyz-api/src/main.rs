//! HTTP API server for rust-workspace.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(unix)]
use std::path::Path as FsPath;
#[cfg(unix)]
use std::time::Duration;

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State, WebSocketUpgrade, ws},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use clap::{Args, Parser};
use log::info;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
#[cfg(unix)]
use tokio::sync::{Mutex, Semaphore};
use tower_http::trace::TraceLayer;

use kyz_core::{
    AppConfig, AppPaths, AuthRequestStore, CreateAuthRequest, DenyAuthRequest, SecretStore,
    VaultStore,
};
// One-time secret submissions and JIT grants are served over the Unix
// socket IPC channel only.
#[cfg(unix)]
use kyz_core::{
    DecisionReason, GrantScope, GrantStore, GrantUseContext, JitGrant, OneTimeSecretSubmission,
    OneTimeSubmissionStore, OriginMetadata,
};

fn main() -> anyhow::Result<()> {
    try_main()
}

#[tokio::main]
async fn try_main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let paths = AppPaths::discover(cli.common.config.as_deref())?;
    paths.ensure_directories()?;
    let config = AppConfig::load(&paths, false)?;

    let vault_store =
        VaultStore::resolve(cli.common.vault.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))?;

    let state = AppState {
        config: Arc::new(config),
        api_token: std::env::var("KYZ_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty()),
        auth_requests: AuthRequestStore::new(),
        vault_store: Arc::new(vault_store),
        #[cfg(unix)]
        one_time_submissions: Arc::new(Mutex::new(OneTimeSubmissionStore::new())),
        #[cfg(unix)]
        grants: Arc::new(Mutex::new(GrantStore::new())),
    };

    // Fail closed: the API brokers secret material and must never serve it
    // unauthenticated by accident. --insecure-no-auth is the explicit opt-out.
    if state.api_token.is_none() && !cli.common.insecure_no_auth {
        anyhow::bail!(
            "refusing to start an unauthenticated API: set KYZ_API_TOKEN (recommended) or pass --insecure-no-auth"
        );
    }

    #[cfg(unix)]
    {
        let ipc_socket = cli
            .common
            .ipc_socket
            .clone()
            .unwrap_or_else(|| paths.state_dir.join("kyz-ipc.sock"));
        start_ipc_server(&ipc_socket, state.clone())?;
    }

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/config", get(get_config))
        .route("/auth/request", post(create_auth_request))
        .route("/auth/request", get(list_auth_requests))
        .route("/auth/request/{id}", get(get_auth_request))
        .route("/auth/deny/{id}", post(deny_auth_request))
        .route("/auth/approve/{id}", post(approve_auth_request))
        .route("/auth/secrets/{id}", get(pickup_secrets))
        .route("/auth/wait/{id}", get(wait_auth_request))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], cli.common.port));
    info!("Starting API server on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Debug, Parser)]
#[command(author, version, about = "HTTP API server for rust-workspace")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
}

#[derive(Debug, Clone, Args)]
struct CommonOpts {
    /// Override the config file path
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Explicit vault file path (overrides auto-discovery).
    #[arg(long, value_name = "PATH")]
    vault: Option<PathBuf>,

    /// Port to listen on
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Local Unix socket path for one-time secret IPC.
    #[arg(long, value_name = "PATH")]
    ipc_socket: Option<PathBuf>,

    /// Explicitly run without bearer-token authentication (insecure; for
    /// isolated single-user environments only).
    #[arg(long, default_value_t = false)]
    insecure_no_auth: bool,
}

#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    api_token: Option<String>,
    auth_requests: AuthRequestStore,
    vault_store: Arc<VaultStore>,
    /// One-time submissions / JIT grants, served over the Unix IPC channel.
    #[cfg(unix)]
    one_time_submissions: Arc<Mutex<OneTimeSubmissionStore>>,
    #[cfg(unix)]
    grants: Arc<Mutex<GrantStore>>,
}

#[derive(Serialize)]
struct RootResponse {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(expected) = &state.api_token else {
        return Ok(next.run(req).await);
    };

    // Keep health endpoint unauthenticated for probes.
    if req.uri().path() == "/health" {
        return Ok(next.run(req).await);
    }

    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();

    if expected.as_bytes().ct_eq(presented.as_bytes()).into() {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn root() -> Json<RootResponse> {
    Json(RootResponse {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn get_config(State(state): State<AppState>) -> Result<Json<AppConfig>, StatusCode> {
    Ok(Json((*state.config).clone()))
}

// ---------------------------------------------------------------------------
// Auth request handlers
// ---------------------------------------------------------------------------

/// `POST /auth/request` — create a new auth request from a headless agent.
async fn create_auth_request(
    State(state): State<AppState>,
    Json(params): Json<CreateAuthRequest>,
) -> Result<(StatusCode, Json<kyz_core::AuthRequest>), StatusCode> {
    let request = state.auth_requests.create(&params).map_err(|e| {
        if e.contains("pickup_capability") {
            log::warn!("auth request rejected: {e}");
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;

    info!(
        "Auth request created: {} from '{}' for {:?}",
        request.id, request.requester, request.scopes
    );

    Ok((StatusCode::CREATED, Json(request)))
}

/// Query parameters for listing auth requests.
#[derive(Debug, Deserialize)]
struct ListAuthQuery {
    /// Filter by status (pending, approved, denied, expired).
    #[serde(default)]
    status: Option<String>,
}

/// `GET /auth/request` — list auth requests.
async fn list_auth_requests(
    State(state): State<AppState>,
    Query(query): Query<ListAuthQuery>,
) -> Result<Json<Vec<kyz_core::AuthRequest>>, StatusCode> {
    let status_filter = query.status.and_then(|s| match s.as_str() {
        "pending" => Some(kyz_core::AuthRequestStatus::Pending),
        "approved" => Some(kyz_core::AuthRequestStatus::Approved),
        "denied" => Some(kyz_core::AuthRequestStatus::Denied),
        "expired" => Some(kyz_core::AuthRequestStatus::Expired),
        _ => None,
    });

    let requests = state
        .auth_requests
        .list(status_filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(requests))
}

/// `GET /auth/request/:id` — get a specific auth request.
async fn get_auth_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<kyz_core::AuthRequest>, StatusCode> {
    state
        .auth_requests
        .get(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// `POST /auth/deny/:id` — deny an auth request.
async fn deny_auth_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(params): Json<DenyAuthRequest>,
) -> Result<Json<kyz_core::AuthRequest>, StatusCode> {
    let request = state.auth_requests.deny(&id, &params).map_err(|e| {
        if e.contains("not found") {
            StatusCode::NOT_FOUND
        } else if e.contains("not pending") {
            StatusCode::CONFLICT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;

    info!("Auth request denied: {}", request.id);

    Ok(Json(request))
}

// ---------------------------------------------------------------------------
// Auth approval handler
// ---------------------------------------------------------------------------

/// Request body for approving an auth request.
#[derive(Debug, Deserialize)]
struct ApproveAuthBody {
    /// Vault passphrase (required to decrypt the requested secrets).
    passphrase: String,
}

/// Response from a successful approval: the resolved secrets.
#[derive(Debug, Serialize)]
struct ApproveAuthResponse {
    /// The auth request (now approved).
    request: kyz_core::AuthRequest,
    /// Resolved secrets keyed by the scope reference that requested them.
    secrets: std::collections::BTreeMap<String, ResolvedSecret>,
}

/// A single resolved secret, either a full entry or a specific field.
#[derive(Debug, Serialize)]
struct ResolvedSecret {
    /// The service/key that was resolved.
    service: String,
    /// The key name.
    key: String,
    /// If a specific field was requested, just that value. Otherwise all fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
    /// The resolved value(s).
    values: std::collections::BTreeMap<String, String>,
}

/// `POST /auth/approve/:id` — approve a request, decrypt and deliver secrets.
async fn approve_auth_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ApproveAuthBody>,
) -> Result<Json<ApproveAuthResponse>, StatusCode> {
    // 1. Look up and validate the request
    let request = state
        .auth_requests
        .get(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if request.status != kyz_core::AuthRequestStatus::Pending {
        return Err(StatusCode::CONFLICT);
    }

    // 2. Temporarily unlock vault with the provided passphrase to read secrets
    let vault = state.vault_store.as_ref();
    vault.unlock(&body.passphrase, 30).map_err(|e| {
        log::error!("Vault unlock failed during approval: {e}");
        StatusCode::UNAUTHORIZED
    })?;

    // 3. Resolve each requested scope
    let mut secrets = std::collections::BTreeMap::new();
    for scope in &request.scopes {
        match resolve_scope(vault, scope) {
            Ok(resolved) => {
                secrets.insert(scope.clone(), resolved);
            }
            Err(e) => {
                log::warn!("Failed to resolve scope '{scope}': {e}");
                // Lock vault and reject — don't partially deliver
                let _ = vault.lock();
                return Err(StatusCode::UNPROCESSABLE_ENTITY);
            }
        }
    }

    // 4. Lock vault immediately after reading
    let _ = vault.lock();

    // 5. Stash secrets for agent pickup
    let mut stash = std::collections::BTreeMap::new();
    for (scope, resolved) in &secrets {
        stash.insert(scope.clone(), resolved.values.clone());
    }
    state
        .auth_requests
        .stash_secrets(&id, stash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 6. Mark the request as approved (fires broadcast notification)
    let approved = state
        .auth_requests
        .approve(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(
        "Auth request approved: {} — delivered {} secret(s)",
        approved.id,
        secrets.len()
    );

    Ok(Json(ApproveAuthResponse {
        request: approved,
        secrets,
    }))
}

/// Parse a scope reference like `"service/key"` or `"service/key:field"` and resolve it.
fn resolve_scope(
    store: &dyn SecretStore,
    scope: &str,
) -> std::result::Result<ResolvedSecret, String> {
    // Split optional field
    let (secret_ref, field_name) = if let Some((s, f)) = scope.split_once(':') {
        (s, Some(f))
    } else {
        (scope, None)
    };

    let (service, key) = secret_ref
        .split_once('/')
        .ok_or_else(|| format!("invalid scope '{scope}', expected service/key[:field]"))?;

    let entry = store
        .get(service, key)
        .map_err(|e| format!("failed to get '{secret_ref}': {e}"))?;

    let mut values = std::collections::BTreeMap::new();

    if let Some(field) = field_name {
        let val = entry
            .field(field)
            .ok_or_else(|| format!("field '{field}' not found in '{secret_ref}'"))?;
        values.insert(field.to_string(), val.to_string());
    } else {
        for (name, value) in &entry.fields {
            values.insert(
                name.clone(),
                secrecy::ExposeSecret::expose_secret(value).to_string(),
            );
        }
    }

    Ok(ResolvedSecret {
        service: service.to_string(),
        key: key.to_string(),
        field: field_name.map(String::from),
        values,
    })
}

// ---------------------------------------------------------------------------
// One-time secret pickup endpoint
// ---------------------------------------------------------------------------

/// Query parameters for the one-time secrets pickup.
#[derive(Debug, Deserialize)]
struct PickupQuery {
    /// Client-generated pickup capability from request creation. Knowing the
    /// request id alone is not sufficient to redeem the stash. Optional at
    /// the type level so a missing parameter yields the same 404 as a wrong
    /// capability (no oracle for "request exists").
    capability: Option<String>,
}

/// `GET /auth/secrets/:id` — one-time pickup of stashed secrets after approval.
/// Requires the pickup capability generated by the requester at creation; a
/// wrong/missing capability is indistinguishable from "nothing to pick up".
async fn pickup_secrets(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<PickupQuery>,
) -> Result<
    Json<std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>>,
    StatusCode,
> {
    let secrets = state
        .auth_requests
        .pickup_secrets(&id, q.capability.as_deref().unwrap_or(""))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    info!("Secrets picked up for auth request: {id}");

    Ok(Json(secrets))
}

// ---------------------------------------------------------------------------
// WebSocket wait endpoint
// ---------------------------------------------------------------------------

/// `GET /auth/wait/:id` — WebSocket upgrade. Sends a JSON message when the
/// request is approved, denied, or expires, then closes.
async fn wait_auth_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
    upgrade: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    // Verify the request exists
    let request = state
        .auth_requests
        .get(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // If already resolved, reject upgrade — caller should just GET the request
    if request.status != kyz_core::AuthRequestStatus::Pending {
        return Err(StatusCode::CONFLICT);
    }

    let auth_store = state.auth_requests;
    let request_id = id;

    Ok(upgrade.on_upgrade(move |socket| handle_wait_ws(socket, auth_store, request_id)))
}

/// Handle the WebSocket connection: subscribe and wait for status change.
async fn handle_wait_ws(
    mut socket: ws::WebSocket,
    auth_store: kyz_core::AuthRequestStore,
    request_id: String,
) {
    let mut rx = auth_store.subscribe();

    // Also check periodically for expiry (every 5 seconds)
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) if event.id == request_id => {
                        let msg = serde_json::json!({
                            "type": "status_change",
                            "id": event.id,
                            "status": event.status,
                        });
                        let _ = socket.send(ws::Message::Text(msg.to_string().into())).await;
                        let _ = socket.send(ws::Message::Close(None)).await;
                        return;
                    }
                    Ok(_)
                    | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {} // different request or lagged
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        let _ = socket.send(ws::Message::Close(None)).await;
                        return;
                    }
                }
            }
            _ = interval.tick() => {
                // Check for expiry
                if let Ok(Some(req)) = auth_store.get(&request_id) {
                    if req.status != kyz_core::AuthRequestStatus::Pending {
                        let msg = serde_json::json!({
                            "type": "status_change",
                            "id": req.id,
                            "status": req.status,
                        });
                        let _ = socket.send(ws::Message::Text(msg.to_string().into())).await;
                        let _ = socket.send(ws::Message::Close(None)).await;
                        return;
                    }
                } else {
                    // Request gone
                    let _ = socket.send(ws::Message::Close(None)).await;
                    return;
                }
            }
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum IpcRequest {
    SubmitSecret {
        /// Caller-chosen id; when omitted the daemon generates a random one
        /// and returns it in the response (avoids predictable ids like
        /// "req-123" that another local process could redeem first).
        request_id: Option<String>,
        service: String,
        key: String,
        value: String,
        expires_at: u64,
        #[serde(default)]
        origin: OriginMetadata,
    },
    ResolveSecret {
        request_id: String,
    },
    IssueGrant {
        token: String,
        secret_refs: Vec<String>,
        #[serde(default)]
        commands: Vec<String>,
        #[serde(default)]
        workspaces: Vec<String>,
        expires_at: u64,
        #[serde(default = "default_grant_use_count")]
        use_count: u32,
    },
    ValidateGrant {
        token: String,
        secret_ref: String,
        command: String,
        workspace: String,
    },
}

#[cfg(unix)]
const fn default_grant_use_count() -> u32 {
    1
}

#[cfg(unix)]
#[derive(Debug, Serialize)]
struct IpcResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[cfg(unix)]
impl IpcResponse {
    const fn accepted() -> Self {
        Self {
            ok: true,
            reason: None,
            request_id: None,
            service: None,
            key: None,
            value: None,
        }
    }

    const fn denied(reason: &'static str) -> Self {
        Self {
            ok: false,
            reason: Some(reason),
            request_id: None,
            service: None,
            key: None,
            value: None,
        }
    }
}

#[cfg(unix)]
fn start_ipc_server(path: &FsPath, state: AppState) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    use tokio::net::UnixListener;

    ensure_secure_socket_parent(path)?;

    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    info!("Starting IPC server on {}", path.display());

    // Bound concurrency: one slow/hostile same-UID client must not exhaust
    // daemon resources (the HTTP auth flow shares this process).
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_IPC_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let accepted = listener.accept().await;
            let Ok((stream, _addr)) = accepted else {
                break;
            };
            let Ok(permit) = permits.clone().acquire_owned().await else {
                break;
            };
            let state_cloned = state.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = handle_ipc_connection(stream, state_cloned).await;
            });
        }
    });

    Ok(())
}

/// Maximum bytes accepted for a single IPC request line.
#[cfg(unix)]
const MAX_IPC_LINE_BYTES: u64 = 64 * 1024;

/// Maximum concurrent IPC connections.
#[cfg(unix)]
const MAX_CONCURRENT_IPC_CONNECTIONS: usize = 64;

/// Seconds to wait for a complete request line before dropping the client.
#[cfg(unix)]
const IPC_READ_TIMEOUT_SECS: u64 = 10;

#[cfg(unix)]
fn ensure_secure_socket_parent(path: &FsPath) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let Some(parent) = path.parent() else {
        return Err(anyhow::anyhow!("invalid IPC socket path"));
    };

    // Never chmod a directory that is not effectively ours, and never use a
    // world-writable one (a pre-created attacker dir would DoS startup; root
    // following the documented /tmp example would otherwise lock down the
    // system temp dir). A writability probe doubles as an ownership check
    // without unsafe libc calls.
    if parent.exists() {
        let meta = std::fs::metadata(parent)?;
        if meta.permissions().mode() & 0o002 != 0 {
            return Err(anyhow::anyhow!(
                "refusing to use world-writable {} as IPC socket parent",
                parent.display()
            ));
        }
        let probe = parent.join(format!(".kyz-ipc-probe-{}", std::process::id()));
        match std::fs::write(&probe, b"") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe);
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "refusing to use {} as IPC socket parent: not writable by the current user ({e})",
                    parent.display()
                ));
            }
        }
    } else {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
async fn handle_ipc_connection(stream: tokio::net::UnixStream, state: AppState) -> Result<()> {
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    // Cap both the line length and the wait: a newline-free stream must grow
    // the buffer only up to the cap, and a stalled client must not hold a
    // connection slot indefinitely.
    let read = tokio::time::timeout(
        Duration::from_secs(IPC_READ_TIMEOUT_SECS),
        (&mut reader).take(MAX_IPC_LINE_BYTES).read_line(&mut line),
    )
    .await;
    let n = match read {
        Ok(Ok(n)) => u64::from(u32::try_from(n).unwrap_or(u32::MAX)),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => anyhow::bail!("ipc client timed out before sending a complete request"),
    };
    if n >= MAX_IPC_LINE_BYTES {
        anyhow::bail!("ipc request line exceeds {MAX_IPC_LINE_BYTES} bytes");
    }

    let request = serde_json::from_str::<IpcRequest>(&line);
    let response = match request {
        Ok(req) => process_ipc_request(req, &state).await,
        Err(_) => IpcResponse::denied(reason_label(DecisionReason::Malformed)),
    };

    let payload = serde_json::to_string(&response)?;
    let socket = reader.get_mut();
    socket.write_all(payload.as_bytes()).await?;
    socket.write_all(b"\n").await?;

    Ok(())
}

#[cfg(unix)]
async fn process_ipc_request(req: IpcRequest, state: &AppState) -> IpcResponse {
    match req {
        IpcRequest::SubmitSecret {
            request_id,
            service,
            key,
            value,
            expires_at,
            origin,
        } => handle_ipc_submit(state, request_id, service, key, value, expires_at, origin).await,
        IpcRequest::ResolveSecret { request_id } => handle_ipc_resolve(state, request_id).await,
        IpcRequest::IssueGrant {
            token,
            secret_refs,
            commands,
            workspaces,
            expires_at,
            use_count,
        } => {
            handle_ipc_issue_grant(
                state,
                token,
                secret_refs,
                commands,
                workspaces,
                expires_at,
                use_count,
            )
            .await
        }
        IpcRequest::ValidateGrant {
            token,
            secret_ref,
            command,
            workspace,
        } => handle_ipc_validate_grant(state, token, secret_ref, command, workspace).await,
    }
}

#[cfg(unix)]
async fn handle_ipc_submit(
    state: &AppState,
    request_id: Option<String>,
    service: String,
    key: String,
    value: String,
    expires_at: u64,
    origin: OriginMetadata,
) -> IpcResponse {
    // Generate a high-entropy id when the caller omits one: predictable
    // caller-chosen ids ("req-123") let another local process redeem the
    // submission first.
    let request_id = match request_id {
        Some(id) if !id.trim().is_empty() => id,
        _ => generate_ipc_request_id(),
    };
    let payload = OneTimeSecretSubmission {
        request_id: request_id.clone(),
        service: service.clone(),
        key: key.clone(),
        value,
        expires_at,
        origin,
    };
    let mut store = state.one_time_submissions.lock().await;
    match store.submit(payload, kyz_core::jit::now_unix()) {
        Ok(()) => {
            log::info!("ipc_submit accepted request_id={request_id} service={service} key={key}");
            let mut response = IpcResponse::accepted();
            response.request_id = Some(request_id);
            response
        }
        Err(reason) => {
            log::warn!(
                "ipc_submit denied request_id={request_id} service={service} key={key} reason={}",
                reason_label(reason)
            );
            IpcResponse::denied(reason_label(reason))
        }
    }
}

#[cfg(unix)]
async fn handle_ipc_resolve(state: &AppState, request_id: String) -> IpcResponse {
    let mut store = state.one_time_submissions.lock().await;
    match store.resolve_once(&request_id, kyz_core::jit::now_unix()) {
        Ok(found) => {
            // Log the redemption (metadata only, never the value): silent
            // one-time theft must at least be auditable.
            log::info!(
                "ipc_resolve accepted request_id={request_id} service={} key={}",
                found.service,
                found.key
            );
            IpcResponse {
                ok: true,
                reason: None,
                request_id: Some(request_id),
                service: Some(found.service),
                key: Some(found.key),
                value: Some(found.value),
            }
        }
        Err(reason) => {
            log::warn!(
                "ipc_resolve denied request_id={request_id} reason={}",
                reason_label(reason)
            );
            IpcResponse::denied(reason_label(reason))
        }
    }
}

#[cfg(unix)]
async fn handle_ipc_issue_grant(
    state: &AppState,
    token: String,
    secret_refs: Vec<String>,
    commands: Vec<String>,
    workspaces: Vec<String>,
    expires_at: u64,
    use_count: u32,
) -> IpcResponse {
    let inserted = {
        let mut grants = state.grants.lock().await;
        let now = kyz_core::jit::now_unix();
        // Refuse to overwrite a still-live grant: any same-UID process can
        // reach the socket, so accepting upserts would let one process widen
        // another's pending grant (scope/TTL/use-count hijack).
        grants.insert(
            JitGrant {
                token,
                scope: GrantScope {
                    secret_refs,
                    commands,
                    workspaces,
                },
                expires_at,
                use_count,
            },
            now,
        )
    };
    match inserted {
        Ok(()) => IpcResponse::accepted(),
        Err(reason) => {
            log::warn!(
                "ipc_grant denied token=<redacted> reason={}",
                reason_label(reason)
            );
            IpcResponse::denied(reason_label(reason))
        }
    }
}

#[cfg(unix)]
async fn handle_ipc_validate_grant(
    state: &AppState,
    token: String,
    secret_ref: String,
    command: String,
    workspace: String,
) -> IpcResponse {
    let mut grants = state.grants.lock().await;
    let use_ctx = GrantUseContext {
        secret_ref: &secret_ref,
        command: &command,
        workspace: &workspace,
    };
    match grants.validate_and_consume(&token, &use_ctx, kyz_core::jit::now_unix()) {
        Ok(()) => IpcResponse::accepted(),
        Err(reason) => IpcResponse::denied(reason_label(reason)),
    }
}

#[cfg(unix)]
const fn reason_label(reason: DecisionReason) -> &'static str {
    match reason {
        DecisionReason::Malformed => "malformed",
        DecisionReason::Replayed => "replayed",
        DecisionReason::Expired => "expired",
        DecisionReason::NotFound => "not_found",
        DecisionReason::OutOfScope => "out_of_scope",
        DecisionReason::UseCountExceeded => "use_count_exceeded",
        DecisionReason::AlreadyExists => "already_exists",
    }
}

/// Generate a random IPC request id for submissions that omit one.
#[cfg(unix)]
fn generate_ipc_request_id() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 16];
    let ok = getrandom::fill(&mut bytes).is_ok();
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    let _ = write!(s, "ipc-");
    if ok {
        for b in &bytes {
            let _ = write!(s, "{b:02x}");
        }
    } else {
        // RNG failure: refuse to mint a guessable/predictable fallback id.
        let _ = write!(s, "unavailable");
    }
    s
}
