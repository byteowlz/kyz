//! HTTP API server for rust-workspace.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

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
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use kyz_core::{
    AppConfig, AppPaths, AuthRequestStore, CreateAuthRequest, DenyAuthRequest, SecretStore,
    VaultStore,
};

fn main() -> anyhow::Result<()> {
    try_main()
}

#[tokio::main]
async fn try_main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let paths = AppPaths::discover(cli.common.config.as_deref())?;
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
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/config", get(get_config))
        .route("/auth/request", post(create_auth_request))
        .route("/auth/request", get(list_auth_requests))
        .route("/auth/request/{id}", get(get_auth_request))
        .route("/auth/deny/{id}", post(deny_auth_request))
        .route("/auth/approve/{id}", post(approve_auth_request))
        .route("/auth/wait/{id}", get(wait_auth_request))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(cors)
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
}

#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    api_token: Option<String>,
    auth_requests: AuthRequestStore,
    vault_store: Arc<VaultStore>,
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
    let request = state
        .auth_requests
        .create(&params)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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

    // 5. Mark the request as approved
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

    let auth_store = state.auth_requests.clone();
    let request_id = id.clone();

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
                    Ok(_) => continue, // different request
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
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
