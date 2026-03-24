//! HTTP API server for rust-workspace.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use clap::{Args, Parser};
use log::info;
use serde::Serialize;
use subtle::ConstantTimeEq as _;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use kyz_core::{AppConfig, AppPaths, AuthRequestStore, CreateAuthRequest, DenyAuthRequest};

fn main() -> anyhow::Result<()> {
    try_main()
}

#[tokio::main]
async fn try_main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let paths = AppPaths::discover(cli.common.config.as_deref())?;
    let config = AppConfig::load(&paths, false)?;

    let state = AppState {
        config: Arc::new(config),
        api_token: std::env::var("KYZ_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty()),
        auth_requests: AuthRequestStore::new(),
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

    /// Port to listen on
    #[arg(short, long, default_value = "3000")]
    port: u16,
}

#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    api_token: Option<String>,
    auth_requests: AuthRequestStore,
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
