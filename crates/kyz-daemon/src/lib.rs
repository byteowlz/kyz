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
//! Credential daemon for kyz.
//!
//! This crate owns the process-facing half of the daemon: secure state
//! directory layout, single-instance locking, structured audit, rotating
//! run logs, the immutable config snapshot, the management IPC transport
//! (Unix domain socket / Windows named pipe), and the lifecycle state
//! machine. `kyz-core` keeps all synchronous domain logic (crypto, config,
//! vault access).

pub mod audit;
pub mod config_snapshot;
pub mod instance;
pub mod ipc;
pub mod lifecycle;
pub mod logging;
pub mod proxy;
pub mod state;
pub mod upstream;

use kyz_core::CoreError;

pub use audit::{AuditEvent, AuditOp, AuditReason, AuditSink};
pub use config_snapshot::{ConfigSnapshot, SnapshotState, SnapshotSummary};
pub use instance::InstanceGuard;
pub use ipc::{
    IpcRequest, IpcRequestKind, IpcResponse, StatusReport, send_request, send_request_blocking,
};
pub use kyz_core::proxy_config::PROXY_TOKEN_HEADER;
pub use lifecycle::{
    DaemonHandle, DaemonOptions, DaemonState, run_blocking, run_daemon, run_daemon_with_upstream,
};
pub use proxy::{ProxyEndpoint, ProxyShared};
pub use state::DaemonPaths;
pub use upstream::{
    DEFAULT_UPSTREAM_TIMEOUT_SECS, UpstreamClient, UpstreamError, UpstreamRequest, UpstreamResponse,
};

/// Errors produced by the daemon crate.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Failure forwarded from `kyz-core`.
    #[error("core error: {0}")]
    Core(#[from] CoreError),

    /// Configuration could not be loaded or failed validation.
    #[error("configuration error: {0}")]
    Config(String),

    /// Another daemon instance already holds the singleton lock.
    #[error("daemon already running: {0}")]
    AlreadyRunning(String),

    /// Management IPC transport or protocol failure.
    #[error("ipc error: {0}")]
    Ipc(String),

    /// Anything else; the message never contains secret material.
    #[error("daemon error: {0}")]
    Internal(String),
}

impl From<kyz_core::proxy_config::ConfigValidationError> for DaemonError {
    fn from(value: kyz_core::proxy_config::ConfigValidationError) -> Self {
        Self::Config(value.to_string())
    }
}

impl From<anyhow::Error> for DaemonError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value.to_string())
    }
}

/// Result alias for daemon operations.
pub type Result<T> = std::result::Result<T, DaemonError>;
