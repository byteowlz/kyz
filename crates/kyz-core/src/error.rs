//! Error types for the core library.

use thiserror::Error;

/// Core library error type.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A configuration-related error.
    #[error("configuration error: {0}")]
    Config(String),

    /// A path resolution or validation error.
    #[error("path error: {0}")]
    Path(String),

    /// An I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// A serialization or deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A secret store operation failed.
    #[error("secret store error: {0}")]
    Secret(String),

    /// A requested secret was not found.
    #[error("secret not found: {0}")]
    SecretNotFound(String),
}

/// Result type alias using `CoreError`.
pub type Result<T> = std::result::Result<T, CoreError>;
