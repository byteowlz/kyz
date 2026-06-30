//! Selector type for addressing a secret independently of a backend.

use std::fmt;

/// A backend-agnostic reference to a single secret entry.
///
/// `SecretRef` is the minimum identifier a caller needs to ask the
/// runtime for a secret: a service namespace and a key within that
/// namespace. It is intentionally cheap to clone and display-safe — it
/// never carries secret field values.
///
/// # Example
///
/// ```
/// use kyz_runtime::SecretRef;
///
/// let r = SecretRef::new("github", "deploy-key");
/// assert_eq!(r.service(), "github");
/// assert_eq!(r.key(), "deploy-key");
/// assert_eq!(format!("{r}"), "github/deploy-key");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    service: String,
    key: String,
}

impl SecretRef {
    /// Build a ref from a service namespace and key.
    #[must_use]
    pub fn new(service: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            key: key.into(),
        }
    }

    /// The service namespace component.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The key component.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.service, self.key)
    }
}
