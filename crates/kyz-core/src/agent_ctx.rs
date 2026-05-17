//! Optional `AGENT_CTX_*` runtime metadata (contract v1).
//!
//! Implements the `AGENT_CTX` environment contract documented at
//! `schemas/agent-context-env/`. Parsing is defensive: missing or malformed
//! variables MUST NOT change behavior. Values are informational metadata only
//! and MUST NOT be used as a security authority.

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Contract version this implementation understands.
pub const CONTRACT_VERSION: &str = "1";

/// Runtime mode reported by the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    /// User-driven local invocation.
    Local,
    /// Agent runner invocation (typically headless).
    Runner,
    /// Sandboxed container invocation.
    Container,
}

impl RunMode {
    /// Parse a string value into a known mode. Unknown values return `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "local" => Some(Self::Local),
            "runner" => Some(Self::Runner),
            "container" => Some(Self::Container),
            _ => None,
        }
    }

    /// Canonical string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Runner => "runner",
            Self::Container => "container",
        }
    }
}

/// Effective `AGENT_CTX` context for the current process.
///
/// Every field is optional: the contract requires tools to keep working when
/// any (or all) variables are absent or malformed.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AgentContext {
    /// Contract version (only `"1"` is accepted, anything else is dropped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Platform name (e.g. `oqto`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_name: Option<String>,
    /// Platform build/version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_version: Option<String>,
    /// Active harness/runtime identifier (e.g. `pi`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// Run mode (`local`, `runner`, `container`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_mode: Option<RunMode>,
    /// Stable platform session id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_session_id: Option<String>,
    /// Harness-native session id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_session_id: Option<String>,
    /// Stable workspace id/hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Absolute workspace path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_path: Option<PathBuf>,
    /// Platform user id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Human-readable session name (display only, not durable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    /// Short friendly id for UI/logs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readable_id: Option<String>,
    /// Active model id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Per-action request id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Cross-service trace id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Active sandbox profile (observability hint only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_profile: Option<String>,
}

impl AgentContext {
    /// Load context from process environment.
    ///
    /// Empty strings and unknown values are silently dropped (treated as
    /// malformed per the contract). Returns an all-`None` instance when no
    /// `AGENT_CTX` vars are set.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_iter_str(env::vars())
    }

    /// Load context from an iterator of `(name, value)` pairs. Useful for
    /// testing without mutating process environment.
    #[must_use]
    pub fn from_iter_str<I, K, V>(iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in iter {
            let key = k.as_ref();
            if key.starts_with("AGENT_CTX_") {
                let val = v.as_ref();
                if !val.is_empty() {
                    map.insert(key.to_string(), val.to_string());
                }
            }
        }
        Self::from_map(&map)
    }

    fn from_map(map: &BTreeMap<String, String>) -> Self {
        let take = |k: &str| map.get(k).cloned();

        // Per the contract, only version "1" is meaningful. If something else
        // is present we silently drop the field rather than erroring.
        let version = take("AGENT_CTX_VERSION").filter(|v| v == CONTRACT_VERSION);
        let run_mode = take("AGENT_CTX_RUN_MODE").and_then(|v| RunMode::parse(&v));
        let workspace_path = take("AGENT_CTX_WORKSPACE_PATH").map(PathBuf::from);

        Self {
            version,
            platform_name: take("AGENT_CTX_PLATFORM_NAME"),
            platform_version: take("AGENT_CTX_PLATFORM_VERSION"),
            harness: take("AGENT_CTX_HARNESS"),
            run_mode,
            platform_session_id: take("AGENT_CTX_PLATFORM_SESSION_ID"),
            harness_session_id: take("AGENT_CTX_HARNESS_SESSION_ID"),
            workspace_id: take("AGENT_CTX_WORKSPACE_ID"),
            workspace_path,
            user_id: take("AGENT_CTX_USER_ID"),
            session_name: take("AGENT_CTX_SESSION_NAME"),
            readable_id: take("AGENT_CTX_READABLE_ID"),
            model: take("AGENT_CTX_MODEL"),
            request_id: take("AGENT_CTX_REQUEST_ID"),
            correlation_id: take("AGENT_CTX_CORRELATION_ID"),
            sandbox_profile: take("AGENT_CTX_SANDBOX_PROFILE"),
        }
    }

    /// True when no `AGENT_CTX` variables were observed (or all were dropped).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.version.is_none()
            && self.platform_name.is_none()
            && self.platform_version.is_none()
            && self.harness.is_none()
            && self.run_mode.is_none()
            && self.platform_session_id.is_none()
            && self.harness_session_id.is_none()
            && self.workspace_id.is_none()
            && self.workspace_path.is_none()
            && self.user_id.is_none()
            && self.session_name.is_none()
            && self.readable_id.is_none()
            && self.model.is_none()
            && self.request_id.is_none()
            && self.correlation_id.is_none()
            && self.sandbox_profile.is_none()
    }

    /// Render the context as ordered `key=value` audit tags. Suitable for
    /// appending to a structured log line. Returns an empty vec when no
    /// fields are present.
    #[must_use]
    pub fn audit_tags(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        let mut push = |k: &'static str, v: Option<String>| {
            if let Some(val) = v {
                out.push((k, val));
            }
        };
        push("ctx_platform", self.platform_name.clone());
        push("ctx_platform_version", self.platform_version.clone());
        push("ctx_harness", self.harness.clone());
        push(
            "ctx_run_mode",
            self.run_mode.map(|m| m.as_str().to_string()),
        );
        push("ctx_session", self.platform_session_id.clone());
        push("ctx_harness_session", self.harness_session_id.clone());
        push("ctx_workspace_id", self.workspace_id.clone());
        push(
            "ctx_workspace",
            self.workspace_path
                .as_ref()
                .map(|p| p.display().to_string()),
        );
        push("ctx_user", self.user_id.clone());
        push("ctx_readable_id", self.readable_id.clone());
        push("ctx_model", self.model.clone());
        push("ctx_request", self.request_id.clone());
        push("ctx_correlation", self.correlation_id.clone());
        push("ctx_sandbox_profile", self.sandbox_profile.clone());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentContext, RunMode};
    use std::path::PathBuf;

    fn minimal() -> Vec<(&'static str, &'static str)> {
        vec![
            ("AGENT_CTX_VERSION", "1"),
            ("AGENT_CTX_PLATFORM_NAME", "oqto"),
            ("AGENT_CTX_PLATFORM_VERSION", "0.17.3"),
            ("AGENT_CTX_HARNESS", "pi"),
            ("AGENT_CTX_RUN_MODE", "runner"),
            ("AGENT_CTX_PLATFORM_SESSION_ID", "sess_8f23"),
            ("AGENT_CTX_WORKSPACE_ID", "ws_a13f"),
            ("AGENT_CTX_WORKSPACE_PATH", "/tmp/ws"),
            ("AGENT_CTX_USER_ID", "u_123"),
        ]
    }

    #[test]
    fn absent_yields_empty() {
        let ctx = AgentContext::from_iter_str(Vec::<(&str, &str)>::new());
        assert!(ctx.is_empty());
        assert!(ctx.audit_tags().is_empty());
    }

    #[test]
    fn minimal_set_parses() {
        let ctx = AgentContext::from_iter_str(minimal());
        assert!(!ctx.is_empty());
        assert_eq!(ctx.version.as_deref(), Some("1"));
        assert_eq!(ctx.platform_name.as_deref(), Some("oqto"));
        assert_eq!(ctx.run_mode, Some(RunMode::Runner));
        assert_eq!(ctx.workspace_path, Some(PathBuf::from("/tmp/ws")));
        let tags = ctx.audit_tags();
        assert!(tags.iter().any(|(k, _)| *k == "ctx_platform"));
        assert!(
            tags.iter()
                .any(|(k, v)| *k == "ctx_workspace" && v == "/tmp/ws")
        );
    }

    #[test]
    fn malformed_version_is_dropped_but_others_kept() {
        let mut env = minimal();
        env[0] = ("AGENT_CTX_VERSION", "2");
        let ctx = AgentContext::from_iter_str(env);
        assert!(
            ctx.version.is_none(),
            "unknown version should drop only the version field"
        );
        assert_eq!(ctx.platform_name.as_deref(), Some("oqto"));
    }

    #[test]
    fn malformed_run_mode_is_dropped() {
        let env = vec![
            ("AGENT_CTX_VERSION", "1"),
            ("AGENT_CTX_RUN_MODE", "not-a-mode"),
        ];
        let ctx = AgentContext::from_iter_str(env);
        assert!(ctx.run_mode.is_none());
        assert_eq!(ctx.version.as_deref(), Some("1"));
    }

    #[test]
    fn empty_values_are_treated_as_unset() {
        let env = vec![
            ("AGENT_CTX_VERSION", "1"),
            ("AGENT_CTX_PLATFORM_NAME", ""),
            ("AGENT_CTX_WORKSPACE_PATH", ""),
        ];
        let ctx = AgentContext::from_iter_str(env);
        assert!(ctx.platform_name.is_none());
        assert!(ctx.workspace_path.is_none());
    }

    #[test]
    fn non_agent_ctx_vars_ignored() {
        let env = vec![
            ("PATH", "/usr/bin"),
            ("AGENT_CTX_USER_ID", "u_42"),
            ("HOME", "/home/u"),
        ];
        let ctx = AgentContext::from_iter_str(env);
        assert_eq!(ctx.user_id.as_deref(), Some("u_42"));
        assert!(ctx.platform_name.is_none());
    }

    #[test]
    fn audit_tag_order_is_stable() {
        let ctx = AgentContext::from_iter_str(minimal());
        let keys: Vec<&str> = ctx.audit_tags().iter().map(|(k, _)| *k).collect();
        assert_eq!(
            keys,
            vec![
                "ctx_platform",
                "ctx_platform_version",
                "ctx_harness",
                "ctx_run_mode",
                "ctx_session",
                "ctx_workspace_id",
                "ctx_workspace",
                "ctx_user",
            ]
        );
    }
}
