//! Structured audit logging for secret access operations.
//!
//! All secret injection events (exec, pipe, wrap) are logged to stderr
//! with timestamps, operation type, secret names, and target commands.
//! Secret values are never included in audit output.
//!
//! When `AGENT_CTX_*` environment variables are present (see
//! `schemas/agent-context-env/`), audit lines are enriched with stable
//! runtime context (platform, harness, session id, workspace, request id).
//! The context is metadata only and never used for authorization decisions.

use std::time::SystemTime;

use crate::agent_ctx::AgentContext;

/// Log an audit event to stderr.
///
/// Format: `[kyz] <ISO8601> op=<op> [secret=<name>] [cmd=<cmd>] [detail=<extra>] [ctx_*=<value>]...`
pub fn audit(op: &str, secret: Option<&str>, command: Option<&str>, detail: Option<&str>) {
    let ts = humantime::format_rfc3339_seconds(SystemTime::now());
    let mut parts = vec![format!("[kyz] {ts} op={op}")];
    if let Some(s) = secret {
        parts.push(format!("secret={s}"));
    }
    if let Some(c) = command {
        parts.push(format!("cmd={c}"));
    }
    if let Some(d) = detail {
        parts.push(format!("detail={d}"));
    }
    for (k, v) in AgentContext::from_env().audit_tags() {
        parts.push(format!("{k}={}", quote_if_needed(&v)));
    }
    eprintln!("{}", parts.join(" "));
}

/// Log an exec operation with multiple secrets.
pub fn audit_exec(secret_names: &[String], command: &str) {
    let names = secret_names.join(",");
    audit(
        "exec",
        Some(&names),
        Some(command),
        Some(&format!("injecting {} secret(s)", secret_names.len())),
    );
}

/// Log a pipe operation.
pub fn audit_pipe(secret_name: &str, command: &str) {
    audit("pipe", Some(secret_name), Some(command), None);
}

/// Log a wrap operation.
pub fn audit_wrap(allowed_secrets: &[String], command: &str) {
    let names = allowed_secrets.join(",");
    audit(
        "wrap",
        Some(&names),
        Some(command),
        Some(&format!("{} secret(s) pre-approved", allowed_secrets.len())),
    );
}

/// Log a policy violation.
pub fn audit_policy_violation(command: &str, reason: &str) {
    audit("policy_deny", None, Some(command), Some(reason));
}

/// Quote a value with double quotes when it contains spaces or quotes, so
/// downstream log scrapers can split on whitespace. Most stable ids never
/// trip this, so unquoted output remains the common case.
fn quote_if_needed(v: &str) -> String {
    if v.is_empty() || v.contains(char::is_whitespace) || v.contains('"') {
        let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::quote_if_needed;

    #[test]
    fn simple_values_are_not_quoted() {
        assert_eq!(quote_if_needed("sess_8f"), "sess_8f");
        assert_eq!(quote_if_needed("/tmp/ws"), "/tmp/ws");
    }

    #[test]
    fn values_with_spaces_are_quoted() {
        assert_eq!(quote_if_needed("hello world"), "\"hello world\"");
    }

    #[test]
    fn values_with_quotes_are_escaped() {
        assert_eq!(quote_if_needed("a\"b"), "\"a\\\"b\"");
    }
}
