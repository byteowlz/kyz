//! Structured audit logging for secret access operations.
//!
//! All secret injection events (exec, pipe, wrap) are logged to stderr
//! with timestamps, operation type, secret names, and target commands.
//! Secret values are never included in audit output.

use std::time::SystemTime;

/// Log an audit event to stderr.
///
/// Format: `[kyz] <ISO8601> op=<op> [secret=<name>] [cmd=<cmd>] [detail=<extra>]`
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
