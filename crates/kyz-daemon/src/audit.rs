//! Structured audit events for the daemon.
//!
//! The audit log is JSON Lines at `state_dir/daemon/audit.log`, separate
//! from the run log. Events are built from a **typed** enum: there is no
//! free-text field anywhere in [`AuditEvent`], so a secret cannot be
//! interpolated into an audit line by construction.
//!
//! Field whitelist: `ts`, `op`, `rule`, `method`, `upstream_host`, `status`,
//! `duration_ms`, `grant`, `reason`. Never recorded: secret values,
//! DK, passphrases, proxy/IPC tokens, request/response bodies,
//! `Authorization`/`X-Api-Key`/`Cookie` headers, full query strings, and
//! URL paths.

use std::path::Path;

use serde::Serialize;

use crate::logging::{DEFAULT_LOG_MAX_BYTES, DEFAULT_LOG_RETAINED, RotatingWriter};

/// Audit operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOp {
    /// Daemon finished starting up.
    DaemonStart,
    /// Daemon began (or completed) a graceful shutdown.
    DaemonStop,
    /// Configuration reload requested; `reason` explains failures.
    DaemonReload,
    /// Proxy forwarded a request upstream.
    ProxyForward,
    /// Proxy refused a request before forwarding.
    ProxyDeny,
    /// Proxy failed while injecting credentials.
    ProxyInjectError,
    /// A script grant resolved secrets for a launch.
    GrantUse,
    /// A script grant was refused.
    GrantDenied,
}

/// Enumerated denial/failure reasons. Never free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReason {
    /// Candidate configuration failed validation (reload).
    ConfigRejected,
    /// Configuration could not be read or parsed (reload).
    ConfigUnreadable,
    /// Routing resolved to multiple equally specific rules.
    AmbiguousRoute,
    /// Method not allowed by the matching rule.
    MethodForbidden,
    /// No rule matched the request.
    NoRoute,
    /// Proxy authentication failed.
    AuthRejected,
    /// Credential resolution or injection failed (fail closed).
    InjectFailed,
    /// Referenced secret or field does not exist.
    MissingSecret,
    /// Request body exceeded the configured limit.
    RequestTooLarge,
    /// Client failed to deliver its declared request body (hung up or
    /// malformed framing mid-body).
    RequestIncomplete,
    /// Upstream response body exceeded the configured limit.
    ResponseTooLarge,
    /// Concurrency limit (`max_in_flight`) reached.
    Overloaded,
    /// Unknown grant requested.
    UnknownGrant,
    /// Script hash mismatch.
    HashMismatch,
    /// Lifecycle timeout reached.
    Timeout,
}

/// One audit event. Every field is typed; see the module docs for the
/// whitelist and the list of values that must never appear here.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    ts: String,
    op: AuditOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<AuditReason>,
}

impl AuditEvent {
    /// `daemon_start`.
    #[must_use]
    pub fn daemon_start() -> Self {
        Self::base(AuditOp::DaemonStart)
    }

    /// `daemon_stop`.
    #[must_use]
    pub fn daemon_stop() -> Self {
        Self::base(AuditOp::DaemonStop)
    }

    /// `daemon_reload` with an optional failure reason.
    #[must_use]
    pub fn daemon_reload(reason: Option<AuditReason>) -> Self {
        let mut event = Self::base(AuditOp::DaemonReload);
        event.reason = reason;
        event
    }

    /// `proxy_forward`.
    #[must_use]
    pub fn proxy_forward(
        rule: &str,
        method: &str,
        upstream_host: &str,
        status: u16,
        duration_ms: u64,
    ) -> Self {
        Self::proxy_forward_with_reason(rule, method, upstream_host, status, duration_ms, None)
    }

    /// `proxy_forward` carrying a typed failure reason (e.g. an upstream
    /// timeout or response-limit where the delivered status is a mapped
    /// 502/504 rather than the upstream's own).
    #[must_use]
    pub fn proxy_forward_with_reason(
        rule: &str,
        method: &str,
        upstream_host: &str,
        status: u16,
        duration_ms: u64,
        reason: Option<AuditReason>,
    ) -> Self {
        let mut event = Self::base(AuditOp::ProxyForward);
        event.rule = Some(rule.to_string());
        event.method = Some(method.to_string());
        event.upstream_host = Some(upstream_host.to_string());
        event.status = Some(status);
        event.duration_ms = Some(duration_ms);
        event.reason = reason;
        event
    }

    /// `proxy_deny`.
    #[must_use]
    pub fn proxy_deny(rule: Option<&str>, method: Option<&str>, reason: AuditReason) -> Self {
        let mut event = Self::base(AuditOp::ProxyDeny);
        event.rule = rule.map(String::from);
        event.method = method.map(String::from);
        event.reason = Some(reason);
        event
    }

    /// `proxy_inject_error`.
    #[must_use]
    pub fn proxy_inject_error(rule: &str, reason: AuditReason) -> Self {
        let mut event = Self::base(AuditOp::ProxyInjectError);
        event.rule = Some(rule.to_string());
        event.reason = Some(reason);
        event
    }

    /// `grant_use`.
    #[must_use]
    pub fn grant_use(grant: &str) -> Self {
        let mut event = Self::base(AuditOp::GrantUse);
        event.grant = Some(grant.to_string());
        event
    }

    /// `grant_denied`.
    #[must_use]
    pub fn grant_denied(grant: Option<&str>, reason: AuditReason) -> Self {
        let mut event = Self::base(AuditOp::GrantDenied);
        event.grant = grant.map(String::from);
        event.reason = Some(reason);
        event
    }

    fn base(op: AuditOp) -> Self {
        Self {
            ts: humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string(),
            op,
            rule: None,
            method: None,
            upstream_host: None,
            status: None,
            duration_ms: None,
            grant: None,
            reason: None,
        }
    }
}

/// JSON Lines audit sink with rotation, written from a dedicated thread.
///
/// [`AuditSink::emit`] only queues (it never blocks on the disk), so async
/// proxy/IPC handlers cannot starve the executor when the disk stalls.
/// Write failures drop the event — the daemon never falls back to stderr
/// for audit data.
#[derive(Debug, Clone)]
pub struct AuditSink {
    sender: std::sync::mpsc::Sender<AuditCommand>,
}

/// One item for the audit writer thread.
enum AuditCommand {
    /// A serialized event line, ready to append.
    Event(String),
    /// Drain barrier: acknowledge once every earlier event is written.
    Flush(std::sync::mpsc::SyncSender<()>),
}

impl AuditSink {
    /// Open (lazily) an audit sink at `path` with default rotation and its
    /// writer thread. Events are appended in emission order.
    #[must_use]
    pub fn open(path: &Path) -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut writer = RotatingWriter::new(path, DEFAULT_LOG_MAX_BYTES, DEFAULT_LOG_RETAINED);
        // Best effort: if the thread cannot spawn, sends fail and events
        // drop — the same degradation as a broken log directory.
        let _ = std::thread::Builder::new()
            .name("audit-writer".to_string())
            .spawn(move || writer_loop(&receiver, &mut writer));
        Self { sender }
    }

    /// Serialize and append one event. Best effort by design; never blocks
    /// on I/O.
    pub fn emit(&self, event: &AuditEvent) {
        let Ok(line) = serde_json::to_string(event) else {
            return;
        };
        let _ = self.sender.send(AuditCommand::Event(line));
    }

    /// Block until every event emitted before this call is on disk (called
    /// during graceful shutdown and after startup teardown).
    pub fn flush(&self) {
        let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel(0);
        if self.sender.send(AuditCommand::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv();
        }
    }
}

/// Write queued events in order until the sink (and its sender) drops.
fn writer_loop(receiver: &std::sync::mpsc::Receiver<AuditCommand>, writer: &mut RotatingWriter) {
    while let Ok(command) = receiver.recv() {
        match command {
            AuditCommand::Event(line) => writer.write_line(&line),
            AuditCommand::Flush(ack) => {
                writer.flush_current();
                let _ = ack.send(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The complete audit field whitelist.
    const WHITELIST: &[&str] = &[
        "ts",
        "op",
        "rule",
        "method",
        "upstream_host",
        "status",
        "duration_ms",
        "grant",
        "reason",
    ];

    #[test]
    fn serialized_events_only_use_whitelist_fields() {
        let events = vec![
            AuditEvent::daemon_start(),
            AuditEvent::daemon_stop(),
            AuditEvent::daemon_reload(Some(AuditReason::ConfigRejected)),
            AuditEvent::daemon_reload(None),
            AuditEvent::proxy_forward("sophify", "POST", "api.sophify.com", 200, 143),
            AuditEvent::proxy_deny(Some("sophify"), Some("TRACE"), AuditReason::MethodForbidden),
            AuditEvent::proxy_deny(None, None, AuditReason::NoRoute),
            AuditEvent::proxy_inject_error("sophify", AuditReason::MissingSecret),
            AuditEvent::grant_use("deploy"),
            AuditEvent::grant_denied(Some("deploy"), AuditReason::HashMismatch),
            AuditEvent::grant_denied(None, AuditReason::UnknownGrant),
        ];

        for event in events {
            let value = serde_json::to_value(&event).expect("audit events must serialize");
            let map = value.as_object().expect("audit event is an object");
            for key in map.keys() {
                assert!(
                    WHITELIST.contains(&key.as_str()),
                    "field '{key}' is not in the audit whitelist"
                );
            }
        }
    }

    #[test]
    fn op_serializes_to_snake_case() {
        let value = serde_json::to_value(AuditEvent::proxy_forward("r", "GET", "h", 200, 1))
            .expect("serialize");
        assert_eq!(value["op"], "proxy_forward");
        assert_eq!(value["rule"], "r");
        assert_eq!(value["upstream_host"], "h");
        assert_eq!(value["status"], 200);
        assert_eq!(value["duration_ms"], 1);
    }

    #[test]
    fn sink_writes_json_lines() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("audit.log");
        let sink = AuditSink::open(&path);
        sink.emit(&AuditEvent::daemon_start());
        sink.emit(&AuditEvent::daemon_stop());
        // Events land on the writer thread; flush is the drain barrier.
        sink.flush();

        let content = std::fs::read_to_string(&path).expect("read audit log");
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("valid json");
        assert_eq!(first["op"], "daemon_start");
    }
}
