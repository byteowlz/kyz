//! Pure (IO-free) validation and matching logic for the credential proxy
//! configuration.
//!
//! These functions are shared by `kyz daemon start` / `reload` (load-time
//! validation) and the request-time router so both sides agree on semantics:
//!
//! - Host normalization (ASCII lowercase, legal port stripping, userinfo
//!   rejection)
//! - Left-side single-label wildcards (`*.example.com`)
//! - Rule precedence: exact host > wildcard, longer `path_prefix` wins
//!   (segment-boundary aware: `/v1` never matches `/v10`), method must be
//!   allowed, identical-prefix multi-matches are configuration ambiguity
//! - Method allowlists with unconditional `CONNECT`/`TRACE` rejection
//! - Header template parsing (literal + `{{alias.field}}` only)
//! - The full load-time validation checklist
//!
//! Error messages deliberately reference only names and positions (rule
//! names, aliases, header names); they never echo template values, which may
//! contain literal secrets.

use std::net::SocketAddr;

use crate::config::{AppConfig, MAX_TIMEOUT_SECS, ProxyRuleConfig};

/// Methods allowed when a rule configures no explicit allowlist.
pub const DEFAULT_ALLOWED_METHODS: &[&str] =
    &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// Methods rejected regardless of configuration.
pub const FORBIDDEN_METHODS: &[&str] = &["CONNECT", "TRACE"];

/// Header name carrying the per-daemon proxy token.
///
/// Owned by the proxy pipeline: stripped from client requests, never
/// injected, and rejected in `headers`/`static_headers` configuration.
pub const PROXY_TOKEN_HEADER: &str = "x-kyz-proxy-token";

/// Hop-by-hop headers never forwarded in either direction.
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
];

/// Header names that `headers`/`static_headers` may not inject.
///
/// Hop-by-hop names, the framing headers kyz regenerates, `Host` (the
/// rule's upstream authority decides the destination), and the proxy token
/// header — injecting any of them would fight the sanitize/reframe
/// pipeline instead of extending it.
pub const RESERVED_HEADER_NAMES: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
    "host",
    "content-length",
    PROXY_TOKEN_HEADER,
];

/// Normalize a request `Host` value for matching.
///
/// Lowercases, strips a legal port (`API.SOPHIFY.COM:8477` →
/// `api.sophify.com`), and rejects userinfo, path separators, whitespace,
/// empty hosts, and malformed ports. `Forwarded`/`X-Forwarded-Host` values
/// must never be passed here.
///
/// # Errors
///
/// Returns a human-readable reason when the host is malformed.
pub fn normalize_host(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("host is empty".to_string());
    }
    if raw.contains('@') {
        return Err("host must not contain userinfo".to_string());
    }
    if raw.contains('/') || raw.contains('\\') {
        return Err("host must not contain path separators".to_string());
    }
    if raw.chars().any(char::is_whitespace) {
        return Err("host must not contain whitespace".to_string());
    }
    if raw.contains('*') {
        return Err("host must not contain wildcards".to_string());
    }

    let host = strip_port(raw)?;
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        return Err("host is empty".to_string());
    }

    // IPv6 literals (still containing ':') pass through as-is.
    if !host.contains(':') {
        for label in host.split('.') {
            if label.is_empty() {
                return Err(format!("host '{host}' has an empty label"));
            }
            if !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(format!("host '{host}' has an invalid label '{label}'"));
            }
        }
    }
    Ok(host)
}

/// Strip a legal `:port` suffix (bracketed `IPv6` aware); validate the port.
fn strip_port(raw: &str) -> Result<String, String> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 literal in host".to_string())?;
        if tail.is_empty() {
            return Ok(host.to_string());
        }
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| "invalid characters after IPv6 literal in host".to_string())?;
        validate_port(port)?;
        return Ok(host.to_string());
    }
    if let Some((host, port)) = raw.rsplit_once(':') {
        if host.contains(':') {
            return Err("bare IPv6 addresses must be bracketed in host".to_string());
        }
        validate_port(port)?;
        if host.is_empty() {
            return Err("host is empty".to_string());
        }
        return Ok(host.to_string());
    }
    Ok(raw.to_string())
}

fn validate_port(port: &str) -> Result<(), String> {
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("invalid port '{port}' in host"));
    }
    if port.parse::<u16>().is_err() {
        return Err(format!("port '{port}' out of range"));
    }
    Ok(())
}

/// Validate a configured host pattern (exact host or `*.domain` wildcard).
///
/// Only a single left-side label wildcard is supported; every other shape is
/// a configuration error.
///
/// # Errors
///
/// Returns a human-readable reason for invalid patterns.
pub fn validate_host_pattern(pattern: &str) -> Result<(), String> {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.contains(':') {
        return Err(format!("host pattern '{pattern}' must not include a port"));
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        if rest.contains('*') {
            return Err(format!(
                "host pattern '{pattern}': only one wildcard label is supported"
            ));
        }
        normalize_host(rest).map_err(|e| format!("host pattern '{pattern}': {e}"))?;
        return Ok(());
    }
    if pattern.contains('*') {
        return Err(format!(
            "host pattern '{pattern}': wildcards are only supported as a single left-side label ('*.example.com')"
        ));
    }
    normalize_host(&pattern)
        .map_err(|e| format!("host pattern '{pattern}': {e}"))
        .map(|_| ())
}

/// Whether a (normalized) request host matches a (validated, normalized)
/// configured pattern.
///
/// Comparison is ASCII case-insensitive, so patterns stored with uppercase
/// letters still match without per-request normalization.
///
/// `*.example.com` matches `api.example.com` but not `example.com` and not
/// `a.b.example.com`.
#[must_use]
pub fn host_matches(pattern: &str, host: &str) -> bool {
    pattern.strip_prefix("*.").map_or_else(
        || pattern.eq_ignore_ascii_case(host),
        |suffix| match host.split_once('.') {
            Some((label, rest)) => !label.is_empty() && rest.eq_ignore_ascii_case(suffix),
            None => false,
        },
    )
}

/// Whether `method` is allowed by a rule.
///
/// `CONNECT` and `TRACE` are always rejected. With no configured allowlist
/// the common API methods are allowed. Comparison is ASCII
/// case-insensitive, so no per-request normalization is needed.
#[must_use]
pub fn method_allowed(configured: Option<&[String]>, method: &str) -> bool {
    if FORBIDDEN_METHODS
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
    {
        return false;
    }
    configured.map_or_else(
        || {
            DEFAULT_ALLOWED_METHODS
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
        },
        |list| list.iter().any(|m| m.eq_ignore_ascii_case(method)),
    )
}

/// The effective method allowlist of a rule (configured or default).
fn effective_methods(rule: &ProxyRuleConfig) -> Vec<String> {
    rule.methods.clone().unwrap_or_else(|| {
        DEFAULT_ALLOWED_METHODS
            .iter()
            .map(|m| (*m).to_string())
            .collect()
    })
}

/// Effective path prefix of a rule (defaults to `/`).
#[must_use]
pub fn effective_path_prefix(rule: &ProxyRuleConfig) -> &str {
    rule.path_prefix.as_deref().unwrap_or("/")
}

/// Outcome of routing a request against the rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleMatch<'a> {
    /// Exactly one rule won.
    Matched(&'a ProxyRuleConfig),
    /// No rule matched host+path.
    NoMatch,
    /// Some rule covers host+path but none allows the method (callers
    /// answer 405 instead of 404; CONNECT/TRACE always land here).
    MethodNotAllowed,
    /// Multiple rules matched with equal specificity: configuration
    /// ambiguity (contains the competing rule names).
    Ambiguous(Vec<String>),
}

/// Specificity of a rule: exact host beats wildcard, then longer
/// `path_prefix`.
///
/// Shared by request-time routing ([`match_rule`]) and load-time ambiguity
/// validation ([`validate_ambiguity`]) so both sides rank rules identically.
fn specificity(rule: &ProxyRuleConfig) -> (bool, usize) {
    (
        !rule.host.starts_with("*."),
        effective_path_prefix(rule).len(),
    )
}

/// Whether `path` falls under a configured `prefix`.
///
/// The prefix must end on a `/` boundary of the request path: `"/v1"`
/// matches `/v1` and `/v1/users` but not `/v10/users`, so a rule can never
/// capture a longer path segment than it declares.
fn path_prefix_matches(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    prefix.ends_with('/') || path.len() == prefix.len() || path.as_bytes()[prefix.len()] == b'/'
}

/// Whether the method allowlists of two rules share at least one method
/// (an unset allowlist means the default set, which is compared like any
/// other).
fn methods_overlap(a: &ProxyRuleConfig, b: &ProxyRuleConfig) -> bool {
    let a_methods = effective_methods(a);
    let b_methods = effective_methods(b);
    a_methods
        .iter()
        .any(|am| b_methods.iter().any(|bm| am.eq_ignore_ascii_case(bm)))
}

/// Pick the rule for a (normalized) host, request path, and method.
///
/// Precedence: exact host over wildcard, then longer `path_prefix` (with
/// [`path_prefix_matches`] boundary semantics). The method must be allowed
/// by the rule. Equal-specificity multi-matches are reported as ambiguity
/// instead of relying on declaration order. Host+path coverage without an
/// allowed method is reported as [`RuleMatch::MethodNotAllowed`] so callers
/// can distinguish 405 from 404 from the same mechanism.
#[must_use]
pub fn match_rule<'a>(
    rules: &'a [ProxyRuleConfig],
    host: &str,
    path: &str,
    method: &str,
) -> RuleMatch<'a> {
    let mut best: Option<&ProxyRuleConfig> = None;
    let mut ambiguous_with: Vec<String> = Vec::new();
    let mut host_path_covered = false;

    for rule in rules {
        if !host_matches(&rule.host, host)
            || !path_prefix_matches(path, effective_path_prefix(rule))
        {
            continue;
        }
        if !method_allowed(rule.methods.as_deref(), method) {
            host_path_covered = true;
            continue;
        }
        match best {
            None => best = Some(rule),
            Some(current) if specificity(rule) == specificity(current) => {
                if ambiguous_with.is_empty() {
                    ambiguous_with.push(current.name.clone());
                }
                ambiguous_with.push(rule.name.clone());
            }
            Some(current) if specificity(rule) > specificity(current) => {
                best = Some(rule);
                ambiguous_with.clear();
            }
            Some(_) => {}
        }
    }

    if !ambiguous_with.is_empty() {
        return RuleMatch::Ambiguous(ambiguous_with);
    }
    if let Some(rule) = best {
        return RuleMatch::Matched(rule);
    }
    if host_path_covered {
        return RuleMatch::MethodNotAllowed;
    }
    RuleMatch::NoMatch
}

/// A `{{alias.field}}` variable occurrence inside a header template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateVar {
    /// Credential alias.
    pub alias: String,
    /// Field name within the credential's declared fields.
    pub field: String,
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// One parsed piece of a header template: literal text or a variable.
///
/// The single owner of the `{{alias.field}}` grammar — both variable
/// extraction (validation) and rendering walk these segments.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TemplateSegment<'a> {
    /// Literal text, emitted verbatim.
    Literal(&'a str),
    /// One `{{alias.field}}` reference.
    Var(TemplateVar),
}

fn parse_template_segments(template: &str) -> Result<Vec<TemplateSegment<'_>>, String> {
    let mut segments = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        if open > 0 {
            segments.push(TemplateSegment::Literal(&rest[..open]));
        }
        let after = &rest[open + 2..];
        let close = after.find("}}").ok_or("template has an unclosed '{{'")?;
        let inner = &after[..close];
        let trimmed = inner.trim();
        if trimmed.contains("{{") {
            return Err("template has nested variable references".to_string());
        }
        if trimmed.contains('(') || trimmed.contains(')') {
            return Err(format!(
                "template variable '{trimmed}' uses an unsupported transform (only literal text and {{{{alias.field}}}} are supported)"
            ));
        }
        let Some((alias, field)) = trimmed.split_once('.') else {
            return Err(format!(
                "template variable '{trimmed}' must have the form alias.field"
            ));
        };
        if !valid_ident(alias) || !valid_ident(field) {
            return Err(format!(
                "template variable '{trimmed}' has an invalid alias or field name"
            ));
        }
        segments.push(TemplateSegment::Var(TemplateVar {
            alias: alias.to_string(),
            field: field.to_string(),
        }));
        rest = &after[close + 2..];
    }
    if !rest.is_empty() {
        segments.push(TemplateSegment::Literal(rest));
    }
    Ok(segments)
}

/// Parse a header template into its variable references.
///
/// Templates support literal text plus direct `{{alias.field}}` substitution
/// only. Transforms (`basic(...)`, `base64(...)`, …), whitespace inside
/// variables, unclosed braces, and empty references are rejected.
///
/// # Errors
///
/// Returns a human-readable reason (never includes the template text).
pub fn parse_template_vars(template: &str) -> Result<Vec<TemplateVar>, String> {
    Ok(parse_template_segments(template)?
        .into_iter()
        .filter_map(|segment| match segment {
            TemplateSegment::Var(var) => Some(var),
            TemplateSegment::Literal(_) => None,
        })
        .collect())
}

/// Why a template render failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateRenderError {
    /// The template violates the [`parse_template_vars`] grammar.
    Malformed,
    /// A referenced `alias.field` had no resolved value.
    Unresolved,
}

/// Render a header template by substituting each `{{alias.field}}` through
/// `lookup` (literal text passes through verbatim).
///
/// Uses the same grammar as load-time validation, so a template that
/// validated can only fail here when a reference resolves to nothing.
///
/// # Errors
///
/// [`TemplateRenderError::Malformed`] for corrupt templates,
/// [`TemplateRenderError::Unresolved`] when `lookup` returns `None`.
pub fn render_template(
    template: &str,
    lookup: impl Fn(&str, &str) -> Option<String>,
) -> Result<String, TemplateRenderError> {
    let segments = parse_template_segments(template).map_err(|_| TemplateRenderError::Malformed)?;
    let mut out = String::with_capacity(template.len());
    for segment in segments {
        match segment {
            TemplateSegment::Literal(text) => out.push_str(text),
            TemplateSegment::Var(var) => {
                let value =
                    lookup(&var.alias, &var.field).ok_or(TemplateRenderError::Unresolved)?;
                out.push_str(&value);
            }
        }
    }
    Ok(out)
}

/// Slice the authority out of an `https://` upstream URL (no scheme,
/// userinfo, path, query, or fragment).
///
/// Shared by validation and host extraction so both agree on the URL shape.
///
/// # Errors
///
/// Returns a human-readable reason (does not echo the URL beyond its scheme
/// shape).
fn upstream_authority(url: &str) -> Result<&str, String> {
    let url = url.trim();
    if url.chars().any(char::is_whitespace) {
        return Err("upstream must not contain whitespace".to_string());
    }
    let lower = url.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("https://") else {
        if lower.starts_with("http://") {
            return Err("upstream must use https".to_string());
        }
        return Err("upstream must be an https:// URL".to_string());
    };
    if rest.is_empty() {
        return Err("upstream has an empty host".to_string());
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &url["https://".len()..][..authority_end];
    if authority.is_empty() {
        return Err("upstream has an empty host".to_string());
    }
    if authority.contains('@') {
        return Err("upstream must not contain userinfo".to_string());
    }
    Ok(authority)
}

/// Validate an upstream URL: must be `https://`, without userinfo, query,
/// or fragment, with a non-empty host and a legal port.
///
/// The URL is a *base*: the client's path and query are appended to it
/// verbatim, so a configured query/fragment could only be spliced into the
/// forwarded path — a shape mismatch rejected here rather than misrouted
/// at request time.
///
/// # Errors
///
/// Returns a human-readable reason (does not echo the URL beyond its scheme
/// shape).
pub fn validate_upstream(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.contains('?') || url.contains('#') {
        return Err(
            "upstream must not contain a query or fragment (the client's path and query are appended)"
                .to_string(),
        );
    }
    upstream_host(url).map(|_| ())
}

/// The normalized host of an upstream URL (port stripped, `IPv6` brackets
/// removed, lowercased) — the audit-safe upstream identity.
///
/// Applies the same parsing and host rules as [`validate_upstream`].
///
/// # Errors
///
/// Returns a human-readable reason for invalid URLs.
pub fn upstream_host(url: &str) -> Result<String, String> {
    let authority = upstream_authority(url)?;
    normalize_host(authority).map_err(|e| format!("upstream host is invalid: {e}"))
}

/// Whether `name` is a valid HTTP header name (RFC 7230 token).
#[must_use]
pub fn valid_header_name(name: &str) -> bool {
    const fn is_tchar(c: char) -> bool {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '#'
                    | '$'
                    | '%'
                    | '&'
                    | '\''
                    | '*'
                    | '+'
                    | '-'
                    | '.'
                    | '^'
                    | '_'
                    | '`'
                    | '|'
                    | '~'
            )
    }
    !name.is_empty() && name.chars().all(is_tchar)
}

/// Whether `name` is reserved for the proxy pipeline (case-insensitive) and
/// therefore cannot be configured as an injected header.
#[must_use]
pub fn is_reserved_header_name(name: &str) -> bool {
    RESERVED_HEADER_NAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name))
}

/// Whether `value` is a valid HTTP header value (RFC 7230 field-content):
/// visible ASCII, space, and horizontal tab only. Notably rejects CR/LF
/// (request smuggling) and every other control byte.
#[must_use]
pub fn valid_header_value(value: &str) -> bool {
    value
        .chars()
        .all(|c| c == ' ' || c == '\t' || c.is_ascii_graphic())
}

/// Parse a `"service/key:field"` secret reference.
///
/// # Errors
///
/// Returns a human-readable reason for malformed references.
pub fn parse_secret_ref(reference: &str) -> Result<(String, String, String), String> {
    let Some((service_key, field)) = reference.rsplit_once(':') else {
        return Err("secret reference must have the form 'service/key:field'".to_string());
    };
    let Some((service, key)) = service_key.split_once('/') else {
        return Err("secret reference must have the form 'service/key:field'".to_string());
    };
    if service.is_empty() || key.is_empty() || field.is_empty() {
        return Err("secret reference has an empty service, key, or field".to_string());
    }
    Ok((service.to_string(), key.to_string(), field.to_string()))
}

/// Whether a string is 64 hexadecimal characters (SHA-256 digest).
#[must_use]
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Aggregated load-time validation failure (one entry per issue).
#[derive(Debug, Clone, thiserror::Error)]
#[error(
    "configuration validation failed ({} issue(s)):\n{}",
    self.issues.len(),
    self.issues.iter().map(|i| format!("  - {i}")).collect::<Vec<_>>().join("\n")
)]
pub struct ConfigValidationError {
    /// Every detected issue, in configuration order.
    pub issues: Vec<String>,
}

/// Validate the daemon/proxy/scripts sections of an [`AppConfig`].
///
/// Runs the full validation checklist plus the script-grant checks. The
/// whole config is rejected when any issue is found — there is no partial
/// load.
///
/// # Errors
///
/// Returns every issue found, never just the first.
pub fn validate_app_config(cfg: &AppConfig) -> Result<(), ConfigValidationError> {
    let mut issues = Vec::new();

    validate_daemon(cfg, &mut issues);
    validate_rules(cfg, &mut issues);
    validate_scripts(cfg, &mut issues);

    if issues.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError { issues })
    }
}

fn validate_daemon(cfg: &AppConfig, issues: &mut Vec<String>) {
    if let Some(listen) = cfg.daemon.listen.as_ref() {
        match listen.parse::<SocketAddr>() {
            Ok(addr) if addr.ip().is_loopback() => {}
            Ok(_) => issues.push(format!(
                "daemon.listen '{listen}' must be a loopback address"
            )),
            Err(_) => issues.push(format!(
                "daemon.listen '{listen}' is not a valid socket address"
            )),
        }
    }
    if cfg.daemon.timeout_secs > MAX_TIMEOUT_SECS {
        issues.push(format!(
            "daemon.timeout_secs {} exceeds the maximum of {MAX_TIMEOUT_SECS} seconds (use 0 to disable the timeout)",
            cfg.daemon.timeout_secs
        ));
    }
    // 0 is not "unlimited" for the size/concurrency knobs — it would reject
    // every request body (413) or response body (502) outright. The
    // schemars range annotations are documentation only, so the floor is
    // enforced here.
    if cfg.daemon.max_in_flight == 0 {
        issues.push("daemon.max_in_flight must be at least 1".to_string());
    }
    if cfg.daemon.request_body_limit_bytes == 0 {
        issues.push(
            "daemon.request_body_limit_bytes must be at least 1 (0 would reject every request body)"
                .to_string(),
        );
    }
    if cfg.daemon.response_body_limit_bytes == 0 {
        issues.push(
            "daemon.response_body_limit_bytes must be at least 1 (0 would fail every response body)"
                .to_string(),
        );
    }
}

fn validate_rules(cfg: &AppConfig, issues: &mut Vec<String>) {
    let rules = &cfg.proxy.rules;
    let mut seen_names = Vec::new();

    for (idx, rule) in rules.iter().enumerate() {
        let label = format!("proxy.rules[{idx}] '{}'", rule.name);
        if rule.name.is_empty() {
            issues.push(format!("proxy.rules[{idx}] has an empty name"));
        } else if seen_names.contains(&rule.name) {
            issues.push(format!("{label}: duplicate rule name '{}'", rule.name));
        }
        seen_names.push(rule.name.clone());

        if let Err(e) = validate_host_pattern(&rule.host) {
            issues.push(format!("{label}: {e}"));
        }
        if let Some(prefix) = rule.path_prefix.as_deref()
            && !prefix.starts_with('/')
        {
            issues.push(format!(
                "{label}: path_prefix '{prefix}' must start with '/'"
            ));
        }
        if let Some(methods) = rule.methods.as_ref() {
            for method in methods {
                let upper = method.to_ascii_uppercase();
                if FORBIDDEN_METHODS.contains(&upper.as_str()) {
                    issues.push(format!(
                        "{label}: method '{upper}' is forbidden (CONNECT and TRACE are never allowed)"
                    ));
                } else if !valid_header_name(method) {
                    issues.push(format!("{label}: invalid method token '{upper}'"));
                }
            }
        }
        if let Err(e) = validate_upstream(&rule.upstream) {
            issues.push(format!("{label}: {e}"));
        }
        for header in &rule.strip {
            if !valid_header_name(header) {
                issues.push(format!("{label}: invalid strip header name '{header}'"));
            }
        }

        validate_credentials(rule, &label, issues);
    }

    validate_ambiguity(rules, issues);
}

fn validate_credentials(rule: &ProxyRuleConfig, label: &str, issues: &mut Vec<String>) {
    let mut seen_aliases = Vec::new();
    for cred in &rule.credentials {
        if cred.alias.is_empty() {
            issues.push(format!("{label}: credential with an empty alias"));
        } else if seen_aliases.contains(&cred.alias) {
            issues.push(format!(
                "{label}: duplicate credential alias '{}'",
                cred.alias
            ));
        }
        seen_aliases.push(cred.alias.clone());

        if cred.service.is_empty() || cred.key.is_empty() {
            issues.push(format!(
                "{label}: credential '{}' has an empty service or key",
                cred.alias
            ));
        }
        if cred.fields.is_empty() {
            issues.push(format!(
                "{label}: credential '{}' must declare at least one field",
                cred.alias
            ));
        } else if cred.fields.iter().any(String::is_empty) {
            issues.push(format!(
                "{label}: credential '{}' declares an empty field name",
                cred.alias
            ));
        }
    }

    for (header, template) in &rule.headers {
        if !valid_header_name(header) {
            issues.push(format!(
                "{label}: invalid header name '{header}' in headers"
            ));
        }
        if is_reserved_header_name(header) {
            issues.push(format!(
                "{label}: header '{header}' in headers is reserved for the proxy pipeline (hop-by-hop, framing, Host, and the proxy token header cannot be injected)"
            ));
        }
        let vars = match parse_template_vars(template) {
            Ok(vars) => vars,
            Err(e) => {
                issues.push(format!("{label}: header '{header}': {e}"));
                continue;
            }
        };
        for var in vars {
            let Some(cred) = rule.credentials.iter().find(|c| c.alias == var.alias) else {
                issues.push(format!(
                    "{label}: header '{header}' references unknown credential alias '{}'",
                    var.alias
                ));
                continue;
            };
            if !cred.fields.iter().any(|f| f == &var.field) {
                issues.push(format!(
                    "{label}: header '{header}' references field '{}' not declared by credential '{}'",
                    var.field, var.alias
                ));
            }
        }
    }

    for (header, value) in &rule.static_headers {
        if !valid_header_name(header) {
            issues.push(format!(
                "{label}: invalid header name '{header}' in static_headers"
            ));
        }
        if is_reserved_header_name(header) {
            issues.push(format!(
                "{label}: static header '{header}' is reserved for the proxy pipeline (hop-by-hop, framing, Host, and the proxy token header cannot be injected)"
            ));
        }
        if value.contains("{{") {
            issues.push(format!(
                "{label}: static header '{header}' must not use templates (use headers instead)"
            ));
        }
        // An invalid value would otherwise surface only per request, as an
        // untyped upstream failure (502).
        if !valid_header_value(value) {
            issues.push(format!(
                "{label}: static header '{header}' has an invalid value (control characters and non-ASCII bytes are not allowed)"
            ));
        }
    }
}

fn validate_ambiguity(rules: &[ProxyRuleConfig], issues: &mut Vec<String>) {
    for (i, a) in rules.iter().enumerate() {
        for b in rules.iter().skip(i + 1) {
            if !a.host.eq_ignore_ascii_case(&b.host) {
                continue;
            }
            // Two rules can only contend for the same request when their
            // path prefixes are identical: different prefixes of the same
            // length can never both match one path, and different lengths
            // are always resolved by the longer-prefix rule. An
            // equal-length pair like "/v1/" vs "/v2/" is therefore sound.
            if effective_path_prefix(a) != effective_path_prefix(b) {
                continue;
            }
            if methods_overlap(a, b) {
                issues.push(format!(
                    "proxy.rules '{}': ambiguous with rule '{}' (same host '{}' and path prefix '{}')",
                    a.name,
                    b.name,
                    a.host.to_ascii_lowercase(),
                    effective_path_prefix(a)
                ));
            }
        }
    }
}

fn validate_scripts(cfg: &AppConfig, issues: &mut Vec<String>) {
    for (grant, script) in &cfg.scripts {
        let label = format!("scripts.{grant}");
        if grant.is_empty() {
            issues.push("scripts has a grant with an empty name".to_string());
        }
        if !std::path::Path::new(&script.path).is_absolute() {
            issues.push(format!("{label}: path must be absolute"));
        }
        if !is_sha256_hex(&script.sha256) {
            issues.push(format!("{label}: sha256 must be 64 hex characters"));
        }
        for (env_var, reference) in &script.env {
            if env_var.is_empty() || env_var.contains('=') || env_var.contains('\0') {
                issues.push(format!(
                    "{label}: invalid environment variable name '{env_var}'"
                ));
            }
            if let Err(e) = parse_secret_ref(reference) {
                issues.push(format!("{label}: env '{env_var}': {e}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::{
        AppConfig, DaemonConfig, ProxyAuthMode, ProxyConfig, ProxyCredentialConfig,
        ProxyRuleConfig, ScriptGrantConfig,
    };

    #[test]
    fn normalize_host_strips_port_and_lowercases() {
        assert_eq!(
            normalize_host("API.SOPHIFY.COM:8477").expect("valid host"),
            "api.sophify.com"
        );
        assert_eq!(
            normalize_host("api.sophify.com").expect("valid host"),
            "api.sophify.com"
        );
        assert_eq!(
            normalize_host("[2001:db8::1]:443").expect("valid ipv6"),
            "2001:db8::1"
        );
    }

    #[test]
    fn normalize_host_rejects_userinfo_and_garbage() {
        assert!(normalize_host("user@api.com").is_err());
        assert!(normalize_host("api.com/path").is_err());
        assert!(normalize_host("api.com:99999").is_err());
        assert!(normalize_host("api.com:abc").is_err());
        assert!(normalize_host("").is_err());
        assert!(normalize_host("*.api.com").is_err());
        assert!(normalize_host("a..b").is_err());
    }

    #[test]
    fn wildcard_matches_single_label_only() {
        let pattern = "*.example.com";
        assert!(host_matches(pattern, "api.example.com"));
        assert!(host_matches(pattern, "foo.example.com"));
        assert!(!host_matches(pattern, "example.com"));
        assert!(!host_matches(pattern, "a.b.example.com"));
    }

    #[test]
    fn host_pattern_validation() {
        assert!(validate_host_pattern("api.example.com").is_ok());
        assert!(validate_host_pattern("*.example.com").is_ok());
        assert!(validate_host_pattern("API.Example.COM").is_ok());
        assert!(validate_host_pattern("*.example.com:8443").is_err());
        assert!(validate_host_pattern("a.*.example.com").is_err());
        assert!(validate_host_pattern("example.*").is_err());
        assert!(validate_host_pattern("*").is_err());
        assert!(validate_host_pattern("*.").is_err());
    }

    fn rule(
        name: &str,
        host: &str,
        prefix: Option<&str>,
        methods: Option<&[&str]>,
    ) -> ProxyRuleConfig {
        ProxyRuleConfig {
            name: name.to_string(),
            host: host.to_string(),
            path_prefix: prefix.map(String::from),
            methods: methods.map(|m| m.iter().map(|s| (*s).to_string()).collect()),
            upstream: String::new(),
            strip: Vec::new(),
            credentials: Vec::new(),
            headers: BTreeMap::new(),
            static_headers: BTreeMap::new(),
        }
    }

    #[test]
    fn match_rule_prefers_exact_then_longer_prefix() {
        let wildcard = rule("wild", "*.example.com", None, None);
        let exact_short = rule("short", "api.example.com", Some("/"), None);
        let exact_long = rule("long", "api.example.com", Some("/v1/"), None);
        let rules = vec![wildcard, exact_short, exact_long];

        match match_rule(&rules, "api.example.com", "/v1/users", "GET") {
            RuleMatch::Matched(r) => assert_eq!(r.name, "long"),
            other => panic!("expected long rule, got {other:?}"),
        }
        match match_rule(&rules, "api.example.com", "/health", "GET") {
            RuleMatch::Matched(r) => assert_eq!(r.name, "short"),
            other => panic!("expected short rule, got {other:?}"),
        }
        match match_rule(&rules, "other.example.com", "/v1/x", "GET") {
            RuleMatch::Matched(r) => assert_eq!(r.name, "wild"),
            other => panic!("expected wild rule, got {other:?}"),
        }
        assert_eq!(
            match_rule(&rules, "api.example.com", "/v1/x", "TRACE"),
            RuleMatch::MethodNotAllowed,
            "CONNECT/TRACE over a covered host+path is method-forbidden, not unroutable"
        );
    }

    #[test]
    fn match_rule_distinguishes_method_forbidden_from_no_route() {
        let restricted = rule(
            "restricted",
            "api.example.com",
            Some("/v1/"),
            Some(&["GET"]),
        );
        let rules = vec![restricted];

        assert_eq!(
            match_rule(&rules, "api.example.com", "/v1/x", "DELETE"),
            RuleMatch::MethodNotAllowed,
            "host+path covered, method not allowed"
        );
        assert_eq!(
            match_rule(&rules, "api.example.com", "/v2/x", "GET"),
            RuleMatch::NoMatch,
            "no rule covers the path at all"
        );
        assert_eq!(
            match_rule(&rules, "other.example.com", "/v1/x", "GET"),
            RuleMatch::NoMatch,
            "no rule covers the host at all"
        );
    }

    #[test]
    fn match_rule_requires_segment_boundaries() {
        let v1 = rule("v1", "api.example.com", Some("/v1"), None);
        let rules = vec![v1];

        match match_rule(&rules, "api.example.com", "/v1", "GET") {
            RuleMatch::Matched(r) => assert_eq!(r.name, "v1"),
            other => panic!("expected exact-path match, got {other:?}"),
        }
        match match_rule(&rules, "api.example.com", "/v1/users", "GET") {
            RuleMatch::Matched(r) => assert_eq!(r.name, "v1"),
            other => panic!("expected boundary match, got {other:?}"),
        }
        assert_eq!(
            match_rule(&rules, "api.example.com", "/v10/users", "GET"),
            RuleMatch::NoMatch,
            "a /v1 rule must not capture /v10/*"
        );
    }

    #[test]
    fn match_rule_reports_ambiguity() {
        let a = rule("a", "api.example.com", Some("/v1/"), None);
        let b = rule("b", "api.example.com", Some("/v1/"), Some(&["POST"]));
        match match_rule(&[a, b], "api.example.com", "/v1/x", "POST") {
            RuleMatch::Ambiguous(names) => {
                assert!(names.contains(&"a".to_string()));
                assert!(names.contains(&"b".to_string()));
            }
            other => panic!("expected ambiguity, got {other:?}"),
        }
    }

    #[test]
    fn method_allowlist_semantics() {
        let configured = vec!["GET".to_string(), "post".to_string()];
        assert!(method_allowed(Some(&configured), "GET"));
        assert!(method_allowed(Some(&configured), "POST"));
        assert!(!method_allowed(Some(&configured), "DELETE"));
        assert!(method_allowed(None, "PATCH"));
        assert!(!method_allowed(None, "PROPFIND"));
        assert!(!method_allowed(None, "connect"));
        assert!(!method_allowed(Some(&configured), "TRACE"));
        assert!(!method_allowed(Some(&["TRACE".to_string()]), "TRACE"));
    }

    #[test]
    fn template_parsing() {
        let vars = parse_template_vars("Bearer {{github.token}}-x").expect("valid template");
        assert_eq!(
            vars,
            vec![TemplateVar {
                alias: "github".to_string(),
                field: "token".to_string()
            }]
        );
        let multi = parse_template_vars("{{a.x}}{{b.y}}").expect("valid template");
        assert_eq!(multi.len(), 2);

        assert!(parse_template_vars("{{basic(user):pw}}").is_err());
        assert!(parse_template_vars("{{ github token }}").is_err());
        assert!(parse_template_vars("{{unclosed").is_err());
        assert!(parse_template_vars("{{no_dot}}").is_err());
        assert!(parse_template_vars("{{a.b}}ok{{c").is_err());
        assert!(parse_template_vars("no-vars").is_ok());
    }

    #[test]
    fn template_rendering_substitutes_and_fails_closed() {
        let lookup =
            |alias: &str, field: &str| (alias == "a" && field == "x").then(|| "VALUE".to_string());
        assert_eq!(
            render_template("Bearer {{ a.x }}-tail", lookup).expect("render"),
            "Bearer VALUE-tail"
        );
        assert_eq!(
            render_template("{{a.x}}{{a.x}}", lookup).expect("render"),
            "VALUEVALUE"
        );
        assert_eq!(render_template("plain", lookup).expect("render"), "plain");
        assert_eq!(
            render_template("", lookup).expect("render"),
            "",
            "an empty template renders empty"
        );
        assert_eq!(
            render_template("{{missing.f}}", lookup),
            Err(TemplateRenderError::Unresolved),
            "unresolved reference fails closed"
        );
        assert_eq!(
            render_template("{{unclosed", lookup),
            Err(TemplateRenderError::Malformed),
            "corrupt template fails closed"
        );
    }

    #[test]
    fn upstream_validation() {
        assert!(validate_upstream("https://api.example.com").is_ok());
        assert!(validate_upstream("https://api.example.com:8443/v1").is_ok());
        assert!(validate_upstream("https://[2001:db8::1]/x").is_ok());
        assert!(validate_upstream("http://api.example.com").is_err());
        assert!(validate_upstream("https://user:pw@api.example.com").is_err());
        assert!(validate_upstream("https://").is_err());
        assert!(validate_upstream("api.example.com").is_err());
        assert!(validate_upstream("https://bad host/").is_err());
        // A query or fragment in the base would be spliced into the joined
        // path at request time; validation and joining must agree.
        assert!(validate_upstream("https://api.example.com/v1?client=x").is_err());
        assert!(validate_upstream("https://api.example.com#frag").is_err());
    }

    #[test]
    fn reserved_and_invalid_injected_headers_are_rejected() {
        let mut r = make_rule("sophify", "api.sophify.com");
        r.headers = BTreeMap::from([("Host".to_string(), "{{app.token}}".to_string())]);
        r.static_headers = BTreeMap::from([
            ("X-Fine".to_string(), "kyz".to_string()),
            ("Content-Length".to_string(), "42".to_string()),
            ("X-Bad-Value".to_string(), "kyz\nproxy".to_string()),
        ]);
        let err = validate_app_config(&base_config(vec![r])).expect_err("must fail");
        let joined = err.issues.join("\n");
        assert!(joined.contains("'Host' in headers is reserved"));
        assert!(joined.contains("static header 'Content-Length' is reserved"));
        assert!(joined.contains("invalid value"));
        assert!(!joined.contains("X-Fine"));
    }

    #[test]
    fn zero_size_or_concurrency_limits_are_rejected() {
        let mut cfg = base_config(Vec::new());
        cfg.daemon = DaemonConfig {
            max_in_flight: 0,
            request_body_limit_bytes: 0,
            response_body_limit_bytes: 0,
            ..DaemonConfig::default()
        };
        let err = validate_app_config(&cfg).expect_err("zero limits must fail");
        let joined = err.issues.join("\n");
        assert!(joined.contains("max_in_flight"));
        assert!(joined.contains("request_body_limit_bytes"));
        assert!(joined.contains("response_body_limit_bytes"));
    }

    #[test]
    fn header_value_shape() {
        assert!(valid_header_value(""));
        assert!(valid_header_value("Bearer abc"));
        assert!(valid_header_value("tab\tallowed"));
        assert!(!valid_header_value("kyz\nproxy"));
        assert!(!valid_header_value("kyz\rproxy"));
        assert!(!valid_header_value("nul\0byte"));
        assert!(!valid_header_value("non-ascii \u{e9}"));
    }

    #[test]
    fn upstream_host_extraction_matches_validation() {
        assert_eq!(
            upstream_host("https://api.example.com").expect("valid upstream"),
            "api.example.com"
        );
        assert_eq!(
            upstream_host("https://api.example.com:8443/v1").expect("valid upstream"),
            "api.example.com"
        );
        assert_eq!(
            upstream_host("https://[2001:db8::1]/x").expect("valid upstream"),
            "2001:db8::1"
        );
        assert!(upstream_host("http://api.example.com").is_err());
    }

    fn make_rule(name: &str, host: &str) -> ProxyRuleConfig {
        let mut r = rule(name, host, None, None);
        r.upstream = "https://upstream.example.com".to_string();
        r
    }

    fn base_config(rules: Vec<ProxyRuleConfig>) -> AppConfig {
        AppConfig {
            proxy: ProxyConfig {
                auth: ProxyAuthMode::Token,
                rules,
            },
            ..AppConfig::default()
        }
    }

    #[test]
    fn validate_accepts_sound_config() {
        let mut r = make_rule("sophify", "api.sophify.com");
        r.path_prefix = Some("/v1/".to_string());
        r.methods = Some(vec!["GET".to_string(), "POST".to_string()]);
        r.credentials = vec![ProxyCredentialConfig {
            alias: "sophify".to_string(),
            service: "sophify".to_string(),
            key: "api".to_string(),
            fields: vec!["token".to_string()],
        }];
        r.headers = BTreeMap::from([("X-Api-Key".to_string(), "{{sophify.token}}".to_string())]);
        r.static_headers = BTreeMap::from([("X-Client".to_string(), "kyz-proxy".to_string())]);

        let mut cfg = base_config(vec![r]);
        cfg.daemon = DaemonConfig {
            listen: Some("127.0.0.1:8477".to_string()),
            ..DaemonConfig::default()
        };
        cfg.scripts.insert(
            "deploy".to_string(),
            ScriptGrantConfig {
                path: if cfg!(windows) {
                    r"C:\home\me\deploy.sh".to_string()
                } else {
                    "/home/me/deploy.sh".to_string()
                },
                sha256: "a".repeat(64),
                env: BTreeMap::from([(
                    "GITHUB_TOKEN".to_string(),
                    "github/deploy-key:token".to_string(),
                )]),
            },
        );

        validate_app_config(&cfg).expect("sound config should validate");
    }

    #[test]
    fn validate_reports_each_issue() {
        let mut bad = make_rule("bad", "a.*.example.com");
        bad.upstream = "http://insecure.example.com".to_string();
        bad.methods = Some(vec!["TRACE".to_string(), "GET".to_string()]);
        bad.headers = BTreeMap::from([("Bad Header".to_string(), "{{nope.field}}".to_string())]);
        let mut cfg = base_config(vec![bad.clone(), bad]);
        cfg.daemon = DaemonConfig {
            listen: Some("0.0.0.0:8477".to_string()),
            ..DaemonConfig::default()
        };
        cfg.scripts.insert(
            "s".to_string(),
            ScriptGrantConfig {
                path: "relative.sh".to_string(),
                sha256: "xyz".to_string(),
                env: BTreeMap::from([("T".to_string(), "no-field-ref".to_string())]),
            },
        );

        let err = validate_app_config(&cfg).expect_err("invalid config must fail");
        let joined = err.issues.join("\n");
        assert!(joined.contains("wildcards"));
        assert!(joined.contains("https"));
        assert!(joined.contains("TRACE"));
        assert!(joined.contains("unknown credential alias"));
        assert!(joined.contains("loopback"));
        assert!(joined.contains("duplicate rule name"));
        assert!(joined.contains("ambiguous"));
        assert!(joined.contains("absolute"));
        assert!(joined.contains("64 hex"));
        assert!(joined.contains("service/key:field"));
    }

    #[test]
    fn validate_rejects_disjoint_method_split_when_default_overlaps() {
        // Two rules, same host and prefix, one with an explicit allowlist that
        // overlaps the other's default allowlist -> ambiguous.
        let a = make_rule("a", "api.example.com");
        let mut b = rule("b", "api.example.com", None, Some(&["POST"]));
        b.upstream = "https://up.example.com".to_string();
        let cfg = base_config(vec![a, b]);
        let err = validate_app_config(&cfg).expect_err("overlap must be ambiguous");
        assert!(err.issues.iter().any(|i| i.contains("ambiguous")));
    }

    #[test]
    fn validate_allows_disjoint_method_allowlists() {
        let mut a = rule("a", "api.example.com", None, Some(&["GET"]));
        a.upstream = "https://up.example.com".to_string();
        let mut b = rule("b", "api.example.com", None, Some(&["POST"]));
        b.upstream = "https://up.example.com".to_string();
        let cfg = base_config(vec![a, b]);
        validate_app_config(&cfg).expect("disjoint methods are not ambiguous");
    }

    #[test]
    fn validate_allows_same_length_disjoint_prefixes() {
        // No single request path can match both "/v1/" and "/v2/": the
        // equal prefix length must not be reported as ambiguity.
        let mut a = make_rule("v1", "api.example.com");
        a.path_prefix = Some("/v1/".to_string());
        let mut b = make_rule("v2", "api.example.com");
        b.path_prefix = Some("/v2/".to_string());
        let mut c = make_rule("api", "api.example.com");
        c.path_prefix = Some("/api".to_string());
        let mut d = make_rule("cms", "api.example.com");
        d.path_prefix = Some("/cms".to_string());
        validate_app_config(&base_config(vec![a, b, c, d]))
            .expect("disjoint equal-length prefixes are never ambiguous");
    }

    #[test]
    fn validate_allows_methods_disjoint_from_default() {
        // PROPFIND is outside the default allowlist, so a rule restricted
        // to it cannot contend with a default-methods rule on the same
        // prefix.
        let mut webdav = make_rule("webdav", "api.example.com");
        webdav.methods = Some(vec!["PROPFIND".to_string()]);
        let rest = make_rule("rest", "api.example.com");
        validate_app_config(&base_config(vec![webdav, rest]))
            .expect("methods disjoint from the default set are not ambiguous");
    }

    #[test]
    fn validate_rejects_absurd_timeout() {
        let mut cfg = base_config(Vec::new());
        cfg.daemon = DaemonConfig {
            timeout_secs: u64::MAX,
            ..DaemonConfig::default()
        };
        let err = validate_app_config(&cfg).expect_err("absurd timeout must be rejected");
        assert!(
            err.issues.iter().any(|i| i.contains("timeout_secs")),
            "expected a timeout_secs issue, got: {:?}",
            err.issues
        );
    }

    #[test]
    fn sha256_shape() {
        assert!(is_sha256_hex(&"ab".repeat(32)));
        assert!(!is_sha256_hex(&"ab".repeat(31)));
        assert!(!is_sha256_hex(&"zz".repeat(32)));
    }

    #[test]
    fn secret_ref_parsing() {
        assert_eq!(
            parse_secret_ref("github/deploy-key:token").expect("valid ref"),
            (
                "github".to_string(),
                "deploy-key".to_string(),
                "token".to_string()
            )
        );
        assert!(parse_secret_ref("github/deploy-key").is_err());
        assert!(parse_secret_ref("github:token").is_err());
        assert!(parse_secret_ref("github/:token").is_err());
    }
}
