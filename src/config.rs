use std::{collections::HashSet, path::Path};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

use crate::rules::Bundle;
use crate::model::RuleId;

fn default_hsts_max_age() -> u64 {
    63_072_000 // two years
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Policy enums.  Serde rejects unrecognised values at parse time, so
// every policy decision is statically known before the process binds a port.
// ---------------------------------------------------------------------------

/// What to do when ClientHello SNI names no configured site,
/// or when no SNI extension is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SniPolicy {
    /// Close the TLS connection.
    Reject,
    /// Fall through to the first site in config order.
    UseDefaultSite,
}

/// Policy when HTTP Host diverges from TLS SNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityMismatchPolicy {
    /// Return 421 Misdirected Request.
    Reject,
    /// Log a warning and continue.
    Log,
}

/// Fail-open or fail-closed on engine errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailPolicy {
    /// Let the request through.
    FailOpen,
    /// Deny the request.
    FailClosed,
}

/// Behaviour on a failed hot-reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReloadPolicy {
    /// Keep serving on the last-known-good state.
    KeepRunningWithOldRules,
}

/// Controls how much of a gRPC request the WAF sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrpcInspection {
    /// Headers only; the body is protobuf and useless to a regex engine.
    HeadersOnly,
    /// Reject all gRPC traffic (501).
    Off,
}

/// Controls how much of a WebSocket upgrade the WAF sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebsocketInspection {
    /// Inspect the upgrade handshake then pass the connection through.
    HandshakeOnly,
    /// Reject WebSocket upgrades (501).
    Off,
}

/// Transport layer to the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendTransport {
    PlainHttp,
    Tls,
    UnixSocket,
}

/// Wire protocol for backend connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendProtocol {
    Http1,
    Http2,
    Http3,
    Auto,
}

/// How request bodies are buffered for inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyMode {
    /// Full buffering before forwarding.
    Buffered,
    /// Pass-through without buffering.
    Streaming,
    /// Buffer up to `max_body_to_buffer`, stream the tail.
    Both,
}

/// Response body mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBodyMode {
    Off,
    Buffered,
}

/// The only meaningful default: pass traffic through when nothing fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Allow,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Json,
    Text,
}

/// Log output destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogTarget {
    Stdout,
    File,
    Both,
}

/// Behaviour when a source IP exceeds the token-bucket rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitExceededAction {
    /// Return 429 Too Many Requests.
    Reject,
    /// Log the event and allow the request through.
    Log,
}

/// Source-IP access control lists.
///
/// `block` is evaluated first.  If the address matches, the connection
/// is dropped without regard to `allow`.  When `allow` is non-empty it
/// acts as a whitelist: anything outside it is refused.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct IpFilter {
    /// CIDRs that are unconditionally refused.  Evaluated before `allow`.
    #[serde(default)]
    pub block: Vec<IpNet>,
    /// When non-empty, only these CIDRs are accepted.
    #[serde(default)]
    pub allow: Vec<IpNet>,
}

/// Schema enforcement: validate JSON request bodies against an OpenAPI
/// specification before the regex engine runs.  Disabled by default.
/// When enabled, requests to endpoints defined in the spec are rejected
/// if the body does not conform to the declared schema.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SchemaEnforcement {
    /// Master switch.  Schema enforcement is off unless explicitly enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Path to a JSON OpenAPI 3.x specification file.  Relative paths
    /// are resolved from the directory containing the config file.
    pub openapi_spec_path: Option<String>,
    /// Maximum request body size (in bytes) that schema enforcement will
    /// parse.  Bodies larger than this are rejected before parsing.
    /// Default: 1048576 (1 MiB).
    pub max_body_bytes: Option<usize>,
    /// Maximum JSON nesting depth allowed.  Prevents stack exhaustion
    /// from pathologically deep input.  Default: 64.
    pub max_depth: Option<usize>,
    /// When true, requests to method + path combinations not declared
    /// in the OpenAPI spec are rejected with 400 before reaching the
    /// regex engine.  Makes the spec the single source of truth for
    /// which endpoints exist.  Default: false.
    pub reject_unknown_endpoints: Option<bool>,
}

/// Per-source-IP token-bucket rate limiter.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimit {
    pub enabled: bool,
    /// Steady-state rate per source IP.
    pub requests_per_second: u32,
    /// Burst allowance above the steady-state rate.
    pub burst_size: u32,
    /// What happens when a client exhausts its bucket.
    pub exceeded_action: RateLimitExceededAction,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 100,
            burst_size: 200,
            exceeded_action: RateLimitExceededAction::Reject,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub config_version: u32,
    pub server: Server,
    pub listener: Listener,
    pub tls: Tls,
    #[serde(default, rename = "site")]
    pub sites: Vec<Site>,
    pub waf: Waf,
    pub protocol_support: ProtocolSupport,
    pub request_inspection: RequestInspection,
    pub response_inspection: ResponseInspection,
    pub forwarded_headers: ForwardedHeaders,
    pub rules: Rules,
    #[serde(default, rename = "backend")]
    pub backends: Vec<Backend>,
    #[serde(default, rename = "route")]
    pub routes: Vec<Route>,
    pub logging: Logging,
    #[serde(default)]
    pub ip_filter: IpFilter,
    #[serde(default)]
    pub rate_limit: RateLimit,
    #[serde(default)]
    pub schema_enforcement: SchemaEnforcement,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub graceful_shutdown_timeout: String,
    pub graceful_reload_timeout: String,
    pub reload_signal: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Listener {
    pub bind: String,
    pub serve_http1: bool,
    pub serve_http2: bool,
    pub serve_http3: bool,
    pub max_header_size: String,
    pub read_timeout: String,
    pub write_timeout: String,
    pub idle_timeout: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tls {
    pub enabled: bool,
    pub default_certificate: String,
    pub default_private_key: String,
    pub minimum_version: String,
    pub unknown_sni: SniPolicy,
    pub missing_sni: SniPolicy,
    pub authority_mismatch: AuthorityMismatchPolicy,
    pub reload_certificates_on_sighup: bool,
    /// Inject `Strict-Transport-Security` on TLS responses.
    #[serde(default)]
    pub hsts_enabled: bool,
    /// HSTS max-age in seconds.  Default: two years (63072000).
    #[serde(default = "default_hsts_max_age")]
    pub hsts_max_age_seconds: u64,
    /// Add `includeSubDomains` to HSTS.  Default: true.
    #[serde(default = "default_true")]
    pub hsts_include_subdomains: bool,
    /// Add `preload` to HSTS.
    #[serde(default)]
    pub hsts_preload: bool,
    /// Session ticket key rotation interval in seconds.  Zero disables
    /// rotation; rustls then uses a single static key.
    #[serde(default)]
    pub ticket_rotation_seconds: u32,
}

/// Per-site mode.
///
/// `Observe` downgrades every blocking/forward action to `log`,
/// turning the WAF into a passive sensor for safe rule development.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SiteMode {
    #[default]
    Normal,
    Observe,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Site {
    pub server_name: String,
    pub certificate: String,
    pub private_key: String,
    pub forward_to: String,
    pub forward_target: Option<String>,
    pub preserve_host_header: bool,
    pub send_sni_to_backend: bool,
    #[serde(default)]
    pub disabled_rules: Vec<RuleId>,
    /// Per-site mode.  `observe` reduces the WAF to a read-only sensor.
    #[serde(default)]
    pub mode: SiteMode,
    /// Per-site anomaly threshold.  Overrides the global `waf` value.
    #[serde(default)]
    pub anomaly_score_threshold: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Waf {
    pub default_action: DefaultAction,
    pub default_forward_target: Option<String>,
    pub on_engine_error: FailPolicy,
    pub on_rule_reload_error: ReloadPolicy,
    pub request_id_header: String,
    pub warn_on_ignored_matches: bool,
    pub max_matches_per_request: u32,
    /// Block when accumulated rule scores reach this value.
    /// `None` disables threshold-based blocking.
    pub anomaly_score_threshold: Option<i32>,
    #[serde(default)]
    pub disabled_rules: Vec<RuleId>,
    /// Emit x-aegira-action and x-aegira-backend headers on responses.
    /// Disabled by default to avoid fingerprinting the WAF.
    #[serde(default)]
    pub emit_debug_headers: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolSupport {
    pub grpc_inspection: GrpcInspection,
    pub websocket_inspection: WebsocketInspection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestInspection {
    pub inspect_headers: bool,
    pub inspect_query_string: bool,
    pub inspect_body: bool,
    pub body_mode: BodyMode,
    pub max_body_to_buffer: String,
    pub max_body_to_scan: String,
    pub spill_large_bodies_to_disk: bool,
    pub spill_directory: String,
    pub decode_form_data: bool,
    pub decode_json: bool,
    pub decode_multipart: bool,
    pub normalize_url_encoding: bool,
    pub normalize_html_entities: bool,
    pub normalize_unicode: bool,
    /// Transparent decompression of gzip/deflate request bodies before
    /// rule evaluation.  The backend still receives the original bytes.
    #[serde(default = "default_true")]
    pub decompress_body: bool,
    /// Parse `Cookie:` into name=value pairs as a distinct engine target.
    #[serde(default = "default_true")]
    pub inspect_cookies: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseInspection {
    pub inspect_headers: bool,
    pub inspect_body: bool,
    pub response_body_mode: ResponseBodyMode,
    pub remove_server_headers: bool,
    pub remove_powered_by_headers: bool,
    pub max_body_to_scan: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForwardedHeaders {
    pub trust_forwarded_headers: bool,
    /// Trusted upstream proxy CIDRs.  When the direct peer falls in
    /// this set, the leftmost X-Forwarded-For entry becomes the client IP.
    pub trust_forwarded_headers_from: Vec<IpNet>,
    pub set_x_forwarded_for: bool,
    pub set_x_forwarded_proto: bool,
    pub set_x_forwarded_host: bool,
    /// Read a PROXY protocol v1/v2 prefix from the TCP stream before TLS.
    /// The upstream LB must send this on every connection.  The address
    /// from the prefix replaces the socket peer for all IP-based decisions.
    #[serde(default)]
    pub proxy_protocol: bool,
    /// When resolving the real client IP, prefer the RFC 7239 `Forwarded:`
    /// header over the de-facto `X-Forwarded-For`.
    #[serde(default)]
    pub parse_forwarded_header: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    pub entrypoint: String,
    pub max_include_depth: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Backend {
    pub name: String,
    pub backend_address: String,
    pub forward_using: BackendTransport,
    pub backend_protocol: BackendProtocol,
    pub backend_server_name: Option<String>,
    pub verify_backend_certificate: Option<bool>,
    pub backend_ca_file: Option<String>,
    pub present_client_certificate: Option<bool>,
    pub connect_timeout: Option<String>,
    pub tls_handshake_timeout: Option<String>,
    pub response_header_timeout: Option<String>,
    pub keepalive: Option<bool>,
    pub keepalive_idle_timeout: Option<String>,
    pub max_idle_connections: Option<u32>,
    pub retry_requests: Option<bool>,
    pub retry_count: Option<u32>,
    pub retry_only_if_idempotent: Option<bool>,
    pub drain_on_reload: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Route {
    pub host: String,
    pub path_prefix: String,
    pub forward_to: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Logging {
    pub format: LogFormat,
    pub write_to: LogTarget,
    pub file: String,
    pub level: String,
    pub redact_cookies: bool,
    pub redact_authorization_header: bool,
    pub redact_set_cookie_header: bool,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let resolved = path
            .canonicalize()
            .with_context(|| format!("resolve config path {}", path.display()))?;
        let contents = std::fs::read_to_string(&resolved)
            .with_context(|| format!("read config file {}", resolved.display()))?;
        let mut config: Self = toml::from_str(&contents)
            .with_context(|| format!("decode config file {}", resolved.display()))?;

        if Path::new(&config.rules.entrypoint).is_relative() {
            let rules_path = resolved
                .parent()
                .unwrap_or(Path::new("."))
                .join(&config.rules.entrypoint);
            config.rules.entrypoint = rules_path.to_string_lossy().into_owned();
        }

        Ok(config)
    }

    pub fn validate(&self, bundle: &Bundle) -> Result<()> {
        if self.config_version != 1 {
            bail!("unsupported config version {}", self.config_version);
        }
        if self.listener.bind.trim().is_empty() {
            bail!("listener.bind is required");
        }
        if self.sites.is_empty() {
            bail!("at least one site is required");
        }
        if self.backends.is_empty() {
            bail!("at least one backend is required");
        }
        if self.rules.entrypoint.trim().is_empty() {
            bail!("rules.entrypoint is required");
        }
        if bundle.rules.is_empty() {
            bail!("at least one rule is required");
        }

        let mut backend_names = HashSet::new();
        for backend in &self.backends {
            if backend.name.trim().is_empty() {
                bail!("backend.name is required");
            }
            if !backend_names.insert(backend.name.as_str()) {
                bail!("duplicate backend {}", backend.name);
            }
        }

        let mut site_names = HashSet::new();
        if let Some(target) = self.waf.default_forward_target.as_deref() {
            if !backend_names.contains(target) {
                bail!("waf.default_forward_target references unknown backend {}", target);
            }
        }

        for site in &self.sites {
            if site.server_name.trim().is_empty() {
                bail!("site.server_name is required");
            }
            if !site_names.insert(site.server_name.as_str()) {
                bail!("duplicate site {}", site.server_name);
            }
            if !backend_names.contains(site.forward_to.as_str()) {
                bail!(
                    "site {} references unknown backend {}",
                    site.server_name,
                    site.forward_to
                );
            }
            if let Some(target) = site.forward_target.as_deref() {
                if !backend_names.contains(target) {
                    bail!(
                        "site {} forward_target references unknown backend {}",
                        site.server_name,
                        target
                    );
                }
            }
        }

        for route in &self.routes {
            if route.host.trim().is_empty() {
                bail!("route.host is required");
            }
            if !site_names.contains(route.host.as_str()) {
                bail!("route host {} has no matching site", route.host);
            }
            if !backend_names.contains(route.forward_to.as_str()) {
                bail!(
                    "route {} references unknown backend {}",
                    route.host,
                    route.forward_to
                );
            }
        }

        for rule in &bundle.rules {
            if rule.r#match.trim().is_empty() {
                bail!("rule {} is missing match pattern", rule.id);
            }
            if rule.when.is_empty() {
                bail!("rule {} must target at least one field", rule.id);
            }
        }

        for site in &self.sites {
            if site_has_forward_action_rule(site, &self.waf.disabled_rules, &bundle.rules) {
                let target = site
                    .forward_target
                    .as_deref()
                    .or(self.waf.default_forward_target.as_deref())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "site {} has forward action rules but no forward target is configured (set site.forward_target or waf.default_forward_target)",
                            site.server_name
                        )
                    })?;
                if !backend_names.contains(target) {
                    bail!(
                        "site {} resolved forward target {} which is not a known backend",
                        site.server_name,
                        target
                    );
                }
            }
        }

        Ok(())
    }

    pub fn site_for_host(&self, host: &str) -> Option<&Site> {
        self.sites
            .iter()
            .find(|site| site.server_name.eq_ignore_ascii_case(host))
    }

    pub fn route_for_host_path(&self, host: &str, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|route| {
                route.host.eq_ignore_ascii_case(host) && path.starts_with(&route.path_prefix)
            })
            .max_by_key(|route| route.path_prefix.len())
    }

    pub fn backend_by_name(&self, name: &str) -> Option<&Backend> {
        self.backends.iter().find(|backend| backend.name == name)
    }

    pub fn default_site(&self) -> Option<&Site> {
        self.sites.first()
    }
}

fn site_has_forward_action_rule(
    site: &Site,
    global_disabled: &[RuleId],
    rules: &[crate::rules::Rule],
) -> bool {
    rules.iter().any(|rule| {
        !site.disabled_rules.contains(&rule.id)
            && !global_disabled.contains(&rule.id)
            && matches!(rule.action, crate::model::Action::Forward)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Config {
        Config {
            config_version: 1,
            server: Server {
                graceful_shutdown_timeout: "30s".into(),
                graceful_reload_timeout: "5m".into(),
                reload_signal: "SIGHUP".into(),
            },
            listener: Listener {
                bind: ":443".into(),
                serve_http1: true,
                serve_http2: true,
                serve_http3: true,
                max_header_size: "64KiB".into(),
                read_timeout: "15s".into(),
                write_timeout: "30s".into(),
                idle_timeout: "90s".into(),
            },
            tls: Tls {
                enabled: true,
                default_certificate: String::new(),
                default_private_key: String::new(),
                minimum_version: "1.2".into(),
                unknown_sni: SniPolicy::Reject,
                missing_sni: SniPolicy::UseDefaultSite,
                authority_mismatch: AuthorityMismatchPolicy::Reject,
                reload_certificates_on_sighup: true,
                hsts_enabled: false,
                hsts_max_age_seconds: default_hsts_max_age(),
                hsts_include_subdomains: true,
                hsts_preload: false,
                ticket_rotation_seconds: 0,
            },
            sites: vec![
                Site {
                    server_name: "example.com".into(),
                    certificate: String::new(),
                    private_key: String::new(),
                    forward_to: "app".into(),
                    forward_target: Some("app".into()),
                    preserve_host_header: true,
                    send_sni_to_backend: true,
                    disabled_rules: vec![],
                    mode: SiteMode::Normal,
                    anomaly_score_threshold: None,
                },
                Site {
                    server_name: "api.example.com".into(),
                    certificate: String::new(),
                    private_key: String::new(),
                    forward_to: "api".into(),
                    forward_target: Some("api".into()),
                    preserve_host_header: true,
                    send_sni_to_backend: true,
                    disabled_rules: vec![],
                    mode: SiteMode::Normal,
                    anomaly_score_threshold: None,
                },
            ],
            waf: Waf {
                default_action: DefaultAction::Allow,
                default_forward_target: None,
                on_engine_error: FailPolicy::FailOpen,
                on_rule_reload_error: ReloadPolicy::KeepRunningWithOldRules,
                request_id_header: "X-Request-ID".into(),
                warn_on_ignored_matches: true,
                max_matches_per_request: 32,
                anomaly_score_threshold: None,
                disabled_rules: vec![],
                emit_debug_headers: false,
            },
            protocol_support: ProtocolSupport {
                grpc_inspection: GrpcInspection::HeadersOnly,
                websocket_inspection: WebsocketInspection::HandshakeOnly,
            },
            request_inspection: RequestInspection {
                inspect_headers: true,
                inspect_query_string: true,
                inspect_body: true,
                body_mode: BodyMode::Both,
                max_body_to_buffer: "1MiB".into(),
                max_body_to_scan: "8MiB".into(),
                spill_large_bodies_to_disk: true,
                spill_directory: "/tmp".into(),
                decode_form_data: true,
                decode_json: true,
                decode_multipart: true,
                normalize_url_encoding: true,
                normalize_html_entities: true,
                normalize_unicode: true,
                decompress_body: true,
                inspect_cookies: true,
            },
            response_inspection: ResponseInspection {
                inspect_headers: true,
                inspect_body: false,
                response_body_mode: ResponseBodyMode::Off,
                remove_server_headers: true,
                remove_powered_by_headers: true,
                max_body_to_scan: "512KiB".into(),
            },
            forwarded_headers: ForwardedHeaders {
                trust_forwarded_headers: false,
                trust_forwarded_headers_from: vec![],
                set_x_forwarded_for: true,
                set_x_forwarded_proto: true,
                set_x_forwarded_host: true,
                proxy_protocol: false,
                parse_forwarded_header: false,
            },
            rules: Rules {
                entrypoint: "rules/main.toml".into(),
                max_include_depth: 16,
            },
            backends: vec![
                Backend {
                    name: "app".into(),
                    backend_address: "unix:///run/app.sock".into(),
                    forward_using: BackendTransport::UnixSocket,
                    backend_protocol: BackendProtocol::Http1,
                    backend_server_name: None,
                    verify_backend_certificate: None,
                    backend_ca_file: None,
                    present_client_certificate: None,
                    connect_timeout: None,
                    tls_handshake_timeout: None,
                    response_header_timeout: None,
                    keepalive: None,
                    keepalive_idle_timeout: None,
                    max_idle_connections: None,
                    retry_requests: None,
                    retry_count: None,
                    retry_only_if_idempotent: None,
                    drain_on_reload: None,
                },
                Backend {
                    name: "api".into(),
                    backend_address: "127.0.0.1:8080".into(),
                    forward_using: BackendTransport::PlainHttp,
                    backend_protocol: BackendProtocol::Http1,
                    backend_server_name: None,
                    verify_backend_certificate: None,
                    backend_ca_file: None,
                    present_client_certificate: None,
                    connect_timeout: None,
                    tls_handshake_timeout: None,
                    response_header_timeout: None,
                    keepalive: None,
                    keepalive_idle_timeout: None,
                    max_idle_connections: None,
                    retry_requests: None,
                    retry_count: None,
                    retry_only_if_idempotent: None,
                    drain_on_reload: None,
                },
            ],
            routes: vec![
                Route {
                    host: "example.com".into(),
                    path_prefix: "/".into(),
                    forward_to: "app".into(),
                },
                Route {
                    host: "api.example.com".into(),
                    path_prefix: "/v1".into(),
                    forward_to: "api".into(),
                },
                Route {
                    host: "api.example.com".into(),
                    path_prefix: "/".into(),
                    forward_to: "app".into(),
                },
            ],
            logging: Logging {
                format: LogFormat::Json,
                write_to: LogTarget::Stdout,
                file: String::new(),
                level: "info".into(),
                redact_cookies: true,
                redact_authorization_header: true,
                redact_set_cookie_header: true,
            },
            ip_filter: IpFilter::default(),
            rate_limit: RateLimit {
                enabled: false,
                requests_per_second: 100,
                burst_size: 200,
                exceeded_action: RateLimitExceededAction::Reject,
            },
            schema_enforcement: SchemaEnforcement::default(),
        }
    }

    #[test]
    fn route_resolution_prefers_longest_prefix() {
        let config = sample_config();
        let route = config
            .route_for_host_path("api.example.com", "/v1/users")
            .expect("route should resolve");
        assert_eq!(route.forward_to, "api");
    }

    #[test]
    fn site_lookup_is_case_insensitive() {
        let config = sample_config();
        let site = config
            .site_for_host("API.EXAMPLE.COM")
            .expect("site should resolve");
        assert_eq!(site.forward_to, "api");
    }
}
