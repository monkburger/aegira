use anyhow::Result;
use regex::Regex;

use crate::{
    config::{Backend, Config, Route, Site},
    model::{Action, NormalizedRequest, NormalizedResponse, RuleId, Target},
    rules::{Bundle, Rule},
};

/// Upper bound on compiled regex automaton size (bytes).
///
/// Without a cap, a pathological pattern can produce a DFA whose state
/// table consumes arbitrary memory at compile time.  10 MiB is large
/// enough for any useful WAF regex while bounding the damage from a
/// degenerate one.
const REGEX_SIZE_LIMIT: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
struct CompiledRule {
    rule: Rule,
    regex: Regex,
}

#[derive(Debug, Clone)]
pub struct Engine {
    rules: Vec<CompiledRule>,
}

#[derive(Debug)]
pub struct MatchedRule {
    pub id: RuleId,
    pub name: Option<String>,
    pub action: Action,
    pub score: i32,
    pub priority: i32,
    /// First matching substring, captured for audit-log evidence.
    pub matched_fragment: Option<String>,
}

#[derive(Debug)]
pub struct InspectionResult<'a> {
    pub site: &'a Site,
    pub route: &'a Route,
    pub backend: &'a Backend,
    pub action: Action,
    pub forward_backend: Option<&'a Backend>,
    pub matched_rules: Vec<MatchedRule>,
    pub anomaly_score: i32,
}

/// Outcome of response-phase rule evaluation.
#[derive(Debug)]
pub struct ResponseInspectionResult {
    pub action: Action,
    pub matched_rules: Vec<MatchedRule>,
    pub anomaly_score: i32,
}

impl Engine {
    pub fn compile(bundle: &Bundle) -> Result<Self> {
        let mut rules = Vec::with_capacity(bundle.rules.len());
        for rule in &bundle.rules {
            let regex = regex::RegexBuilder::new(&rule.r#match)
                .size_limit(REGEX_SIZE_LIMIT)
                .case_insensitive(true)
                .build()?;
            rules.push(CompiledRule {
                rule: rule.clone(),
                regex,
            });
        }
        Ok(Self { rules })
    }

    pub fn inspect<'a>(
        &'a self,
        config: &'a Config,
        request: &NormalizedRequest,
    ) -> Result<InspectionResult<'a>> {
        let site = config
            .site_for_host(&request.host)
            .ok_or_else(|| anyhow::anyhow!("no site configured for host {}", request.host))?;
        let route = config
            .route_for_host_path(&request.host, &request.path)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no route configured for host {} and path {}",
                    request.host,
                    request.path
                )
            })?;
        let backend = config.backend_by_name(&route.forward_to).ok_or_else(|| {
            anyhow::anyhow!(
                "route {} references unknown backend {}",
                route.host,
                route.forward_to
            )
        })?;

        let header_blob = request.header_blob();
        let cookie_blob = request.cookie_blob();
        let mut matched_rules = Vec::new();
        let mut anomaly_score = 0;
        let max_matches = config.waf.max_matches_per_request as usize;

        for compiled in &self.rules {
            if max_matches > 0 && matched_rules.len() >= max_matches {
                break;
            }
            if site.disabled_rules.contains(&compiled.rule.id)
                || config.waf.disabled_rules.contains(&compiled.rule.id)
            {
                continue;
            }

            // Rules that exclusively target the response phase are skipped
            // during request inspection.
            if compiled.rule.when.iter().all(|t| t.is_response()) {
                continue;
            }

            // Use find() to capture the matching fragment for the audit log.
            let fragment = compiled.rule.when.iter().find_map(|target| {
                let text: &str = match target {
                    Target::Path => &request.path,
                    Target::QueryString => &request.query_string,
                    Target::RequestHeaders => &header_blob,
                    Target::RequestBody => &request.body,
                    Target::Cookies => &cookie_blob,
                    Target::ResponseHeaders | Target::ResponseBody => return None,
                };
                compiled.regex.find(text).map(|m| m.as_str().to_string())
            });

            if fragment.is_some() {
                anomaly_score += compiled.rule.score;
                matched_rules.push(MatchedRule {
                    id: compiled.rule.id,
                    name: compiled.rule.name.clone(),
                    action: compiled.rule.action,
                    score: compiled.rule.score,
                    priority: compiled.rule.priority,
                    matched_fragment: fragment,
                });
            }
        }

        matched_rules.sort_by(|left, right| {
            right
                .action
                .precedence_rank()
                .cmp(&left.action.precedence_rank())
                .then(right.priority.cmp(&left.priority))
                .then(left.id.cmp(&right.id))
        });

        let winning_action = matched_rules
            .first()
            .map(|matched| matched.action)
            .unwrap_or(Action::Log);

        let forward_backend = if winning_action == Action::Forward {
            site.forward_target
                .as_deref()
                .or(config.waf.default_forward_target.as_deref())
                .and_then(|backend_name| config.backend_by_name(backend_name))
        } else {
            None
        };

        Ok(InspectionResult {
            site,
            route,
            backend,
            action: winning_action,
            forward_backend,
            matched_rules,
            anomaly_score,
        })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Run response-phase rules (those with `response_headers` or
    /// `response_body` targets).  Request-only rules are skipped.
    ///
    /// The caller should enforce the returned action (e.g. synthesise
    /// 502 when `Drop` is the winner).
    pub fn inspect_response(
        &self,
        config: &Config,
        request_host: &str,
        response: &NormalizedResponse,
    ) -> Result<ResponseInspectionResult> {
        let site = config
            .site_for_host(request_host)
            .ok_or_else(|| anyhow::anyhow!("no site configured for host {}", request_host))?;

        let header_blob = response.header_blob();
        let mut matched_rules = Vec::new();
        let mut anomaly_score = 0;

        for compiled in &self.rules {
            if site.disabled_rules.contains(&compiled.rule.id)
                || config.waf.disabled_rules.contains(&compiled.rule.id)
            {
                continue;
            }

            // Skip rules whose targets are all request-scoped.
            if compiled.rule.when.iter().all(|t| !t.is_response()) {
                continue;
            }

            let fragment = compiled.rule.when.iter().find_map(|target| {
                let text: &str = match target {
                    Target::ResponseHeaders => &header_blob,
                    Target::ResponseBody => &response.body,
                    _ => return None,
                };
                compiled.regex.find(text).map(|m| m.as_str().to_string())
            });

            if fragment.is_some() {
                anomaly_score += compiled.rule.score;
                matched_rules.push(MatchedRule {
                    id: compiled.rule.id,
                    name: compiled.rule.name.clone(),
                    action: compiled.rule.action,
                    score: compiled.rule.score,
                    priority: compiled.rule.priority,
                    matched_fragment: fragment,
                });
            }
        }

        matched_rules.sort_by(|left, right| {
            right
                .action
                .precedence_rank()
                .cmp(&left.action.precedence_rank())
                .then(right.priority.cmp(&left.priority))
                .then(left.id.cmp(&right.id))
        });

        let action = matched_rules
            .first()
            .map(|m| m.action)
            .unwrap_or(Action::Log);

        Ok(ResponseInspectionResult {
            action,
            matched_rules,
            anomaly_score,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
    config::{
        AuthorityMismatchPolicy, Backend, BackendProtocol, BackendTransport, BodyMode,
        Config, DefaultAction, FailPolicy, ForwardedHeaders, GrpcInspection, IpFilter,
        Listener, Logging, LogFormat, LogTarget, ProtocolSupport, RateLimit,
        RateLimitExceededAction, ReloadPolicy, RequestInspection, ResponseBodyMode,
        ResponseInspection, Route, Rules, SchemaEnforcement, Server, Site, SiteMode,
        SniPolicy, Tls, Waf, WebsocketInspection,
    },
    rules::Bundle,
};

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
                serve_http3: false,
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
                hsts_max_age_seconds: 63_072_000,
                hsts_include_subdomains: true,
                hsts_preload: false,
                ticket_rotation_seconds: 0,
            },
            sites: vec![Site {
                server_name: "example.com".into(),
                certificate: String::new(),
                private_key: String::new(),
                forward_to: "primary".into(),
                forward_target: Some("honeypot".into()),
                preserve_host_header: true,
                send_sni_to_backend: true,
                disabled_rules: vec![],
                mode: SiteMode::Normal,
                anomaly_score_threshold: None,
            }],
            waf: Waf {
                default_action: DefaultAction::Allow,
                default_forward_target: Some("honeypot".into()),
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
                spill_large_bodies_to_disk: false,
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
                entrypoint: String::new(),
                max_include_depth: 16,
            },
            backends: vec![
                Backend {
                    name: "primary".into(),
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
                Backend {
                    name: "honeypot".into(),
                    backend_address: "127.0.0.1:18080".into(),
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
            routes: vec![Route {
                host: "example.com".into(),
                path_prefix: "/".into(),
                forward_to: "primary".into(),
            }],
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

    fn sample_bundle() -> Bundle {
        Bundle {
            rules: vec![
                Rule {
                    id: RuleId(1),
                    name: Some("scanner".into()),
                    description: None,
                    tags: vec![],
                    enabled: true,
                    when: vec![Target::RequestHeaders],
                    r#match: "sqlmap".into(),
                    action: Action::Forward,
                    priority: 10,
                    score: 5,
                    tests: vec![],
                },
                Rule {
                    id: RuleId(2),
                    name: Some("union".into()),
                    description: None,
                    tags: vec![],
                    enabled: true,
                    when: vec![Target::QueryString],
                    r#match: "(?i)union.*select".into(),
                    action: Action::Drop,
                    priority: 100,
                    score: 10,
                    tests: vec![],
                },
            ],
            sources: vec![],
        }
    }

    #[test]
    fn drop_beats_forward() {
        let engine = Engine::compile(&sample_bundle()).expect("engine compiles");
        let config = sample_config();
        let request = NormalizedRequest {
            host: "example.com".into(),
            path: "/login".into(),
            query_string: "q=UNION SELECT password".into(),
            headers: vec![("user-agent".into(), "sqlmap/1.8".into())],
            cookies: vec![],
            body: String::new(),
        };

        let result = engine
            .inspect(&config, &request)
            .expect("inspection succeeds");
        assert_eq!(result.action, Action::Drop);
        assert_eq!(result.anomaly_score, 15);
        assert!(result.forward_backend.is_none());
    }

    #[test]
    fn forward_uses_config_scoped_target() {
        let engine = Engine::compile(&sample_bundle()).expect("engine compiles");
        let config = sample_config();
        let request = NormalizedRequest {
            host: "example.com".into(),
            path: "/login".into(),
            query_string: String::new(),
            headers: vec![("user-agent".into(), "sqlmap/1.8".into())],
            cookies: vec![],
            body: String::new(),
        };

        let result = engine
            .inspect(&config, &request)
            .expect("inspection succeeds");
        assert_eq!(result.action, Action::Forward);
        let forward_backend = result.forward_backend.expect("forward target resolved");
        assert_eq!(forward_backend.name, "honeypot");
    }

    #[test]
    fn global_disabled_rules_suppresses_match() {
        let engine = Engine::compile(&sample_bundle()).expect("engine compiles");
        let mut config = sample_config();
        // Rule 2 (union/reject) would fire; disable it globally.
        config.waf.disabled_rules = vec![RuleId(2)];
        let request = NormalizedRequest {
            host: "example.com".into(),
            path: "/login".into(),
            query_string: "q=UNION SELECT password".into(),
            headers: vec![],
            cookies: vec![],
            body: String::new(),
        };
        let result = engine.inspect(&config, &request).expect("inspection succeeds");
        // Only rule 2 matched; with it disabled the result defaults to Log.
        assert_eq!(result.action, Action::Log);
        assert!(result.matched_rules.is_empty());
        assert_eq!(result.anomaly_score, 0);
    }

    #[test]
    fn site_disabled_rules_suppresses_match() {
        let engine = Engine::compile(&sample_bundle()).expect("engine compiles");
        let mut config = sample_config();
        // Disable rule 2 for the site only.
        config.sites[0].disabled_rules = vec![RuleId(2)];
        let request = NormalizedRequest {
            host: "example.com".into(),
            path: "/login".into(),
            query_string: "q=UNION SELECT password".into(),
            headers: vec![],
            cookies: vec![],
            body: String::new(),
        };
        let result = engine.inspect(&config, &request).expect("inspection succeeds");
        assert_eq!(result.action, Action::Log);
        assert!(result.matched_rules.is_empty());
    }

    #[test]
    fn target_alias_body_matches() {
        let bundle = Bundle {
            rules: vec![Rule {
                id: RuleId(99),
                name: None,
                description: None,
                tags: vec![],
                enabled: true,
                when: vec![Target::RequestBody],
                r#match: "malicious".into(),
                action: Action::Drop,
                priority: 10,
                score: 5,
                tests: vec![],
            }],
            sources: vec![],
        };
        let engine = Engine::compile(&bundle).expect("engine compiles");
        let config = sample_config();
        let request = NormalizedRequest {
            host: "example.com".into(),
            path: "/".into(),
            query_string: String::new(),
            headers: vec![],
            cookies: vec![],
            body: "this is malicious content".into(),
        };
        let result = engine.inspect(&config, &request).expect("inspection succeeds");
        assert_eq!(result.action, Action::Drop);
    }

    #[test]
    fn target_alias_headers_matches() {
        let bundle = Bundle {
            rules: vec![Rule {
                id: RuleId(98),
                name: None,
                description: None,
                tags: vec![],
                enabled: true,
                when: vec![Target::RequestHeaders],
                r#match: "sqlmap".into(),
                action: Action::Drop,
                priority: 100,
                score: 0,
                tests: vec![],
            }],
            sources: vec![],
        };
        let engine = Engine::compile(&bundle).expect("engine compiles");
        let config = sample_config();
        let request = NormalizedRequest {
            host: "example.com".into(),
            path: "/".into(),
            query_string: String::new(),
            headers: vec![("user-agent".into(), "sqlmap/1.8".into())],
            cookies: vec![],
            body: String::new(),
        };
        let result = engine.inspect(&config, &request).expect("inspection succeeds");
        assert_eq!(result.action, Action::Drop);
    }

    #[test]
    fn nameless_rule_produces_none_name_in_result() {
        let bundle = Bundle {
            rules: vec![Rule {
                id: RuleId(97),
                name: None,
                description: None,
                tags: vec![],
                enabled: true,
                when: vec![Target::Path],
                r#match: "^/secret".into(),
                action: Action::Drop,
                priority: 10,
                score: 0,
                tests: vec![],
            }],
            sources: vec![],
        };
        let engine = Engine::compile(&bundle).expect("engine compiles");
        let config = sample_config();
        let request = NormalizedRequest {
            host: "example.com".into(),
            path: "/secret/data".into(),
            query_string: String::new(),
            headers: vec![],
            cookies: vec![],
            body: String::new(),
        };
        let result = engine.inspect(&config, &request).expect("inspection succeeds");
        assert_eq!(result.action, Action::Drop);
        assert!(result.matched_rules[0].name.is_none());
    }

    // -- bypass-specific tests --

    #[test]
    fn case_insensitive_regex_always_matches() {
        // A rule written in lowercase must still fire when the payload
        // uses mixed case, because Engine::compile forces case-insensitive.
        let bundle = Bundle {
            rules: vec![Rule {
                id: RuleId(50),
                name: None,
                description: None,
                tags: vec![],
                enabled: true,
                when: vec![Target::QueryString],
                r#match: "union.*select".into(),
                action: Action::Drop,
                priority: 10,
                score: 5,
                tests: vec![],
            }],
            sources: vec![],
        };
        let engine = Engine::compile(&bundle).expect("engine compiles");
        let config = sample_config();
        let request = NormalizedRequest {
            host: "example.com".into(),
            path: "/".into(),
            query_string: "q=UnIoN SeLeCt 1".into(),
            headers: vec![],
            cookies: vec![],
            body: String::new(),
        };
        let result = engine.inspect(&config, &request).expect("inspection succeeds");
        assert_eq!(result.action, Action::Drop, "case toggle should not evade the rule");
    }

    #[test]
    fn max_matches_per_request_enforced() {
        // Create 5 rules that all match, but set max_matches to 2.
        let rules: Vec<Rule> = (1..=5)
            .map(|i| Rule {
                id: RuleId(i),
                name: None,
                description: None,
                tags: vec![],
                enabled: true,
                when: vec![Target::Path],
                r#match: "/".into(),
                action: Action::Log,
                priority: 1,
                score: 1,
                tests: vec![],
            })
            .collect();
        let bundle = Bundle { rules, sources: vec![] };
        let engine = Engine::compile(&bundle).expect("engine compiles");
        let mut config = sample_config();
        config.waf.max_matches_per_request = 2;
        let request = NormalizedRequest {
            host: "example.com".into(),
            path: "/anything".into(),
            query_string: String::new(),
            headers: vec![],
            cookies: vec![],
            body: String::new(),
        };
        let result = engine.inspect(&config, &request).expect("inspection succeeds");
        assert_eq!(result.matched_rules.len(), 2, "should stop after max_matches_per_request");
    }
}
