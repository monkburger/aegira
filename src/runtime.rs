use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
    time::Instant,
};

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{
        header::{CONNECTION, HOST, UPGRADE},
        HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version,
    },
    response::IntoResponse,
    routing::any,
    Router,
};
use bytes::Buf;
use bytes::Bytes;
use h3::server::RequestResolver;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use percent_encoding;
use quinn::Endpoint;
use reqwest::Client;
use rustls::ServerConfig;
use tokio::{sync::Notify, time::timeout};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{error, info, warn};

use crate::{
    config::{
        AuthorityMismatchPolicy, Backend, BackendProtocol, BackendTransport, Config,
        ForwardedHeaders, GrpcInspection, RateLimitExceededAction, RequestInspection,
        SiteMode, SniPolicy, WebsocketInspection,
    },
    engine::Engine,
    model::{Action, NormalizedRequest, NormalizedResponse},
    proxy_protocol,
    rules, tls as tls_mod, uds,
    schema::{self, SchemaRegistry, ValidationOutcome},
    tls::RotatingTicketEncrypter,
};

/// Headers that MUST NOT be forwarded across a proxy boundary (RFC 9110 S7.6.1).
pub struct HopByHopHeaders;

impl HopByHopHeaders {
    pub const NAMES: &'static [&'static str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];
}

/// Per-config snapshot swapped atomically on SIGHUP.
struct ReloadableState {
    config: Arc<Config>,
    engine: Arc<Engine>,
    /// When schema enforcement is enabled, holds the compiled OpenAPI
    /// validators.  None when disabled or unconfigured.
    schema_registry: Option<Arc<SchemaRegistry>>,
    /// Pre-built HTTP clients keyed by backend name.  Reusing a single
    /// `Client` per backend enables TCP connection pooling (keep-alive)
    /// and avoids the ~1.8 µs construction overhead on every request.
    backend_clients: HashMap<String, Client>,
}

/// Per-IP token bucket for rate limiting.
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64) -> Self {
        Self { tokens: capacity, last_refill: Instant::now() }
    }

    /// Refill tokens by elapsed time, then try to spend one.
    /// Returns true when the request is permitted.
    fn try_consume(&mut self, rate_per_sec: f64, burst: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * rate_per_sec).min(burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct RateLimiterState {
    buckets: std::sync::Mutex<HashMap<IpAddr, TokenBucket>>,
}

impl RateLimiterState {
    fn new() -> Self {
        Self { buckets: std::sync::Mutex::new(HashMap::new()) }
    }

    fn check_and_consume(&self, ip: IpAddr, rate_per_sec: f64, burst: f64) -> bool {
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let bucket = map.entry(ip).or_insert_with(|| TokenBucket::new(burst));
        bucket.try_consume(rate_per_sec, burst)
    }
}

#[derive(Clone)]
struct AppState {
    /// Swapped on SIGHUP.
    reloadable: Arc<ArcSwap<ReloadableState>>,
    /// Config file location for re-reading on reload.
    config_path: String,
    /// Live TLS ServerConfig, present only when TLS is on.
    /// Written by SIGHUP; read on each TCP accept.
    tls_server_config: Option<Arc<ArcSwap<ServerConfig>>>,
    /// Shared across the key-rotation task and the SIGHUP path so that
    /// rotated keys survive config reloads.
    ticket_encrypter: Option<Arc<RotatingTicketEncrypter>>,
    /// Set while a SIGHUP reload is draining and swapping.
    reload_in_progress: Arc<AtomicBool>,
    /// In-flight request count for graceful drain.
    in_flight_requests: Arc<AtomicUsize>,
    /// Wakes the reload path when in-flight drops to zero.
    in_flight_notify: Arc<Notify>,
    /// Prevents concurrent reloads.
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    /// QUIC endpoint for HTTP/3 (if active).
    h3_endpoint: Arc<Mutex<Option<Endpoint>>>,
    /// Broadcast notifier for listener shutdown.
    shutdown_notify: Arc<Notify>,
    /// Health-endpoint readiness flag.
    ready: Arc<AtomicBool>,
    /// Lifetime request counter.
    requests_total: Arc<AtomicUsize>,
    /// Requests terminated by policy.
    blocked_total: Arc<AtomicUsize>,
    /// Requests sent to a backend.
    forwarded_total: Arc<AtomicUsize>,
    /// Requests diverted by a forward-action rule.
    forward_reroute_total: Arc<AtomicUsize>,
    /// Backend-side failures.
    backend_error_total: Arc<AtomicUsize>,
    /// Reload attempts.
    reload_total: Arc<AtomicUsize>,
    /// Per-source-IP token buckets for rate limiting.
    rate_limiter: Arc<RateLimiterState>,
}

pub async fn serve(config: Config, engine: Engine, config_path: &str) -> Result<()> {
    if config.listener.serve_http3 && !config.tls.enabled {
        return Err(anyhow!(
            "frontend HTTP/3 requires tls.enabled = true because QUIC uses TLS 1.3"
        ));
    }

    for backend in &config.backends {
        if backend.backend_protocol == BackendProtocol::Http3 {
            warn!(
                backend = %backend.name,
                "backend_protocol=http3 is configured; evaluated as optional v2 and currently disabled in stable build"
            );
        }
    }

    // ── TLS setup ─────────────────────────────────────────────────────
    // The ticket encrypter is shared between the key-rotation task and
    // every SIGHUP so key material persists across reloads and clients
    // can resume sessions after a config swap.
    let ticket_encrypter: Option<Arc<RotatingTicketEncrypter>> =
        if config.tls.enabled && config.tls.ticket_rotation_seconds > 0 {
            Some(Arc::new(RotatingTicketEncrypter::new(
                config.tls.ticket_rotation_seconds,
            )))
        } else {
            None
        };

    let tls_server_config: Option<Arc<ArcSwap<ServerConfig>>> = if config.tls.enabled {
        let sc = tls_mod::build_server_config(&config, ticket_encrypter.as_ref())
            .context("build TLS server config")?
            .context("TLS config absent despite tls.enabled = true")?;
        Some(Arc::new(ArcSwap::new(sc)))
    } else {
        None
    };

    // ── Reloadable state ──────────────────────────────────────────────────
    let schema_registry = schema::build_registry(&config.schema_enforcement)
        .context("build schema registry")?
        .map(Arc::new);

    let backend_clients = build_backend_clients(&config)
        .context("build backend HTTP clients")?;

    let reloadable = Arc::new(ArcSwap::from_pointee(ReloadableState {
        config: Arc::new(config.clone()),
        engine: Arc::new(engine),
        schema_registry,
        backend_clients,
    }));

    let state = Arc::new(AppState {
        reloadable: Arc::clone(&reloadable),
        config_path: config_path.to_string(),
        tls_server_config: tls_server_config.clone(),
        ticket_encrypter: ticket_encrypter.clone(),
        reload_in_progress: Arc::new(AtomicBool::new(false)),
        in_flight_requests: Arc::new(AtomicUsize::new(0)),
        in_flight_notify: Arc::new(Notify::new()),
        reload_lock: Arc::new(tokio::sync::Mutex::new(())),
        h3_endpoint: Arc::new(Mutex::new(None)),
        shutdown_notify: Arc::new(Notify::new()),
        ready: Arc::new(AtomicBool::new(true)),
        requests_total: Arc::new(AtomicUsize::new(0)),
        blocked_total: Arc::new(AtomicUsize::new(0)),
        forwarded_total: Arc::new(AtomicUsize::new(0)),
        forward_reroute_total: Arc::new(AtomicUsize::new(0)),
        backend_error_total: Arc::new(AtomicUsize::new(0)),
        reload_total: Arc::new(AtomicUsize::new(0)),
        rate_limiter: Arc::new(RateLimiterState::new()),
    });

    // ── Ticket rotation background task ───────────────────────────────────
    if let Some(enc) = &ticket_encrypter {
        let enc = Arc::clone(enc);
        let interval = Duration::from_secs(config.tls.ticket_rotation_seconds as u64);
        let shutdown = Arc::clone(&state.shutdown_notify);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.notified() => break,
                    _ = tokio::time::sleep(interval) => {
                        enc.rotate();
                        info!(interval_secs = interval.as_secs(), "TLS session ticket keys rotated");
                    }
                }
            }
        });
    }

    // ── Axum router ───────────────────────────────────────────────────────
    let app: Router = Router::new()
        .route("/health", any(health_handler))
        .route("/metrics", any(metrics_handler))
        .route("/", any(handle_request))
        .route("/{*path}", any(handle_request))
        .with_state(Arc::clone(&state));

    let bind = parse_bind(&config.listener.bind)?;
    let shutdown_after = parse_duration_or_default(&config.server.graceful_shutdown_timeout, 30);
    let reload_timeout = parse_duration_or_default(&config.server.graceful_reload_timeout, 300);

    // ── Ctrl-C graceful shutdown ──────────────────────────────────────────
    {
        let state_ref = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(err) = tokio::signal::ctrl_c().await {
                error!(error = %err, "failed to listen for shutdown signal");
                return;
            }
            info!("shutdown signal received; draining requests");
            state_ref.shutdown_notify.notify_waiters();
            if let Some(endpoint) = state_ref
                .h3_endpoint
                .lock()
                .ok()
                .and_then(|guard| guard.clone())
            {
                endpoint.close(0u32.into(), b"shutdown");
            }
        });
    }

    // ── SIGHUP hot-reload ─────────────────────────────────────────────────
    {
        let state_ref = Arc::clone(&state);
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sighup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(err) => {
                    warn!(error = %err, "SIGHUP handler unavailable; hot-reload disabled");
                    return;
                }
            };
            loop {
                sighup.recv().await;
                info!("SIGHUP received; reloading config and rules");
                if let Err(err) = reload_config(&state_ref, reload_timeout).await {
                    warn!(error = %err, "config reload failed; keeping previous config");
                }
            }
        });
    }

    // ── HTTP/3 QUIC frontend ──────────────────────────────────────────────
    if config.listener.serve_http3 {
        let h3_server_config = tls_mod::build_quic_server_config(&config, ticket_encrypter.as_ref())
            .context("build HTTP/3 QUIC server config")?
            .context("HTTP/3 config absent despite serve_http3 = true")?;
        let endpoint = Endpoint::server(h3_server_config, bind)
            .with_context(|| format!("bind HTTP/3 QUIC endpoint on {bind}"))?;
        if let Ok(mut guard) = state.h3_endpoint.lock() {
            *guard = Some(endpoint.clone());
        }
        let h3_app = app.clone();
        let h3_state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(err) = serve_http3(endpoint, h3_app, h3_state).await {
                error!(error = %err, "HTTP/3 listener exited with error");
            }
        });
        info!(listen = %bind, "starting HTTP/3 QUIC listener");
    }

    // ── TCP (HTTP/1.1 + HTTP/2) frontend ─────────────────────────────────
    // We manage the TCP accept loop manually so we can:
    //   1. Optionally parse a PROXY protocol v1/v2 header before TLS.
    //   2. Inject the real client IP as ConnectInfo for all three transports.
    //   3. Atomically swap TLS certificates without restarting the listener.
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind listener on {bind}"))?;

    if config.tls.enabled {
        info!(listen = %bind, "starting TLS listener");
    } else {
        info!(listen = %bind, "starting plain HTTP listener");
    }

    let proxy_proto_enabled = config.forwarded_headers.proxy_protocol;

    loop {
        let accept_result = tokio::select! {
            _ = state.shutdown_notify.notified() => break,
            r = listener.accept() => r,
        };

        let (mut tcp_stream, peer_addr) = match accept_result {
            Ok(conn) => conn,
            Err(err) => {
                warn!(error = %err, "TCP accept error");
                continue;
            }
        };

        let app = app.clone();
        let tls_sc = tls_server_config.clone();

        tokio::spawn(async move {
            // PROXY protocol: read the prefix (if enabled) and extract
            // the real client IP before any TLS bytes arrive.
            let real_ip: IpAddr = if proxy_proto_enabled {
                match proxy_protocol::read_proxy_header(&mut tcp_stream, peer_addr.ip()).await {
                    Ok(ip) => ip,
                    Err(err) => {
                        warn!(
                            peer = %peer_addr,
                            error = %err,
                            "PROXY protocol parse failed; using TCP peer IP"
                        );
                        peer_addr.ip()
                    }
                }
            } else {
                peer_addr.ip()
            };

            let effective_addr = SocketAddr::new(real_ip, peer_addr.port());

            // Per-connection service that injects ConnectInfo with the
            // correct (post-PROXY-protocol) peer address.
            let svc = hyper::service::service_fn({
                let app = app.clone();
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        let (mut parts, body) = req.into_parts();
                        parts.extensions.insert(ConnectInfo(effective_addr));
                        let req = Request::from_parts(parts, Body::new(body));
                        app.oneshot(req)
                            .await
                            .map_err(|inf| -> std::convert::Infallible { match inf {} })
                    }
                }
            });

            if let Some(swapper) = tls_sc {
                // Build a TlsAcceptor from the current ServerConfig.
                // Atomic swap on SIGHUP means new connections immediately
                // pick up reloaded certificates.
                let sc = swapper.load_full();
                let tls_acceptor = TlsAcceptor::from(Arc::clone(&sc));
                match tls_acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        let builder = auto::Builder::new(TokioExecutor::new());
                        let conn = builder
                            .serve_connection_with_upgrades(TokioIo::new(tls_stream), svc);
                        if let Err(err) = conn.await {
                            // Connection-level errors (client RST, close_notify)
                            // are noise; only log when there is signal.
                            let msg = err.to_string();
                            if !msg.contains("connection closed")
                                && !msg.contains("early eof")
                            {
                                warn!(peer = %peer_addr, error = %msg, "TLS connection error");
                            }
                        }
                    }
                    Err(err) => {
                        // Handshake failures are common (port scanners, etc.)
                        // and should not pollute the error log.
                        let msg = err.to_string();
                        if !msg.contains("peer closed connection")
                            && !msg.contains("os error 104")
                        {
                            warn!(peer = %peer_addr, error = %msg, "TLS handshake failed");
                        }
                    }
                }
            } else {
                let builder = auto::Builder::new(TokioExecutor::new());
                let conn =
                    builder.serve_connection_with_upgrades(TokioIo::new(tcp_stream), svc);
                if let Err(err) = conn.await {
                    let msg = err.to_string();
                    if !msg.contains("connection closed") && !msg.contains("early eof") {
                        warn!(peer = %peer_addr, error = %msg, "HTTP connection error");
                    }
                }
            }
        });
    }

    info!("accept loop stopped; waiting for in-flight requests to drain");
    wait_for_in_flight_drain(&state, shutdown_after).await;
    info!("shutdown complete");
    Ok(())
}

/// Reload config and rules from disk, recompile the engine, and swap
/// the reloadable state atomically.  On failure, the previous state
/// remains active.
async fn reload_config(state: &AppState, _reload_timeout: Duration) -> Result<()> {
    let _reload_guard = state.reload_lock.lock().await;
    state.reload_total.fetch_add(1, Ordering::SeqCst);
    state.reload_in_progress.store(true, Ordering::SeqCst);
    state.ready.store(false, Ordering::SeqCst);

    if !wait_for_in_flight_drain(state, _reload_timeout).await {
        warn!(
            timeout = ?_reload_timeout,
            still_in_flight = state.in_flight_requests.load(Ordering::SeqCst),
            "reload drain timeout reached; continuing with atomic swap"
        );
    }

    let reload_result = async {
        let new_config = Config::load(&state.config_path)
            .with_context(|| format!("reload config from {}", state.config_path))?;
        let new_bundle = rules::load_bundle(
            &new_config.rules.entrypoint,
            new_config.rules.max_include_depth,
        )
        .context("reload rules bundle")?;
        new_config
            .validate(&new_bundle)
            .context("validate reloaded config")?;
        let new_engine = Engine::compile(&new_bundle).context("compile reloaded engine")?;

        info!(
            sites = new_config.sites.len(),
            backends = new_config.backends.len(),
            rules = new_bundle.rules.len(),
            compiled_rules = new_engine.len(),
            "hot-reload complete"
        );

        // Rotate TLS certs if enabled.
        if new_config.tls.enabled && new_config.tls.reload_certificates_on_sighup {
            // Swap the TLS ServerConfig so new connections immediately
            // see updated certificates.  The ticket encrypter is shared
            // and keeps rotating undisturbed.
            if let Some(swapper) = &state.tls_server_config {
                match tls_mod::build_server_config(&new_config, state.ticket_encrypter.as_ref()) {
                    Ok(Some(sc)) => {
                        swapper.store(sc);
                        info!("TLS certificates reloaded");
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(error = %err, "TLS cert reload failed; keeping previous certs");
                    }
                }
            }

            if let Ok(guard) = state.h3_endpoint.lock() {
                if let Some(endpoint) = guard.as_ref() {
                    match tls_mod::build_quic_server_config(
                        &new_config,
                        state.ticket_encrypter.as_ref(),
                    ) {
                        Ok(Some(server_config)) => {
                            endpoint.set_server_config(Some(server_config));
                            info!("HTTP/3 QUIC certificates reloaded");
                        }
                        Ok(None) => {}
                        Err(err) => {
                            warn!(error = %err, "HTTP/3 QUIC config reload failed; keeping previous config");
                        }
                    }
                }
            }
        }

        let new_schema_registry = schema::build_registry(&new_config.schema_enforcement)
            .context("rebuild schema registry on reload")?
            .map(Arc::new);

        let backend_clients = build_backend_clients(&new_config)
            .context("build backend HTTP clients on reload")?;

        state.reloadable.store(Arc::new(ReloadableState {
            config: Arc::new(new_config),
            engine: Arc::new(new_engine),
            schema_registry: new_schema_registry,
            backend_clients,
        }));

        Ok(())
    }
    .await;

    state.reload_in_progress.store(false, Ordering::SeqCst);
    state.ready.store(true, Ordering::SeqCst);
    reload_result
}

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ready =
        state.ready.load(Ordering::SeqCst) && !state.reload_in_progress.load(Ordering::SeqCst);
    let in_flight = state.in_flight_requests.load(Ordering::SeqCst);

    let body = format!(
        "{{\"ready\":{},\"reload_in_progress\":{},\"in_flight\":{}}}",
        ready,
        state.reload_in_progress.load(Ordering::SeqCst),
        in_flight
    );

    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    if let Ok(value) = HeaderValue::from_str("application/json") {
        response.headers_mut().insert("content-type", value);
    }
    response
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let metrics = format!(
        concat!(
            "# TYPE aegira_requests_total counter\n",
            "aegira_requests_total {}\n",
            "# TYPE aegira_in_flight gauge\n",
            "aegira_in_flight {}\n",
            "# TYPE aegira_blocked_total counter\n",
            "aegira_blocked_total {}\n",
            "# TYPE aegira_forwarded_total counter\n",
            "aegira_forwarded_total {}\n",
            "# TYPE aegira_forward_reroute_total counter\n",
            "aegira_forward_reroute_total {}\n",
            "# TYPE aegira_backend_error_total counter\n",
            "aegira_backend_error_total {}\n",
            "# TYPE aegira_reload_total counter\n",
            "aegira_reload_total {}\n",
            "# TYPE aegira_ready gauge\n",
            "aegira_ready {}\n"
        ),
        state.requests_total.load(Ordering::SeqCst),
        state.in_flight_requests.load(Ordering::SeqCst),
        state.blocked_total.load(Ordering::SeqCst),
        state.forwarded_total.load(Ordering::SeqCst),
        state.forward_reroute_total.load(Ordering::SeqCst),
        state.backend_error_total.load(Ordering::SeqCst),
        state.reload_total.load(Ordering::SeqCst),
        if state.ready.load(Ordering::SeqCst) {
            1
        } else {
            0
        }
    );

    let mut response = Response::new(Body::from(metrics));
    if let Ok(value) = HeaderValue::from_str("text/plain; version=0.0.4") {
        response.headers_mut().insert("content-type", value);
    }
    response
}

async fn handle_request(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> impl IntoResponse {
    let request_started = Instant::now();
    state.requests_total.fetch_add(1, Ordering::SeqCst);

    if state.reload_in_progress.load(Ordering::SeqCst) {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "reload in progress; please retry",
        );
    }

    let _in_flight_guard = InFlightRequestGuard::new(
        Arc::clone(&state.in_flight_requests),
        Arc::clone(&state.in_flight_notify),
    );

    // Load the current state snapshot.  The Arc keeps it alive for this
    // request even if a SIGHUP fires mid-flight.
    let snap = state.reloadable.load_full();

    let (parts, body) = request.into_parts();

    // Determine the real client IP.  If the direct peer is a trusted
    // proxy, use the leftmost X-Forwarded-For address.
    let client_ip = real_client_ip(
        peer_addr.ip(),
        &parts.headers,
        &snap.config.forwarded_headers,
    );

    // Generate or carry forward a request ID for log correlation.
    // Reuse the incoming header value when present; mint a UUIDv4 otherwise.
    let request_id: String = {
        let header_name = &snap.config.waf.request_id_header;
        parts
            .headers
            .get(header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    };

    // IP filter: block list first, then allow list.
    if snap.config.ip_filter.block.iter().any(|net| net.contains(&client_ip)) {
        return error_response(StatusCode::FORBIDDEN, "blocked by policy");
    }
    if !snap.config.ip_filter.allow.is_empty()
        && !snap.config.ip_filter.allow.iter().any(|net| net.contains(&client_ip))
    {
        return error_response(StatusCode::FORBIDDEN, "blocked by policy");
    }

    // Rate limit: per-source-IP token bucket.
    if snap.config.rate_limit.enabled {
        let rate = snap.config.rate_limit.requests_per_second as f64;
        let burst = snap.config.rate_limit.burst_size as f64;
        if !state.rate_limiter.check_and_consume(client_ip, rate, burst) {
            match snap.config.rate_limit.exceeded_action {
                RateLimitExceededAction::Reject => {
                    return error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate limit exceeded",
                    );
                }
                RateLimitExceededAction::Log => {
                    warn!(client_ip = %client_ip, "rate limit exceeded (log-only mode)");
                }
            }
        }
    }

    let is_grpc = is_grpc_request(&parts.headers);
    let is_websocket = is_websocket_upgrade(&parts.headers);

    if is_grpc && snap.config.protocol_support.grpc_inspection == GrpcInspection::Off {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "gRPC handling is disabled by protocol_support.grpc_inspection",
        );
    }
    if is_websocket
        && snap.config.protocol_support.websocket_inspection == WebsocketInspection::Off
    {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "WebSocket handling is disabled by protocol_support.websocket_inspection",
        );
    }

    let host_header = parts
        .headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(strip_port)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let authority_host = parts
        .uri
        .authority()
        .map(|value| strip_port(value.as_str()).to_string());

    if let (Some(authority), Some(header)) = (authority_host.as_deref(), host_header.as_deref()) {
        if !authority.eq_ignore_ascii_case(header)
            && snap.config.tls.authority_mismatch == AuthorityMismatchPolicy::Reject
        {
            return error_response(
                StatusCode::MISDIRECTED_REQUEST,
                "authority mismatch rejected",
            );
        }
        if !authority.eq_ignore_ascii_case(header)
            && snap.config.tls.authority_mismatch != AuthorityMismatchPolicy::Reject
        {
            warn!(authority = %authority, host = %header, "authority mismatch accepted by policy");
        }
    }

    let mut resolved_host = host_header.or(authority_host).unwrap_or_default();
    if resolved_host.is_empty() {
        if snap.config.tls.missing_sni == SniPolicy::Reject {
            return error_response(
                StatusCode::MISDIRECTED_REQUEST,
                "host missing and rejected by policy",
            );
        }
        if let Some(site) = snap.config.default_site() {
            resolved_host = site.server_name.clone();
        }
    }

    if snap.config.site_for_host(&resolved_host).is_none() {
        if snap.config.tls.unknown_sni == SniPolicy::Reject {
            return error_response(
                StatusCode::MISDIRECTED_REQUEST,
                "unknown host rejected by policy",
            );
        }
        if let Some(site) = snap.config.default_site() {
            resolved_host = site.server_name.clone();
        }
    }

    // Recursive percent-decode to neutralise double/triple-encoding
    // bypass attempts.  Path segments are then collapsed so that
    // /foo/../../etc/passwd normalises to /etc/passwd.
    let path = if snap.config.request_inspection.normalize_url_encoding {
        let decoded = recursive_percent_decode(parts.uri.path());
        // Normalise backslashes to forward slashes before collapsing.
        // Some parsers treat '\' as a path separator; leaving them
        // lets \..\..\etc\passwd bypass collapse_path.
        let decoded = decoded.replace('\\', "/");
        collapse_path(&decoded)
    } else {
        parts.uri.path().to_string()
    };
    let query_string = if snap.config.request_inspection.normalize_url_encoding {
        let raw = parts.uri.query().unwrap_or_default();
        // Decode recursively. Replace + with space (form convention).
        recursive_percent_decode(raw).replace('+', " ")
    } else {
        parts.uri.query().unwrap_or_default().to_string()
    };
    // Strip null bytes that could truncate C-backed string comparisons.
    let path = strip_null_bytes(&path);
    let query_string = strip_null_bytes(&query_string);
    // Apply HTML-entity and unicode normalisation for inspection.
    let path = normalize_inspection_str(&path, &snap.config.request_inspection);
    let query_string = normalize_inspection_str(&query_string, &snap.config.request_inspection);

    // Collect fields for the engine according to inspection flags.
    // Headers are percent-decoded and normalised so that encoded
    // payloads in Referer, User-Agent, etc. cannot evade rules.
    let headers_for_engine = if snap.config.request_inspection.inspect_headers {
        parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|text| {
                        let decoded = if snap.config.request_inspection.normalize_url_encoding {
                            strip_null_bytes(&recursive_percent_decode(text))
                        } else {
                            text.to_string()
                        };
                        let normalized = normalize_inspection_str(
                            &decoded,
                            &snap.config.request_inspection,
                        );
                        (name.as_str().to_string(), normalized)
                    })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let query_for_engine = if snap.config.request_inspection.inspect_query_string {
        query_string.clone()
    } else {
        String::new()
    };
    // RFC 6265: split Cookie header into name=value pairs for the
    // `cookies` target.  The raw header stays in headers_for_engine;
    // parsed pairs are harder to evade with encoding tricks.
    let cookies_for_engine = if snap.config.request_inspection.inspect_cookies {
        parse_cookies(&parts.headers)
            .into_iter()
            .map(|(name, value)| {
                let decoded = if snap.config.request_inspection.normalize_url_encoding {
                    strip_null_bytes(&recursive_percent_decode(&value))
                } else {
                    value
                };
                let normalized = normalize_inspection_str(
                    &decoded,
                    &snap.config.request_inspection,
                );
                (name, normalized)
            })
            .collect()
    } else {
        Vec::new()
    };

    // RFC 9110 S10.1.1: Expect: 100-continue early check.
    // The client has not sent its body yet.  If headers/path/query/cookies
    // alone produce a decisive block, reject before the body arrives.
    if parts
        .headers
        .get("expect")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("100-continue"))
        .unwrap_or(false)
    {
        let pre = NormalizedRequest {
            host: resolved_host.clone(),
            path: path.clone(),
            query_string: query_for_engine.clone(),
            headers: headers_for_engine.clone(),
            cookies: cookies_for_engine.clone(),
            body: String::new(),
        };
        if let Ok(pre_result) = snap.engine.inspect(&snap.config, &pre) {
            let pre_threshold = pre_result
                .site
                .anomaly_score_threshold
                .or(snap.config.waf.anomaly_score_threshold);
            let score_breach = pre_threshold.map_or(false, |t| pre_result.anomaly_score >= t);
            let observe = matches!(pre_result.site.mode, SiteMode::Observe);
            if !observe
                && (matches!(pre_result.action, Action::Drop) || score_breach)
            {
                state.blocked_total.fetch_add(1, Ordering::SeqCst);
                return error_response(StatusCode::FORBIDDEN, "blocked by policy");
            }
        }
    }

    // Materialise the request body now that early inspection passed.
    let body = match materialize_body(body, &snap.config.request_inspection).await {
        Ok(bytes) => bytes,
        Err(status) => return error_response(status, "request body too large"),
    };
    let max_body = parse_byte_size(&snap.config.request_inspection.max_body_to_scan);

    // RFC 9110 S8.4: decompress for inspection only.
    // The backend receives the original compressed bytes; only the
    // inspection copy is inflated.  Output is capped at max_body_to_scan
    // to block decompression bombs.
    let inspection_body = if snap.config.request_inspection.decompress_body {
        decompress_for_inspection(
            parts.headers.get("content-encoding").and_then(|v| v.to_str().ok()),
            &body,
            max_body,
        )
    } else {
        body.clone()
    };

    let content_type = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Schema enforcement: validate against the OpenAPI spec before the
    // regex engine sees the request.  Two modes:
    //  1. Body validation: JSON bodies are checked against the request
    //     body schema for the matching endpoint.
    //  2. Endpoint gating (reject_unknown_endpoints): requests to
    //     method + path combos not in the spec are rejected outright.
    // Both fire before the regex engine runs.
    if let Some(ref registry) = snap.schema_registry {
        let body_to_check = if content_type.contains("json") {
            &inspection_body[..]
        } else {
            &[]
        };
        match registry.validate(
            parts.method.as_str(),
            &path,
            body_to_check,
        ) {
            ValidationOutcome::Valid | ValidationOutcome::NoSchema => {}
            ValidationOutcome::Invalid(reason) => {
                state.blocked_total.fetch_add(1, Ordering::SeqCst);
                info!(
                    path = %path,
                    reason = %reason,
                    "schema enforcement rejected request"
                );
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "request body does not conform to schema",
                );
            }
            ValidationOutcome::UnknownEndpoint => {
                state.blocked_total.fetch_add(1, Ordering::SeqCst);
                info!(
                    path = %path,
                    method = %parts.method,
                    "schema enforcement rejected unknown endpoint"
                );
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "endpoint not defined in API specification",
                );
            }
        }
    }

    let body_for_engine = if snap.config.request_inspection.inspect_body {
        let raw_body = maybe_inspected_body(&snap.config, is_grpc, is_websocket, &inspection_body);
        prepare_body_for_inspection(
            &snap.config.request_inspection,
            &raw_body,
            &inspection_body,
            &content_type,
        )
    } else {
        String::new()
    };

    let normalized = NormalizedRequest {
        host: resolved_host,
        path: path.clone(),
        query_string: query_for_engine,
        headers: headers_for_engine,
        cookies: cookies_for_engine,
        body: body_for_engine,
    };

    let inspection = match snap.engine.inspect(&snap.config, &normalized) {
        Ok(result) => result,
        Err(err) => {
            state.backend_error_total.fetch_add(1, Ordering::SeqCst);
            error!(error = %err, host = %normalized.host, path = %normalized.path, "request inspection error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    // Observe mode: downgrade blocking/forward actions to Log so
    // the WAF acts as a passive sensor.
    let effective_action = if matches!(inspection.site.mode, SiteMode::Observe)
        && matches!(inspection.action, Action::Drop | Action::Forward)
    {
        warn!(
            host = %normalized.host,
            path = %normalized.path,
            original_action = inspection.action.as_header_value(),
            request_id = %request_id,
            "observe_mode: action downgraded to log"
        );
        Action::Log
    } else {
        inspection.action
    };

    // Compute rule_ids and match_fragments once; reused in all audit log calls.
    let rule_ids = inspection
        .matched_rules
        .iter()
        .map(|rule| rule.id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let match_fragments = inspection
        .matched_rules
        .iter()
        .filter_map(|r| r.matched_fragment.as_deref())
        .collect::<Vec<_>>()
        .join("|");

    if matches!(effective_action, Action::Drop) {
        state.blocked_total.fetch_add(1, Ordering::SeqCst);
        info!(
            action = effective_action.as_header_value(),
            request_id = %request_id,
            backend = %inspection.backend.name,
            matched_rule_ids = %rule_ids,
            match_fragments = %match_fragments,
            latency_ms = request_started.elapsed().as_millis() as u64,
            "request_audit"
        );
        return error_response(StatusCode::FORBIDDEN, "blocked by policy");
    }

    // Anomaly score threshold: per-site overrides global.
    // Individual rules may score below the threshold, but their sum
    // can cross it; this is the core of anomaly-detection rulesets.
    let anomaly_threshold = inspection
        .site
        .anomaly_score_threshold
        .or(snap.config.waf.anomaly_score_threshold);
    if let Some(threshold) = anomaly_threshold {
        if inspection.anomaly_score >= threshold {
            state.blocked_total.fetch_add(1, Ordering::SeqCst);
            info!(
                action = "anomaly_score_block",
                request_id = %request_id,
                anomaly_score = inspection.anomaly_score,
                threshold,
                matched_rule_ids = %rule_ids,
                match_fragments = %match_fragments,
                latency_ms = request_started.elapsed().as_millis() as u64,
                "request_audit"
            );
            return error_response(StatusCode::FORBIDDEN, "blocked by policy");
        }
    }

    let target_backend = if effective_action == Action::Forward {
        state.forward_reroute_total.fetch_add(1, Ordering::SeqCst);
        inspection.forward_backend.unwrap_or(inspection.backend)
    } else {
        inspection.backend
    };

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // Build outbound headers from the incoming set, appending any
    // X-Forwarded-* headers the config requires.
    let mut outbound_headers = parts.headers.clone();
    add_forwarded_headers(&mut outbound_headers, client_ip, &snap.config);

    // Propagate the request ID to the backend for log correlation.
    if !snap.config.waf.request_id_header.is_empty() {
        if let (Ok(name), Ok(value)) = (
            snap.config.waf.request_id_header.parse::<HeaderName>(),
            HeaderValue::from_str(&request_id),
        ) {
            outbound_headers.insert(name, value);
        }
    }

    let backend_client = snap.backend_clients.get(&target_backend.name);

    let mut response = match forward_request(
        &state,
        target_backend,
        &parts.method,
        &outbound_headers,
        &path_and_query,
        &body,
        backend_client,
    )
    .await
    {
        Ok(resp) => resp,
        Err(err) => {
            state.backend_error_total.fetch_add(1, Ordering::SeqCst);
            error!(error = %err, backend = %inspection.backend.name, "backend forward error");
            return error_response(StatusCode::BAD_GATEWAY, "upstream error");
        }
    };

    // Response-phase rule evaluation for `response_headers` and
    // `response_body` targets.  The body is already buffered by
    // forward_http, so the read here is free.
    if snap.config.response_inspection.inspect_headers
        || snap.config.response_inspection.inspect_body
    {
        let (resp_parts, resp_body_raw) = response.into_parts();
        let resp_bytes = to_bytes(resp_body_raw, usize::MAX).await.unwrap_or_default();
        let max_resp = parse_byte_size(&snap.config.response_inspection.max_body_to_scan);

        let resp_headers = if snap.config.response_inspection.inspect_headers {
            resp_parts
                .headers
                .iter()
                .filter_map(|(n, v)| {
                    v.to_str()
                        .ok()
                        .map(|s| (n.as_str().to_string(), s.to_string()))
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };

        let resp_body_str = if snap.config.response_inspection.inspect_body {
            let cap = max_resp.min(resp_bytes.len());
            String::from_utf8_lossy(&resp_bytes[..cap]).to_string()
        } else {
            String::new()
        };

        let norm_resp = NormalizedResponse {
            status: resp_parts.status.as_u16(),
            headers: resp_headers,
            body: resp_body_str,
        };

        match snap
            .engine
            .inspect_response(&snap.config, &normalized.host, &norm_resp)
        {
            Ok(resp_insp)
                if matches!(resp_insp.action, Action::Drop) =>
            {
                state.blocked_total.fetch_add(1, Ordering::SeqCst);
                let resp_rule_ids = resp_insp
                    .matched_rules
                    .iter()
                    .map(|r| r.id.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                info!(
                    action = "response_blocked",
                    request_id = %request_id,
                    matched_rule_ids = %resp_rule_ids,
                    status = %resp_parts.status,
                    latency_ms = request_started.elapsed().as_millis() as u64,
                    "request_audit"
                );
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    "response blocked by policy",
                );
            }
            _ => {}
        }

        response = Response::from_parts(resp_parts, Body::from(resp_bytes));
    }

    // Strip backend-identifying headers.
    if snap.config.response_inspection.remove_server_headers {
        response.headers_mut().remove("server");
    }
    if snap.config.response_inspection.remove_powered_by_headers {
        response.headers_mut().remove("x-powered-by");
    }

    state.forwarded_total.fetch_add(1, Ordering::SeqCst);
    info!(
        action = effective_action.as_header_value(),
        request_id = %request_id,
        backend = %target_backend.name,
        matched_rule_ids = %rule_ids,
        match_fragments = %match_fragments,
        status = %response.status(),
        latency_ms = request_started.elapsed().as_millis() as u64,
        "request_audit"
    );

    if snap.config.waf.emit_debug_headers {
        if let Ok(value) = HeaderValue::from_str(effective_action.as_header_value()) {
            response.headers_mut().insert("x-aegira-action", value);
        }
        if let Ok(value) = HeaderValue::from_str(&target_backend.name) {
            response.headers_mut().insert("x-aegira-backend", value);
        }
    }

    // RFC 6797 HSTS: inject Strict-Transport-Security on TLS responses.
    if snap.config.tls.enabled && snap.config.tls.hsts_enabled {
        if let Ok(value) = HeaderValue::from_str(&build_hsts_value(&snap.config.tls)) {
            response
                .headers_mut()
                .insert("strict-transport-security", value);
        }
    }

    response
}

/// Build the `Strict-Transport-Security` header value.
fn build_hsts_value(tls: &crate::config::Tls) -> String {
    let mut value = format!("max-age={}", tls.hsts_max_age_seconds);
    if tls.hsts_include_subdomains {
        value.push_str("; includeSubDomains");
    }
    if tls.hsts_preload {
        value.push_str("; preload");
    }
    value
}

async fn forward_request(
    _state: &AppState,
    backend: &Backend,
    method: &Method,
    headers: &HeaderMap,
    path_and_query: &str,
    body: &Bytes,
    cached_client: Option<&Client>,
) -> Result<Response<Body>> {
    let retry_requests = backend.retry_requests.unwrap_or(false);
    let retry_count = backend.retry_count.unwrap_or(0) as usize;
    let retry_only_if_idempotent = backend.retry_only_if_idempotent.unwrap_or(true);
    let method_is_idempotent = is_idempotent_method(method);

    let retries_allowed = retry_requests && (!retry_only_if_idempotent || method_is_idempotent);
    let max_attempts = if retries_allowed { retry_count + 1 } else { 1 };

    let connect_timeout = backend_effective_connect_timeout(backend)?;
    let response_header_timeout = parse_backend_duration(
        backend.response_header_timeout.as_deref(),
        backend,
        "response_header_timeout",
    )?;
    let backend_protocol = backend.backend_protocol;

    for attempt in 1..=max_attempts {
        let result = match backend.forward_using {
            BackendTransport::UnixSocket => {
                let socket_path = backend
                    .backend_address
                    .strip_prefix("unix://")
                    .ok_or_else(|| anyhow!("unix backend address must start with unix://"))?;

                // Build a proper hyper Request so the UDS forwarder can use the
                // real HTTP/1.1 codec instead of manual string building.
                let uri = path_and_query
                    .parse::<axum::http::Uri>()
                    .with_context(|| format!("parse path_and_query as URI: {path_and_query}"))?;
                let mut req_builder = Request::builder().method(method.clone()).uri(uri);
                for (name, value) in headers {
                    req_builder = req_builder.header(name, value);
                }
                let hyper_req = req_builder
                    .body(body.clone())
                    .context("build hyper request for UDS forward")?;
                uds::forward_unix_socket(
                    socket_path,
                    hyper_req,
                    connect_timeout,
                    response_header_timeout,
                )
                .await
            }
            BackendTransport::PlainHttp | BackendTransport::Tls => {
                let scheme = if backend.forward_using == BackendTransport::Tls {
                    "https"
                } else {
                    "http"
                };
                let url = format!("{scheme}://{}{}", backend.backend_address, path_and_query);
                // Use the pre-built pooled client when available
                // (reuse_connections = true, the default).  Fall back
                // to a fresh throwaway client when the backend opts
                // out of connection reuse.
                let owned_client;
                let http_client = match cached_client {
                    Some(c) => c,
                    None => {
                        owned_client = build_backend_http_client(
                            connect_timeout,
                            backend_protocol,
                        )?;
                        &owned_client
                    }
                };
                forward_http(
                    http_client,
                    &url,
                    method,
                    headers,
                    body,
                    response_header_timeout,
                    backend_protocol,
                )
                .await
            }
        };

        match result {
            Ok(response) => {
                if attempt < max_attempts && should_retry_status(response.status()) {
                    warn!(
                        backend = %backend.name,
                        method = %method,
                        status = %response.status(),
                        attempt,
                        max_attempts,
                        "retrying request due to retryable backend status"
                    );
                    continue;
                }
                return Ok(response);
            }
            Err(err) => {
                if attempt < max_attempts {
                    warn!(
                        backend = %backend.name,
                        method = %method,
                        attempt,
                        max_attempts,
                        error = %err,
                        "retrying request after backend forward error"
                    );
                    continue;
                }
                return Err(err);
            }
        }
    }

    Err(anyhow!("retry loop exited unexpectedly"))
}

async fn forward_http(
    client: &Client,
    url: &str,
    method: &Method,
    headers: &HeaderMap,
    body: &Bytes,
    response_header_timeout: Option<Duration>,
    backend_protocol: BackendProtocol,
) -> Result<Response<Body>> {
    let hop_by_hop: Vec<HeaderName> = HopByHopHeaders::NAMES
        .iter()
        .filter_map(|name| name.parse::<HeaderName>().ok())
        .collect();

    let mut builder = client.request(method.clone(), url);
    for (name, value) in headers {
        if hop_by_hop.contains(name) {
            continue;
        }
        builder = builder.header(name, value);
    }

    match backend_protocol {
        BackendProtocol::Http1 => {
            builder = builder.version(Version::HTTP_11);
        }
        BackendProtocol::Http2 => {
            builder = builder.version(Version::HTTP_2);
        }
        BackendProtocol::Http3 => {
            return Err(anyhow!(
                "backend_protocol=http3 is evaluated as optional v2 but unavailable in stable build (reqwest http3 is unstable)"
            ));
        }
        BackendProtocol::Auto => {}
    }

    if let Some(timeout) = response_header_timeout {
        builder = builder.timeout(timeout);
    }

    let response = builder
        .body(body.clone())
        .send()
        .await
        .with_context(|| format!("send outbound request to {url}"))?;

    let mut axum_response = Response::builder().status(response.status());
    for (name, value) in response.headers() {
        if hop_by_hop.contains(name) {
            continue;
        }
        axum_response = axum_response.header(name, value);
    }

    let response_body = response
        .bytes()
        .await
        .context("read outbound response body")?;
    axum_response
        .body(Body::from(response_body))
        .map_err(|err| anyhow!("build response: {err}"))
}

async fn serve_http3(endpoint: Endpoint, app: Router, state: Arc<AppState>) -> Result<()> {
    loop {
        let incoming = tokio::select! {
            _ = state.shutdown_notify.notified() => {
                break;
            }
            incoming = endpoint.accept() => incoming,
        };

        let Some(incoming) = incoming else {
            break;
        };

        let app = app.clone();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(err) = handle_h3_connection(incoming, app, state).await {
                warn!(error = %err, "HTTP/3 connection failed");
            }
        });
    }

    Ok(())
}

async fn handle_h3_connection(
    incoming: quinn::Incoming,
    app: Router,
    state: Arc<AppState>,
) -> Result<()> {
    let connection = incoming.await.context("accept QUIC connection")?;
    let peer_addr = connection.remote_address();
    let mut h3_conn = h3::server::builder()
        .build(h3_quinn::Connection::new(connection))
        .await
        .context("build HTTP/3 server connection")?;

    loop {
        let accepted = tokio::select! {
            _ = state.shutdown_notify.notified() => {
                break;
            }
            accepted = h3_conn.accept() => accepted,
        };

        match accepted {
            Ok(Some(resolver)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_h3_request(resolver, app, peer_addr).await {
                        warn!(error = %err, "HTTP/3 request handling failed");
                    }
                });
            }
            Ok(None) => break,
            Err(err) => return Err(anyhow!("accept HTTP/3 request: {err}")),
        }
    }

    Ok(())
}

async fn handle_h3_request(
    resolver: RequestResolver<h3_quinn::Connection, Bytes>,
    app: Router,
    peer_addr: SocketAddr,
) -> Result<()> {
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .context("resolve HTTP/3 request")?;

    let mut request_body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .context("read HTTP/3 request body")?
    {
        let remaining = chunk.remaining();
        request_body.extend_from_slice(&chunk.copy_to_bytes(remaining));
    }
    let _ = stream.recv_trailers().await;

    let (mut parts, ()) = request.into_parts();
    parts.version = Version::HTTP_3;
    let mut axum_request = Request::from_parts(parts, Body::from(request_body));
    axum_request.extensions_mut().insert(ConnectInfo(peer_addr));

    let response = match app.oneshot(axum_request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };

    send_h3_response(stream, response).await
}

async fn send_h3_response<S>(
    mut stream: h3::server::RequestStream<S, Bytes>,
    response: Response<Body>,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes> + h3::quic::SendStream<Bytes>,
{
    let hop_by_hop: Vec<HeaderName> = HopByHopHeaders::NAMES
        .iter()
        .filter_map(|name| name.parse::<HeaderName>().ok())
        .collect();

    let (parts, body) = response.into_parts();
    let mut builder = Response::builder()
        .status(parts.status)
        .version(Version::HTTP_3);
    for (name, value) in &parts.headers {
        if hop_by_hop.contains(name) {
            continue;
        }
        builder = builder.header(name, value);
    }
    let headers_only = builder.body(()).context("build HTTP/3 headers response")?;
    stream
        .send_response(headers_only)
        .await
        .context("send HTTP/3 response headers")?;

    let response_body = to_bytes(body, usize::MAX)
        .await
        .context("buffer HTTP/3 response body")?;
    if !response_body.is_empty() {
        stream
            .send_data(response_body)
            .await
            .context("send HTTP/3 response body")?;
    }
    stream.finish().await.context("finish HTTP/3 response")?;
    Ok(())
}

fn parse_bind(bind: &str) -> Result<SocketAddr> {
    if bind.starts_with(':') {
        let port = bind.trim_start_matches(':');
        return format!("0.0.0.0:{port}")
            .parse::<SocketAddr>()
            .with_context(|| format!("parse listener bind {bind}"));
    }

    bind.parse::<SocketAddr>()
        .with_context(|| format!("parse listener bind {bind}"))
}

struct InFlightRequestGuard {
    counter: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl InFlightRequestGuard {
    fn new(counter: Arc<AtomicUsize>, notify: Arc<Notify>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self { counter, notify }
    }
}

impl Drop for InFlightRequestGuard {
    fn drop(&mut self) {
        let previous = self.counter.fetch_sub(1, Ordering::SeqCst);
        if previous == 1 {
            self.notify.notify_waiters();
        }
    }
}

async fn wait_for_in_flight_drain(state: &AppState, drain_timeout: Duration) -> bool {
    if state.in_flight_requests.load(Ordering::SeqCst) == 0 {
        return true;
    }

    let wait_loop = async {
        loop {
            if state.in_flight_requests.load(Ordering::SeqCst) == 0 {
                break;
            }
            state.in_flight_notify.notified().await;
        }
    };

    timeout(drain_timeout, wait_loop).await.is_ok()
}

fn parse_duration_or_default(value: &str, default_secs: u64) -> Duration {
    humantime::parse_duration(value).unwrap_or_else(|_| Duration::from_secs(default_secs))
}

fn is_idempotent_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
    )
}

fn is_grpc_request(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().starts_with("application/grpc"))
        .unwrap_or(false)
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("websocket"))
        .unwrap_or(false);
    let connection_upgrade = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);

    upgrade && connection_upgrade
}

/// Parse RFC 6265 `Cookie` header into name=value pairs.
///
/// Semicolon-delimited; whitespace trimmed.  Handles multiple
/// `Cookie` lines via `get_all`.
fn parse_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|header_value| {
            header_value.split(';').filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let name = parts.next()?.trim();
                let value = parts.next().unwrap_or("").trim();
                if name.is_empty() {
                    None
                } else {
                    Some((name.to_string(), value.to_string()))
                }
            })
        })
        .collect()
}

/// Decompress an HTTP request body for WAF inspection.
///
/// Supports gzip, x-gzip, and deflate.  Output is capped at `max_bytes`
/// via `Read::take` to prevent decompression bombs.  On any error the
/// original bytes are returned so the engine still scans something.
///
/// The caller forwards the original compressed bytes to the backend;
/// this function returns an inspection-only copy.
fn decompress_for_inspection(
    content_encoding: Option<&str>,
    body: &Bytes,
    max_bytes: usize,
) -> Bytes {
    use flate2::read::{GzDecoder, ZlibDecoder};
    use std::io::Read;

    let encoding = match content_encoding {
        Some(enc) => enc.trim().to_ascii_lowercase(),
        None => return body.clone(),
    };

    match encoding.as_str() {
        "gzip" | "x-gzip" => {
            let mut output = Vec::new();
            let mut decoder = GzDecoder::new(body.as_ref()).take(max_bytes as u64);
            if decoder.read_to_end(&mut output).is_ok() {
                Bytes::from(output)
            } else {
                body.clone()
            }
        }
        "deflate" => {
            let mut output = Vec::new();
            let mut decoder = ZlibDecoder::new(body.as_ref()).take(max_bytes as u64);
            if decoder.read_to_end(&mut output).is_ok() {
                Bytes::from(output)
            } else {
                body.clone()
            }
        }
        "br" => {
            let mut output = Vec::new();
            let mut decoder = brotli::Decompressor::new(body.as_ref(), 4096);
            let mut limited = (&mut decoder as &mut dyn std::io::Read).take(max_bytes as u64);
            if limited.read_to_end(&mut output).is_ok() {
                Bytes::from(output)
            } else {
                body.clone()
            }
        }
        "zstd" => {
            let mut output = Vec::new();
            match zstd::stream::Decoder::new(body.as_ref()) {
                Ok(decoder) => {
                    let mut limited = decoder.take(max_bytes as u64);
                    if limited.read_to_end(&mut output).is_ok() {
                        Bytes::from(output)
                    } else {
                        body.clone()
                    }
                }
                Err(_) => body.clone(),
            }
        }
        // identity and unknown encodings are passed through.
        _ => body.clone(),
    }
}

/// Materialise the request body into `Bytes`.
///
/// Without spill: bodies exceeding `max_body_to_scan` yield 413.
/// With spill: overflow past `max_body_to_buffer` goes to a temp file.
async fn materialize_body(body: Body, config: &RequestInspection) -> Result<Bytes, StatusCode> {
    let max_scan = parse_byte_size(&config.max_body_to_scan);
    if !config.spill_large_bodies_to_disk {
        to_bytes(body, max_scan)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)
    } else {
        buffer_with_spill(
            body,
            parse_byte_size(&config.max_body_to_buffer),
            &config.spill_directory,
        )
        .await
    }
}

/// Spill-to-disk body buffer.
///
/// Once the in-memory buffer crosses `max_buffer`, further chunks go
/// to a temp file.  After the last chunk the file is read back in full.
/// Peak memory equals the full body size, but that cost is inherent
/// when the body must be forwarded.
async fn buffer_with_spill(
    body: Body,
    max_buffer: usize,
    spill_dir: &str,
) -> Result<Bytes, StatusCode> {
    use http_body_util::BodyExt as _;
    use std::io::Write as _;

    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    let mut spill: Option<tempfile::NamedTempFile> = None;

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        let Ok(data) = frame.into_data() else { continue };

        if let Some(ref mut f) = spill {
            f.write_all(&data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        } else if buf.len().saturating_add(data.len()) > max_buffer {
            // Threshold crossed: open temp file and drain the in-memory buffer.
            let mut f = tempfile::Builder::new()
                .prefix("aegira-spill-")
                .tempfile_in(spill_dir)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            f.write_all(&buf).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            f.write_all(&data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            buf.clear();
            buf.shrink_to_fit();
            spill = Some(f);
        } else {
            buf.extend_from_slice(&data);
        }
    }

    if let Some(mut f) = spill {
        // Read back through the open fd, not the path, to close the
        // TOCTOU window (an attacker controlling spill_directory could
        // substitute a different file between write and read).
        use std::io::{Read as _, Seek as _, SeekFrom};
        let file = f.as_file_mut();
        file.seek(SeekFrom::Start(0)).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Bytes::from(bytes))
    } else {
        Ok(Bytes::from(buf))
    }
}

/// Decode and normalise a request body for rule evaluation.
///
/// The raw UTF-8 text is the primary surface.  When the content-type
/// indicates a structured format and the matching `decode_*` flag is set,
/// decoded key=value pairs are appended so rules match against both the
/// raw form and the decoded representation.  HTML-entity and NFKC
/// normalisation are applied to the combined string.
fn prepare_body_for_inspection(
    config: &RequestInspection,
    body_str: &str,
    body_bytes: &Bytes,
    content_type: &str,
) -> String {
    if body_str.is_empty() {
        return String::new();
    }

    let mut supplement = String::new();

    if config.decode_form_data
        && content_type.starts_with("application/x-www-form-urlencoded")
    {
        let decoded = decode_form_data_body(body_str);
        if !decoded.is_empty() {
            supplement.push('\n');
            supplement.push_str(&decoded);
        }
    }
    // Decode JSON regardless of Content-Type when the body looks like
    // JSON.  Attackers can send JSON payloads as text/plain or other
    // innocuous types to bypass the Content-Type gate.
    let looks_like_json = {
        let trimmed = body_str.trim_start();
        trimmed.starts_with('{') || trimmed.starts_with('[')
    };
    if config.decode_json
        && (content_type.contains("application/json")
            || content_type.contains("text/json")
            || looks_like_json)
    {
        let decoded = decode_json_body(body_str);
        if !decoded.is_empty() {
            supplement.push('\n');
            supplement.push_str(&decoded);
        }
    }
    if config.decode_multipart && content_type.starts_with("multipart/form-data") {
        let decoded = decode_multipart_body(body_bytes, content_type);
        if !decoded.is_empty() {
            supplement.push('\n');
            supplement.push_str(&decoded);
        }
    }

    let combined = if supplement.is_empty() {
        body_str.to_owned()
    } else {
        format!("{}{}", body_str, supplement)
    };

    normalize_inspection_str(&combined, config)
}

/// URL-decode form fields and return each decoded value on its own line.
///
/// Duplicate parameter names are concatenated with a space so that
/// split-payload attacks (HTTP Parameter Pollution) cannot hide a
/// malicious value across two identical keys.
fn decode_form_data_body(body: &str) -> String {
    use std::collections::BTreeMap;
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for pair in body.split('&') {
        let mut parts = pair.splitn(2, '=');
        let Some(key) = parts.next() else { continue };
        let raw_value = parts.next().unwrap_or("");
        let decoded = recursive_percent_decode(raw_value).replace('+', " ");
        if decoded.is_empty() {
            continue;
        }
        params
            .entry(key.to_string())
            .and_modify(|existing| {
                existing.push(' ');
                existing.push_str(&decoded);
            })
            .or_insert(decoded);
    }
    params.values().cloned().collect::<Vec<_>>().join("\n")
}

/// Flatten JSON to `key=value` lines.  Nested objects use dot notation;
/// arrays use `key[N]`.
fn decode_json_body(body: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return String::new();
    };
    let mut out = String::new();
    flatten_json_value("", &value, &mut out);
    out
}

fn flatten_json_value(prefix: &str, value: &serde_json::Value, out: &mut String) {
    use serde_json::Value as V;
    match value {
        V::Object(map) => {
            for (k, v) in map {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                flatten_json_value(&p, v, out);
            }
        }
        V::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                flatten_json_value(&format!("{}[{}]", prefix, i), v, out);
            }
        }
        V::Null => {}
        _ => {
            if !prefix.is_empty() {
                out.push_str(prefix);
                out.push('=');
            }
            let s = value.to_string();
            out.push_str(s.trim_matches('"'));
            out.push('\n');
        }
    }
}

/// Extract text-typed parts from a multipart body.  Binary parts are skipped.
fn decode_multipart_body(body: &Bytes, content_type: &str) -> String {
    let boundary = content_type
        .split(';')
        .map(str::trim)
        .find_map(|part| {
            let lower = part.to_ascii_lowercase();
            if lower.starts_with("boundary=") {
                Some(part["boundary=".len()..].trim_matches('"').to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    if boundary.is_empty() {
        return String::new();
    }

    let Ok(body_str) = std::str::from_utf8(body.as_ref()) else {
        return String::new();
    };

    let delimiter = format!("--{}", boundary);
    let mut output = String::new();

    for part in body_str.split(&delimiter) {
        let trimmed = part.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("--") {
            continue;
        }
        let body_start = part
            .find("\r\n\r\n")
            .map(|i| i + 4)
            .or_else(|| part.find("\n\n").map(|i| i + 2));
        if let Some(start) = body_start {
            let headers_section = &part[..start];
            let is_text = !headers_section
                .to_ascii_lowercase()
                .contains("content-type:")
                || headers_section
                    .to_ascii_lowercase()
                    .contains("text/");
            if is_text {
                let part_body = part[start..].trim_end_matches("--").trim();
                if !part_body.is_empty() {
                    output.push_str(part_body);
                    output.push('\n');
                }
            }
        }
    }
    output
}

/// Percent-decode in a loop until the output stabilises.
///
/// A single `percent_decode_str` call only peels one layer.  Attackers
/// use double- or triple-encoding (`%252e` -> `%2e` -> `.`) to smuggle
/// payloads.  Three iterations cover realistic nesting depths without
/// burning CPU on deliberately crafted chains.
fn recursive_percent_decode(input: &str) -> String {
    let mut current = input.to_string();
    for _ in 0..3 {
        let decoded = percent_encoding::percent_decode_str(&current)
            .decode_utf8_lossy()
            .into_owned();
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

/// Collapse `.` and `..` segments so `/foo/../bar` becomes `/bar`.
///
/// Path traversal sequences that survive percent-decoding can mislead
/// rules that match on literal path prefixes.  Collapsing them reveals
/// the canonical resource being targeted.
fn collapse_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "." | "" => {}
            ".." => { segments.pop(); }
            other => segments.push(other),
        }
    }
    let mut result = String::from("/");
    result.push_str(&segments.join("/"));
    if path.ends_with('/') && !result.ends_with('/') {
        result.push('/');
    }
    result
}

/// Remove null bytes that could truncate C-backed comparisons.
fn strip_null_bytes(s: &str) -> String {
    if s.contains('\0') {
        s.replace('\0', "")
    } else {
        s.to_string()
    }
}

/// Characters that carry no visible width and serve only to disrupt
/// pattern matching when inserted between keyword characters.
const INVISIBLE_CHARS: &[char] = &[
    '\u{200B}', // zero-width space
    '\u{200C}', // zero-width non-joiner
    '\u{200D}', // zero-width joiner
    '\u{FEFF}', // byte-order mark / zero-width no-break space
    '\u{00AD}', // soft hyphen
    '\u{200E}', // left-to-right mark
    '\u{200F}', // right-to-left mark
    '\u{2060}', // word joiner
    '\u{2061}', // function application (invisible)
    '\u{2062}', // invisible times
    '\u{2063}', // invisible separator
    '\u{2064}', // invisible plus
    '\u{180E}', // Mongolian vowel separator
];

/// Apply HTML-entity decoding, invisible-character stripping, and
/// NFKC normalisation per config flags.
fn normalize_inspection_str(s: &str, config: &RequestInspection) -> String {
    let s = if config.normalize_html_entities {
        std::borrow::Cow::Owned(decode_html_entities(s))
    } else {
        std::borrow::Cow::Borrowed(s)
    };
    // Strip zero-width / invisible characters that break keyword matching.
    let s: std::borrow::Cow<'_, str> = if s.chars().any(|c| INVISIBLE_CHARS.contains(&c)) {
        std::borrow::Cow::Owned(s.chars().filter(|c| !INVISIBLE_CHARS.contains(c)).collect())
    } else {
        s
    };
    if config.normalize_unicode {
        use unicode_normalization::UnicodeNormalization;
        s.nfkc().collect()
    } else {
        s.into_owned()
    }
}

/// Decode common HTML character references.
///
/// Named entities: `&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;`, `&nbsp;`.
/// Numeric forms: `&#60;`, `&#x3C;`.  Unknown names pass through unchanged.
fn decode_html_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '&' {
            result.push(c);
            continue;
        }
        // Collect an entity name up to the closing ';'.
        let mut entity = String::new();
        let mut closed = false;
        for ec in chars.by_ref() {
            if ec == ';' {
                closed = true;
                break;
            }
            if entity.len() >= 10 {
                break;
            }
            entity.push(ec);
        }
        if !closed {
            result.push('&');
            result.push_str(&entity);
            continue;
        }
        let replacement = match entity.as_str() {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{00A0}'),
            e if e.starts_with('#') => {
                let rest = &e[1..];
                let (num_str, radix) = if rest.starts_with('x') || rest.starts_with('X') {
                    (&rest[1..], 16u32)
                } else {
                    (rest, 10u32)
                };
                u32::from_str_radix(num_str, radix)
                    .ok()
                    .and_then(char::from_u32)
            }
            _ => None,
        };
        match replacement {
            Some(rc) => result.push(rc),
            None => {
                result.push('&');
                result.push_str(&entity);
                result.push(';');
            }
        }
    }
    result
}

fn maybe_inspected_body(
    config: &Config,
    is_grpc: bool,
    is_websocket: bool,
    raw_body: &Bytes,
) -> String {
    if is_grpc && config.protocol_support.grpc_inspection == GrpcInspection::HeadersOnly {
        return String::new();
    }
    if is_websocket
        && config.protocol_support.websocket_inspection == WebsocketInspection::HandshakeOnly
    {
        return String::new();
    }
    String::from_utf8_lossy(raw_body).to_string()
}

/// Resolve the effective client IP.
///
/// When `trust_forwarded_headers` is on and the direct peer falls in the
/// trusted CIDR set (or the set is empty), the leftmost X-Forwarded-For
/// address is used.  Otherwise the TCP peer IP is returned as-is.
fn real_client_ip(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    fwd: &ForwardedHeaders,
) -> IpAddr {
    if !fwd.trust_forwarded_headers {
        return peer_ip;
    }
    // Fail-closed: an empty trust list means trust nobody, not everybody.
    let peer_is_trusted = !fwd.trust_forwarded_headers_from.is_empty()
        && fwd.trust_forwarded_headers_from.iter().any(|net| net.contains(&peer_ip));
    if !peer_is_trusted {
        return peer_ip;
    }

    // RFC 7239: prefer the Forwarded header when configured.
    // The first comma-delimited directive is the client's; its `for`
    // parameter holds the address (IPv6 in brackets, optional port).
    if fwd.parse_forwarded_header {
        if let Some(ip) = parse_forwarded_header_for_client(headers) {
            return ip;
        }
    }

    // De-facto X-Forwarded-For: leftmost entry is the client.
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or(peer_ip)
}

/// Extract the client IP from the RFC 7239 `Forwarded` header.
///
/// Returns the address from the `for` parameter of the first directive.
/// Returns `None` when the header is absent, malformed, or carries an
/// obfuscated identifier (`_token`) instead of an address.
fn parse_forwarded_header_for_client(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("forwarded")?.to_str().ok()?;
    // Only the first comma-separated directive describes the client.
    let first_directive = value.split(',').next()?;
    for part in first_directive.split(';') {
        let part = part.trim();
        if !part.to_ascii_lowercase().starts_with("for=") {
            continue;
        }
        let addr_raw = part[4..].trim().trim_matches('"');
        // IPv6 is wrapped in brackets: "[2001:db8::1]" or "[::1]:port"
        let addr_str = if addr_raw.starts_with('[') {
            addr_raw.trim_start_matches('[').split(']').next()?
        } else {
            // IPv4 optionally followed by ":port"
            addr_raw.split(':').next()?
        };
        return addr_str.trim().parse::<IpAddr>().ok();
    }
    None
}

/// Append X-Forwarded-* headers to outbound requests per config.
///
/// Runs after IP filtering and rate limiting, so `client_ip` is the
/// resolved real address.
fn add_forwarded_headers(headers: &mut HeaderMap, client_ip: IpAddr, config: &Config) {
    if config.forwarded_headers.set_x_forwarded_for {
        let existing = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let value = if existing.is_empty() {
            client_ip.to_string()
        } else {
            format!("{existing}, {client_ip}")
        };
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert("x-forwarded-for", v);
        }
    }
    let scheme = if config.tls.enabled { "https" } else { "http" };
    if config.forwarded_headers.set_x_forwarded_proto {
        if let Ok(v) = HeaderValue::from_str(scheme) {
            headers.insert("x-forwarded-proto", v);
        }
    }
    if config.forwarded_headers.set_x_forwarded_host {
        if let Some(host) = headers.get(HOST).cloned() {
            headers.insert("x-forwarded-host", host);
        }
    }
}

fn should_retry_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
}

fn parse_backend_duration(
    value: Option<&str>,
    backend: &Backend,
    field_name: &str,
) -> Result<Option<Duration>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let parsed = humantime::parse_duration(raw).with_context(|| {
        format!(
            "invalid {} value '{}' for backend {}",
            field_name, raw, backend.name
        )
    })?;
    Ok(Some(parsed))
}

fn backend_effective_connect_timeout(backend: &Backend) -> Result<Option<Duration>> {
    let connect_timeout = parse_backend_duration(
        backend.connect_timeout.as_deref(),
        backend,
        "connect_timeout",
    )?;
    let tls_handshake_timeout = parse_backend_duration(
        backend.tls_handshake_timeout.as_deref(),
        backend,
        "tls_handshake_timeout",
    )?;

    let effective = match (connect_timeout, tls_handshake_timeout) {
        (Some(connect), Some(tls)) => Some(connect.min(tls)),
        (Some(connect), None) => Some(connect),
        (None, Some(tls)) => Some(tls),
        (None, None) => None,
    };

    Ok(effective)
}

/// Build one `reqwest::Client` per HTTP/TLS backend at config load time.
///
/// Clients are stored in `ReloadableState` and reused for the lifetime
/// of that config snapshot.  This avoids the per-request construction
/// overhead (~1.8 µs) and enables TCP connection pooling (keep-alive).
fn build_backend_clients(config: &Config) -> Result<HashMap<String, Client>> {
    let mut clients = HashMap::new();
    for backend in &config.backends {
        if matches!(backend.forward_using, BackendTransport::UnixSocket) {
            continue;
        }
        if !backend.reuse_connections.unwrap_or(true) {
            continue;
        }
        let connect_timeout = backend_effective_connect_timeout(backend)?;
        let client = build_backend_http_client(connect_timeout, backend.backend_protocol)?;
        clients.insert(backend.name.clone(), client);
    }
    Ok(clients)
}

fn build_backend_http_client(
    connect_timeout: Option<Duration>,
    backend_protocol: BackendProtocol,
) -> Result<Client> {
    let mut builder = Client::builder()
        .use_rustls_tls()
        .http2_adaptive_window(true);

    if matches!(backend_protocol, BackendProtocol::Http3) {
        return Err(anyhow!(
            "backend_protocol=http3 is evaluated as optional v2 but unavailable in stable build (reqwest http3 is unstable)"
        ));
    }

    if let Some(timeout) = connect_timeout {
        builder = builder.connect_timeout(timeout);
    }
    builder.build().context("build backend HTTP client")
}

fn strip_port(host: &str) -> &str {
    // IPv6 literal: "[::1]" or "[::1]:443" — return up to and including ']'
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        };
    }
    // Hostname or IPv4: strip trailing ":port" only when digits follow the colon
    if let Some(pos) = host.rfind(':') {
        if host[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
            return &host[..pos];
        }
    }
    host
}

/// Parse a human-readable byte size string (e.g. "8MiB", "64KiB", "1024") into
/// a `usize` byte count.  Unrecognised units fall back to plain bytes.  Returns
/// a hard minimum of 1 byte so callers never pass 0 to `to_bytes`.
fn parse_byte_size(s: &str) -> usize {
    let s = s.trim();
    let split_pos = s.find(|c: char| c.is_alphabetic()).unwrap_or(s.len());
    let num: usize = s[..split_pos].trim().parse().unwrap_or(0);
    let unit = s[split_pos..].trim().to_ascii_uppercase();
    let multiplier: usize = match unit.as_str() {
        "" | "B" => 1,
        "KB" | "KIB" => 1_024,
        "MB" | "MIB" => 1_048_576,
        "GB" | "GIB" => 1_073_741_824,
        _ => 1,
    };
    num.saturating_mul(multiplier).max(1)
}

fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(message.to_string()));
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_port_plain_hostname() {
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("example.com:8080"), "example.com");
    }

    #[test]
    fn strip_port_ipv4() {
        assert_eq!(strip_port("127.0.0.1"), "127.0.0.1");
        assert_eq!(strip_port("127.0.0.1:80"), "127.0.0.1");
    }

    #[test]
    fn strip_port_ipv6() {
        assert_eq!(strip_port("[::1]"), "[::1]");
        assert_eq!(strip_port("[::1]:443"), "[::1]");
        assert_eq!(strip_port("[2001:db8::1]:8080"), "[2001:db8::1]");
    }

    #[test]
    fn parse_byte_size_units() {
        assert_eq!(parse_byte_size("1024"), 1024);
        assert_eq!(parse_byte_size("1KiB"), 1024);
        assert_eq!(parse_byte_size("1KB"), 1024);
        assert_eq!(parse_byte_size("1MiB"), 1_048_576);
        assert_eq!(parse_byte_size("8MiB"), 8 * 1_048_576);
        assert_eq!(parse_byte_size("512KiB"), 512 * 1024);
        assert_eq!(parse_byte_size("64KiB"), 64 * 1024);
        assert_eq!(parse_byte_size("1GiB"), 1_073_741_824);
    }

    #[test]
    fn parse_byte_size_zero_floors_to_one() {
        assert_eq!(parse_byte_size("0"), 1);
        assert_eq!(parse_byte_size(""), 1);
    }

    // -- bypass-specific tests --

    #[test]
    fn recursive_percent_decode_double_encoded() {
        // %252e -> %2e -> .
        assert_eq!(recursive_percent_decode("%252e%252e"), "..");
        // Triple-encoded: %25252e -> %252e -> %2e -> .
        assert_eq!(recursive_percent_decode("%25252e"), ".");
    }

    #[test]
    fn recursive_percent_decode_plain_ascii_unchanged() {
        assert_eq!(recursive_percent_decode("hello"), "hello");
    }

    #[test]
    fn collapse_path_traversal() {
        assert_eq!(collapse_path("/foo/../bar"), "/bar");
        assert_eq!(collapse_path("/foo/../../etc/passwd"), "/etc/passwd");
        assert_eq!(collapse_path("/a/b/c/../d"), "/a/b/d");
        assert_eq!(collapse_path("/a/./b"), "/a/b");
    }

    #[test]
    fn collapse_path_preserves_trailing_slash() {
        assert_eq!(collapse_path("/a/b/"), "/a/b/");
    }

    #[test]
    fn strip_null_bytes_removes_nulls() {
        assert_eq!(strip_null_bytes("hel\0lo"), "hello");
        assert_eq!(strip_null_bytes("clean"), "clean");
    }

    #[test]
    fn decode_form_data_hpp_concatenation() {
        // Duplicate "q" keys should be merged with a space so split
        // payloads like q=UNION&q=SELECT are visible as one value.
        let result = decode_form_data_body("q=UNION&q=SELECT&other=1");
        assert!(result.contains("UNION SELECT"), "got: {result}");
    }

    #[test]
    fn decode_form_data_recursive_decode() {
        // Double-encoded value should be fully decoded.
        let result = decode_form_data_body("x=%252e%252e");
        assert!(result.contains(".."), "got: {result}");
    }

    #[test]
    fn normalize_strips_zero_width_characters() {
        // A ZWSP between "SEL" and "ECT" must be removed so regex can match.
        let config = RequestInspection {
            inspect_headers: true,
            inspect_query_string: true,
            inspect_body: true,
            body_mode: crate::config::BodyMode::Both,
            max_body_to_buffer: "1MiB".into(),
            max_body_to_scan: "1MiB".into(),
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
        };

        let input = "SEL\u{200B}ECT";
        let result = normalize_inspection_str(input, &config);
        assert_eq!(result, "SELECT");

        // BOM at start should be stripped.
        let input_bom = "\u{FEFF}UNION SELECT";
        let result_bom = normalize_inspection_str(input_bom, &config);
        assert_eq!(result_bom, "UNION SELECT");

        // Soft hyphen should be stripped.
        let input_shy = "UNI\u{00AD}ON";
        let result_shy = normalize_inspection_str(input_shy, &config);
        assert_eq!(result_shy, "UNION");
    }

    #[test]
    fn collapse_path_normalizes_backslash() {
        // Backslashes are normalised to forward slashes before the
        // path is collapsed, handled at the call site in handle_request.
        // Test the raw collapse_path with pre-normalised input.
        let normalised = "/foo\\..\\..\\etc\\passwd".replace('\\', "/");
        assert_eq!(collapse_path(&normalised), "/etc/passwd");
    }
}
