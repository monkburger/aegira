# Aegira

Aegira is a WAF (Web Application Firewall) with an integrated TLS-terminating reverse proxy. It sits in front of web applications and inspects every request against a set of regex-based rules before a single byte is forwarded to any backend. Traffic is allowed through, blocked with a 403, or silently rerouted to a secondary backend (e.g. a honeypot or logging sink) depending on what the rules say. Configuration is plain TOML and hot-reloads on `SIGHUP` without dropping connections.

Aegira is not an API gateway. It does not handle authentication, issue tokens, manage API keys, split traffic by weight, or speak to identity providers. It inspects requests and enforces policy. The proxy is the transport layer; the WAF is the product.

**AEGIRA IS IN BETA** 


## Purpose

Most WAF deployments bolt filtering onto an existing proxy as a plugin or Lua script. Aegira is built the other way: the WAF decision is the first-class operation and the proxy is the transport layer. Every request goes through `Engine::evaluate` before a single byte is forwarded. Rules are structured data, not stringly-typed config; scoring, action, and target backend are all typed at load time.

The rule model is intentionally flat. A bundle is a collection of rules, each with an ID, a regex, and an action. Includes let you split rules across files and directories, but the evaluation model never changes: scan the request fields in order, accumulate scores, and apply the first decisive action. No pipelines, no conditional chains, no plugin hooks.

## Design Philosophy

Aegira follows three constraints that determine what it does and, more importantly, what it refuses to do.

**Inspect first, forward second.** Every request passes through the WAF engine before a single byte reaches any backend. The proxy exists to carry bytes; the engine exists to decide whether those bytes should move. This is the opposite of the plugin model, where filtering is an afterthought bolted onto a proxy that was designed to forward first and ask questions later.

**Deny by default at the type level.** Configuration errors are caught at parse time, not at request time. Every policy field is a Rust enum deserialized by serde; an unrecognised value is a hard error before the process binds a port. The same principle applies to rule actions: a rule with an invalid score, a duplicate ID, or an unrecognised action is rejected at load. There is no runtime string comparison that silently falls through to a default case.

**No scope creep.** Aegira is not an API gateway. It does not authenticate users, issue tokens, manage API keys, weight-split traffic, or talk to identity providers. Features that belong in an application layer (session management, business-rule routing, A/B testing) will never be added. The WAF inspects; the proxy transports. Each additional responsibility would dilute the security posture by increasing the attack surface of the process that terminates TLS and handles untrusted input.

## Architecture

**Async runtime.** tokio multi-thread scheduler, epoll on Linux. Each accepted connection gets a task; there is no shared per-connection mutable state in the hot path. In-flight request counts are tracked with an `AtomicUsize` for graceful drain during reload.

**Hot reload.** Config, rules, and TLS certificates are wrapped in `Arc<ArcSwap<ReloadableState>>`. On `SIGHUP`, the new state is built on a background task, validated, and swapped atomically. In-flight requests finish against the old state. If validation fails, the old state is kept and a warning is logged.

**Type-driven config.** All policy fields are typed Rust enums (`SniPolicy`, `BackendTransport`, `BackendProtocol`, `FailPolicy`, etc.) and deserialized by serde. Invalid values are rejected at parse time, before any runtime code runs. There are no `.eq_ignore_ascii_case("reject")` comparisons scattered through the codebase.

**Error handling.** Library code (`rules.rs`, `config.rs`, `engine.rs`, `tls.rs`) returns typed errors via `thiserror`. The binary entry point and daemon layer use `anyhow` and the `?` operator converts via `From`. Callers never need to inspect error strings to distinguish cases.

**Regex engine.** The Rust `regex` crate compiles to a DFA. Match time is linear in input length; there is no catastrophic backtracking. Patterns are compiled once at rule load time and reused across requests via `Arc<Regex>`. Per-request cost is O(n x r) where n is the total bytes inspected and r is the number of rules.

**Transport.** Frontend: axum 0.8 router over a manual `tokio::net::TcpListener` + `tokio-rustls` TLS accept loop for HTTP/1.1 and HTTP/2; quinn 0.11 + h3 for HTTP/3. The manual accept loop enables PROXY protocol v1/v2 header reading before TLS negotiation, and atomic certificate hot-swaps via `ArcSwap<rustls::ServerConfig>`. Backend: reqwest (hyper core) for TCP-based backends; a hand-rolled hyper client over tokio `UnixStream` for Unix domain socket backends. TLS is AWS-LC backed; no OpenSSL dependency.

## Request processing pipeline

The full request lifecycle, from TCP accept through response delivery, is
documented in [PIPELINE.md](PIPELINE.md).  That document covers:

- Theoretical foundations: why the architecture is split into a Type 2
  (context-free) positive security model and a Type 3 (regular) negative
  security model, grounded in the Chomsky Hierarchy
- The complete 31-stage pipeline with function names, files, and line numbers
- How normalization contracts encoded payloads toward a canonical form before
  inspection (Shannon entropy analysis)
- The falsifiability-driven test philosophy and the specific bypass hypotheses
  each test attempts to refute
- Configuration design rationale via Relevance Theory

## Benchmarks

No formal benchmarks yet. Contributions welcome. The relevant numbers to measure are: requests/second at wire line against a noop backend, latency overhead per rule added to a bundle, and peak memory under connection storms.

## Usage

```sh
# Build release binary
cargo build --release

# Start with a config file
./target/release/aegira --config configs/aegira.toml

# Validate config and rules without starting
./target/release/aegira --check-config --config configs/aegira.toml

# Hot-reload running instance
kill -HUP $(pidof aegira)
```

## Features

**Protocol support**
- HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) on the frontend
- HTTP/1.1 and HTTP/2 to backends over plain TCP, TLS, or Unix domain socket
- TLS 1.2 and TLS 1.3 via rustls + AWS-LC, with per-site certificate selection via SNI
- ALPN negotiation for all supported protocol versions

**WAF engine**
- Inspect request path, query string, headers, cookies, and body using Rust `regex` patterns
- Inspect response headers and body against rules after the backend responds
- Three rule actions: `log` (pass through and record), `drop` (block with 403), and `forward` (reroute to a secondary backend)
- Rules are global; individual rule IDs can be disabled per site or globally in config without editing rule files
- Rule bundles are built from a tree of TOML files using path, directory, and glob includes
- Anomaly scoring: each rule can carry a numeric score added to a per-request total; threshold configurable globally or overridden per site
- Body decoding before inspection: `application/x-www-form-urlencoded`, `application/json` (flattened to `key=value` pairs), and `multipart/form-data` part extraction
- Normalisation: HTML entity decoding (`&lt;`, `&#xNN;`, `&#x3c;`) and NFKC Unicode normalisation before rule matching
- Per-site observe mode: `mode = "observe"` downgrades all blocking actions to `log` for safe shadow-testing of new rules against live traffic
- Request ID end-to-end tracing: UUID v4 generated per request (or carried from a trusted upstream header), forwarded to the backend, and present in every audit log event
- Inline rule tests: `[[rule.test]]` blocks in TOML, verified by `--check-config` without starting the daemon

**Schema enforcement (positive security model)**
- Point aegira at an OpenAPI 3.x spec and every endpoint is registered automatically: body schemas for request validation, plus the full method + path inventory for endpoint gating
- Bodies that violate the declared schema are rejected with HTTP 400; no regex rule is needed
- `reject_unknown_endpoints`: requests to method + path combinations not in the spec are blocked before the regex engine runs
- Path parameter wildcards (e.g. `/users/{id}`) and `$ref` resolution across components
- Endpoints without a `requestBody` (GET, DELETE, etc.) are still registered for endpoint gating
- Schema-protected endpoints get body validation; non-schema endpoints still get the full regex/normalization pipeline
- Configurable body size limit and JSON nesting depth cap to block oversized or pathologically nested input
- POSIX file permission check on the spec file to prevent local privilege escalation via spec tampering
- Opt-in per deployment; disabled by default

**Operational**
- Hot-reload of config, rules, and TLS certificates on `SIGHUP` without dropping in-flight connections
- QUIC endpoint certificate rotation wired to the same reload path
- `GET /health` endpoint returns JSON status and in-flight request count
- `GET /metrics` endpoint returns Prometheus text format counters and gauges
- Structured logging in JSON or human-readable text format, with configurable field redaction (cookies, Authorization, Set-Cookie)

**Request handling**
- Hop-by-hop header stripping in both directions on all transports
- WebSocket upgrade detection with configurable WAF gating (handshake inspection or reject)
- gRPC detection with configurable WAF gating (headers-only inspection or reject)
- Retry on backend errors for idempotent HTTP methods
- 413 on bodies exceeding the configured scan limit, 421 on TLS SNI / Host header mismatch

## RFC support

The table below lists the specifications that aegira implements directly. Library-level support (e.g. TLS record framing handled entirely inside rustls) is included where it materially affects what aegira can accept or send.

| RFC | Title | Status |
|-----|-------|--------|
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | Partial. Idempotent method classification, `421 Misdirected Request`, `413 Content Too Large`, `502`/`503` gateway status codes. §8.4 `Content-Encoding` decompression (gzip/deflate) for WAF inspection with decompression-bomb protection. §10.1.1 `Expect: 100-continue` early inspection: requests blocked on headers/cookies before the body is ever received. No redirect generation, no caching, no content negotiation. |
| [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265) | HTTP State Management Mechanism (Cookies) | Implemented. `Cookie:` header parsed into individual name=value pairs as a first-class WAF inspection target (`when: ["cookies"]`). Handles semicolon-separated pairs, trims whitespace, and supports `=` in cookie values via `splitn(2, '=')`. |
| [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) | HTTP/1.1 | Full. Frontend via axum/hyper, backend via reqwest/hyper. Hop-by-hop header stripping per §9.6. |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) | HTTP/2 | Full. Frontend and backend. Adaptive flow control window enabled on backend connections. |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 | Frontend only. Backend HTTP/3 not available. |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC Transport | Frontend only, via quinn. Graceful shutdown with CONNECTION_CLOSE on `SIGHUP`. |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS with QUIC | Frontend only. Mandates TLS 1.3; aegira enforces this at config validation. |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | TLS 1.3 | Implemented via rustls 0.23 + AWS-LC. Session ticket key rotation (§4.6.3) via `RotatingTicketEncrypter` with AES-256-GCM, configurable interval, and one-rotation grace window. |
| [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) | TLS 1.2 | Implemented via rustls 0.23 + AWS-LC. |
| [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) | TLS ALPN Extension | Implemented. `h2`, `http/1.1`, and `h3` tokens advertised per configuration. |
| [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) | OCSP Stapling | **Deprecated and not implemented.** Let's Encrypt shut down their OCSP responder; Chrome and other major browsers removed OCSP checking. Short-lived certificates are the current revocation mechanism. |
| [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) | HTTP Strict Transport Security (HSTS) | Implemented. Inject `Strict-Transport-Security` on all TLS responses. Configurable `max-age`, `includeSubDomains`, and `preload` flags per deployment. |
| [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239) | Forwarded HTTP Extension | Implemented. When `parse_forwarded_header = true` the RFC 7239 `Forwarded:` header is preferred over `X-Forwarded-For` for real-client-IP extraction (IPv4, IPv6 in brackets, optional port). |
| HAProxy PROXY protocol | PROXY Protocol v1/v2 | Implemented in `proxy_protocol.rs`. When `proxy_protocol = true`, the PROXY header is read from the raw TCP stream before TLS negotiation, restoring the correct client IP for all IP-based security features. |
| [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) | TLS Extensions (SNI) | Implemented. Per-site certificate dispatch from ClientHello SNI. Configurable policy for missing or unrecognised SNI. |
| [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) | PEM Format | Certificate and private key files loaded via rustls-pemfile. |
| [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) | QPACK Header Compression | Handled internally by the h3 crate. |
| [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) | HPACK Header Compression | Handled internally by hyper. |
| [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) | WebSocket | Detection and WAF gating only. Actual WebSocket frame proxying is not implemented. |

## Building

You need a recent stable Rust toolchain. No special system dependencies beyond a C linker and the AWS-LC library (pulled in automatically by `aws-lc-sys`).

```sh
# Debug build
make build

# Optimised release binary, written to target/release/aegira
make release

# Run the test suite
make test

# Validate a config file without starting the daemon
make check-config CONFIG=/etc/aegira/aegira.toml
```

The `make release` build bakes the current git tag, commit hash, and UTC timestamp into the binary. `aegira --version` will print all three.

## Installation

There is no installer yet. Copy the release binary somewhere on your `$PATH`, create a config directory, and drop your certificate files in place:

```sh
cp target/release/aegira /usr/local/bin/
mkdir -p /etc/aegira/certs /etc/aegira/rules
cp configs/aegira.toml /etc/aegira/
cp configs/rules/main.toml /etc/aegira/rules/
```

A minimal systemd unit:

```ini
[Unit]
Description=Aegira WAF proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/aegira --config /etc/aegira/aegira.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

## Running

```sh
# Start (default config path is configs/aegira.toml)
aegira

# Specify a config file
aegira --config /etc/aegira/aegira.toml

# Check config and rules without starting (useful in CI or pre-deploy hooks)
aegira --check-config --config /etc/aegira/aegira.toml

# Print version, commit, and build date
aegira --version
```

To hot-reload config and rules without restarting:

```sh
kill -HUP $(pidof aegira)
```

Aegira will drain in-flight requests before swapping state. If the new config fails validation, it keeps running with the old one and logs a warning.

---

## Configuration reference

The main config file is TOML. All sections are required unless noted. Durations use human-readable strings (`"30s"`, `"5m"`, `"1h"`). Byte sizes use `"64KiB"`, `"8MiB"`, `"1GiB"`, etc.

### `config_version`

```toml
config_version = 1
```

Must be `1`. This exists so future breaking changes can be detected cleanly.

---

### `[server]`

```toml
[server]
graceful_shutdown_timeout = "30s"
graceful_reload_timeout   = "5m"
reload_signal             = "SIGHUP"
```

| Key | Description |
|-----|-------------|
| `graceful_shutdown_timeout` | How long to wait for in-flight requests to finish after Ctrl-C before forcing shutdown. |
| `graceful_reload_timeout` | Maximum time to wait for in-flight requests to drain before a hot-reload completes. If the timeout is reached, the state is swapped anyway and a warning is logged. |
| `reload_signal` | Signal that triggers a hot-reload. Only `SIGHUP` is supported. |

---

### `[listener]`

```toml
[listener]
bind          = ":443"
serve_http1   = true
serve_http2   = true
serve_http3   = true
max_header_size = "64KiB"
read_timeout  = "15s"
write_timeout = "30s"
idle_timeout  = "90s"
```

| Key | Description |
|-----|-------------|
| `bind` | Address to listen on. `:443` binds all interfaces on port 443. Use `127.0.0.1:8443` to bind a specific interface. |
| `serve_http1` | Accept HTTP/1.1 connections. |
| `serve_http2` | Accept HTTP/2 connections (requires TLS). |
| `serve_http3` | Accept HTTP/3 (QUIC) connections (requires TLS). |
| `max_header_size` | Maximum total size of request headers. Requests exceeding this are rejected. |
| `read_timeout` | Timeout for reading the full request. |
| `write_timeout` | Timeout for writing the full response. |
| `idle_timeout` | How long a keep-alive connection can sit idle before being closed. |

---

### `[tls]`

```toml
[tls]
enabled                    = true
default_certificate        = "/etc/aegira/certs/default/fullchain.pem"
default_private_key        = "/etc/aegira/certs/default/privkey.pem"
minimum_version            = "1.2"
unknown_sni                = "reject"
missing_sni                = "use_default_site"
authority_mismatch         = "reject"
reload_certificates_on_sighup = true
```

| Key | Description |
|-----|-------------|
| `enabled` | Set to `false` for plain HTTP (useful behind another TLS terminator or in development). |
| `default_certificate` / `default_private_key` | PEM files used when no site-specific cert matches, or as a fallback. |
| `minimum_version` | Minimum TLS version: `"1.2"` or `"1.3"`. |
| `unknown_sni` | What to do when the SNI name doesn't match any configured site. `"reject"` closes the connection; `"use_default_site"` falls back to the first site. |
| `missing_sni` | What to do when the client sends no SNI at all. Same options as `unknown_sni`. |
| `authority_mismatch` | What to do when the HTTP `Host` header doesn't match the TLS SNI. `"reject"` returns 421; `"log"` warns and continues. |
| `reload_certificates_on_sighup` | Re-read cert files from disk on SIGHUP alongside config reload. |
| `hsts_enabled` | Inject `Strict-Transport-Security` on all TLS responses. Default: `false`. |
| `hsts_max_age_seconds` | Value for the `max-age` directive. Default: `63072000` (two years). |
| `hsts_include_subdomains` | Add the `includeSubDomains` directive. Default: `true`. |
| `hsts_preload` | Add the `preload` directive. Default: `false`. |
| `ticket_rotation_seconds` | Interval for TLS session ticket key rotation (AES-256-GCM). `0` disables rotation. Default: `0`. |

---

### `[[site]]`

Each `[[site]]` block defines a virtual host. You need at least one.

```toml
[[site]]
server_name              = "example.com"
certificate              = "/etc/aegira/certs/example.com/fullchain.pem"
private_key              = "/etc/aegira/certs/example.com/privkey.pem"
forward_to               = "app_main"
forward_target           = "honeypot"
preserve_host_header     = true
send_sni_to_backend      = true
disabled_rules           = []
mode                     = "normal"
# anomaly_score_threshold = 50
```

| Key | Description |
|-----|-------------|
| `server_name` | The hostname this site handles. Must match what clients send in SNI / Host header. |
| `certificate` / `private_key` | PEM cert chain and key for this site. Leave empty to use the TLS defaults. |
| `forward_to` | Name of the backend that normal (non-blocked) traffic goes to. |
| `forward_target` | Optional. Name of the backend to send traffic matching a `forward` rule action. Overrides `waf.default_forward_target` for this site. |
| `preserve_host_header` | Pass the original `Host` header to the backend rather than rewriting it to the backend address. Almost always `true`. |
| `send_sni_to_backend` | Send the original SNI name in the TLS handshake to the backend (relevant for `forward_using = "tls"` backends). |
| `disabled_rules` | List of rule IDs to skip for this site only. `[1001, 1002]`. See the [Disabling rules](#disabling-rules) section. |
| `mode` | `"normal"` (default) or `"observe"`. In observe mode, all `drop` and `forward` actions are downgraded to `log`. Use this to shadow-test new rules against live traffic before enforcing them. |
| `anomaly_score_threshold` | Integer. If set, overrides `waf.anomaly_score_threshold` for this site only. Requests whose accumulated rule scores meet or exceed this value are blocked. |

---

### `[waf]`

```toml
[waf]
default_action           = "allow"
default_forward_target   = "honeypot"
on_engine_error          = "fail_open"
on_rule_reload_error     = "keep_running_with_old_rules"
request_id_header        = "X-Request-ID"
warn_on_ignored_matches  = true
max_matches_per_request  = 32
anomaly_score_threshold  = 50
disabled_rules           = []
```

| Key | Description |
|-----|-------------|
| `default_action` | What to do when no rule matches. Only `"allow"` is meaningful here (log-and-pass). |
| `default_forward_target` | The backend name that `forward` rule actions reroute traffic to, unless a site overrides it with `forward_target`. |
| `on_engine_error` | What to do if the rule engine throws an unexpected error. `"fail_open"` passes the request through; `"fail_closed"` blocks it. |
| `on_rule_reload_error` | What to do if a hot-reload produces invalid config. `"keep_running_with_old_rules"` is the only safe option. |
| `request_id_header` | Header name for request correlation IDs. If the header is present on the incoming request, its value is reused; otherwise a UUID v4 is generated. The ID is forwarded to the backend on the same header and included in all audit log events. |
| `anomaly_score_threshold` | Global default anomaly score threshold. When a request's accumulated rule scores reach this value it is blocked. Can be overridden per site with `site.anomaly_score_threshold`. |
| `warn_on_ignored_matches` | Log a warning if a rule matched but its action was superseded by a higher-priority action. |
| `max_matches_per_request` | Stop evaluating rules after this many matches. Prevents runaway scoring on heavily-malformed requests. |
| `disabled_rules` | Rule IDs to disable globally across all sites. |

---

### `[protocol_support]`

```toml
[protocol_support]
grpc_inspection     = "headers_only"
websocket_inspection = "handshake_only"
```

| Key | Options | Description |
|-----|---------|-------------|
| `grpc_inspection` | `"headers_only"`, `"off"` | `"headers_only"` inspects request headers only and skips the body (gRPC bodies are binary-framed and not useful to a regex engine). `"off"` rejects all gRPC traffic with 501. |
| `websocket_inspection` | `"handshake_only"`, `"off"` | `"handshake_only"` inspects the HTTP upgrade request then passes the connection through. `"off"` rejects WebSocket upgrades with 501. |

---

### `[request_inspection]`

Controls what parts of each request are fed to the rule engine.

```toml
[request_inspection]
inspect_headers            = true
inspect_query_string       = true
inspect_body               = true
body_mode                  = "both"
max_body_to_buffer         = "1MiB"
max_body_to_scan           = "8MiB"
spill_large_bodies_to_disk = true
spill_directory            = "/var/lib/aegira/spool"
decode_form_data           = true
decode_json                = true
decode_multipart           = true
normalize_url_encoding     = true
normalize_html_entities    = true
normalize_unicode          = true
decompress_body            = true
inspect_cookies            = true
```

| Key | Description |
|-----|-------------|
| `inspect_headers` | Run header values through the rule engine. |
| `inspect_query_string` | Run the URL query string through the rule engine. |
| `inspect_body` | Run the request body through the rule engine. |
| `body_mode` | `"buffered"` reads the full body before forwarding. `"streaming"` passes it through without buffering. `"both"` buffers up to `max_body_to_buffer` for inspection, then streams the rest. |
| `max_body_to_buffer` | Maximum body size to hold in memory during inspection. |
| `max_body_to_scan` | Hard limit on body bytes fed to the rule engine. Requests with bodies larger than this get a 413. |
| `spill_large_bodies_to_disk` | If a body exceeds `max_body_to_buffer`, write the overflow to a temp file rather than rejecting it. |
| `spill_directory` | Directory for temporary body spool files. Must be writable by the aegira process. |
| `decode_form_data` | URL-decode `application/x-www-form-urlencoded` bodies before scanning. |
| `decode_json` | Flatten JSON bodies into a string representation before scanning. |
| `decode_multipart` | Decode `multipart/form-data` part names and values before scanning. |
| `normalize_url_encoding` | Decode `%XX` sequences in paths and query strings before rule evaluation. |
| `normalize_html_entities` | Decode `&lt;`, `&#x3c;`, `&#NN;`, `&#xNN;`, named entities (`&amp;`, `&quot;`, etc.) before rule evaluation. |
| `normalize_unicode` | Apply Unicode NFKC normalisation to path, query, and body text before rule evaluation. |
| `decompress_body` | Decompress `gzip` and `deflate` request bodies into an inspection-only copy before rule matching. Original compressed bytes are forwarded to the backend unchanged. Protected against decompression bombs via `max_body_to_scan`. |
| `inspect_cookies` | Parse the `Cookie:` header into individual name=value pairs and present them as the `cookies` inspection target. Enables rules with `when = ["cookies"]`. |

---

### `[response_inspection]`

```toml
[response_inspection]
inspect_headers          = true
inspect_body             = false
response_body_mode       = "off"
remove_server_headers    = true
remove_powered_by_headers = true
max_body_to_scan         = "512KiB"
```

| Key | Description |
|-----|-------------|
| `inspect_headers` | Run response headers through the rule engine. |
| `inspect_body` | Run the response body through the rule engine. Disabled by default; only useful for data-loss-prevention style rules on responses. |
| `response_body_mode` | `"off"`, `"buffered"`. Must be `"buffered"` if `inspect_body = true`. |
| `remove_server_headers` | Strip the `Server` header from all responses. |
| `remove_powered_by_headers` | Strip `X-Powered-By` headers from all responses. |
| `max_body_to_scan` | Maximum response body bytes to scan if `inspect_body = true`. |

---

### `[forwarded_headers]`

```toml
[forwarded_headers]
trust_forwarded_headers      = false
trust_forwarded_headers_from = ["127.0.0.1/32", "::1/128"]
set_x_forwarded_for          = true
set_x_forwarded_proto        = true
set_x_forwarded_host         = true
```

| Key | Description |
|-----|-------------|
| `trust_forwarded_headers` | If `true`, Aegira trusts `X-Forwarded-For` etc. from upstream. Only enable if you know what's in front of aegira. |
| `trust_forwarded_headers_from` | CIDR list of upstream IPs to trust. Only used when `trust_forwarded_headers = true`. |
| `set_x_forwarded_for` | Append the client IP to `X-Forwarded-For` before forwarding. |
| `set_x_forwarded_proto` | Set `X-Forwarded-Proto` to `https` or `http` depending on whether TLS is active. |
| `set_x_forwarded_host` | Set `X-Forwarded-Host` to the original `Host` header value. |
| `proxy_protocol` | Read a HAProxy PROXY protocol v1/v2 header from the raw TCP stream before TLS negotiation, restoring the correct client IP. Default: `false`. |
| `parse_forwarded_header` | Prefer the RFC 7239 `Forwarded:` header over `X-Forwarded-For` for real-client-IP extraction. Default: `false`. |

---

### `[rules]`

```toml
[rules]
entrypoint       = "rules/main.toml"
max_include_depth = 16
```

| Key | Description |
|-----|-------------|
| `entrypoint` | Path to the root rules TOML file. Relative paths are resolved from the config file's directory. |
| `max_include_depth` | Maximum nesting depth for `include` chains. Prevents accidental cycles. |

---

### `[ip_filter]`

IP-based allow/block lists evaluated before any request processing. Both lists are empty by default (all IPs allowed).

```toml
[ip_filter]
block = ["192.168.1.0/24", "10.0.0.5/32"]
allow = ["203.0.113.0/24"]
```

| Key | Description |
|-----|-------------|
| `block` | CIDR list of IPs to block unconditionally. Checked before `allow`. |
| `allow` | CIDR list of IPs to allow unconditionally. When non-empty, only listed IPs are permitted. |

---

### `[rate_limit]`

Per-client-IP rate limiting using a token bucket.

```toml
[rate_limit]
enabled             = false
requests_per_second = 100
burst_size          = 200
exceeded_action     = "reject"
```

| Key | Description |
|-----|-------------|
| `enabled` | Enable rate limiting. Default: `false`. |
| `requests_per_second` | Sustained request rate allowed per client IP. Default: `100`. |
| `burst_size` | Maximum burst above the sustained rate. Default: `200`. |
| `exceeded_action` | `"reject"` returns 429 Too Many Requests. `"log"` logs the event and allows the request through. Default: `"reject"`. |

---

### `[schema_enforcement]`

Positive security model: validate JSON request bodies against an OpenAPI 3.x specification before the regex engine runs. All operations declared in the spec are registered, including those without a request body (GET, DELETE, etc.). When `reject_unknown_endpoints` is true, requests to method + path combinations not in the spec are rejected with 400. Endpoints not declared in the spec are unaffected when `reject_unknown_endpoints` is false (the default).

This is opt-in. When `enabled = false` (the default), no spec is loaded and no validation occurs.

```toml
[schema_enforcement]
enabled                    = false
openapi_spec_path          = "openapi.json"
max_body_bytes             = 1048576
max_depth                  = 64
reject_unknown_endpoints   = false
```

| Key | Description |
|-----|-------------|
| `enabled` | Master switch. Default: `false`. |
| `openapi_spec_path` | Path to a JSON OpenAPI 3.0 or 3.1 specification file. YAML is not supported; convert with any JSON/YAML tool. Relative paths are resolved from the config file directory. The file must not be world-writable (POSIX permission check). |
| `max_body_bytes` | Maximum body size in bytes that will be parsed for schema validation. Bodies exceeding this limit are rejected before JSON parsing begins. Default: `1048576` (1 MiB). |
| `max_depth` | Maximum JSON nesting depth. Deeply nested structures are rejected before schema evaluation to prevent stack exhaustion. Default: `64`. |
| `reject_unknown_endpoints` | When `true`, requests to method + path combinations not declared in the spec are rejected with 400 before the regex engine runs. When `false`, unlisted endpoints pass through to the regex pipeline as usual. Default: `false`. |

**How it works.** At startup (and on each SIGHUP reload), aegira loads the OpenAPI spec and registers every operation declared under `paths`, not just those with a `requestBody`. For operations that declare an `application/json` request body, the schema is resolved (including `$ref` pointers) and compiled using the `jsonschema` crate. On each request, the method + path is matched against the spec inventory. If the endpoint has a body schema and the request carries a JSON body, the body is validated; violations are rejected with HTTP 400. If the endpoint is known but has no body schema, the request passes through to the regex engine. If `reject_unknown_endpoints` is true and the method + path is not in the spec at all, the request is rejected with 400 before any WAF rule is evaluated.

Path parameters in OpenAPI templates (e.g. `/users/{id}`) are matched as wildcards. `$ref` resolution handles both inline and `#/components/schemas/...` references, with circular reference detection to prevent infinite expansion.

---

### `[[route]]`

Each `[[route]]` maps a host and path prefix to a backend. At least one route is required. Routes are evaluated by longest `path_prefix` match.

```toml
[[route]]
host        = "example.com"
path_prefix = "/"
forward_to  = "app_main"

[[route]]
host        = "example.com"
path_prefix = "/api/v2/"
forward_to  = "api_main"
```

| Key | Description |
|-----|-------------|
| `host` | Hostname to match against the request's `Host` header / SNI. |
| `path_prefix` | URL path prefix. The longest matching prefix wins. |
| `forward_to` | Backend name to forward matched requests to. Must reference a `[[backend]]` by name. |

---

### `[[backend]]`

Each `[[backend]]` block defines a forwarding target. You need at least one.

```toml
[[backend]]
name                     = "app_main"
backend_address          = "unix:///run/app.sock"
forward_using            = "unix_socket"
backend_protocol         = "http1"
connect_timeout          = "3s"
tls_handshake_timeout    = "5s"
response_header_timeout  = "10s"
keepalive                = true
keepalive_idle_timeout   = "90s"
max_idle_connections     = 128
retry_requests           = true
retry_count              = 2
retry_only_if_idempotent = true
drain_on_reload          = true
```

| Key | Description |
|-----|-------------|
| `name` | Unique name. Referenced by `site.forward_to`, `site.forward_target`, and `waf.default_forward_target`. |
| `backend_address` | For `plain_http` / `tls`: `host:port`. For `unix_socket`: `unix:///path/to/socket`. |
| `forward_using` | Transport: `"plain_http"`, `"tls"`, or `"unix_socket"`. |
| `backend_protocol` | Wire protocol: `"http1"`, `"http2"`, `"http3"`, or `"auto"`. Use `"auto"` to let reqwest negotiate. Note: `"http3"` requires QUIC (UDP + TLS 1.3) and is not available for backend connections in the current build. |
| `backend_server_name` | TLS SNI name to use when connecting (for `forward_using = "tls"`). Defaults to the host part of `backend_address`. |
| `verify_backend_certificate` | Whether to verify the backend's TLS certificate. Default `true`. |
| `backend_ca_file` | PEM CA bundle to use for backend cert verification. Uses system roots if omitted. |
| `present_client_certificate` | Not yet implemented. Reserved for mTLS to backends. |
| `connect_timeout` | Timeout for establishing a connection to the backend. |
| `tls_handshake_timeout` | Timeout for completing a TLS handshake with the backend. |
| `response_header_timeout` | Timeout for receiving the first response header byte after sending the request. |
| `keepalive` | Enable HTTP keep-alive for backend connections. |
| `keepalive_idle_timeout` | How long to keep an idle connection alive in the pool. |
| `max_idle_connections` | Maximum number of idle connections to keep in the pool per backend. |
| `retry_requests` | Retry failed requests automatically. |
| `retry_count` | Number of additional attempts after the first failure. |
| `retry_only_if_idempotent` | Only retry `GET`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`, `TRACE`. Prevents double-posting on `POST` / `PATCH`. |
| `drain_on_reload` | Wait for in-flight requests to finish before this backend is swapped out during a hot-reload. |

---

### `[logging]`

```toml
[logging]
format                     = "json"
write_to                   = "file"
file                       = "/var/log/aegira/events.json"
level                      = "info"
redact_cookies             = true
redact_authorization_header = true
redact_set_cookie_header   = true
```

| Key | Options | Description |
|-----|---------|-------------|
| `format` | `"json"`, `"text"` | `"json"` emits structured newline-delimited JSON. `"text"` emits human-readable lines. Use `"json"` in production. |
| `write_to` | `"stdout"`, `"file"`, `"both"` | Where log lines go. |
| `file` | path | Log file path. Required when `write_to` is `"file"` or `"both"`. |
| `level` | `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` | Minimum log level. Override at runtime with the `RUST_LOG` environment variable. |
| `redact_cookies` | bool | Replace cookie values with `[redacted]` in logs. |
| `redact_authorization_header` | bool | Replace the `Authorization` header value with `[redacted]` in logs. |
| `redact_set_cookie_header` | bool | Replace `Set-Cookie` values with `[redacted]` in logs. |

---

## Rules

### Writing rules

Rules live in TOML files under your rules directory. The bare minimum for a working rule is four fields:

```toml
[[rule]]
id     = 1001
when   = ["query_string", "body"]
match  = "(?i)union[\\s/\\*]+select"
action = "drop"
```

A fully annotated rule:

```toml
[[rule]]
id          = 1001
name        = "sql_union_select"
description = "UNION-based SQL injection probe in query string or body."
tags        = ["sqli", "owasp-a03"]
enabled     = true
when        = ["query_string", "body"]
match       = "(?i)union[\\s/\\*]+select"
action      = "drop"
priority    = 100
score       = 10
```

**Field reference:**

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | yes | — | Integer greater than zero. Unique across all loaded rule files. If the same ID appears more than once, the first definition wins and a warning is logged. |
| `when` | yes | — | Which parts of the request (or response) to run the pattern against. Request targets: `path`, `query_string`, `headers`, `cookies`, `body`. Response targets: `response_headers`, `response_body`. You can list multiple; the rule fires if any target matches. |
| `match` | yes | — | Rust `regex` crate pattern. Case-sensitive by default; use `(?i)` for case-insensitive matching. |
| `action` | yes | — | `"log"`, `"drop"`, or `"forward"`. See below. |
| `name` | no | — | Short label. Shows up in audit log entries. |
| `description` | no | — | Free-text note. Not used at runtime. |
| `tags` | no | `[]` | String array. Not used at runtime but useful for grouping and grepping. |
| `enabled` | no | `true` | Set to `false` to skip this rule at load time without removing it from the file. |
| `priority` | no | `0` | When multiple rules match, higher priority wins within the same action tier. |
| `score` | no | `0` | Non-negative integer added to the request's anomaly score when this rule matches. |

### Inline rule tests

Every rule can carry self-contained test cases. They are validated by `--check-config` and never affect runtime behaviour:

```toml
[[rule]]
id     = 1001
when   = ["query_string", "body"]
match  = "(?i)union[\\s/\\*]+select"
action = "drop"

  [[rule.test]]
  input  = "foo=1 UNION SELECT * FROM users"
  target = "body"
  expect = "match"

  [[rule.test]]
  input  = "foo=hello+world"
  target = "query_string"
  expect = "no_match"
```

| Field | Description |
|-------|-------------|
| `input` | The string to run the regex against. |
| `target` | The inspection target label (`path`, `query_string`, `headers`, `cookies`, `body`). |
| `expect` | `"match"` asserts the pattern fires; `"no_match"` asserts it does not. |

Run `aegira --check-config` to execute all inline tests and print a summary. The process exits non-zero if any test fails.

### Actions

When multiple rules match the same request, the winning action follows this precedence: `drop` beats `forward` beats `log`. Within the same tier, higher `priority` wins; ties are broken by lower `id`.

| Action | What happens |
|--------|-------------|
| `log` | The match is recorded in the audit log. The request continues to the backend normally. |
| `drop` | Returns `403 Forbidden` to the client. The request never reaches the backend. |
| `forward` | Reroutes the request to the configured forward target backend (e.g. a honeypot) instead of the normal backend. The match is logged. |

**Action aliases** (normalised at parse time):

| Alias | Resolves to |
|-------|-------------|
| `allow`, `allow_and_log` | `log` |
| `send_to_honeypot` | `forward` |
| `reject`, `block` | `drop` |

### Disabling rules

Rules are global and apply to all sites by default. To turn off a specific rule:

```toml
# Disable globally (affects every site)
[waf]
disabled_rules = [1001, 1002]

# Disable for one site only
[[site]]
server_name    = "api.example.com"
disabled_rules = [1001]
```

To disable a rule in the rule file itself without deleting it, set `enabled = false`. That rule will be silently skipped when the bundle is loaded.

### Organising rule files

The rules entrypoint (`rules.entrypoint`) is a TOML file that can include other files:

```toml
# rules/main.toml
include = [
  "rules/baseline",
  "rules/custom",
  "rules/local.toml",
]
```

Include entries can be:
- a **file path**: loads exactly that file
- a **directory path**: loads all `*.toml` files in the directory, sorted lexically
- a **glob**: loads all matching files, sorted lexically

A suggested layout:

```
rules/
  main.toml
  baseline/
    00-sqli.toml
    10-xss.toml
    20-scanners.toml
  custom/
    50-api-rules.toml
  local.toml          ← machine-specific tweaks, gitignored
```

Naming convention: `00`–`49` for baseline/shared rules, `50`–`89` for service-specific rules, `90`–`99` for local overrides.

A few things to know about how loading works:
- Files visited more than once (through overlapping includes) are only loaded once.
- If a rule ID appears more than once, the first definition wins. A warning is logged.
- An include entry that resolves to zero files is a hard error at startup.
- `enabled = false` rules are dropped before the bundle is returned to the engine.
- Rules with a negative `score` are rejected at load time.

---

## Observability

### Health endpoint

`GET /health` returns JSON and HTTP 200 when the daemon is ready, or 503 during a reload:

```json
{"ready":true,"reload_in_progress":false,"in_flight":3}
```

### Metrics endpoint

`GET /metrics` returns Prometheus text format:

```
# TYPE aegira_requests_total counter
aegira_requests_total 12483
# TYPE aegira_blocked_total counter
aegira_blocked_total 17
# TYPE aegira_forwarded_total counter
aegira_forwarded_total 11901
# TYPE aegira_forward_reroute_total counter
aegira_forward_reroute_total 24
# TYPE aegira_backend_error_total counter
aegira_backend_error_total 2
# TYPE aegira_reload_total counter
aegira_reload_total 1
# TYPE aegira_in_flight gauge
aegira_in_flight 3
# TYPE aegira_ready gauge
aegira_ready 1
```

### Audit log

Every request produces a structured log line. With `format = "json"`, each line contains:

- `request_id`: UUID v4 correlation ID, either generated for this request or carried from the configured `waf.request_id_header`. Same value is forwarded to the backend and can be cross-referenced in application logs.
- `action`: the winning rule action (`log`, `reject`, `drop`, `forward`). In observe mode this reflects the downgraded action; the original intended action is logged separately.
- `backend`: which backend the request was forwarded to (or would have gone to)
- `matched_rule_ids`: list of rule IDs that fired on this request
- `match_fragments`: the exact substrings matched by each triggered rule, in the same order as `matched_rule_ids`. Lets operators see precisely what text triggered a rule without replaying the request.
- `status`: HTTP response status (forwarded requests only)
- `latency_ms`: total request handling time in milliseconds

---

## License

MIT

