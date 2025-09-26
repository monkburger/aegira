# Aegira Design

## Purpose
Aegira is a virtual-host-aware reverse-proxy WAF daemon. It terminates TLS, inspects request data, applies policy actions (`log`, `forward`, `drop`), and forwards traffic to configured backends.

## Core Goals
- Virtual host awareness for TLS termination and routing.
- Protocol-aware frontend with HTTP/1.1, HTTP/2, and HTTP/3 (QUIC).
- Config in TOML with a separate TOML ruleset tree.
- Rules loaded through a ModSecurity-like include chain (`entrypoint` + includes).
- Deterministic conflict resolution: one final action per request.
- Structured operation with graceful shutdown/reload semantics.

## Configuration Model
Main daemon config: `configs/aegira.toml`
Rules entrypoint: `configs/rules/main.toml`

The main config carries listener, TLS, sites, backends, routes, and logging.
Rules live in separate files and support include entries as:
- single file path (`common/base.toml`)
- directory path (loads all `*.toml` in lexical order)
- glob pattern (`sites/*.toml`)

## Ruleset Include Order
Rule loading is deterministic and follows these rules:
- Includes are processed in the same order they appear in the `include` list.
- A directory include loads all `*.toml` files in lexical order.
- A glob include loads matched files in lexical order.
- A file include loads exactly that file.
- A previously loaded file is not reloaded if referenced again through another include path.

Failure behavior:
- If an include resolves to zero files, loading fails.
- Duplicate rule `id`: the first definition wins; the duplicate is skipped with a warning.
- If include depth exceeds `rules.max_include_depth`, loading fails.

Recommended layout:
- `common/` for base rules
- `sites/` for per-site rule groups
- `overrides/` for local tuning

Recommended include order in entrypoint:
1. `common`
2. `sites`
3. `overrides`

This order keeps baseline detections first and local customization last while preserving deterministic startup behavior.

Example layout and naming:
```text
configs/rules/
  main.toml
  common/
    00-base.toml
  sites/
    50-api.toml
  overrides/
    99-local.toml
```

Recommended filename ranges:
- `00-49`: shared baseline
- `50-89`: site-specific rule files
- `90-99`: local overrides/tuning

## Virtual Host Model
- Site selection uses host matching.
- Route selection uses host + longest path prefix.
- TLS cert files are configured by path.

## Backend Communication
Backends support:
- `plain_http`
- `tls`
- `unix_socket`

Forwarding behavior:
- Normal requests route to configured backend.
- `forward` rules can reroute to a config-scoped forward target backend.
- `drop` returns `403` immediately.

## Rule Engine
Rules are loaded from TOML files into a bundle.
Each rule contains:
- `id` (required), `name`, `description`, `tags` (optional metadata)
- `enabled` (default `true`; `false` skips the rule at load time)
- `when` targets: `path`, `query_string`, `request_headers` (alias: `headers`), `request_body` (alias: `body`), `cookies` (alias: `cookie`), `response_headers`, `response_body`
- regex pattern (`match`)
- `action`: `log`, `drop`, `forward`
- `priority`, `score` (both default to `0`)

Disabling rules is config-driven, not rule-file-driven:
- `waf.disabled_rules`: IDs disabled for all sites
- `site.disabled_rules`: IDs disabled for a specific site

Forward target resolution is config-scoped:
- global default: `waf.default_forward_target`
- per-site override: `site.forward_target`

Compilation:
- Regexes are pre-compiled at startup.
- Invalid regex fails fast; duplicate IDs emit a warning (first wins).

Evaluation:
- Request is normalized (`host`, `path`, `query`, headers, body text).
- Matching rules are collected and scored.
- Winning action precedence:
  1. `drop`
  2. `forward`
  3. `log`
- Tie-breakers: higher rule priority, then lower rule ID.

## Runtime Architecture
- Async runtime via Tokio.
- Incoming HTTP served by Axum/Axum Server.
- Optional TLS termination enabled by config.
- Request body captured, normalized, inspected, then proxied.
- Proxy path:
  - `plain_http` and `tls`: Reqwest client
  - `unix_socket`: Unix stream HTTP/1.1 forwarder

## Graceful Behavior
- Ctrl+C triggers graceful drain.
- Grace period parsed from `server.graceful_shutdown_timeout`.

## HTTP/2 and HTTP/3 Notes
- Frontend HTTP/1.1, HTTP/2, and HTTP/3 (QUIC via quinn + h3) are active.
- Backend HTTP/3 is not available; QUIC requires TLS 1.3 at the transport level, which is not applicable to backend connections.

## Crate Selection and Stability
Selected crates are stable releases (no beta/alpha/rc in use):
- `tokio` 1.x: production async runtime.
- `axum` 0.8: production web framework on Hyper 1.
- `axum-server` 0.7: production listener with rustls integration.
- `reqwest` 0.12: production HTTP client.
- `rustls` 0.23: production TLS stack.
- `regex` 1.x: Rust linear-time regex engine.
- `serde` + `toml`: stable config parsing.

No beta-only crates are part of the design baseline.

## Security and Reliability Notes
- Header trust policy is explicit in config.
- Backend references and rule references are validated at load time.
- Rule include depth is bounded.
- Rule includes with no matched files are treated as errors to avoid silent drift.

## Implemented Since Initial Design
- Per-site SNI certificate selection (each `[[site]]` carries its own cert/key pair).
- HTTP/3 (QUIC) listener via quinn + h3.
- Structured JSON event logger with configurable redaction.
- Zero-downtime SIGHUP reload of config, rules, and TLS certificates.
- HSTS header injection with configurable `max-age`, `includeSubDomains`, and `preload`.
- TLS session ticket key rotation via `RotatingTicketEncrypter`.
- Cookie parsing as a first-class WAF inspection target.
- Response header and body inspection targets.
- Inline rule tests (`[[rule.test]]`) validated by `--check-config`.
- Anomaly score threshold (global and per-site).
- PROXY protocol v1/v2 and RFC 7239 `Forwarded:` header support.
- `Content-Encoding` decompression (gzip/deflate) for WAF inspection.
- `Expect: 100-continue` early inspection.
