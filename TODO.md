# Aegira TODO

## Completed
- [x] Migrate scaffold from Go to Rust.
- [x] Preserve TOML config + separate TOML rules files.
- [x] Implement rules include loader with duplicate rule detection.
- [x] Add regex-based rule compilation and inspection engine.
- [x] Add site and route resolution helpers.
- [x] Add basic listener + forwarding runtime.
- [x] Add backend forwarding modes: `plain_http`, `tls`, `unix_socket`.
- [x] Add action precedence and honeypot diversion support.

## In Progress
- [x] Strengthen TLS virtual-host behavior with SNI cert selection per site.
- [x] Improve graceful reload support (`SIGHUP`) with in-flight request draining and atomic swap.

## Next Priority
1. TLS and vhost
- [x] Implement certificate map resolver for all configured sites.
- [x] Enforce `unknown_sni` and `missing_sni` policy at handshake level.
- [x] Add authority mismatch handling in request pipeline.

2. Transport and proxy
- [x] Replace minimal UDS forwarder with full HTTP codec and streaming body support.
- [x] Add backend timeout policy wiring from config (`connect`, `header`, `idle`).
- [x] Add retry policy for idempotent methods.

3. Runtime controls
- [x] Add SIGHUP reload for config and rules.
- [x] Keep old rules active when reload validation fails.
- [x] Add health endpoint and internal readiness state.

4. Logging and observability
- [x] Structured JSON logging to stdout/file according to `logging` config.
- [x] Add per-request audit fields: action, matched rule IDs, backend target, latency.
- [x] Add basic metrics endpoint.

5. Protocol work
- [x] Implement frontend HTTP/3 support.
- [x] Evaluate backend HTTP/3 support as optional v2.
- [x] Add explicit gRPC and WebSocket handling modes from config toggles.

6. Rulesets and action model
- [x] Formalize the ruleset file structure and loading conventions (`main.toml`, shared rule directories, per-site rule directories).
- [x] Define the stable rule schema with explicit metadata (`name`, internal `id`, rule set name, targets, regex match, priority, score) and no inline backend target.
- [x] Add a separate config-driven forward target setting for `forward` actions, scoped globally and overridable per virtual host.
- [x] Keep Rust `regex` as the initial matching engine and document the supported targets/fields clearly.
- [x] Normalize user-facing rule actions to `log`, `drop`, and `forward`.
- [x] Make `log` audit-only: record the match and continue normal request handling without blocking or rerouting.
- [x] Make `drop` return a permission-denied HTTP response by default.
- [x] Make `forward` allow the request to continue with logging, while rerouting according to the configured global or per-vhost forward target (for example a honeypot backend).

7. Testing
- [x] Integration tests with local backend over TCP and Unix socket.
- [x] TLS integration tests with multiple vhosts.
- [x] Rule conflict tests and reload failure tests.

## Crate Policy
- [x] Use stable crates only (no beta/alpha/rc).
- [ ] Review dependency versions quarterly and pin known-good ranges.
- [ ] Add `cargo audit` and `cargo deny` checks in CI.

## Deferred WAF Features

### Schema enforcement (positive security model)
- [x] `schema_enforcement.enabled`: validate JSON request bodies against an OpenAPI 3.x specification before the regex engine runs.  Bodies violating the schema are rejected with 400.
- [x] OpenAPI 3.0/3.1 spec loading with `$ref` resolution and path parameter wildcards.
- [x] Register all operations from the spec (GET, DELETE, etc.), not just those with a `requestBody`.  The spec is the full endpoint inventory.
- [x] `reject_unknown_endpoints`: block requests to method + path combinations not declared in the spec.
- [x] POSIX file permission check on the spec file.
- [x] Configurable body size limit and JSON nesting depth cap.
- [x] Strategy Pattern (`SchemaValidator` trait) for future XML/Protobuf validators.
- [ ] Per-route schema assignment: allow different specs per `[[route]]` instead of a single global spec.
- [ ] Support YAML OpenAPI specs via an optional `serde_yaml` dependency.
- [ ] Schema validation performance counters on the `/metrics` endpoint.
- [ ] Learning mode: observe traffic, infer schemas, and propose them to the operator.

### Body decoding before inspection
- [x] `request_inspection.decode_form_data`: parse `application/x-www-form-urlencoded` bodies and extract field values for inspection as plain text.
- [x] `request_inspection.decode_json`: flatten `application/json` bodies to `key=value` pairs for inspection.
- [x] `request_inspection.decode_multipart`: extract part bodies from `multipart/form-data` for individual inspection.

### Additional normalisation passes
- [x] `request_inspection.normalize_html_entities`: decode `&lt;`, `&gt;`, `&amp;`, `&#NN;`, `&#xNN;` before rule matching.
- [x] `request_inspection.normalize_unicode`: apply NFKC normalisation to path, query, and body text before rule matching.

### Response inspection wired
- [x] `response_inspection.inspect_headers` and `inspect_body` are declared in config but not yet evaluated by the engine.  Wire a response inspection pass after the backend responds.
- [x] `request_inspection.spill_large_bodies_to_disk`: back bodies exceeding `max_body_to_buffer` with a temp file in `spill_directory` instead of rejecting or truncating.

### Matched fragment in audit log
- [x] Add a `matched_fragment` field to `MatchedRule` containing the matched substring from `regex.find()`.  Include it in the `request_audit` log event so operators can see exactly what triggered each rule without replaying the request.

### Per-site observe mode
- [x] Add `site.mode = "observe"` that downgrades all `drop` and `forward` actions to `log` for a specific virtual host.  Enables deploying new rules against real traffic before going live.

### Inline rule tests
- [x] Add `[[rule.test]]` blocks to the rule TOML schema: `input`, `target`, `expect = "match" | "no_match"`.  Checkable via `--check-config` without starting the daemon.

### Per-site anomaly score threshold
- [x] Add `site.anomaly_score_threshold: Option<i32>` to override the global `waf.anomaly_score_threshold` for a specific virtual host.

### Request ID end-to-end tracing
- [x] `waf.request_id_header` is declared but not wired.  On each request: generate a UUID (or use an existing header value if trusted), attach it to the forwarded request headers, and include it in `request_audit` log events so WAF log lines can be correlated with backend application logs.

---

## Platform and Protocol Hardening

### Linux OS features
- [ ] **`SO_REUSEPORT` + in-place binary upgrade.** New process binds the same port before the old one exits. Kernel distributes connections between them during the handoff window. Zero dropped connections without a load balancer in front.
- [ ] **Systemd socket activation (`LISTEN_FDS` / `sd_notify`).** Accept pre-bound fds from systemd at startup; signal `READY=1` once the engine is hot. Enables socket-level activation and integrates socket handoff with the init system.
- [ ] **`seccomp-bpf` syscall filter post-startup.** After binding ports and loading certs, install a seccomp allowlist covering only the syscalls tokio's epoll loop uses. A memory-corruption exploit in any dependency then cannot `exec`, open arbitrary files, or `ptrace`.
- [ ] **Privilege drop after bind.** Bind :443 as root, then `setuid`/`setgid` to a service account. Retain `CAP_NET_BIND_SERVICE` only. Process runs unprivileged in steady state.
- [ ] **`prctl(PR_SET_DUMPABLE, 0)` + `mlockall(MCL_CURRENT)`.** Prevent core dumps and `/proc/self/mem` reads that would expose TLS private keys in memory. `mlockall` ensures private key material never lands in swap.
- [ ] **Slow-loris floor.** Enforce a minimum inbound bytes-per-second rate on request header reads. Connections that trickle headers below the floor are closed. Complements the existing per-read timeout which a slow-loris attack intentionally stays under.
- [ ] **Per-IP concurrent connection limit.** Distinct from rate limiting: `ip_filter.max_connections_per_ip` caps how many simultaneous keep-alive connections a single IP may hold. Blocks connection exhaustion attacks against the TLS stack without touching request rate.

### RFCs not yet covered
- [x] **RFC 7239: `Forwarded` header.** Parse the IETF-standardized `Forwarded:` header as an alternative to `X-Forwarded-For`. GCP, Fastly, and Cloudflare Workers emit this in preference to the de-facto headers.
- [x] **PROXY protocol v1/v2 (HAProxy spec).** AWS NLB, GCP internal LB, and Cloudflare Spectrum inject a PROXY protocol prefix at the TCP level before any HTTP bytes. Without it, all traffic from these load balancers appears to originate from the LB IP. The `tokio-proxy-protocol` crate handles parsing.
- ~~**RFC 6960: OCSP stapling.**~~ Deprecated. Let's Encrypt shut down their OCSP responder in 2025; Chrome removed OCSP checking; the CA/Browser Forum has moved to short-lived certificates as the revocation mechanism. Not implemented.
- [x] **RFC 6797: HSTS.** Inject `Strict-Transport-Security: max-age=63072000; includeSubDomains` on all TLS responses. Per-site configurable with an optional `preload` flag. One header prevents the entire class of protocol-downgrade attacks.
- [x] **RFC 8446 §4.6.3: TLS session ticket key rotation.** Rotate session ticket keys on a configurable schedule (e.g. every 6 hours); accept the previous key for a grace period. Restores forward secrecy at the session resumption layer. rustls exposes `TicketResolver` for this.
- [x] **RFC 9110 §8.4: Content-Encoding decompression.** Decompress `gzip` and `deflate` request bodies into an inspection-only copy before rule matching; original bytes forwarded to the backend unchanged. Decompression-bomb protection via `Read::take(max_body_to_scan)`.
- [x] **RFC 9110 §10.1.1: Expect: 100-continue.** Inspect headers, path, query, and cookies before materialising the body. A decisive block/drop is returned before the client sends the body bytes.
- [x] **RFC 6265: Cookie parsing.** Parse individual `Cookie: name=value` pairs into a first-class `cookies` inspection target. Rules can target `"cookies"` to match parsed name/value pairs rather than the raw header string.

### Distributed observability
- [ ] **W3C Trace Context (RFC 9234) + OpenTelemetry OTLP export.** Generate or propagate `traceparent`/`tracestate` headers. Export spans to a configured OTLP endpoint (Jaeger, Grafana Tempo, Honeycomb). The request ID TODO is the manual baseline; this replaces it with a production-grade standard.

### Backend reliability
- [ ] **Circuit breaker per backend.** Track per-backend error rate with an `AtomicU32` counter and a cooldown timestamp. When the error rate exceeds a threshold, open the circuit and return 502 immediately instead of waiting a full `connect_timeout` per request. Probe with a single request after the cooldown (half-open state).
- [ ] **Active backend health checks.** Periodic probes (`GET` to a configurable path) update a per-backend `alive: AtomicBool`. The router skips unavailable backends before a request arrives, rather than discovering failures per-request. Complements the circuit breaker.

---

## Futuristic / Forward-looking

### Plugin system
- [ ] **Wasm plugin host via `wasmtime`.** Load `.wasm` modules at startup that implement a defined ABI: `on_request(headers, path, query) -> Decision` and `on_response(headers, status) -> Decision`. Plugins run in isolated sandboxes with no access to the host process. Hot-reload on SIGHUP. This gives operators custom logic (bot fingerprinting, session validation, business-rule enforcement) without recompiling aegira or accepting arbitrary native code.
- [ ] **Lua scripting via `mlua`.** Lighter-weight alternative to Wasm for operators already familiar with nginx/HAProxy Lua. A `script` field on a rule file loads a Lua chunk that receives the request context and returns an action string. Sandboxed with a configurable instruction limit to prevent infinite loops.

### LLM-assisted detection
- [ ] **Embedding-based semantic WAF rule.** Run a quantized sentence embedding model (e.g. `all-MiniLM-L6-v2` via `candle`) on request bodies and compare cosine similarity against a library of known-malicious prompt embeddings. Catches obfuscated SQL injection, prompt injection into LLM-backed APIs, and novel attack variants that regex rules miss. Score is added to the anomaly total and can be thresholded independently.
- [ ] **LLM-assisted rule generation.** `aegira rule-suggest --log access.log` reads recent audit log entries for `log`-action matches and calls a local or remote LLM to propose tighter regex rules. Output is TOML ready to drop into `overrides/`. The human reviews and approves. Reduces the rule-tuning loop from days to minutes.
- [ ] **Anomaly baseline via online learning.** Build a per-path rolling histogram of request features (body length, header count, query parameter count). Flag requests that deviate beyond N standard deviations as anomalous (not blocked, but scored) without any explicit rule. Self-tunes to the application's normal traffic shape without operator input. Models stored in a compact on-disk format and updated atomically.

### Advanced routing
- [ ] **Response rewriting rules.** A lightweight set of text substitution rules applied to response bodies before delivery (e.g. strip internal hostnames from JSON error messages, redact PAN data in responses using a regex). Complements response inspection.

### Operational tooling
- [ ] **`aegira explain --request <file>` CLI command.** Reads a raw HTTP request from a file or stdin, runs it through the current rule set, and prints which rules matched, their individual scores, the final action, and the anomaly total, without starting a server. Makes rule debugging and CI pre-flight validation concrete.
- [ ] **Rule diff on reload.** When a SIGHUP reload changes the active rule set, log a structured diff: rules added, removed, score changed, action changed. Makes it visible in the audit log exactly what changed and avoids silent rule regressions after a deploy.
- [ ] **Prometheus alerting rules file generation.** `aegira gen-alerts` emits a `alerts.yaml` for Prometheus Alertmanager based on the current config: alert if block rate exceeds N%, alert if backend error rate exceeds threshold, alert if rule reload failure. Closes the loop between config and observability setup.

---

## eBPF Integration

Toolchain: all kernel-side programs written in `aya-ebpf` (`#![no_std]` Rust); map access and program loading via the `aya` userspace crate. BPF objects are compiled with a cross-target and embedded in the aegira binary with `include_bytes!()`. No C, no clang, no BCC runtime dependency. Gated behind a `--features ebpf` flag so the binary runs on kernels without BTF.

### XDP: pre-stack packet drop (ingress, before sk_buff allocation)

- [ ] **IP blocklist at XDP drop rate.** Userspace writes blocked CIDRs into a `BPF_MAP_TYPE_LRU_HASH`. The XDP program checks `src_ip` and returns `XDP_DROP`. Blocked IPs never reach the TLS stack or consume a rustls context. Replaces the current userspace `ip_filter.block` for high-volume DoS sources and operates at line rate.
- [ ] **SYN flood mitigation.** XDP tracks SYN-per-second per source IP in a `BPF_MAP_TYPE_PERCPU_HASH`. IPs exceeding the burst threshold are promoted to the blocklist map. No userspace thread is involved; the kernel continues issuing SYN cookies independently.
- [ ] **QUIC Initial packet rate limiter.** Aegira's HTTP/3 frontend receives raw UDP. An XDP program rate-limits QUIC Initial packets per source IP before quinn reads them, preventing QUIC amplification abuse at the point where it is cheapest.
- [ ] **Per-CPU packet and byte counters.** XDP increments `BPF_MAP_TYPE_PERCPU_ARRAY` counters per interface and direction with zero atomic operations. The userspace metrics task aggregates the per-CPU slots for the Prometheus `/metrics` endpoint. Zero overhead on the forwarding hot path.

### TC BPF: L3/L4 both directions (ingress and egress)

- [ ] **Egress bandwidth shaping per IP.** A TC egress program buckets outbound bytes per destination IP. Prevents a single client from saturating the NIC with large response bodies. Complements request-rate limiting which counts requests, not bytes.
- [ ] **Egress response header scrubbing.** A TC egress program strips `Server:` and `X-Powered-By:` byte patterns from HTTP/1.1 response headers before they leave the NIC. Defense-in-depth behind the existing response stripping in `handle_request`; catches headers added by libraries aegira does not control.

### Socket-level BPF: after TCP reassembly, before userspace read()

- [ ] **`SK_SKB` stream parser for HTTP/1.1 header framing.** A `BPF_PROG_TYPE_SK_SKB` program locates the end of each HTTP header block (`\r\n\r\n`) and publishes the header section offset to userspace via a ring buffer. Lets aegira inspect headers without buffering an unbounded stream.
- [ ] **Slow-loris detection via bytes-per-second measurement.** Attach a BPF program to the accept socket. Track `(socket_cookie → bytes_received, last_seen)` in a BPF map. A periodic Tokio task reads the map and issues `shutdown(SHUT_RD)` on connections where throughput falls below the configured floor. More accurate than per-read timeouts because it measures sustained throughput across the full header phase rather than individual read gaps.

### Kprobes / Tracepoints: kernel observability

- [ ] **Per-IP concurrent connection tracking.** Kprobe on `inet_csk_accept` (increment) and `tcp_close` (decrement) to maintain a `BPF_MAP_TYPE_PERCPU_HASH` of `src_ip → active_count`. The `ip_filter.max_connections_per_ip` check reads this map via a `SO_ATTACH_BPF` socket filter before the three-way handshake completes. No per-request lock in the Rust hot path.
- [ ] **Backend latency tracing with sub-microsecond precision.** Kprobe on `tcp_sendmsg` / `tcp_recvmsg` for sockets owned by the aegira process. Measures kernel-to-kernel roundtrip time for backend connections without the `CLOCK_REALTIME` syscall overhead of `Instant::now()` in userspace. Results published to the ring buffer and included in audit log latency fields.
- [ ] **TLS session key extraction for diagnostic mode.** Uprobe on the rustls encryption entry point. Writes session keys to a ring buffer in NSS SSLKEYLOGFILE format when aegira is started with `--key-log`. Keeps all key-logging code outside the security-sensitive TLS path and entirely absent from production builds.

### BPF LSM: post-compromise process lockdown

Loaded after startup and cert load. Restricts what the aegira process itself is permitted to do at the kernel level, regardless of what user-space code attempts.

- [ ] **`socket_connect` allowlist.** Permit outbound TCP connections only to the backend IPs and ports declared in the active config. Any attempt to connect to an unlisted address (e.g. an attacker pivoting to an internal metadata service) receives `EPERM` from the kernel, not the application. Cannot be bypassed by memory corruption in userspace.
- [ ] **`file_open` allowlist.** After startup, restrict `open()` calls to the configured log path, rules directory, and cert directory. Prevents a compromised process from reading `/etc/shadow`, private keys outside the configured path, or probing arbitrary filesystem locations.
- [ ] **`execve` hard deny.** aegira never needs to spawn child processes. Denying `execve` entirely eliminates the command injection → shell escape attack class even if an attacker achieves arbitrary code execution inside the process.

### BPF Ring Buffer: kernel-to-userspace event delivery

- [ ] **Unified event channel for XDP / TC / kprobe programs.** All eBPF programs write structured event records (blocked IP, rate-exceeded IP, slow-loris candidate, connection count) to a single `BPF_MAP_TYPE_RINGBUF`. A dedicated Tokio task polls it via `epoll`. Events arrive with kernel-precision timestamps and feed directly into the audit log and Prometheus counters. Guaranteed delivery with no per-CPU overflow, no UDP, no IPC overhead.

---

## SIMD / Vectorized Scanning

All items in this section are userspace, safe Rust, and portable; they use runtime CPU feature detection so the binary runs on any x86-64 target and takes the fastest available path (SSE2 / SSE4.2 / AVX2 / AVX-512) at startup.

### Multi-pattern body scanning: Vectorscan / Hyperscan / Aho-Corasick

- [ ] **Replace sequential regex passes with a SIMD multi-pattern engine.** Three candidate backends in priority order: (1) **Vectorscan** (`vectorscan-rs`), the open-source community fork of Hyperscan, Apache-2.0, actively maintained, runs on any x86-64 and aarch64 with NEON; (2) **Hyperscan** (`hyperscan` crate), Intel's original, higher peak throughput on Xeon but x86-only and has had licensing ambiguity on versions > 5.4; (3) **Aho-Corasick** (`aho-corasick` crate), pure safe Rust, no C dependency, handles literal and prefix/suffix patterns only but covers a large fraction of real WAF rules and is the right fallback when neither SIMD library is available. All three share the same integration contract: at rule load time compile rules whose patterns are expressible without lookahead/lookbehind into the chosen engine's compiled database; rules that cannot be expressed fall back to the existing `regex` path. At inspection time, `Engine::inspect()` makes **one pass** over the body regardless of how many rules are loaded, then evaluates only the rule IDs the engine reports as matching. Changes inspection complexity from O(rules x body) to O(body + matching\_rules). On AVX2, Vectorscan/Hyperscan scan at 5-20 GB/s depending on pattern complexity. This is the single most impactful change available to the engine. Select the backend via a compile-time feature flag: `--features simd-vectorscan`, `--features simd-hyperscan`, or `--features simd-aho-corasick` (default, zero native deps).
- [ ] **Dual-database split: streaming vs. block mode.** Vectorscan and Hyperscan both support a streaming mode (for chunked/spilled bodies) and a block mode (for fully-buffered bodies). Compile two databases at rule load time; dispatch based on whether the body fit within `max_body_to_buffer`. Streaming mode maintains per-connection scratch state across chunks with no performance cliff when body size exceeds the buffer limit. Aho-Corasick operates in block mode only; invoke it per-chunk and union the match sets.
- [ ] **SIMD engine scratch pool.** `hs_scratch_t` (Vectorscan/Hyperscan) is not thread-safe and must not be shared across concurrent requests. Maintain a `crossbeam` channel-backed pool of pre-allocated scratch objects (one per tokio worker thread) so the hot path never calls `hs_alloc_scratch`. The Aho-Corasick automaton is read-only and needs no per-thread state. Pool is rebuilt on SIGHUP when the rule set changes.

### Byte delimiter scanning: `memchr`

- [ ] **Replace all manual `find()`/`position()` header parsing with `memchr`.** `memchr::memchr()`, `memchr2()`, and `memchr3()` use SSE2 `_mm_cmpeq_epi8` + `_mm_movemask_epi8` under the hood and are already in the dependency graph of most Rust HTTP stacks. Concrete targets: `\r\n\r\n` header block boundary, `:` header name/value split, `=` and `&` query string field separators, `%` percent-encode prefix detection. Each is currently a scalar byte loop.
- [ ] **Suspicious character pre-filter using `memchr3` before regex.** Scan each inspection target for `<`, `'`, `"` (XSS markers) or `(`, `;`, `-` (SQLi markers) with `memchr3` before dispatching to either Vectorscan or the `regex` path. Requests with none of the trigger bytes skip the full pattern match entirely. Reduces engine CPU for benign traffic to near zero.

### UTF-8 validation: `simdutf8`

- [ ] **Replace `std::str::from_utf8` with `simdutf8::basic::from_utf8`.** Applied as the first step in body inspection before any normalization or decode pass. `simdutf8` uses SSE4.2 or AVX2 to validate 16/32 bytes per iteration, approximately 8x faster than the scalar stdlib check on a 10 KB body. Invalid UTF-8 is rejected before any rule ever runs, eliminating a class of encoding-confusion attacks.

### Base64 decode: `base64-simd`

- [ ] **`request_inspection.decode_base64_values` config flag.** When enabled, detect base64-encoded blobs in query parameter values and request body fields (heuristic: value length divisible by 4, character set `[A-Za-z0-9+/=]`), decode with `base64-simd` (AVX2 `vpshufb`, ~4x faster than scalar), and run rule matching against both the original and decoded form. Catches encoded SQL injection, encoded shell commands, and encoded prompt injection payloads that trivially bypass string-matching rules.

### Byte-class scan: `wide` crate (`PSHUFB` LUT)

- [ ] **SIMD character-class scanner for normalization pre-pass.** Before HTML-entity or unicode normalization runs, scan the full input for `&`, `%`, `\`, `+` using a `PSHUFB`-based 16-entry lookup table via the `wide` crate. This classifies 16 bytes per instruction and produces a bitmask of positions requiring normalization work. The normalizer then only processes those offsets rather than iterating every byte. Zero-cost for inputs with no special characters (the common case for benign traffic).

### Consistent-hash acceleration: `crc32fast`

- [ ] **Use `crc32fast` for the IP blocklist Bloom filter hash.** The `CRC32` instruction (SSE4.2) runs in 1 CPU cycle per 4 bytes vs. ~10 cycles for software CRC. Wire as both hash functions for the IP blocklist Bloom filter front-end. `crc32fast` detects SSE4.2 at runtime and falls back to a software implementation on older hardware.

### Benchmarking harness

- [ ] **Add a `benches/` directory with `criterion` microbenchmarks** covering: single-rule regex scan (baseline), Vectorscan N-rule scan, `memchr` delimiter search vs scalar, `simdutf8` vs stdlib, `base64-simd` vs `base64`. Run in CI on every PR that touches `engine.rs` or `runtime.rs`. Regressions in scan throughput are caught before merge, not in production.

