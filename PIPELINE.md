# Request Processing Pipeline

This document describes the request lifecycle inside aegira. I mapped out what happens to every byte from TCP accept to response delivery, which function handles each stage, and why the design is structured this way. We did not build this pipeline by accident. I want to make sure the next developer understands the landmines we avoided.

## Table of contents

1. [Theoretical foundations](#1-theoretical-foundations)
2. [Pipeline overview](#2-pipeline-overview)
3. [Stage-by-stage reference](#3-stage-by-stage-reference)
4. [Positive and negative security models](#4-positive-and-negative-security-models)
5. [Source file map](#5-source-file-map)
6. [Test philosophy](#6-test-philosophy)
7. [Configuration design rationale](#7-configuration-design-rationale)
8. [References](#8-references)

## 1. Theoretical foundations

Four bodies of theory constrain our architecture. They answer why we split the pipeline and how we keep the system alive under load.

### 1.1 Chomsky Hierarchy and Thompson's Construction

Trying to parse SQL or HTML with regular expressions is a fool's errand. We wanted to avoid that entirely. The Chomsky Hierarchy (Chomsky 1956) classifies formal languages by the computational power required to recognize them.

| Type | Language class    | Recognizer              | Examples           |
|------|-------------------|-------------------------|--------------------|
| 3    | Regular           | Finite automaton (DFA)  | `SELECT.*FROM`     |
| 2    | Context-free      | Pushdown automaton      | HTML, JSON, SQL    |
| 1    | Context-sensitive | Linear bounded automaton| Natural language   |
| 0    | Recursively enum. | Turing machine          | Arbitrary programs |

Regex sits at Type 3. SQL, JSON, and HTML are Type 2 context-free languages. A regular expression cannot match balanced parentheses or recursive subqueries because it has no stack. If you rely solely on regex for input validation, you are mathematically incapable of enforcing a context-free grammar.

We rely on the Rust `regex` crate because it implements Thompson's construction (Thompson 1968). This gives us $O(n)$ time complexity and prevents the ReDoS (Regular Expression Denial of Service) landmines that plague NFA-based engines like PCRE. We get a strict performance guarantee. But it means our regex layer (`Engine::inspect`, `engine.rs:75`) functions strictly as a negative-security heuristic for known-bad patterns.

To handle the context-free problem, we use JSON Schema. The `SchemaRegistry` (`schema.rs:506`) validates structural invariants that regex cannot express. The two models cover different levels of the hierarchy.

### 1.2 Shannon Entropy and Normalization

We spend a lot of CPU cycles fighting the attacker on their own ground before the engine even sees the payload. Entropy reduction is our primary tool against obfuscation.

Claude Shannon defined the entropy of a discrete random variable as:

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

Natural language and SQL keywords have low entropy. Their symbol distribution is heavily skewed. An attacker who encodes shellcode inside base64 or hex strings pushes that entropy toward the theoretical maximum. The encoding flattens the distribution and hides the pattern.

Every normalization step we apply forces the representation back to a lowest-entropy canonical form:

* `recursive_percent_decode` (`runtime.rs:1973`): We decode up to three iterations of percent-encoding to stop double-encoding bypasses.
* `decode_html_entities` (`runtime.rs:2062`): We convert entity forms like `&lt;` back to `<`.
* `normalize_inspection_str` (`runtime.rs:2038`): Attackers love homoglyphs. By forcing NFKC normalization early (Unicode Consortium 2024), we collapse those "look-alike" characters into a single form before the regex engine even sees them. It is about reducing the search space.
* `decompress_for_inspection` (`runtime.rs:1644`): We inflate compressed bodies. Compression is entropy coding. The attacker uses it to hide the payload structure. We cap the output at `max_body_to_scan` to stop the CPU from melting when someone sends a 10 GB gzip bomb.

### 1.3 Relevance Theory and Configuration Design

Sperber and Wilson (1986) model human communication as an optimization problem in Relevance Theory. We applied this to the config design. Every configuration key must produce the maximum cognitive effect for the lowest cognitive effort.

We use typed enums for all policy fields instead of arbitrary strings. Serde rejects invalid values at parse time. A senior engineer can read one site block and confidently know the exact enforcement behavior. We don't use merge logic or priority layering for site configuration overrides. The site override replaces the global default entirely. One read yields one conclusion.

## 2. Pipeline overview

Every request passes through the stages below in this exact order. A stage that rejects the request short-circuits the pipeline. Later stages never execute. The positive-security model and the negative-security model are complementary steps in the same sequence.

```
                              +-----------------------------+
                              |      TCP Accept             |
                              |  serve()    runtime.rs:165  |
                              +--------------+--------------+
                                             |
                              +--------------v--------------+
                              |   PROXY Protocol (opt-in)   |
                              |  read_proxy_header()        |
                              |  proxy_protocol.rs:35       |
                              +--------------+--------------+
                                             |
                              +--------------v--------------+
                              |   TLS Termination / SNI     |
                              |  PolicyCertResolver::resolve|
                              |  tls.rs:138                 |
                              +--------------+--------------+
                                             |
                              +--------------v--------------+
                              |      Per-request handler    |
                              |  handle_request()           |
                              |  runtime.rs:614             |
                              +--------------+--------------+
                                             |
          +----------------------------------+----------------------------------+
          | Connection-level gates                                              |
          |                                                                     |
          |  IP Filter (block/allow CIDRs) ---- runtime.rs:665                  |
          |  Rate Limit (token bucket) -------- runtime.rs:679                  |
          +----------------------------------+----------------------------------+
                                             |
          +----------------------------------v----------------------------------+
          | Normalization                                                       |
          |                                                                     |
          |  Host resolution & SNI policy ---------- runtime.rs:708             |
          |  Recursive percent-decode -------------- recursive_percent_decode() |
          |                                          runtime.rs:1973            |
          |  Path collapse (../ traversal) --------- collapse_path()            |
          |                                          runtime.rs:1992            |
          |  Null-byte stripping ------------------- strip_null_bytes()         |
          |                                          runtime.rs:2010            |
          |  HTML entity + Unicode normalization --- normalize_inspection_str() |
          |                                          runtime.rs:2038            |
          |  Header normalization ------------------ runtime.rs:793             |
          |  Cookie parsing ------------------------ parse_cookies()            |
          |                                          runtime.rs:1616            |
          +----------------------------------+----------------------------------+
                                             |
                              +--------------v--------------+
                              |  Expect: 100-continue early |
                              |  rejection (pre-body scan)  |
                              |  runtime.rs:843             |
                              +--------------+--------------+
                                             |
                              +--------------v--------------+
                              |  Body materialization       |
                              |  materialize_body()         |
                              |  runtime.rs:1709            |
                              +--------------+--------------+
                                             |
                              +--------------v--------------+
                              |  Content-Encoding           |
                              |  decompression (inspect)    |
                              |  decompress_for_inspection()|
                              |  runtime.rs:1644            |
                              +--------------+--------------+
                                             |
                 +---------------------------v----------------------------+
                 |  POSITIVE SECURITY MODEL (Type 2: context-free)        |
                 |  Schema enforcement (OpenAPI 3.x)                      |
                 |                                                        |
                 |  SchemaRegistry::validate()     schema.rs:506          |
                 |  Called from runtime.rs:912                            |
                 |                                                        |
                 |  +- UnknownEndpoint  -> 400 (reject_unknown_endpoints) |
                 |  +- Invalid body     -> 400 (schema violation)         |
                 |  +- Valid body       -> continue                       |
                 |  +- NoSchema         -> continue (no spec coverage)    |
                 +---------------------------+----------------------------+
                                             |
                              +--------------v--------------+
                              |  Body inspection prep       |
                              |  prepare_body_for_inspection|
                              |  runtime.rs:1787            |
                              |  (form / JSON / multipart   |
                              |   decode + normalize)       |
                              +--------------+--------------+
                                             |
                 +---------------------------v----------------------------+
                 |  NEGATIVE SECURITY MODEL (Type 3: regular)             |
                 |  WAF / regex engine inspection                         |
                 |                                                        |
                 |  Engine::inspect()          engine.rs:75               |
                 |  Called from runtime.rs:972                            |
                 |                                                        |
                 |  Targets: path, query, headers, body, cookies          |
                 |  Actions: Drop > Forward > Log (precedence)            |
                 |  Anomaly scoring with per-site threshold               |
                 |                                                        |
                 |  +- Drop         -> 403                                |
                 |  +- Score >= thr -> 403                                |
                 |  +- Forward      -> honeypot/tarpit                    |
                 |  +- Log / none   -> continue                           |
                 +---------------------------+----------------------------+
                                             |
                              +--------------v--------------+
                              |  Observe mode downgrade     |
                              |  (Drop/Forward -> Log)      |
                              |  runtime.rs:983             |
                              +--------------+--------------+
                                             |
                              +--------------v--------------+
                              |  Proxy to backend           |
                              |  forward_request()          |
                              |  runtime.rs:1219            |
                              |  forward_http()   :1327     |
                              |  forward_unix_socket() uds  |
                              +--------------+--------------+
                                             |
                              +--------------v--------------+
                              |  Response-phase rules       |
                              |  Engine::inspect_response() |
                              |  engine.rs:191              |
                              |  runtime.rs:1100            |
                              |  (response_headers,         |
                              |   response_body targets)    |
                              |  Drop -> 502                |
                              +--------------+--------------+
                                             |
          +----------------------------------v----------------------------------+
          | Response finalization                                               |
          |                                                                     |
          |  Server / X-Powered-By stripping ---- runtime.rs:1167               |
          |  Audit logging ---------------------- runtime.rs:1175               |
          |  Debug headers (x-aegira-*) --------- runtime.rs:1189               |
          |  HSTS injection --------------------- build_hsts_value()          |
          |                                       runtime.rs:1208               |
          +----------------------------------+----------------------------------+
                                             |
                                             v
                                       Response sent
```

## 3. Stage-by-stage reference

Every stage runs in sequence. I documented the failure outcomes and locations so you can trace the logic quickly.

| # | Stage | Outcome on error | Function | File | Line |
|---|-------|------------------|----------|------|------|
| 1 | TCP accept | Connection refused | `serve` | `runtime.rs` | 165 |
| 2 | PROXY protocol | Falls back to TCP peer IP | `read_proxy_header` | `proxy_protocol.rs` | 35 |
| 3 | TLS / SNI routing | Handshake failure | `PolicyCertResolver::resolve` | `tls.rs` | 138 |
| 4 | Request counter | 503 during reload | `handle_request` | `runtime.rs` | 614 |
| 5 | Client IP resolution | Always succeeds | `real_client_ip` | `runtime.rs` | 2145 |
| 6 | Request ID | Mints UUIDv4 | inline | `runtime.rs` | 656 |
| 7 | IP filter | 403 | inline | `runtime.rs` | 665 |
| 8 | Rate limiting | 429 or log-only | `RateLimiterState::check_and_consume`| `runtime.rs` | 679 |
| 9 | Protocol detection | 501 | `is_grpc_request` | `runtime.rs` | 1589 |
| 10| Host resolution | 421 per policy | `strip_port` | `runtime.rs` | 708 |
| 11| URL normalization | Mutes exploits | `recursive_percent_decode` | `runtime.rs` | 1973 |
| 12| Null-byte stripping | Mutes exploits | `strip_null_bytes` | `runtime.rs` | 2010 |
| 13| HTML / Unicode norm.| Mutes exploits | `normalize_inspection_str` | `runtime.rs` | 2038 |
| 14| Header normalization| Mutes exploits | inline | `runtime.rs` | 793 |
| 15| Cookie parsing | Mutes exploits | `parse_cookies` | `runtime.rs` | 1616 |
| 16| 100-continue early| 403 | `engine.inspect` | `runtime.rs` | 843 |
| 17| Body materialize | 413 | `materialize_body` | `runtime.rs` | 1709 |
| 18| Decompression | Falls to raw bytes | `decompress_for_inspection`| `runtime.rs` | 1644 |
| 19| Schema enforcement| 400 | `SchemaRegistry::validate` | `schema.rs` | 506 |
| 20| Body inspection prep| Mutes exploits | `prepare_body_for_inspection`| `runtime.rs` | 1787 |
| 21| WAF regex engine | 403 | `Engine::inspect` | `engine.rs` | 75 |
| 22| Observe mode | Action logged | inline | `runtime.rs` | 983 |
| 23| Drop enforcement | 403 | inline | `runtime.rs` | 1010 |
| 24| Anomaly threshold | 403 | inline | `runtime.rs` | 1029 |
| 25| Forward reroute | Redirects | inline | `runtime.rs` | 1048 |
| 26| Proxy to backend | 502 | `forward_request` | `runtime.rs` | 1219 |
| 27| Response rules | 502 | `Engine::inspect_response` | `engine.rs` | 191 |
| 28| Header stripping | Cleans data | inline | `runtime.rs` | 1167 |
| 29| Audit logging | Writes metadata | inline | `runtime.rs` | 1175 |
| 30| Debug headers | Injects metadata | inline | `runtime.rs` | 1189 |
| 31| HSTS injection | Injects headers | `build_hsts_value` | `runtime.rs` | 1208 |

## 4. Positive and negative security models

### 4.1 Positive model: schema enforcement (Type 2)

OWASP has argued for years that "allow-listing" is superior to "block-listing" (OWASP 2023). Our `SchemaRegistry` is how we actually implement that. If it is not in the OpenAPI spec, it does not get in the building.

We use `from_openapi` (`schema.rs:103`) to load the inventory directly into memory. We validate incoming paths against the spec. If `reject_unknown_endpoints` is true and a client asks for a path we do not support, we drop the connection with a 400. If the body contains unrecognized fields and `additionalProperties: false` is active, we drop the connection. We don't bother asking the regex engine to look at it.

### 4.2 Negative model: regex engine (Type 3)

The negative model checks requests for known attack signatures. We built `Engine::inspect` (`engine.rs:75`) to iterate over compiled regex rules and match patterns against the payload. The engine accumulates an anomaly score and processes rules by strict precedence: Drop, then Forward, then Log.

## 5. Source file map

| File | Purpose |
|------|---------|
| `src/runtime.rs` | Main handler, normalization helpers, decompression, routing. |
| `src/tls.rs` | SNI routing, session ticket rotation. |
| `src/proxy_protocol.rs` | PROXY protocol parsing. |
| `src/engine.rs` | Regex rule processing and anomaly threshold matching. |
| `src/schema.rs` | OpenAPI processing and JSON schema validation. |
| `src/model.rs` | Type definitions for requests and actions. |
| `src/config.rs` | Parse-time serde validation for typed settings. |
| `src/rules.rs` | Loading rules from TOML. |
| `src/uds.rs` | Unix domain socket routing. |
| `src/daemon.rs` | Hot reload and signal tracking. |

## 6. Test philosophy

Karl Popper's falsifiability theory (Popper 1934) tells us that a theory is only meaningful if you can specify an observation to refute it. A test suite that just confirms "valid requests get handled correctly" provides zero confidence.

Our tests act like a hostile penetration tester. Every test encodes a specific bypass attack. We ask: "does this exploit succeed?" If the test passes, the bypass failed. If the test fails, we merge a fix.

### 6.1 Tested regex engine bypasses

| Test | Bypass Attempt |
|------|----------------|
| `drop_beats_forward` (`engine.rs:478`) | A later Forward rule overrides an earlier Drop rule |
| `global_disabled_rules_suppresses_match` (`engine.rs:520`) | Disabled rules execute anyway |
| `site_disabled_rules_suppresses_match` (`engine.rs:541`) | Site-level disables fail to apply locally |
| `max_matches_per_request_enforced` (`engine.rs:693`) | An attacker causes unbounded matching load |
| `case_insensitive_regex_always_matches` (`engine.rs:659`) | Mixed-case payload beats case-insensitive settings |

### 6.2 Tested normalization bypasses

| Test | Bypass Attempt |
|------|----------------|
| `recursive_percent_decode_double_encoded` (`runtime.rs:2389`) | Double encoding hides a string payload |
| `collapse_path_traversal` (`runtime.rs:2402`) | Path traversal inputs execute without collapsing |
| `collapse_path_normalizes_backslash` (`runtime.rs:2473`) | Backslash breaks the path separator collapse |
| `normalize_strips_zero_width_characters` (`runtime.rs:2436`) | Invisible Unicode tricks the keyword matcher |
| `decode_form_data_recursive_decode` (`runtime.rs:2429`) | Encoded form parameters skip the inspector |
| `decode_form_data_hpp_concatenation` (`runtime.rs:2421`) | HTTP parameter pollution splits the bad payload |
| `strip_null_bytes_removes_nulls` (`runtime.rs:2415`) | Null bytes force early string truncation |

### 6.3 Tested schema enforcement bypasses

| Test | Bypass Attempt |
|------|----------------|
| `missing_required_field_fails` (`schema.rs:624`) | Missing fields sail through unchecked |
| `extra_field_rejected_by_additional_properties_false` (`schema.rs:638`) | Fat data payloads beat the schema check |
| `wrong_type_fails` (`schema.rs:652`) | Data type swaps ruin checking |
| `deeply_nested_json_rejected` (`schema.rs:791`) | Massive nest depth causes failure |
| `body_exceeding_max_bytes_fails` (`schema.rs:777`) | Large bodies melt the JSON parser |
| `malformed_json_fails` (`schema.rs:751`) | Garbage data gets skipped |
| `reject_unknown_endpoints_blocks_unlisted_path` (`schema.rs`) | Unlisted endpoints get processed regardless |
| `world_writable_spec_rejected` (`schema.rs:885`) | Attackers modify the local spec easily |

## 7. Configuration design rationale

We optimized the config layout directly. It takes one file edit to turn on enforcement. You add one file to the rules folder to expand capacity. You do not edit massive monolithic blocks of code. Adding detection means adding a TOML target. Removing action means deleting the TOML target. No fragile line offset indexing.

## 8. References

* Chomsky, N. (1956). "Three models for the description of language." *IRE Transactions on Information Theory*, 2(3), 113-124.
* OWASP (2023). "Injection Prevention Cheat Sheet." *Open Worldwide Application Security Project*.
* Popper, K. (1934). *Logik der Forschung*. Vienna: Julius Springer Verlag. English translation: *The Logic of Scientific Discovery* (1959). London: Hutchinson.
* Shannon, C.E. (1948). "A Mathematical Theory of Communication." *The Bell System Technical Journal*, 27(3), 379-423.
* Sperber, D. and Wilson, D. (1986). *Relevance: Communication and Cognition*. Oxford: Blackwell.
* The Unicode Consortium (2024). "Unicode Normalization Forms (UAX #15)."
* Thompson, K. (1968). "Regular Expression Search Algorithm." *Communications of the ACM*, 11(6), 419-422.
