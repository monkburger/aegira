WAF Ruleset Design Specification

Version: 1.1
Status: Current
Last Updated: 2026-03-20

## 1. Purpose

This document defines the implemented rules schema for aegira, including load behavior, validation rules, and target/action semantics.

A separate section covers suggested improvements and fields that would be useful to add in a future iteration.

## 2. Implemented Rules Schema (normative)

Rules are TOML objects under `[[rule]]`.

Required fields:

- `id` (u32, must be non-zero and unique across loaded files)
- `when` (array of strings; one or more targets)
- `match` (string; Rust `regex` syntax)
- `action` (string; see supported actions)

Optional fields and their defaults:

- `name` (string; default: none)
- `description` (string; default: none)
- `tags` (array of strings; default: `[]`)
- `enabled` (bool; default: `true`)
- `priority` (integer; default: `0`)
- `score` (non-negative integer; default: `0`)

Current Rust struct:

```rust
pub struct Rule {
    pub id: RuleId,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub when: Vec<Target>,
    pub r#match: String,
    pub action: Action,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub score: i32,
    #[serde(default, rename = "test")]
    pub tests: Vec<RuleTest>,
}
```

`RuleId` is a newtype wrapper: `pub struct RuleId(pub u32)`. `Action` and `Target` are typed enums deserialized by serde with alias support (see sections 2.1 and 2.2). `RuleTest` carries `input`, `target`, and `expect` fields for inline testing (see section 7.5).

### 2.1 Supported Targets (`when`)

| Canonical value | Alias | What is inspected |
|-----------------|-------|-------------------|
| `path` | | The URL path component |
| `query_string` | `query` | The raw query string |
| `request_headers` | `headers` | All request header values concatenated |
| `request_body` | `body` | The request body as a UTF-8 string |
| `cookies` | `cookie` | Individual cookie name=value pairs parsed from the `Cookie:` header |
| `response_headers` | | Response header values (requires `[response_inspection] inspect_headers = true`) |
| `response_body` | | Response body text (requires `[response_inspection] inspect_body = true`) |

Both the canonical and alias forms are accepted. Any other value causes a compile error at engine build time.

### 2.2 Supported Actions (`action`)

Canonical values:

- `log`
- `forward`
- `drop`

Accepted aliases (normalised at parse time):

- `allow`, `allow_and_log` resolve to `log`
- `send_to_honeypot` resolves to `forward`
- `reject`, `block` resolve to `drop`

### 2.3 Action Precedence

When multiple rules match the same request, the winning action is chosen by:

1. Action priority: `drop` (3) > `forward` (2) > `log` (1)
2. If two rules share the same action, the one with the higher `priority` field wins.
3. If priority is also equal, the rule with the lower `id` wins.

### 2.4 Forward Target Resolution

Rules do not carry per-rule destination fields. When the winning action is `forward`, the backend is resolved as:

1. `site.forward_target` if set on the matching site, else
2. `waf.default_forward_target` if set globally.

Both values reference a backend by name. Config validation fails if a forward target cannot be resolved.

### 2.5 Disabling Rules

Rules can be disabled in two ways:

- Set `enabled = false` in the rule file. The rule is skipped at load time and never enters the compiled bundle. This is a rule-author mechanism (e.g. temporarily retiring a rule without deleting it).
- List rule IDs under `disabled_rules` in `[waf]` (global) or in a `[[site]]` block (per-site). This is an operator mechanism applied at config load, without touching rule files.

## 3. Rule File Loading and Include Behavior (normative)

Rules are loaded from a configured entrypoint TOML file specified by `rules.entrypoint`. Each rule file may contain:

- `include = [ ... ]` (a list of paths to include)
- zero or more `[[rule]]` entries

Include entries support:

- a single file path
- a directory path (loads all `.toml` files in that directory)
- a glob pattern (`*`, `?`, `[]`)

Behavioral guarantees:

- Include depth is bounded by `rules.max_include_depth`.
- Files are deduplicated by canonical path; a file reached via multiple include paths is loaded only once.
- Directory and glob expansions are sorted lexically for deterministic load order.
- An include entry that resolves to zero files is a hard load error.
- `enabled = false` rules are dropped before the bundle is returned to the engine. They do not occupy an ID slot.
- Duplicate IDs: the first definition encountered wins. Subsequent definitions with the same ID are skipped and a warning is logged. This is not a fatal error.

## 4. Validation Rules (normative)

Load fails on:

- `id` is 0 or missing
- `score` is negative
- unsupported target in `when`
- unsupported or empty `action`
- invalid regex in `match`
- include path not found
- include that resolves to zero files
- include depth limit exceeded

Config validation also fails when:

- `site.forward_to` or `waf.default_forward_target` references an unknown backend name
- a site has rules that produce a `forward` action but no forward target is resolvable

Duplicate rule IDs produce a warning but do not fail the load.

## 5. Regex Engine Constraints (normative)

`match` uses the Rust `regex` crate.

Practical constraints:

- Linear-time matching; no catastrophic backtracking.
- No backreferences.
- No look-around assertions (lookahead/lookbehind).
- Invalid patterns cause a compile error at engine build time.

## 6. Minimal Valid Example

```toml
# rules/main.toml
include = ["common", "custom"]

[[rule]]
id     = 1001
when   = ["query_string", "body"]
match  = "(?i)(union\\s+select|sleep\\s*\\()"
action = "drop"
```

A rule with all optional fields set:

```toml
[[rule]]
id          = 1002
name        = "scanner_probe"
description = "Common scanner and fuzzer User-Agent strings."
tags        = ["recon", "scanner"]
enabled     = true
when        = ["headers"]
match       = "(?i)(sqlmap|nikto|acunetix|nuclei|dirbuster)"
action      = "forward"
priority    = 40
score       = 5
```

## 7. Extensions and Suggested Improvements

This section documents both implemented extensions (marked as such) and suggested additions worth considering in future iterations.

### 7.1 Rule Identity and Lifecycle Fields

**`severity`** (string or integer)

A human-readable severity classification with a fixed vocabulary: `info`, `low`, `medium`, `high`, `critical`. Useful for dashboards, alerting thresholds, and filtering rule reports without relying on the numeric `score`.

```toml
severity = "high"
```

**`cve`** / **`references`** (array of strings)

Links to the vulnerability or technique the rule detects. Useful when managing large rulesets and tracking which rules cover which known issues.

```toml
references = ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"]
```

**`created`** / **`updated`** (date strings)

Rule authorship dates. Useful for auditing which rules have not been reviewed recently.

```toml
created = "2025-11-01"
updated = "2026-02-15"
```

**`author`** (string)

Who wrote or last reviewed the rule. Especially useful in team environments.

```toml
author = "ops-team"
```

### 7.2 Method and Content-Type Constraints

A `methods` field restricts a rule to specific HTTP methods, avoiding false positives. For example, a rule targeting the body should not fire on a GET request.

```toml
methods     = ["POST", "PUT", "PATCH"]
content_types = ["application/json", "application/x-www-form-urlencoded"]
```

Without this, body-targeting rules currently match against an empty string on GET requests rather than being skipped.

### 7.3 Score Threshold Action (implemented)

Anomaly scoring is implemented. Each rule's `score` is accumulated per request. When the total reaches a configurable threshold, the request is blocked.

```toml
# In [waf]
anomaly_score_threshold = 50

# Per-site override in [[site]]
anomaly_score_threshold = 30
```

The global threshold is set in `[waf]` and can be overridden per `[[site]]` block. This follows the OWASP ModSecurity CRS model: individual rules contribute scores and the threshold determines when the accumulated evidence is sufficient to block.

### 7.4 Per-Rule Transforms

Before the regex is applied, a transforms list would preprocess the target value. This reduces rule duplication when the same pattern needs to handle multiple encoding layers.

```toml
transforms = ["url_decode", "lowercase", "html_entity_decode"]
```

Useful transforms: `url_decode`, `base64_decode`, `html_entity_decode`, `lowercase`, `normalize_whitespace`, `remove_nulls`.

This is separate from the global normalization flags in `[request_inspection]` because per-rule transforms let you target only the rules where they are relevant.

### 7.5 Inline Rule Tests (implemented)

Inline test cases are implemented. Each `[[rule]]` can carry `[[rule.test]]` blocks that are validated by `--check-config` without starting the daemon.

```toml
[[rule.test]]
input  = "' UNION SELECT 1,2,3--"
target = "query_string"
expect = "match"

[[rule.test]]
input  = "SELECT product FROM catalog WHERE id = 5"
target = "query_string"
expect = "no_match"
```

Note: the TOML key is `[[rule.test]]` (singular), not `[[rule.tests]]`. The struct field uses `#[serde(rename = "test")]`.

### 7.6 Rule Chaining / Compound Conditions

Some detection logic requires multiple conditions to all be true before firing. A `requires_all` field listing other rule IDs could gate a rule so it only applies if all listed rules also matched in the same request.

```toml
id           = 2050
requires_all = [2001, 2002]
when         = ["body"]
match        = "..."
action       = "drop"
```

This keeps individual detection rules simple while allowing complex compound logic without putting everything into one large regex.

### 7.7 Response Rules (partially implemented)

Response inspection targets are implemented in the `Target` enum: `response_headers` and `response_body`. Rules using these targets inspect the response rather than the request. No separate `direction` field is needed — the target itself determines inspection direction.

```toml
[[rule]]
id     = 9001
when   = ["response_headers"]
match  = "(?i)x-powered-by"
action = "log"
```

Response inspection must be enabled in config:

```toml
[response_inspection]
inspect_headers = true
inspect_body    = false   # enable for DLP-style rules
```

