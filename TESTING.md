# Manual Testing Guide

This document describes how to exercise aegira by hand. It covers build verification, config validation, WAF inspection, hot reload, TLS, and observability. Each section is self-contained; run whichever tests are relevant to your change.

## Prerequisites

- Rust stable toolchain (1.75+)
- `curl` with HTTP/2 support (`curl --version` should list `http2`)
- `openssl` CLI (for generating test certificates)
- `jq` (for reading structured JSON logs)
- A local TCP listener to act as a backend (Python, netcat, or any HTTP server)

## 1. Build and Automated Tests

Run these first. If they fail, nothing below will work.

```sh
# Debug build
make build

# Release build (bakes version, commit, build date into binary)
make release

# Full test suite: 21 unit tests + 4 integration tests
make test

# Lint
make clippy
```

Verify the version stamp on the release binary:

```sh
./target/release/aegira --version
# Expected: aegira version=<tag> commit=<hash> build_date=<ISO8601>
```

## 2. Config and Rule Validation

`--check-config` parses the config, loads all rule files, and runs every `[[rule.test]]` inline test. It never starts a listener.

```sh
# Against the default config
make check-config

# Against a specific config
./target/debug/aegira --check-config --config /path/to/aegira.toml
```

**Expected output (success):**

```
config ok: sites=2 backends=3 routes=0 rules=3 rule_tests=0
```

The `rule_tests` count reflects how many `[[rule.test]]` blocks were executed.

### Deliberately break things

Test that validation catches errors:

```sh
# Duplicate rule ID
cp configs/rules/common/00-base.toml /tmp/dup.toml
cat >> /tmp/dup.toml <<'EOF'
[[rule]]
id    = 1001
when  = ["path"]
match = "foo"
action = "log"
EOF
# Point a config at a rules dir containing the duplicate, expect a load error.

# Invalid action
cat > /tmp/bad-action.toml <<'EOF'
[[rule]]
id    = 9999
when  = ["path"]
match = "test"
action = "explode"
EOF
# Expect: parse error for unknown action variant.

# Negative score
cat > /tmp/bad-score.toml <<'EOF'
[[rule]]
id    = 9998
when  = ["path"]
match = "test"
action = "log"
score = -5
EOF
# Expect: "negative score" error at load time.

# Zero ID
cat > /tmp/bad-id.toml <<'EOF'
[[rule]]
id    = 0
when  = ["path"]
match = "test"
action = "log"
EOF
# Expect: "zero id" error at load time.
```

### Inline rule test failure

Add a test case that should fail:

```toml
[[rule]]
id    = 9000
when  = ["body"]
match = "(?i)drop\\s+table"
action = "drop"

  [[rule.test]]
  input  = "harmless text"
  target = "body"
  expect = "match"
```

Run `--check-config`. Expected output:

```
FAIL rule 9000 test[0]: input "harmless text" against target 'body' expected match got no_match
```

Exit code should be non-zero.

## 3. Local Test Environment Setup

### Generate self-signed certificates

```sh
mkdir -p /tmp/aegira-test/certs

# Default cert
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /tmp/aegira-test/certs/default.key.pem \
  -out /tmp/aegira-test/certs/default.crt.pem \
  -days 1 -nodes -subj "/CN=localhost"

# Site cert (example: test.local)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /tmp/aegira-test/certs/test.local.key.pem \
  -out /tmp/aegira-test/certs/test.local.crt.pem \
  -days 1 -nodes -subj "/CN=test.local" \
  -addext "subjectAltName=DNS:test.local"
```

### Start a mock backend

A minimal HTTP server that echoes back whatever it receives:

```sh
# Python (listens on 127.0.0.1:8080)
python3 -c '
import http.server, json

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = json.dumps({"path": self.path, "method": "GET",
                           "headers": dict(self.headers)})
        self.wfile.write(body.encode())
    do_POST = do_GET

http.server.HTTPServer(("127.0.0.1", 8080), H).serve_forever()
' &
```

### Write a minimal test config

```sh
cat > /tmp/aegira-test/aegira.toml <<'TOML'
config_version = 1

[server]
graceful_shutdown_timeout = "5s"
graceful_reload_timeout = "10s"
reload_signal = "SIGHUP"

[listener]
bind = "127.0.0.1:8443"
serve_http1 = true
serve_http2 = true
serve_http3 = false
max_header_size = "64KiB"
read_timeout = "15s"
write_timeout = "30s"
idle_timeout = "90s"

[tls]
enabled = true
default_certificate = "/tmp/aegira-test/certs/default.crt.pem"
default_private_key = "/tmp/aegira-test/certs/default.key.pem"
minimum_version = "1.2"
unknown_sni = "use_default_site"
missing_sni = "use_default_site"
authority_mismatch = "log"
reload_certificates_on_sighup = true
hsts_enabled = false
hsts_max_age_seconds = 0
hsts_include_subdomains = false
hsts_preload = false
ticket_rotation_seconds = 0

[[site]]
server_name = "test.local"
certificate = "/tmp/aegira-test/certs/test.local.crt.pem"
private_key = "/tmp/aegira-test/certs/test.local.key.pem"
forward_to = "echo"
forward_target = "honeypot"
preserve_host_header = true
send_sni_to_backend = false
disabled_rules = []

[waf]
default_action = "allow"
default_forward_target = "honeypot"
on_engine_error = "fail_open"
on_rule_reload_error = "keep_running_with_old_rules"
request_id_header = "X-Request-ID"
warn_on_ignored_matches = true
max_matches_per_request = 32
anomaly_score_threshold = 50
disabled_rules = []

[protocol_support]
grpc_inspection = "headers_only"
websocket_inspection = "handshake_only"

[request_inspection]
inspect_headers = true
inspect_query_string = true
inspect_body = true
body_mode = "both"
max_body_to_buffer = "1MiB"
max_body_to_scan = "8MiB"
spill_large_bodies_to_disk = false
spill_directory = "/tmp"
decode_form_data = true
decode_json = true
decode_multipart = true
normalize_url_encoding = true
normalize_html_entities = true
normalize_unicode = true
decompress_body = true
inspect_cookies = true

[response_inspection]
inspect_headers = true
inspect_body = false
response_body_mode = "off"
remove_server_headers = true
remove_powered_by_headers = true
max_body_to_scan = "512KiB"

[forwarded_headers]
trust_forwarded_headers = false
trust_forwarded_headers_from = ["127.0.0.1/32"]
set_x_forwarded_for = true
set_x_forwarded_proto = true
set_x_forwarded_host = true

[ip_filter]
block = []
allow = []

[rate_limit]
enabled = false
requests_per_second = 100
burst_size = 200
exceeded_action = "reject"

[rules]
entrypoint = "rules/main.toml"
max_include_depth = 16

[[backend]]
name = "echo"
backend_address = "127.0.0.1:8080"
forward_using = "plain_http"
backend_protocol = "http1"
connect_timeout = "3s"
response_header_timeout = "10s"
keepalive = true
keepalive_idle_timeout = "30s"
max_idle_connections = 16
retry_requests = false
drain_on_reload = true

[[backend]]
name = "honeypot"
backend_address = "127.0.0.1:8080"
forward_using = "plain_http"
backend_protocol = "http1"
connect_timeout = "3s"
response_header_timeout = "10s"
keepalive = true
keepalive_idle_timeout = "30s"
max_idle_connections = 8
retry_requests = false
drain_on_reload = true

[logging]
format = "json"
write_to = "stdout"
level = "info"
redact_cookies = true
redact_authorization_header = true
redact_set_cookie_header = true
TOML
```

Copy the rule files into the test directory:

```sh
cp -r configs/rules /tmp/aegira-test/
```

### Start aegira

```sh
./target/debug/aegira --config /tmp/aegira-test/aegira.toml
```

Watch stdout for the startup log line:

```
aegira scaffold active  listen=127.0.0.1:8443  sites=1  backends=2  rules=3
```

## 4. Health and Metrics

```sh
# Health check (HTTPS, skip cert verification)
curl -sk https://127.0.0.1:8443/health | jq .
# Expected: {"ready":true,"reload_in_progress":false,"in_flight":0}

# Prometheus metrics
curl -sk https://127.0.0.1:8443/metrics
# Expected: text block with aegira_requests_total, aegira_in_flight, etc.
```

Verify that `aegira_ready` is `1` and `aegira_in_flight` is `0` at idle.

## 5. WAF Rule Inspection

All curl commands below use `-k` to skip TLS verification for the self-signed cert.

### 5.1 Clean request (should pass through)

```sh
curl -sk https://127.0.0.1:8443/hello
# Expected: 200 OK, response from the echo backend
```

### 5.2 SQL injection (drop action)

```sh
curl -sk -o /dev/null -w '%{http_code}\n' \
  'https://127.0.0.1:8443/search?q=1+UNION+SELECT+*+FROM+users'
# Expected: 403

curl -sk 'https://127.0.0.1:8443/search?q=1+UNION+SELECT+*+FROM+users'
# Expected body: "blocked by Aegira policy"
```

### 5.3 SQL injection in POST body

```sh
curl -sk -X POST -d 'payload=1 UNION SELECT password FROM accounts' \
  -o /dev/null -w '%{http_code}\n' \
  https://127.0.0.1:8443/api/data
# Expected: 403
```

### 5.4 Scanner detection (forward action)

Rule 1002 matches scanner user-agent strings and reroutes to the honeypot backend.

```sh
curl -sk -H 'User-Agent: sqlmap/1.5#stable' \
  https://127.0.0.1:8443/probe
# Expected: 200 (request is forwarded to honeypot, not blocked)
# Check aegira stdout for the audit log line showing action=forward
```

### 5.5 Admin path probe (log action)

Rule 2001 matches `/admin` on the path and logs without blocking.

```sh
curl -sk https://127.0.0.1:8443/admin/dashboard
# Expected: 200 (passes through to backend)
# Check aegira stdout for audit log line with matched_rule_ids containing 2001
```

### 5.6 Verify response headers

```sh
curl -sk -I https://127.0.0.1:8443/hello 2>&1 | grep -i 'x-aegira\|server\|x-powered-by'
# Expected:
#   x-aegira-action: allow (or log)
#   x-aegira-backend: echo
#   No 'Server:' header (removed by response_inspection.remove_server_headers)
#   No 'X-Powered-By' header
```

### 5.7 Request ID header

```sh
# Without a request ID (aegira generates one)
curl -sk -D- https://127.0.0.1:8443/hello 2>&1 | grep -i x-request-id
# Expected: X-Request-ID: <uuid-v4>

# With a request ID (aegira carries it through)
curl -sk -H 'X-Request-ID: my-trace-123' -D- https://127.0.0.1:8443/hello \
  2>&1 | grep -i x-request-id
# Expected: X-Request-ID: my-trace-123
```

### 5.8 Disabled rules

Disable rule 1001 (SQLi) for the test site and reload:

```sh
# Edit the config to add disabled_rules = [1001] under [[site]]
# Then: kill -HUP $(pidof aegira)

# Now the SQLi probe should pass through:
curl -sk -o /dev/null -w '%{http_code}\n' \
  'https://127.0.0.1:8443/search?q=1+UNION+SELECT+*+FROM+users'
# Expected: 200 (rule 1001 is disabled for this site)
```

### 5.9 Cookie inspection

```sh
curl -sk -b 'session=1 UNION SELECT * FROM users' \
  -o /dev/null -w '%{http_code}\n' \
  https://127.0.0.1:8443/page
# Expected: 403 (rule 1001 matches cookies target)
```

## 6. Body Handling

### 6.1 JSON body decoding

When `decode_json = true`, JSON bodies are flattened to key=value pairs before scanning.

```sh
curl -sk -X POST \
  -H 'Content-Type: application/json' \
  -d '{"query": "1 UNION SELECT * FROM users"}' \
  -o /dev/null -w '%{http_code}\n' \
  https://127.0.0.1:8443/api
# Expected: 403
```

### 6.2 Multipart body decoding

```sh
curl -sk -X POST \
  -F 'field=1 UNION SELECT * FROM users' \
  -o /dev/null -w '%{http_code}\n' \
  https://127.0.0.1:8443/upload
# Expected: 403
```

### 6.3 Compressed body (Content-Encoding: gzip)

```sh
echo '1 UNION SELECT * FROM users' | gzip | \
  curl -sk -X POST \
    -H 'Content-Encoding: gzip' \
    -H 'Content-Type: text/plain' \
    --data-binary @- \
    -o /dev/null -w '%{http_code}\n' \
    https://127.0.0.1:8443/api
# Expected: 403 (body is decompressed before inspection)
```

### 6.4 Large body rejection

```sh
# Generate a body larger than max_body_to_scan (8 MiB)
dd if=/dev/zero bs=1M count=9 2>/dev/null | \
  curl -sk -X POST \
    -H 'Content-Type: application/octet-stream' \
    --data-binary @- \
    -o /dev/null -w '%{http_code}\n' \
    https://127.0.0.1:8443/upload
# Expected: 413 Content Too Large
```

## 7. Normalisation

### 7.1 HTML entity evasion

Rule 1001 should still match after HTML entity decoding:

```sh
curl -sk -X POST \
  -d 'q=1 UNION&#x20;SELECT&#x20;*&#x20;FROM&#x20;users' \
  -o /dev/null -w '%{http_code}\n' \
  https://127.0.0.1:8443/search
# Expected: 403 (if normalize_html_entities is working, entities are decoded before matching)
```

### 7.2 URL encoding evasion

```sh
curl -sk -o /dev/null -w '%{http_code}\n' \
  'https://127.0.0.1:8443/search?q=1%20UNION%20SELECT%20%2A%20FROM%20users'
# Expected: 403
```

## 8. TLS

### 8.1 SNI-based certificate selection

```sh
# Request with a known SNI name
curl -sk --resolve test.local:8443:127.0.0.1 https://test.local:8443/hello
# Expected: 200, served with the test.local certificate

# Verify the cert
echo | openssl s_client -connect 127.0.0.1:8443 -servername test.local 2>/dev/null \
  | openssl x509 -noout -subject
# Expected: subject=CN = test.local
```

### 8.2 Unknown SNI

With `unknown_sni = "reject"` in the config:

```sh
curl -sk --resolve unknown.host:8443:127.0.0.1 https://unknown.host:8443/hello
# Expected: TLS handshake failure (connection refused at TLS level)
```

With `unknown_sni = "use_default_site"`:

```sh
# Falls back to the default certificate; connection succeeds
curl -sk --resolve unknown.host:8443:127.0.0.1 https://unknown.host:8443/hello
# Expected: 200 (served via the default site)
```

### 8.3 HSTS header

Enable HSTS in the test config (`hsts_enabled = true`, `hsts_max_age_seconds = 3600`), reload, then:

```sh
curl -sk -I https://127.0.0.1:8443/hello | grep -i strict-transport
# Expected: Strict-Transport-Security: max-age=3600
```

### 8.4 HTTP/2

```sh
curl -sk --http2 https://127.0.0.1:8443/hello -o /dev/null -w '%{http_version}\n'
# Expected: 2
```

### 8.5 TLS minimum version

Set `minimum_version = "1.3"` in config, reload, then:

```sh
curl -sk --tls-max 1.2 https://127.0.0.1:8443/hello
# Expected: TLS handshake failure (TLS 1.2 is below the minimum)
```

## 9. Hot Reload (SIGHUP)

### 9.1 Basic reload

```sh
# Send SIGHUP
kill -HUP $(pidof aegira)

# Check health immediately
curl -sk https://127.0.0.1:8443/health | jq .
# During reload: {"ready":false,"reload_in_progress":true,...}
# After reload:  {"ready":true,"reload_in_progress":false,...}

# Verify reload counter incremented
curl -sk https://127.0.0.1:8443/metrics | grep aegira_reload_total
# Expected: aegira_reload_total 1
```

### 9.2 Rule change on reload

Add a new rule, reload, and verify it takes effect:

```sh
cat >> /tmp/aegira-test/rules/common/00-base.toml <<'EOF'

[[rule]]
id    = 3001
when  = ["path"]
match = "(?i)/secret"
action = "drop"
EOF

kill -HUP $(pidof aegira)
sleep 1

curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/secret
# Expected: 403
```

### 9.3 Bad config survives reload

Introduce a syntax error and verify aegira keeps running with the old config:

```sh
echo 'INVALID TOML =' >> /tmp/aegira-test/aegira.toml

kill -HUP $(pidof aegira)
sleep 1

# Aegira should still be running with the old config
curl -sk https://127.0.0.1:8443/health | jq .
# Expected: {"ready":true,...}

# Fix the config
sed -i '/INVALID TOML/d' /tmp/aegira-test/aegira.toml
```

### 9.4 Certificate reload

Generate a fresh cert and swap it in:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /tmp/aegira-test/certs/test.local.key.pem \
  -out /tmp/aegira-test/certs/test.local.crt.pem \
  -days 1 -nodes -subj "/CN=test.local.refreshed" \
  -addext "subjectAltName=DNS:test.local"

kill -HUP $(pidof aegira)
sleep 1

echo | openssl s_client -connect 127.0.0.1:8443 -servername test.local 2>/dev/null \
  | openssl x509 -noout -subject
# Expected: subject=CN = test.local.refreshed
```

## 10. Per-Site Observe Mode

Set `mode = "observe"` on a site, reload, then send a request that would normally be blocked:

```sh
# Add mode = "observe" to the [[site]] block, then kill -HUP $(pidof aegira)

curl -sk -o /dev/null -w '%{http_code}\n' \
  'https://127.0.0.1:8443/search?q=1+UNION+SELECT+*+FROM+users'
# Expected: 200 (not 403; the drop action is downgraded to log)
# Check stdout log: action should be "log", with a note that the original action was "drop"
```

## 11. Anomaly Scoring

Test that requests accumulate scores and are blocked when the threshold is reached.

If a rule (e.g. ID 2001, `score = 5`) matches, the request accumulates 5 points. With a threshold of 50, a single match is not enough to block. But if you set `anomaly_score_threshold = 5` for the site:

```sh
# Edit the site block: anomaly_score_threshold = 5
# Reload: kill -HUP $(pidof aegira)

curl -sk -o /dev/null -w '%{http_code}\n' \
  https://127.0.0.1:8443/admin/dashboard
# Expected: 403 (score 5 meets threshold 5, request blocked)
```

## 12. Metrics Under Load

Send a batch of requests and verify counters:

```sh
# 100 clean requests
for i in $(seq 1 100); do
  curl -sk -o /dev/null https://127.0.0.1:8443/hello &
done
wait

curl -sk https://127.0.0.1:8443/metrics | grep aegira_requests_total
# Expected: aegira_requests_total >= 100

# 10 blocked requests
for i in $(seq 1 10); do
  curl -sk -o /dev/null 'https://127.0.0.1:8443/?q=UNION+SELECT' &
done
wait

curl -sk https://127.0.0.1:8443/metrics | grep aegira_blocked_total
# Expected: aegira_blocked_total >= 10
```

## 13. Graceful Shutdown

```sh
# Start a slow request in the background
curl -sk https://127.0.0.1:8443/slow &
CURL_PID=$!

# Send SIGTERM (or Ctrl-C)
kill $(pidof aegira)

# The slow request should complete (within graceful_shutdown_timeout)
wait $CURL_PID
echo "Exit code: $?"
# Expected: 0 (request completed before shutdown)
```

## 14. Audit Log Verification

With `format = "json"` and `write_to = "stdout"`, send a request that triggers a rule and inspect the log:

```sh
curl -sk 'https://127.0.0.1:8443/?q=UNION+SELECT+1' 2>/dev/null

# In the aegira terminal output, look for a JSON line containing:
# "message": "request_audit"
# "action": "drop"
# "matched_rule_ids": "1001"
# "match_fragments": "<the matched substring>"
# "request_id": "<uuid>"
```

Verify that `redact_cookies = true` is working:

```sh
curl -sk -b 'session=secret123' https://127.0.0.1:8443/hello

# In the log output, cookie values should appear as [redacted], not "secret123"
```

## 15. Cleanup

```sh
# Stop the mock backend
kill %1  # or whatever job number the Python server is

# Remove test artifacts
rm -rf /tmp/aegira-test
```
