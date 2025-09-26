use std::{
    convert::Infallible,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Once,
    time::Duration,
};

use aegira::{config::Config, engine::Engine, rules, runtime};
use anyhow::{Context, Result};
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    body::Incoming,
    server::conn::http1,
    service::service_fn,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use rcgen::generate_simple_self_signed;
use reqwest::StatusCode;
use serial_test::serial;
use tempfile::TempDir;
use tokio::{
    net::{TcpListener as TokioTcpListener, UnixListener},
    task::JoinHandle,
    time::{sleep, timeout},
};

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    let port = listener
        .local_addr()
        .context("read local address")?
        .port();
    Ok(port)
}

fn der_to_pem(label: &str, der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {label}-----\n"));
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn write_self_signed_pair(dir: &Path, host: &str, prefix: &str) -> Result<(PathBuf, PathBuf)> {
    let cert = generate_simple_self_signed(vec![host.to_string()])
        .context("generate self-signed certificate")?;

    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();

    let cert_path = dir.join(format!("{prefix}.crt.pem"));
    let key_path = dir.join(format!("{prefix}.key.pem"));

    fs::write(&cert_path, der_to_pem("CERTIFICATE", &cert_der))
        .with_context(|| format!("write cert PEM {}", cert_path.display()))?;
    fs::write(&key_path, der_to_pem("PRIVATE KEY", &key_der))
        .with_context(|| format!("write key PEM {}", key_path.display()))?;

    Ok((cert_path, key_path))
}

async fn spawn_tcp_backend(label: &'static str) -> Result<(u16, JoinHandle<()>)> {
    let listener = TokioTcpListener::bind("127.0.0.1:0")
        .await
        .context("bind TCP backend")?;
    let port = listener
        .local_addr()
        .context("read TCP backend local addr")?
        .port();

    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(label.to_string()))))
                });
                let io = TokioIo::new(stream);
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    Ok((port, task))
}

async fn spawn_uds_backend(socket_path: &Path, label: &'static str) -> Result<JoinHandle<()>> {
    if socket_path.exists() {
        fs::remove_file(socket_path)
            .with_context(|| format!("remove existing socket {}", socket_path.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind UDS backend {}", socket_path.display()))?;

    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(label.to_string()))))
                });
                let io = TokioIo::new(stream);
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    Ok(task)
}

fn install_rustls_provider_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn write_rules_file(temp: &TempDir, content: &str) -> Result<PathBuf> {
    let rules_dir = temp.path().join("rules");
    fs::create_dir_all(&rules_dir)
        .with_context(|| format!("create rules dir {}", rules_dir.display()))?;
    let rules_path = rules_dir.join("main.toml");
    fs::write(&rules_path, content)
        .with_context(|| format!("write rules file {}", rules_path.display()))?;
    Ok(rules_path)
}

async fn wait_for_health(base_url: &str, https: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(https)
        .timeout(Duration::from_millis(500))
        .build()
        .context("build health-check client")?;

    for _ in 0..80 {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await {
            if resp.status() == StatusCode::OK {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    anyhow::bail!("server did not become healthy at {base_url}")
}

async fn start_aegira_in_process(config_path: &Path) -> Result<JoinHandle<Result<()>>> {
    let config = Config::load(config_path)
        .with_context(|| format!("load config {}", config_path.display()))?;
    let bundle = rules::load_bundle(&config.rules.entrypoint, config.rules.max_include_depth)
        .context("load rules bundle")?;
    config.validate(&bundle).context("validate config")?;
    let engine = Engine::compile(&bundle).context("compile engine")?;
    let config_path_str = config_path.to_string_lossy().to_string();

    Ok(tokio::spawn(async move {
        runtime::serve(config, engine, &config_path_str).await
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn integration_tcp_and_unix_socket_backends() -> Result<()> {
    let temp = TempDir::new().context("create tempdir")?;

    let (tcp_port, tcp_task) = spawn_tcp_backend("tcp-backend").await?;
    let uds_socket = temp.path().join("echo.sock");
    let uds_task = spawn_uds_backend(&uds_socket, "uds-backend").await?;

    let rules_path = write_rules_file(
        &temp,
        r#"
[[rule]]
id = 1
name = "No-op"
when = ["path"]
match = "never_matches_this_path"
action = "log"
priority = 1
score = 0
"#,
    )?;

    let aegira_port = free_port()?;
    let config_path = temp.path().join("aegira.toml");
    let config_text = format!(
        r#"
config_version = 1

[server]
graceful_shutdown_timeout = "5s"
graceful_reload_timeout = "5s"
reload_signal = "SIGHUP"

[listener]
bind = "127.0.0.1:{aegira_port}"
serve_http1 = true
serve_http2 = false
serve_http3 = false
max_header_size = "64KiB"
read_timeout = "5s"
write_timeout = "5s"
idle_timeout = "10s"

[tls]
enabled = false
default_certificate = ""
default_private_key = ""
minimum_version = "1.2"
unknown_sni = "reject"
missing_sni = "use_default_site"
authority_mismatch = "reject"
reload_certificates_on_sighup = false

[[site]]
server_name = "tcp.test"
certificate = ""
private_key = ""
forward_to = "tcp_backend"
preserve_host_header = true
send_sni_to_backend = true

[[site]]
server_name = "uds.test"
certificate = ""
private_key = ""
forward_to = "uds_backend"
preserve_host_header = true
send_sni_to_backend = true

[waf]
default_action = "allow"
on_engine_error = "fail_open"
on_rule_reload_error = "keep_running_with_old_rules"
request_id_header = "X-Request-ID"
warn_on_ignored_matches = true
max_matches_per_request = 32
emit_debug_headers = true

[protocol_support]
grpc_inspection = "headers_only"
websocket_inspection = "handshake_only"

[request_inspection]
inspect_headers = true
inspect_query_string = true
inspect_body = true
body_mode = "both"
max_body_to_buffer = "1MiB"
max_body_to_scan = "1MiB"
spill_large_bodies_to_disk = false
spill_directory = "/tmp"
decode_form_data = true
decode_json = true
decode_multipart = true
normalize_url_encoding = true
normalize_html_entities = true
normalize_unicode = true

[response_inspection]
inspect_headers = true
inspect_body = false
response_body_mode = "off"
remove_server_headers = false
remove_powered_by_headers = false
max_body_to_scan = "128KiB"

[forwarded_headers]
trust_forwarded_headers = false
trust_forwarded_headers_from = []
set_x_forwarded_for = true
set_x_forwarded_proto = true
set_x_forwarded_host = true

[rules]
entrypoint = "{}"
max_include_depth = 16

[[backend]]
name = "tcp_backend"
backend_address = "127.0.0.1:{tcp_port}"
forward_using = "plain_http"
backend_protocol = "http1"

[[backend]]
name = "uds_backend"
backend_address = "unix://{}"
forward_using = "unix_socket"
backend_protocol = "http1"

[[route]]
host = "tcp.test"
path_prefix = "/"
forward_to = "tcp_backend"

[[route]]
host = "uds.test"
path_prefix = "/"
forward_to = "uds_backend"

[logging]
format = "text"
write_to = "stdout"
file = ""
level = "info"
redact_cookies = true
redact_authorization_header = true
redact_set_cookie_header = true
"#,
        rules_path.display(),
        uds_socket.display(),
    );
    fs::write(&config_path, config_text)
        .with_context(|| format!("write config {}", config_path.display()))?;

    let aegira_task = start_aegira_in_process(&config_path).await?;
    let base_url = format!("http://127.0.0.1:{aegira_port}");
    wait_for_health(&base_url, false).await?;

    let client = reqwest::Client::new();

    let tcp_resp = client
        .get(format!("{base_url}/ping"))
        .header("Host", "tcp.test")
        .send()
        .await
        .context("request through TCP site")?;
    assert_eq!(tcp_resp.status(), StatusCode::OK);
    assert_eq!(
        tcp_resp
            .headers()
            .get("x-aegira-backend")
            .and_then(|v| v.to_str().ok()),
        Some("tcp_backend")
    );
    assert_eq!(tcp_resp.text().await?, "tcp-backend");

    let uds_resp = client
        .get(format!("{base_url}/ping"))
        .header("Host", "uds.test")
        .send()
        .await
        .context("request through UDS site")?;
    assert_eq!(uds_resp.status(), StatusCode::OK);
    assert_eq!(
        uds_resp
            .headers()
            .get("x-aegira-backend")
            .and_then(|v| v.to_str().ok()),
        Some("uds_backend")
    );
    assert_eq!(uds_resp.text().await?, "uds-backend");

    aegira_task.abort();
    tcp_task.abort();
    uds_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn integration_tls_multi_vhost_routing() -> Result<()> {
    install_rustls_provider_once();
    let temp = TempDir::new().context("create tempdir")?;

    let (alpha_backend_port, alpha_task) = spawn_tcp_backend("alpha-backend").await?;
    let (beta_backend_port, beta_task) = spawn_tcp_backend("beta-backend").await?;

    let (default_cert, default_key) = write_self_signed_pair(temp.path(), "alpha.tls.test", "default")?;
    let (alpha_cert, alpha_key) = write_self_signed_pair(temp.path(), "alpha.tls.test", "alpha")?;
    let (beta_cert, beta_key) = write_self_signed_pair(temp.path(), "beta.tls.test", "beta")?;

    let rules_path = write_rules_file(
        &temp,
        r#"
[[rule]]
id = 11
name = "No-op"
when = ["path"]
match = "never_matches_this_path"
action = "log"
priority = 1
score = 0
"#,
    )?;

    let aegira_port = free_port()?;
    let config_path = temp.path().join("aegira.toml");
    let config_text = format!(
        r#"
config_version = 1

[server]
graceful_shutdown_timeout = "5s"
graceful_reload_timeout = "5s"
reload_signal = "SIGHUP"

[listener]
bind = "127.0.0.1:{aegira_port}"
serve_http1 = true
serve_http2 = false
serve_http3 = false
max_header_size = "64KiB"
read_timeout = "5s"
write_timeout = "5s"
idle_timeout = "10s"

[tls]
enabled = true
default_certificate = "{}"
default_private_key = "{}"
minimum_version = "1.2"
unknown_sni = "reject"
missing_sni = "reject"
authority_mismatch = "reject"
reload_certificates_on_sighup = false

[[site]]
server_name = "alpha.tls.test"
certificate = "{}"
private_key = "{}"
forward_to = "alpha_backend"
preserve_host_header = true
send_sni_to_backend = true

[[site]]
server_name = "beta.tls.test"
certificate = "{}"
private_key = "{}"
forward_to = "beta_backend"
preserve_host_header = true
send_sni_to_backend = true

[waf]
default_action = "allow"
on_engine_error = "fail_open"
on_rule_reload_error = "keep_running_with_old_rules"
request_id_header = "X-Request-ID"
warn_on_ignored_matches = true
max_matches_per_request = 32
emit_debug_headers = true

[protocol_support]
grpc_inspection = "headers_only"
websocket_inspection = "handshake_only"

[request_inspection]
inspect_headers = true
inspect_query_string = true
inspect_body = true
body_mode = "both"
max_body_to_buffer = "1MiB"
max_body_to_scan = "1MiB"
spill_large_bodies_to_disk = false
spill_directory = "/tmp"
decode_form_data = true
decode_json = true
decode_multipart = true
normalize_url_encoding = true
normalize_html_entities = true
normalize_unicode = true

[response_inspection]
inspect_headers = true
inspect_body = false
response_body_mode = "off"
remove_server_headers = false
remove_powered_by_headers = false
max_body_to_scan = "128KiB"

[forwarded_headers]
trust_forwarded_headers = false
trust_forwarded_headers_from = []
set_x_forwarded_for = true
set_x_forwarded_proto = true
set_x_forwarded_host = true

[rules]
entrypoint = "{}"
max_include_depth = 16

[[backend]]
name = "alpha_backend"
backend_address = "127.0.0.1:{alpha_backend_port}"
forward_using = "plain_http"
backend_protocol = "http1"

[[backend]]
name = "beta_backend"
backend_address = "127.0.0.1:{beta_backend_port}"
forward_using = "plain_http"
backend_protocol = "http1"

[[route]]
host = "alpha.tls.test"
path_prefix = "/"
forward_to = "alpha_backend"

[[route]]
host = "beta.tls.test"
path_prefix = "/"
forward_to = "beta_backend"

[logging]
format = "text"
write_to = "stdout"
file = ""
level = "info"
redact_cookies = true
redact_authorization_header = true
redact_set_cookie_header = true
"#,
        default_cert.display(),
        default_key.display(),
        alpha_cert.display(),
        alpha_key.display(),
        beta_cert.display(),
        beta_key.display(),
        rules_path.display(),
    );
    fs::write(&config_path, config_text)
        .with_context(|| format!("write config {}", config_path.display()))?;

    let aegira_task = start_aegira_in_process(&config_path).await?;

    let alpha_addr = format!("127.0.0.1:{aegira_port}").parse()?;
    let beta_addr = format!("127.0.0.1:{aegira_port}").parse()?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve("alpha.tls.test", alpha_addr)
        .resolve("beta.tls.test", beta_addr)
        .timeout(Duration::from_millis(700))
        .build()
        .context("build TLS test client")?;

    for _ in 0..80 {
        if let Ok(resp) = client
            .get(format!("https://alpha.tls.test:{aegira_port}/health"))
            .send()
            .await
        {
            if resp.status() == StatusCode::OK {
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    let health = client
        .get(format!("https://alpha.tls.test:{aegira_port}/health"))
        .send()
        .await
        .context("health check after warmup")?;
    assert_eq!(health.status(), StatusCode::OK);

    let alpha_resp = client
        .get(format!("https://alpha.tls.test:{aegira_port}/route"))
        .send()
        .await
        .context("request alpha vhost")?;
    assert_eq!(alpha_resp.status(), StatusCode::OK);
    assert_eq!(
        alpha_resp
            .headers()
            .get("x-aegira-backend")
            .and_then(|v| v.to_str().ok()),
        Some("alpha_backend")
    );
    assert_eq!(alpha_resp.text().await?, "alpha-backend");

    let beta_resp = client
        .get(format!("https://beta.tls.test:{aegira_port}/route"))
        .send()
        .await
        .context("request beta vhost")?;
    assert_eq!(beta_resp.status(), StatusCode::OK);
    assert_eq!(
        beta_resp
            .headers()
            .get("x-aegira-backend")
            .and_then(|v| v.to_str().ok()),
        Some("beta_backend")
    );
    assert_eq!(beta_resp.text().await?, "beta-backend");

    aegira_task.abort();
    alpha_task.abort();
    beta_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn integration_reload_failure_keeps_old_rules() -> Result<()> {
    let temp = TempDir::new().context("create tempdir")?;

    let (backend_port, backend_task) = spawn_tcp_backend("reload-backend").await?;

    let rules_path = write_rules_file(
        &temp,
        r#"
[[rule]]
id = 21
name = "Drop blocked path"
when = ["path"]
match = "blocked"
action = "drop"
priority = 90
score = 10
"#,
    )?;

    let aegira_port = free_port()?;
    let config_path = temp.path().join("aegira.toml");
    let config_text = format!(
        r#"
config_version = 1

[server]
graceful_shutdown_timeout = "5s"
graceful_reload_timeout = "5s"
reload_signal = "SIGHUP"

[listener]
bind = "127.0.0.1:{aegira_port}"
serve_http1 = true
serve_http2 = false
serve_http3 = false
max_header_size = "64KiB"
read_timeout = "5s"
write_timeout = "5s"
idle_timeout = "10s"

[tls]
enabled = false
default_certificate = ""
default_private_key = ""
minimum_version = "1.2"
unknown_sni = "reject"
missing_sni = "use_default_site"
authority_mismatch = "reject"
reload_certificates_on_sighup = false

[[site]]
server_name = "reload.test"
certificate = ""
private_key = ""
forward_to = "main_backend"
preserve_host_header = true
send_sni_to_backend = true

[waf]
default_action = "allow"
on_engine_error = "fail_open"
on_rule_reload_error = "keep_running_with_old_rules"
request_id_header = "X-Request-ID"
warn_on_ignored_matches = true
max_matches_per_request = 32

[protocol_support]
grpc_inspection = "headers_only"
websocket_inspection = "handshake_only"

[request_inspection]
inspect_headers = true
inspect_query_string = true
inspect_body = true
body_mode = "both"
max_body_to_buffer = "1MiB"
max_body_to_scan = "1MiB"
spill_large_bodies_to_disk = false
spill_directory = "/tmp"
decode_form_data = true
decode_json = true
decode_multipart = true
normalize_url_encoding = true
normalize_html_entities = true
normalize_unicode = true

[response_inspection]
inspect_headers = true
inspect_body = false
response_body_mode = "off"
remove_server_headers = false
remove_powered_by_headers = false
max_body_to_scan = "128KiB"

[forwarded_headers]
trust_forwarded_headers = false
trust_forwarded_headers_from = []
set_x_forwarded_for = true
set_x_forwarded_proto = true
set_x_forwarded_host = true

[rules]
entrypoint = "{}"
max_include_depth = 16

[[backend]]
name = "main_backend"
backend_address = "127.0.0.1:{backend_port}"
forward_using = "plain_http"
backend_protocol = "http1"

[[route]]
host = "reload.test"
path_prefix = "/"
forward_to = "main_backend"

[logging]
format = "text"
write_to = "stdout"
file = ""
level = "info"
redact_cookies = true
redact_authorization_header = true
redact_set_cookie_header = true
"#,
        rules_path.display(),
    );
    fs::write(&config_path, config_text)
        .with_context(|| format!("write config {}", config_path.display()))?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_aegira"))
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn aegira binary")?;

    let base_url = format!("http://127.0.0.1:{aegira_port}");
    wait_for_health(&base_url, false).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build reload test client")?;

    let before = client
        .get(format!("{base_url}/blocked"))
        .header("Host", "reload.test")
        .send()
        .await
        .context("request before reload")?;
    assert_eq!(before.status(), StatusCode::FORBIDDEN);

    fs::write(
        &rules_path,
        r#"
[[rule]]
id = 21
name = "Broken regex rule"
when = ["path"]
match = "("
action = "drop"
priority = 90
score = 10
"#,
    )
    .with_context(|| format!("write broken rules {}", rules_path.display()))?;

    let pid = child.id();
    let status = Command::new("kill")
        .arg("-HUP")
        .arg(pid.to_string())
        .status()
        .context("send SIGHUP")?;
    if !status.success() {
        anyhow::bail!("failed to signal aegira for reload");
    }

    sleep(Duration::from_millis(500)).await;

    let after = client
        .get(format!("{base_url}/blocked"))
        .header("Host", "reload.test")
        .send()
        .await
        .context("request after failed reload")?;
    assert_eq!(after.status(), StatusCode::FORBIDDEN);

    shutdown_child(&mut child).await?;
    backend_task.abort();
    Ok(())
}

#[tokio::test]
#[serial]
async fn integration_rule_conflict_duplicate_id_fails_load() -> Result<()> {
    let temp = TempDir::new().context("create tempdir")?;
    let rules_root = temp.path().join("rules");
    fs::create_dir_all(rules_root.join("common")).context("create rules directories")?;

    fs::write(
        rules_root.join("main.toml"),
        r#"
include = ["common"]
"#,
    )
    .context("write entrypoint rules")?;

    fs::write(
        rules_root.join("common/00-first.toml"),
        r#"
[[rule]]
id = 77
name = "First"
when = ["path"]
match = "a"
action = "log"
priority = 10
score = 1
"#,
    )
    .context("write first conflicting rule")?;

    fs::write(
        rules_root.join("common/10-second.toml"),
        r#"
[[rule]]
id = 77
name = "Second"
when = ["path"]
match = "b"
action = "drop"
priority = 20
score = 2
"#,
    )
    .context("write second conflicting rule")?;

    let err = rules::load_bundle(rules_root.join("main.toml"), 16)
        .expect_err("duplicate rule id should fail bundle load");
    let msg = format!("{err:#}");
    assert!(msg.contains("duplicate rule id 77"), "unexpected error: {msg}");
    Ok(())
}

async fn shutdown_child(child: &mut Child) -> Result<()> {
    let _ = child.kill();
    let _ = timeout(Duration::from_secs(2), async {
        let _ = child.wait();
    })
    .await;
    Ok(())
}
