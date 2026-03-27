//! Benchmark: reqwest::Client reuse vs per-request construction.
//!
//! Demonstrates the performance impact of building a new HTTP client on
//! every proxied request (current) vs sharing a pre-built client (fixed).
//!
//! Two benchmark groups:
//!
//! 1. `client_lifecycle` -- pure overhead of Client::builder().build()
//!    vs Client::clone().  This cost is added to every single proxied
//!    request in the current code.
//!
//! 2. `connection_reuse` -- sends batches of real HTTP requests to a
//!    local mock backend.  The "new client" variant opens a fresh TCP
//!    connection per request (no keep-alive); the "reused client"
//!    variant pools connections across the batch.
//!
//! Run:  cargo bench --bench client_reuse

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use reqwest::Client;
use std::time::Duration;

/// Build a reqwest::Client with the same settings as
/// `build_backend_http_client()` in runtime.rs.
fn build_client() -> Client {
    Client::builder()
        .use_rustls_tls()
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

/// Build a throwaway client that aggressively closes idle connections.
/// This mirrors the current per-request behavior but avoids exhausting
/// ephemeral ports during benchmarking.
fn build_throwaway_client() -> Client {
    Client::builder()
        .use_rustls_tls()
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap()
}

// -----------------------------------------------------------------------
// Group 1: raw construction cost
// -----------------------------------------------------------------------

fn bench_client_lifecycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("client_lifecycle");

    // Current code path: build a brand-new Client on every request.
    // This allocates a connection pool, configures TLS, etc.
    group.bench_function("build_new_client", |b| {
        b.iter(|| black_box(build_client()));
    });

    // Fixed code path: clone an existing Client.
    // reqwest::Client uses Arc internally -- clone is ~1 atomic increment.
    let existing = build_client();
    group.bench_function("clone_existing_client", |b| {
        b.iter(|| black_box(existing.clone()));
    });

    group.finish();
}

// -----------------------------------------------------------------------
// Group 2: actual HTTP requests showing connection pooling benefit
// -----------------------------------------------------------------------

fn bench_connection_reuse(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Spin up a minimal axum backend that returns "ok" for any request.
    let addr = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let app =
            axum::Router::new().route("/", axum::routing::any(|| async { "ok" }));

        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        // Give the server a moment to accept.
        tokio::time::sleep(Duration::from_millis(100)).await;
        addr
    });

    let url = format!("http://{addr}/");

    let mut group = c.benchmark_group("connection_reuse");
    // The per-request client variant opens a fresh TCP connection each
    // time; under sustained benchmarking this fills the OS TIME_WAIT
    // table and eventually exhausts ephemeral ports -- which is itself
    // a production symptom of the bug.  We use iter_custom to measure
    // only the operation time and tolerate the occasional EADDRNOTAVAIL.
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));

    // Current: a fresh Client (and fresh TCP connection) per request.
    group.bench_function("new_client_single_request", |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let url = url.clone();
            async move {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = std::time::Instant::now();
                    let client = build_throwaway_client();
                    // May fail under heavy bench load (ephemeral port
                    // exhaustion).  The client construction + TCP
                    // attempt cost is still captured.
                    match client.get(&url).send().await {
                        Ok(resp) => { black_box(resp.status()); }
                        Err(_) => {}
                    }
                    total += start.elapsed();
                }
                total
            }
        });
    });

    // Fixed: one shared Client; TCP connections are pooled & reused.
    // The pooled client keeps TCP connections alive so subsequent
    // requests skip the connect + handshake entirely.
    let shared = build_client();
    group.bench_function("reused_client_single_request", |b| {
        let client = shared.clone();
        b.to_async(&rt).iter_custom(|iters| {
            let client = client.clone();
            let url = url.clone();
            async move {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = std::time::Instant::now();
                    // Tolerate initial connection failures caused by
                    // ephemeral port exhaustion from the prior bench.
                    match client.get(&url).send().await {
                        Ok(resp) => { black_box(resp.status()); }
                        Err(_) => {}
                    }
                    total += start.elapsed();
                }
                total
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_client_lifecycle, bench_connection_reuse);
criterion_main!(benches);
