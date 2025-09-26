use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result};
use axum::body::Body;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::{net::UnixStream, time::timeout};
use tower::Service;
use tracing::warn;

use crate::runtime::HopByHopHeaders;

/// Minimal `tower::Service` connector that opens a fresh `UnixStream`
/// to a fixed path on each call.  Connection pooling is unnecessary
/// here because UDS backends are typically per-worker sockets with
/// trivial connect overhead.
#[derive(Clone)]
pub struct UnixConnector {
    path: String,
}

impl UnixConnector {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl Service<()> for UnixConnector {
    type Response = TokioIo<UnixStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        let path = self.path.clone();
        Box::pin(async move {
            let stream = UnixStream::connect(&path).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

/// Forward a request over a Unix domain socket using hyper's HTTP/1.1 codec.
pub async fn forward_unix_socket(
    socket_path: &str,
    request: Request<Bytes>,
    connect_timeout: Option<Duration>,
    response_header_timeout: Option<Duration>,
) -> Result<Response<Body>> {
    let connect_fut = UnixStream::connect(socket_path);
    let stream = if let Some(limit) = connect_timeout {
        timeout(limit, connect_fut).await.with_context(|| {
            format!(
                "connect timeout after {:?} to unix socket {socket_path}",
                limit
            )
        })??
    } else {
        connect_fut
            .await
            .with_context(|| format!("connect to unix socket {socket_path}"))?
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake::<_, Full<Bytes>>(io)
        .await
        .with_context(|| format!("HTTP/1.1 handshake over unix socket {socket_path}"))?;

    // Drive the connection in the background; it completes when the
    // backend closes.
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            warn!(error = %err, "unix socket connection error");
        }
    });

    // Convert the body to Full<Bytes> and strip hop-by-hop headers.
    let (mut parts, body) = request.into_parts();
    for name in HopByHopHeaders::NAMES {
        parts.headers.remove(*name);
    }
    let hyper_req = Request::from_parts(parts, Full::new(body));

    let send_fut = sender.send_request(hyper_req);
    let hyper_resp = if let Some(limit) = response_header_timeout {
        timeout(limit, send_fut).await.with_context(|| {
            format!(
                "response header timeout after {:?} from unix socket {socket_path}",
                limit
            )
        })??
    } else {
        send_fut
            .await
            .with_context(|| format!("send request over unix socket {socket_path}"))?
    };

    let (resp_parts, resp_body) = hyper_resp.into_parts();

    // Collect the full response body.
    let body_bytes = resp_body
        .collect()
        .await
        .with_context(|| format!("read response body from unix socket {socket_path}"))?
        .to_bytes();

    let mut response = Response::from_parts(resp_parts, Body::from(body_bytes));

    // Strip hop-by-hop headers from the response too.
    for name in HopByHopHeaders::NAMES {
        response.headers_mut().remove(*name);
    }

    Ok(response)
}
