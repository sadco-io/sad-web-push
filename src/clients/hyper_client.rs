use std::{io, time::Duration};

use async_trait::async_trait;
use http::header::RETRY_AFTER;
use hyper::{body::HttpBody, client::HttpConnector, Body, Client, Request as HttpRequest};
use hyper_tls::HttpsConnector;
use log::{debug, trace};

use crate::{
    clients::{request_builder, WebPushClient, DEFAULT_CONNECT_TIMEOUT, DEFAULT_TIMEOUT, MAX_RESPONSE_SIZE},
    error::WebPushError,
    message::WebPushMessage,
};

/// An async client for sending the notification payload.
///
/// This client is thread-safe. Clones of this client will share the same underlying resources,
/// so cloning is a cheap and effective method to provide access to the client.
///
/// This client is [`hyper`](https://crates.io/crates/hyper) based, and will only work in Tokio contexts.
#[derive(Clone)]
pub struct HyperWebPushClient {
    client: Client<HttpsConnector<HttpConnector>>,
    timeout: Option<Duration>,
}

impl Default for HyperWebPushClient {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Client<HttpsConnector<HttpConnector>>> for HyperWebPushClient {
    /// Creates a new client from a custom hyper HTTP client with the default 30s request timeout.
    fn from(client: Client<HttpsConnector<HttpConnector>>) -> Self {
        Self {
            client,
            timeout: Some(DEFAULT_TIMEOUT),
        }
    }
}

impl HyperWebPushClient {
    /// Creates a new client with default timeouts (30s request, 10s connect).
    pub fn new() -> Self {
        Self::build_with_timeouts(DEFAULT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT)
    }

    /// Creates a new client with a custom per-request timeout.
    ///
    /// The connect timeout is bounded by `min(10s, timeout)`.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self::build_with_timeouts(timeout, DEFAULT_CONNECT_TIMEOUT.min(timeout))
    }

    fn build_with_timeouts(timeout: Duration, connect_timeout: Duration) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(connect_timeout));
        let https = HttpsConnector::new_with_connector(http);

        Self {
            client: Client::builder().build(https),
            timeout: Some(timeout),
        }
    }

    async fn send_inner(&self, request: HttpRequest<Body>) -> Result<(), WebPushError> {
        let response = self.client.request(request).await?;

        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|ra| ra.to_str().ok())
            .and_then(request_builder::parse_retry_after);

        let response_status = response.status();
        trace!("Response status: {}", response_status);

        let mut chunks = response.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = chunks.data().await {
            let chunk = chunk?;
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_SIZE {
                return Err(WebPushError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }

        let response = request_builder::parse_response(response_status, body);

        debug!("Push response status: {}", response_status);

        if let Err(WebPushError::ServerError {
            retry_after: None,
            info,
        }) = response
        {
            Err(WebPushError::ServerError { retry_after, info })
        } else {
            response
        }
    }
}

#[async_trait]
impl WebPushClient for HyperWebPushClient {
    /// Sends a notification using the client's configured timeouts.
    async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        let ttl = message.ttl;
        let request: HttpRequest<Body> = request_builder::try_build_request(message)?;

        debug!("Sending push request: host={:?} ttl={}", request.uri().host(), ttl);

        let fut = self.send_inner(request);
        match self.timeout {
            Some(duration) => tokio::time::timeout(duration, fut)
                .await
                .map_err(|_| WebPushError::Io(io::Error::new(io::ErrorKind::TimedOut, "push request timed out")))?,
            None => fut.await,
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{SubscriptionInfo, WebPushMessageBuilder};

    fn local_message(addr: std::net::SocketAddr) -> WebPushMessage {
        let sub = SubscriptionInfo::new(
            format!("http://{addr}/push"),
            "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU".to_string(),
            "EvcWjEgzr4rbvhfi3yds0A".to_string(),
        );
        let mut builder = WebPushMessageBuilder::new(&sub);
        builder.allow_insecure_endpoint(true);
        builder.build().unwrap()
    }

    #[tokio::test]
    async fn times_out_on_stalled_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let _server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = HyperWebPushClient::with_timeout(Duration::from_millis(100));
        let err = client.send(local_message(addr)).await.unwrap_err();
        assert!(matches!(err, WebPushError::Io(ref e) if e.kind() == io::ErrorKind::TimedOut));
    }

    #[tokio::test]
    async fn rejects_oversized_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let Ok(Ok((mut socket, _))) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let payload = vec![b'A'; MAX_RESPONSE_SIZE + 128];
            let header = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(&payload).await;
        });

        let client = HyperWebPushClient::with_timeout(Duration::from_secs(5));
        let err = client.send(local_message(addr)).await.unwrap_err();
        server.abort();
        assert!(matches!(err, WebPushError::ResponseTooLarge));
    }

    #[tokio::test]
    async fn attaches_retry_after_on_429() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let Ok(Ok((mut socket, _))) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let resp =
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 42\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
        });

        let client = HyperWebPushClient::with_timeout(Duration::from_secs(5));
        let err = client.send(local_message(addr)).await.unwrap_err();
        server.abort();

        assert!(matches!(
            err,
            WebPushError::ServerError {
                retry_after: Some(d),
                ..
            } if d == Duration::from_secs(42)
        ));
    }

    #[tokio::test]
    async fn does_not_follow_redirects() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_hit = Arc::new(AtomicBool::new(false));
        let target_hit_clone = Arc::clone(&target_hit);

        let target_server = tokio::spawn(async move {
            if let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(Duration::from_secs(5), target_listener.accept()).await
            {
                target_hit_clone.store(true, Ordering::SeqCst);
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });

        let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_addr = redirect_listener.local_addr().unwrap();

        let redirect_server = tokio::spawn(async move {
            let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(Duration::from_secs(5), redirect_listener.accept()).await
            else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{target_addr}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        });

        let client = HyperWebPushClient::with_timeout(Duration::from_secs(5));
        let err = client.send(local_message(redirect_addr)).await.unwrap_err();
        redirect_server.abort();
        target_server.abort();

        assert!(matches!(err, WebPushError::Other(ref info) if info.code == 302));
        assert!(
            !target_hit.load(Ordering::SeqCst),
            "client must not follow HTTP redirects"
        );
    }
}
