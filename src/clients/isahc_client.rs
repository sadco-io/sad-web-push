use std::time::Duration;

use async_trait::async_trait;
use futures_lite::AsyncReadExt;
use http::header::RETRY_AFTER;
use isahc::{
    config::{Configurable, RedirectPolicy},
    HttpClient,
};
use log::trace;

use crate::{
    clients::{request_builder, WebPushClient, DEFAULT_CONNECT_TIMEOUT, DEFAULT_TIMEOUT, MAX_RESPONSE_SIZE},
    error::WebPushError,
    message::WebPushMessage,
};

/// An async client for sending the notification payload. This client is expensive to create, and
/// should be reused.
///
/// This client is thread-safe. Clones of this client will share the same underlying resources,
/// so cloning is a cheap and effective method to provide access to the client.
///
/// This client is built on [`isahc`](https://crates.io/crates/isahc), and will therefore work on any async executor.
#[derive(Clone)]
pub struct IsahcWebPushClient {
    client: HttpClient,
}

impl Default for IsahcWebPushClient {
    /// Creates a new client with default timeouts (30s request, 10s connect).
    ///
    /// # Panics
    ///
    /// Panics if the underlying `isahc::HttpClient` cannot be initialized (for example
    /// under severe OS resource depletion). Prefer [`IsahcWebPushClient::new`] in fallible contexts.
    fn default() -> Self {
        Self::new().expect("failed to initialize default IsahcWebPushClient")
    }
}

impl From<HttpClient> for IsahcWebPushClient {
    /// Creates a new client from a custom Isahc HTTP client.
    fn from(client: HttpClient) -> Self {
        Self { client }
    }
}

impl IsahcWebPushClient {
    /// Creates a new client with default timeouts (30s request, 10s connect) and
    /// redirects disabled. Can fail under resource depletion.
    pub fn new() -> Result<Self, WebPushError> {
        let client = HttpClient::builder()
            .timeout(DEFAULT_TIMEOUT)
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .redirect_policy(RedirectPolicy::None)
            .build()?;
        Ok(Self { client })
    }

    /// Creates a new client with a custom per-request timeout and redirects disabled.
    ///
    /// The connect timeout is bounded by `min(10s, timeout)`.
    pub fn with_timeout(timeout: Duration) -> Result<Self, WebPushError> {
        let client = HttpClient::builder()
            .timeout(timeout)
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT.min(timeout))
            .redirect_policy(RedirectPolicy::None)
            .build()?;
        Ok(Self { client })
    }
}

fn disable_redirects<T>(request: http::Request<T>) -> Result<http::Request<T>, WebPushError> {
    let (parts, body) = request.into_parts();
    let mut builder = http::Request::builder()
        .method(parts.method)
        .uri(parts.uri)
        .version(parts.version)
        .redirect_policy(RedirectPolicy::None);
    if let Some(headers) = builder.headers_mut() {
        *headers = parts.headers;
    }
    builder.body(body).map_err(|_| WebPushError::Unspecified)
}

#[async_trait]
impl WebPushClient for IsahcWebPushClient {
    /// Sends a notification using the client's configured timeouts.
    async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        let ttl = message.ttl;
        let request = disable_redirects(request_builder::try_build_request::<isahc::AsyncBody>(message)?)?;

        trace!("Sending push request: host={:?} ttl={}", request.uri().host(), ttl);

        let response = self.client.send_async(request).await?;

        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|ra| ra.to_str().ok())
            .and_then(request_builder::parse_retry_after);

        let response_status = response.status();
        trace!("Response status: {}", response_status);

        let mut body = Vec::new();
        if response
            .into_body()
            .take(MAX_RESPONSE_SIZE as u64 + 1)
            .read_to_end(&mut body)
            .await?
            > MAX_RESPONSE_SIZE
        {
            return Err(WebPushError::ResponseTooLarge);
        }

        let response = request_builder::parse_response(response_status, body);

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

        let client = IsahcWebPushClient::with_timeout(Duration::from_secs(5)).unwrap();
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
    async fn times_out_on_stalled_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let _server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = IsahcWebPushClient::with_timeout(Duration::from_millis(150)).unwrap();
        let err = client.send(local_message(addr)).await.unwrap_err();
        assert!(matches!(err, WebPushError::Io(ref e) if e.kind() == std::io::ErrorKind::TimedOut));
    }

    #[tokio::test]
    async fn does_not_follow_redirects_even_with_custom_client() {
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
            for _ in 0..2 {
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
            }
        });

        // 1. Default client
        let default_client = IsahcWebPushClient::with_timeout(Duration::from_secs(5)).unwrap();
        let err = default_client.send(local_message(redirect_addr)).await.unwrap_err();
        assert!(matches!(err, WebPushError::Other(ref info) if info.code == 302));

        // 2. Custom HttpClient configured with RedirectPolicy::Follow must still be overridden per-request.
        let custom_http = HttpClient::builder()
            .redirect_policy(RedirectPolicy::Follow)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let wrapped_client = IsahcWebPushClient::from(custom_http);
        let err = wrapped_client.send(local_message(redirect_addr)).await.unwrap_err();
        assert!(matches!(err, WebPushError::Other(ref info) if info.code == 302));

        redirect_server.abort();
        target_server.abort();
        assert!(
            !target_hit.load(Ordering::SeqCst),
            "client must not follow HTTP redirects"
        );
    }
}
