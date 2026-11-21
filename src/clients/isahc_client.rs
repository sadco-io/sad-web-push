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
    endpoint::validate_uri,
    error::WebPushError,
    message::WebPushMessage,
};

/// Builder for configuring an [`IsahcWebPushClient`].
#[derive(Debug, Clone)]
pub struct IsahcWebPushClientBuilder {
    timeout: Duration,
    connect_timeout: Duration,
    allow_insecure_endpoints: bool,
}

impl Default for IsahcWebPushClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IsahcWebPushClientBuilder {
    /// Creates a new builder with default timeouts (30s request, 10s connect) and
    /// URL-level HTTPS/SSRF validation enabled.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            allow_insecure_endpoints: false,
        }
    }

    /// Sets the overall per-request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Allows `http://` and loopback/private endpoints when set to `true`
    /// (intended for local testing and mock servers).
    ///
    /// Note that `isahc` (libcurl) validates only the initial URL and does not
    /// filter IP addresses after DNS resolution; for connect-time IP pinning,
    /// prefer `HyperWebPushClient` (feature `hyper-client`).
    pub fn allow_insecure_endpoints(mut self, allow: bool) -> Self {
        self.allow_insecure_endpoints = allow;
        self
    }

    /// Builds the configured [`IsahcWebPushClient`] with HTTP redirects disabled.
    pub fn build(self) -> Result<IsahcWebPushClient, WebPushError> {
        let client = HttpClient::builder()
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .redirect_policy(RedirectPolicy::None)
            .build()?;
        Ok(IsahcWebPushClient {
            client,
            allow_insecure_endpoints: self.allow_insecure_endpoints,
        })
    }
}

/// An async client for sending the notification payload. This client is expensive to create, and
/// should be reused.
///
/// This client is thread-safe. Clones of this client will share the same underlying resources,
/// so cloning is a cheap and effective method to provide access to the client.
///
/// This client is built on [`isahc`](https://crates.io/crates/isahc) (`2.x`), and will therefore
/// work on any async executor. `IsahcWebPushClient` validates the initial URL at send time and
/// enforces `RedirectPolicy::None` per request, but delegates DNS resolution, proxy handling,
/// and TLS to `isahc`; for connect-time IP pinning, prefer `HyperWebPushClient`.
#[derive(Clone)]
pub struct IsahcWebPushClient {
    client: HttpClient,
    allow_insecure_endpoints: bool,
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
    /// Creates a new client from a custom Isahc HTTP client with URL-level HTTPS/SSRF
    /// validation and per-request `RedirectPolicy::None` enabled.
    ///
    /// The supplied client's proxy, TLS, and timeout settings are preserved.
    fn from(client: HttpClient) -> Self {
        Self {
            client,
            allow_insecure_endpoints: false,
        }
    }
}

impl IsahcWebPushClient {
    /// Creates a new client with default timeouts (30s request, 10s connect).
    /// Can fail under resource depletion.
    pub fn new() -> Result<Self, WebPushError> {
        Self::builder().build()
    }

    /// Creates a new client with a custom per-request timeout.
    ///
    /// The connect timeout is bounded by `min(10s, timeout)`.
    pub fn with_timeout(timeout: Duration) -> Result<Self, WebPushError> {
        Self::builder()
            .timeout(timeout)
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT.min(timeout))
            .build()
    }

    /// Returns an [`IsahcWebPushClientBuilder`] for customizing timeouts and endpoint policy.
    pub fn builder() -> IsahcWebPushClientBuilder {
        IsahcWebPushClientBuilder::new()
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
    /// Sends a notification using the client's configured timeouts and URL validation policy.
    async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        validate_uri(&message.endpoint, self.allow_insecure_endpoints)?;

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
        let bytes_read = response
            .into_body()
            .take(MAX_RESPONSE_SIZE as u64 + 1)
            .read_to_end(&mut body)
            .await
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::TimedOut {
                    WebPushError::Timeout
                } else {
                    WebPushError::Io(err)
                }
            })?;
        if bytes_read > MAX_RESPONSE_SIZE {
            return Err(WebPushError::ResponseTooLarge);
        }

        let response = request_builder::parse_response(response_status, body);

        match response {
            Err(WebPushError::TooManyRequests {
                retry_after: None,
                info,
            }) => Err(WebPushError::TooManyRequests { retry_after, info }),
            Err(WebPushError::ServerError {
                retry_after: None,
                info,
            }) => Err(WebPushError::ServerError { retry_after, info }),
            other => other,
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
    use crate::{SubscriptionInfo, VapidSignature, WebPushMessageBuilder};

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

        let server = tokio::spawn(async move {
            let Ok(Ok((_socket, _))) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await else {
                return;
            };
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = IsahcWebPushClient::builder()
            .timeout(Duration::from_millis(150))
            .connect_timeout(Duration::from_millis(150))
            .allow_insecure_endpoints(true)
            .build()
            .unwrap();
        let err = client.send(local_message(addr)).await.unwrap_err();
        server.abort();
        assert!(matches!(err, WebPushError::Timeout));
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

        let client = IsahcWebPushClient::builder()
            .timeout(Duration::from_secs(5))
            .allow_insecure_endpoints(true)
            .build()
            .unwrap();
        let err = client.send(local_message(addr)).await.unwrap_err();
        server.abort();
        assert!(matches!(err, WebPushError::ResponseTooLarge));
    }

    #[tokio::test]
    async fn returns_too_many_requests_with_retry_after_on_429() {
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

        let client = IsahcWebPushClient::builder()
            .timeout(Duration::from_secs(5))
            .allow_insecure_endpoints(true)
            .build()
            .unwrap();
        let err = client.send(local_message(addr)).await.unwrap_err();
        server.abort();

        assert!(matches!(
            err,
            WebPushError::TooManyRequests {
                retry_after: Some(d),
                ..
            } if d == Duration::from_secs(42)
        ));
    }

    #[tokio::test]
    async fn rejects_insecure_endpoints_by_default() {
        let client = IsahcWebPushClient::new().unwrap();
        let hand_constructed = WebPushMessage {
            endpoint: "http://127.0.0.1:8080/push".parse().unwrap(),
            ttl: 60,
            urgency: None,
            topic: None,
            payload: None,
            vapid_signature: None,
        };
        let err = client.send(hand_constructed).await.unwrap_err();
        assert!(matches!(err, WebPushError::InvalidUri));
    }

    #[tokio::test]
    async fn empty_payload_vapid_push_sends_authorization_without_content_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let Ok(Ok((mut socket, _))) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req_text = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = tx.send(req_text);
            let resp = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
        });

        let sub = SubscriptionInfo::new(
            format!("http://{addr}/push"),
            "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU".to_string(),
            "EvcWjEgzr4rbvhfi3yds0A".to_string(),
        );
        let mut builder = WebPushMessageBuilder::new(&sub);
        builder.allow_insecure_endpoint(true);
        builder.set_vapid_signature(VapidSignature {
            auth_t: "header.payload.sig".into(),
            auth_k: vec![4, 1, 2, 3],
        });

        let client = IsahcWebPushClient::builder()
            .timeout(Duration::from_secs(5))
            .allow_insecure_endpoints(true)
            .build()
            .unwrap();
        client.send(builder.build().unwrap()).await.unwrap();

        let raw_request = tokio::time::timeout(Duration::from_secs(5), rx).await.unwrap().unwrap();
        server.abort();

        let lower = raw_request.to_ascii_lowercase();
        assert!(lower.contains("authorization: vapid t=header.payload.sig, k="));
        assert!(!lower.contains("content-encoding:"));
        // Note: libcurl automatically adds `Content-Type: application/x-www-form-urlencoded`
        // to POST requests when no Content-Type is set, so verify no encrypted payload
        // Content-Type (`application/octet-stream`) was sent.
        assert!(!lower.contains("application/octet-stream"));
    }

    #[tokio::test]
    async fn times_out_during_response_body_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let Ok(Ok((mut socket, _))) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 100\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = IsahcWebPushClient::builder()
            .timeout(Duration::from_millis(200))
            .connect_timeout(Duration::from_millis(200))
            .allow_insecure_endpoints(true)
            .build()
            .unwrap();
        let err = client.send(local_message(addr)).await.unwrap_err();
        server.abort();
        assert!(
            matches!(err, WebPushError::Timeout),
            "expected WebPushError::Timeout on stalled body read, got {err:?}"
        );
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

        // 1. Default builder client
        let default_client = IsahcWebPushClient::builder()
            .timeout(Duration::from_secs(5))
            .allow_insecure_endpoints(true)
            .build()
            .unwrap();
        let err = default_client.send(local_message(redirect_addr)).await.unwrap_err();
        assert!(matches!(err, WebPushError::Other(ref info) if info.code == 302));

        // 2. Custom HttpClient with RedirectPolicy::Follow must still be overridden per-request.
        let custom_http = HttpClient::builder()
            .redirect_policy(RedirectPolicy::Follow)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mut wrapped_client = IsahcWebPushClient::from(custom_http);
        wrapped_client.allow_insecure_endpoints = true;
        let err = wrapped_client.send(local_message(redirect_addr)).await.unwrap_err();
        assert!(matches!(err, WebPushError::Other(ref info) if info.code == 302));

        redirect_server.abort();
        target_server.abort();
        assert!(
            !target_hit.load(Ordering::SeqCst),
            "client must not follow HTTP redirects"
        );
    }

    #[tokio::test]
    async fn returns_server_error_with_retry_after_on_503() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let Ok(Ok((mut socket, _))) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let resp =
                "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 75\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
        });

        let client = IsahcWebPushClient::builder()
            .timeout(Duration::from_secs(5))
            .allow_insecure_endpoints(true)
            .build()
            .unwrap();
        let err = client.send(local_message(addr)).await.unwrap_err();
        server.abort();

        assert!(matches!(
            err,
            WebPushError::ServerError {
                retry_after: Some(d),
                ..
            } if d == Duration::from_secs(75)
        ));
    }
}
