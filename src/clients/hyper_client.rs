use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

use crate::{
    clients::{
        safe_connector::{send_hyper_request, SafeHttpConnector},
        WebPushClient, DEFAULT_CONNECT_TIMEOUT, DEFAULT_TIMEOUT,
    },
    error::WebPushError,
    message::WebPushMessage,
};

/// Builder for configuring a [`HyperWebPushClient`].
#[derive(Debug, Clone)]
pub struct HyperWebPushClientBuilder {
    timeout: Duration,
    connect_timeout: Duration,
    allow_insecure_endpoints: bool,
}

impl Default for HyperWebPushClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperWebPushClientBuilder {
    /// Creates a new builder with default timeouts (30s request, 10s connect) and
    /// SSRF / HTTPS-only endpoint enforcement enabled.
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

    /// Sets the DNS resolution + TCP connect timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Allows `http://` and loopback/private endpoints when set to `true`
    /// (intended for local testing and mock servers).
    ///
    /// Defaults to `false`, which requires canonical `https` endpoints, checks every
    /// DNS-resolved IP address against the configured IP policy on each new connection,
    /// and dials only the checked addresses directly while preserving URI-host TLS
    /// certificate verification and DNS-name SNI.
    pub fn allow_insecure_endpoints(mut self, allow: bool) -> Self {
        self.allow_insecure_endpoints = allow;
        self
    }

    /// Builds the configured [`HyperWebPushClient`].
    ///
    /// Uses an explicit `ring` [`rustls::crypto::CryptoProvider`] and OS native root
    /// certificates (`rustls-native-certs`), without relying on the process-global
    /// rustls default provider.
    pub fn build(self) -> Result<HyperWebPushClient, WebPushError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls_builder = HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(provider)
            .map_err(WebPushError::Io)?;

        let scheme_builder = if self.allow_insecure_endpoints {
            tls_builder.https_or_http()
        } else {
            tls_builder.https_only()
        };

        let connector = SafeHttpConnector::new(self.connect_timeout, self.allow_insecure_endpoints);
        let https = scheme_builder.enable_http1().enable_http2().wrap_connector(connector);

        let client = Client::builder(TokioExecutor::new()).build(https);

        Ok(HyperWebPushClient {
            client,
            timeout: self.timeout,
            allow_insecure_endpoints: self.allow_insecure_endpoints,
        })
    }
}

/// Default async Web Push client built on `hyper 1.x` and pure-Rust TLS (`hyper-rustls` + `ring`).
///
/// This client is thread-safe and cheap to clone. It requires a Tokio runtime and
/// enforces HTTPS-only endpoints plus post-DNS-resolution public IP verification by default.
#[derive(Clone)]
pub struct HyperWebPushClient {
    client: Client<HttpsConnector<SafeHttpConnector>, Full<Bytes>>,
    timeout: Duration,
    allow_insecure_endpoints: bool,
}

impl HyperWebPushClient {
    /// Creates a new client with default timeouts (30s request, 10s connect) and
    /// SSRF / HTTPS-only endpoint enforcement enabled.
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

    /// Returns a [`HyperWebPushClientBuilder`] for customizing timeouts and endpoint policy.
    pub fn builder() -> HyperWebPushClientBuilder {
        HyperWebPushClientBuilder::new()
    }
}

#[async_trait]
impl WebPushClient for HyperWebPushClient {
    /// Sends a notification using the client's configured timeouts and endpoint policy.
    async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        send_hyper_request(&self.client, self.timeout, self.allow_insecure_endpoints, message).await
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{clients::MAX_RESPONSE_SIZE, SubscriptionInfo, VapidSignature, WebPushMessageBuilder};

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

        let client = HyperWebPushClient::builder()
            .timeout(Duration::from_millis(100))
            .connect_timeout(Duration::from_millis(100))
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

        let client = HyperWebPushClient::builder()
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

        let client = HyperWebPushClient::builder()
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
    async fn rejects_ssrf_and_non_https_by_default_even_for_hand_constructed_message() {
        let client = HyperWebPushClient::new().unwrap();

        for endpoint in [
            "http://updates.push.services.mozilla.com/wpush/v2/token",
            "https://127.0.0.1:8443/push",
            "https://localhost/push",
            "https://169.254.169.254/latest/meta-data/",
        ] {
            let hand_constructed = WebPushMessage {
                endpoint: endpoint.parse().unwrap(),
                ttl: 60,
                urgency: None,
                topic: None,
                payload: None,
                vapid_signature: None,
            };
            let err = client.send(hand_constructed).await.unwrap_err();
            assert!(
                matches!(err, WebPushError::InvalidUri),
                "expected InvalidUri for {endpoint}, got {err:?}"
            );
        }
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

        let client = HyperWebPushClient::builder()
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
        assert!(!lower.contains("content-type:"));
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

        let client = HyperWebPushClient::builder()
            .timeout(Duration::from_secs(5))
            .allow_insecure_endpoints(true)
            .build()
            .unwrap();
        let err = client.send(local_message(redirect_addr)).await.unwrap_err();
        redirect_server.abort();
        target_server.abort();

        assert!(matches!(err, WebPushError::Other(ref info) if info.code == 302));
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

        let client = HyperWebPushClient::builder()
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

    #[tokio::test]
    async fn rejects_non_canonical_uppercase_scheme() {
        let non_canonical = http::Uri::builder()
            .scheme("HTTPS")
            .authority("push.example.com")
            .path_and_query("/send")
            .build()
            .unwrap();

        let client = HyperWebPushClient::builder()
            .allow_insecure_endpoints(true)
            .build()
            .unwrap();
        let msg = WebPushMessage {
            endpoint: non_canonical,
            ttl: 60,
            urgency: None,
            topic: None,
            payload: None,
            vapid_signature: None,
        };
        assert!(matches!(client.send(msg).await, Err(WebPushError::InvalidUri)));
    }
}
