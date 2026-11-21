use std::{
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{header::RETRY_AFTER, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::{
    client::legacy::{connect::Connect, Client},
    rt::TokioIo,
};
use log::{debug, trace};
use tokio::net::TcpStream;
use tower_service::Service;

use crate::{
    clients::{request_builder, MAX_RESPONSE_SIZE},
    endpoint::{is_public_ip, validate_explicit_port, validate_uri},
    error::WebPushError,
    message::WebPushMessage,
};

/// Error produced by [`SafeHttpConnector`].
#[derive(Debug)]
pub(crate) enum SafeConnectError {
    /// URI or resolved IP address is disallowed by the endpoint policy.
    DisallowedEndpoint,
    /// DNS lookup or TCP connection timed out.
    TimedOut,
    /// Underlying network or DNS I/O failure.
    Io(io::Error),
}

impl fmt::Display for SafeConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SafeConnectError::DisallowedEndpoint => {
                write!(f, "push endpoint URI or resolved IP address is disallowed")
            }
            SafeConnectError::TimedOut => write!(f, "push connection timed out"),
            SafeConnectError::Io(err) => write!(f, "connection i/o error: {err}"),
        }
    }
}

impl Error for SafeConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SafeConnectError::Io(err) => Some(err),
            _ => None,
        }
    }
}

/// Connect-time IP-pinning TCP connector for `hyper 1.x` TLS connectors.
///
/// When `allow_insecure` is `false` (the default), every new connection:
/// 1. validates the target [`Uri`] is canonical `https` with a valid host, valid explicit port
///    (if any), and no userinfo;
/// 2. resolves hostnames via [`tokio::net::lookup_host`];
/// 3. verifies **every** resolved [`SocketAddr::ip`] satisfies [`is_public_ip`]; and
/// 4. dials only the checked [`SocketAddr`] values directly (interleaving IPv6/IPv4 families
///    with fair per-attempt time budgets within `connect_timeout`), while TLS connectors still
///    verify certificates and send SNI for the original endpoint host.
#[derive(Clone, Debug)]
pub(crate) struct SafeHttpConnector {
    connect_timeout: Duration,
    allow_insecure: bool,
}

impl SafeHttpConnector {
    pub(crate) fn new(connect_timeout: Duration, allow_insecure: bool) -> Self {
        Self {
            connect_timeout,
            allow_insecure,
        }
    }
}

fn verify_resolved_addrs(addrs: &[SocketAddr], allow_insecure: bool) -> Result<(), SafeConnectError> {
    if addrs.is_empty() {
        return Err(SafeConnectError::Io(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "DNS lookup returned no addresses",
        )));
    }

    if !allow_insecure && !addrs.iter().all(|addr| is_public_ip(addr.ip())) {
        return Err(SafeConnectError::DisallowedEndpoint);
    }

    Ok(())
}

/// Interleaves IPv6 and IPv4 addresses (preserving relative order within each family)
/// so a single unreachable address family does not starve fallback addresses.
fn interleave_address_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();
    for addr in addrs {
        match addr {
            SocketAddr::V6(_) => v6.push(addr),
            SocketAddr::V4(_) => v4.push(addr),
        }
    }

    let mut ordered = Vec::with_capacity(v6.len() + v4.len());
    let mut i6 = v6.into_iter();
    let mut i4 = v4.into_iter();
    loop {
        match (i6.next(), i4.next()) {
            (Some(a6), Some(a4)) => {
                ordered.push(a6);
                ordered.push(a4);
            }
            (Some(a6), None) => {
                ordered.push(a6);
                ordered.extend(i6);
                break;
            }
            (None, Some(a4)) => {
                ordered.push(a4);
                ordered.extend(i4);
                break;
            }
            (None, None) => break,
        }
    }
    ordered
}

/// Connects to the first reachable address in `addrs`, dividing the remaining time
/// budget fairly across remaining addresses so one blackholed address cannot starve
/// fallback addresses while keeping total duration strictly bounded by `deadline`.
async fn connect_addrs_with_deadline(
    addrs: Vec<SocketAddr>,
    deadline: tokio::time::Instant,
) -> Result<TokioIo<TcpStream>, SafeConnectError> {
    let ordered = interleave_address_families(addrs);
    let total = ordered.len();
    let mut last_err = None;
    let mut timed_out_any = false;

    for (idx, addr) in ordered.into_iter().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(SafeConnectError::TimedOut);
        }

        let remaining_addrs = (total - idx) as u32;
        let attempt_timeout = if remaining_addrs <= 1 {
            remaining
        } else {
            (remaining / remaining_addrs).max(Duration::from_millis(1))
        };

        match tokio::time::timeout(attempt_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(TokioIo::new(stream));
            }
            Ok(Err(err)) => last_err = Some(err),
            Err(_) => timed_out_any = true,
        }
    }

    if let Some(err) = last_err {
        Err(SafeConnectError::Io(err))
    } else if timed_out_any {
        Err(SafeConnectError::TimedOut)
    } else {
        Err(SafeConnectError::Io(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "failed to connect to any address",
        )))
    }
}

impl Service<Uri> for SafeHttpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = SafeConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connect_timeout = self.connect_timeout;
        let allow_insecure = self.allow_insecure;

        Box::pin(async move {
            validate_uri(&uri, allow_insecure).map_err(|_| SafeConnectError::DisallowedEndpoint)?;

            let scheme = uri.scheme_str().ok_or(SafeConnectError::DisallowedEndpoint)?;
            let authority = uri.authority().ok_or(SafeConnectError::DisallowedEndpoint)?;
            let raw_host = uri.host().ok_or(SafeConnectError::DisallowedEndpoint)?;
            let host = raw_host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(raw_host)
                .to_owned();

            let port = validate_explicit_port(authority)
                .map_err(|_| SafeConnectError::DisallowedEndpoint)?
                .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });

            let deadline = tokio::time::Instant::now() + connect_timeout;
            let connect_fut = async move {
                let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
                    vec![SocketAddr::new(ip, port)]
                } else {
                    tokio::net::lookup_host((host.as_str(), port))
                        .await
                        .map_err(SafeConnectError::Io)?
                        .collect()
                };

                verify_resolved_addrs(&addrs, allow_insecure)?;
                connect_addrs_with_deadline(addrs, deadline).await
            };

            tokio::time::timeout_at(deadline, connect_fut)
                .await
                .map_err(|_| SafeConnectError::TimedOut)?
        })
    }
}

/// Shared execution pipeline for `hyper 1.x` push clients (`hyper-rustls` and `hyper-tls`).
pub(crate) async fn send_hyper_request<C>(
    client: &Client<C, Full<Bytes>>,
    timeout: Duration,
    allow_insecure: bool,
    message: WebPushMessage,
) -> Result<(), WebPushError>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    validate_uri(&message.endpoint, allow_insecure)?;

    let ttl = message.ttl;
    let request: Request<Full<Bytes>> = request_builder::try_build_request(message)?;

    debug!("Sending push request: host={:?} ttl={}", request.uri().host(), ttl);

    let fut = async {
        let response = client.request(request).await?;

        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|ra| ra.to_str().ok())
            .and_then(request_builder::parse_retry_after);

        let response_status = response.status();
        trace!("Response status: {}", response_status);

        let mut incoming = response.into_body();
        let mut body = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame?;
            if let Some(chunk) = frame.data_ref() {
                if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_SIZE {
                    return Err(WebPushError::ResponseTooLarge);
                }
                body.extend_from_slice(chunk);
            }
        }

        let parsed = request_builder::parse_response(response_status, body);
        debug!("Push response status: {}", response_status);

        match parsed {
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
    };

    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| WebPushError::Timeout)?
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn verify_resolved_addrs_requires_all_public_by_default() {
        let public_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
        let public_v6 = SocketAddr::new(IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()), 443);
        let loopback_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let metadata_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 443);
        let ula_v6 = SocketAddr::new(IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap()), 443);
        let mapped_loopback = SocketAddr::new(IpAddr::V6("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap()), 443);

        assert!(verify_resolved_addrs(&[public_v4, public_v6], false).is_ok());

        for bad in [loopback_v4, metadata_v4, ula_v6, mapped_loopback] {
            // Even when mixed with a public IP, ANY non-public resolved IP must be rejected.
            assert!(matches!(
                verify_resolved_addrs(&[public_v4, bad], false),
                Err(SafeConnectError::DisallowedEndpoint)
            ));
            // Allowed only when explicitly opted in.
            assert!(verify_resolved_addrs(&[public_v4, bad], true).is_ok());
        }

        assert!(matches!(
            verify_resolved_addrs(&[], false),
            Err(SafeConnectError::Io(_))
        ));
    }

    #[tokio::test]
    async fn connector_blocks_loopback_and_http_by_default() {
        let mut connector = SafeHttpConnector::new(Duration::from_secs(2), false);

        for uri in [
            "http://example.com/push",
            "https://127.0.0.1/push",
            "https://[::1]/push",
            "https://localhost/push",
            "https://169.254.169.254/latest/meta-data/",
        ] {
            let err = connector.call(uri.parse().unwrap()).await.unwrap_err();
            assert!(
                matches!(err, SafeConnectError::DisallowedEndpoint),
                "expected DisallowedEndpoint for {uri}, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn connector_connects_to_loopback_when_allow_insecure_enabled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;
        });

        let mut connector = SafeHttpConnector::new(Duration::from_secs(2), true);
        let uri: Uri = format!("http://{addr}/push").parse().unwrap();
        let res = connector.call(uri).await;
        server.abort();
        assert!(res.is_ok());
    }

    #[test]
    fn interleave_address_families_alternates_v6_and_v4() {
        let v6_a = SocketAddr::new(IpAddr::V6("2606:4700:4700::1111".parse().unwrap()), 443);
        let v6_b = SocketAddr::new(IpAddr::V6("2606:4700:4700::1001".parse().unwrap()), 443);
        let v4_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);

        let ordered = interleave_address_families(vec![v6_a, v6_b, v4_a]);
        assert_eq!(ordered, vec![v6_a, v4_a, v6_b]);
    }

    #[test]
    fn verify_resolved_addrs_blocks_ipv6_transition_and_non_global_ranges() {
        let public_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
        for bad_ip in [
            "2002:7f00:0001::1",
            "2001::1",
            "::ffff:0:127.0.0.1",
            "3fff::1",
            "0200::1",
            "4000::1",
            "192.88.99.1",
        ] {
            let bad = SocketAddr::new(bad_ip.parse::<IpAddr>().unwrap(), 443);
            assert!(
                matches!(
                    verify_resolved_addrs(&[public_v4, bad], false),
                    Err(SafeConnectError::DisallowedEndpoint)
                ),
                "expected DisallowedEndpoint for {bad_ip}"
            );
        }
    }

    #[tokio::test]
    async fn hyper_legacy_client_downcasts_safe_connect_errors_to_web_push_errors() {
        use hyper_util::rt::TokioExecutor;

        // 1. SafeConnectError::DisallowedEndpoint -> WebPushError::InvalidUri
        let connector = SafeHttpConnector::new(Duration::from_secs(1), false);
        let client: Client<SafeHttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);
        let req = Request::post("http://127.0.0.1:8080/push")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let legacy_err = client.request(req).await.unwrap_err();
        let mapped = WebPushError::from(legacy_err);
        assert!(
            matches!(mapped, WebPushError::InvalidUri),
            "expected InvalidUri from SafeConnectError::DisallowedEndpoint, got {mapped:?}"
        );

        // 2. SafeConnectError::TimedOut -> WebPushError::Timeout
        #[derive(Clone)]
        struct AlwaysTimeoutConnector;

        impl Service<Uri> for AlwaysTimeoutConnector {
            type Response = TokioIo<TcpStream>;
            type Error = SafeConnectError;
            type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _uri: Uri) -> Self::Future {
                Box::pin(async { Err(SafeConnectError::TimedOut) })
            }
        }

        let timeout_client: Client<AlwaysTimeoutConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(AlwaysTimeoutConnector);
        let req = Request::post("http://example.com/push")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let legacy_err = timeout_client.request(req).await.unwrap_err();
        let mapped = WebPushError::from(legacy_err);
        assert!(
            matches!(mapped, WebPushError::Timeout),
            "expected Timeout from SafeConnectError::TimedOut, got {mapped:?}"
        );
    }
}
