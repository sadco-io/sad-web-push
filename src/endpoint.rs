use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use http::uri::{Authority, Scheme, Uri};

use crate::error::WebPushError;

/// Validates a push subscription endpoint URI string.
///
/// By default (`allow_insecure == false`), endpoints must:
/// - parse as a valid `http::Uri` with an explicit canonical `https` scheme and non-empty host;
/// - contain no userinfo (`@` in the authority) and, if an explicit port is present,
///   a valid non-zero `u16` port;
/// - not target `localhost`, `*.localhost`, non-canonical numeric IPv4 forms, or
///   disallowed IPv4/IPv6 ranges.
///
/// When `allow_insecure == true`, canonical `http` and `https` schemes as well as loopback
/// and private addresses are permitted (intended for local testing and mock servers),
/// while still requiring a valid scheme, non-empty host, valid explicit port (if present),
/// and no userinfo.
pub(crate) fn validate_endpoint(endpoint: &str, allow_insecure: bool) -> Result<Uri, WebPushError> {
    let uri: Uri = endpoint.parse().map_err(|_| WebPushError::InvalidUri)?;
    validate_uri(&uri, allow_insecure)?;
    Ok(uri)
}

/// Validates a parsed [`Uri`] against the endpoint policy.
pub(crate) fn validate_uri(uri: &Uri, allow_insecure: bool) -> Result<(), WebPushError> {
    let scheme = uri.scheme().ok_or(WebPushError::InvalidUri)?;
    let is_https = *scheme == Scheme::HTTPS && scheme.as_str() == "https";
    let is_http = *scheme == Scheme::HTTP && scheme.as_str() == "http";

    let authority = uri.authority().ok_or(WebPushError::InvalidUri)?;

    // Reject embedded userinfo (e.g. https://user:pass@host/...)
    if authority.as_str().contains('@') {
        return Err(WebPushError::InvalidUri);
    }

    let host = uri.host().ok_or(WebPushError::InvalidUri)?;
    if host.is_empty() {
        return Err(WebPushError::InvalidUri);
    }

    // Reject malformed, zero, or out-of-range explicit ports (e.g. `:0`, `:99999`, `:+443`, `:`).
    validate_explicit_port(authority)?;

    if allow_insecure {
        if !is_https && !is_http {
            return Err(WebPushError::InvalidUri);
        }
        return Ok(());
    }

    if !is_https {
        return Err(WebPushError::InvalidUri);
    }

    validate_public_host(host)?;

    Ok(())
}

/// Validates any explicit port present in an [`Authority`].
///
/// Returns `Ok(None)` when no port delimiter is present, `Ok(Some(port))` for a valid
/// non-zero `u16` port consisting strictly of ASCII decimal digits (RFC 3986 §3.2.3), and
/// `Err(WebPushError::InvalidUri)` if an explicit `:` is present with an empty, signed,
/// non-numeric, zero, or out-of-range port (preventing silent fallback to a default port).
pub(crate) fn validate_explicit_port(authority: &Authority) -> Result<Option<u16>, WebPushError> {
    let raw = authority.as_str();
    let host_port = match raw.rsplit_once('@') {
        Some((_, after)) => after,
        None => raw,
    };

    let after_host = if let Some(rest) = host_port.strip_prefix('[') {
        let Some((_, after_bracket)) = rest.split_once(']') else {
            return Err(WebPushError::InvalidUri);
        };
        if !after_bracket.is_empty() && !after_bracket.starts_with(':') {
            return Err(WebPushError::InvalidUri);
        }
        after_bracket
    } else {
        host_port
    };

    if let Some((_, port_str)) = after_host.split_once(':') {
        if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WebPushError::InvalidUri);
        }
        let port = authority.port_u16().ok_or(WebPushError::InvalidUri)?;
        if port == 0 {
            return Err(WebPushError::InvalidUri);
        }
        Ok(Some(port))
    } else {
        Ok(None)
    }
}

/// Redacts a push endpoint [`Uri`] for safe `Debug` formatting, preserving only
/// `<scheme>://<host>[:<port>]/[REDACTED]` so RFC 8030 §5 capability tokens in
/// the path or query string are never logged.
pub(crate) fn redact_endpoint_uri(uri: &Uri) -> String {
    match (uri.scheme_str(), uri.host()) {
        (Some(scheme), Some(host)) if !host.is_empty() => match uri.port_u16() {
            Some(port) => format!("{scheme}://{host}:{port}/[REDACTED]"),
            None => format!("{scheme}://{host}/[REDACTED]"),
        },
        _ => "[REDACTED]".to_string(),
    }
}

/// Redacts a push endpoint string for safe `Debug` formatting.
pub(crate) fn redact_endpoint_str(endpoint: &str) -> String {
    match endpoint.parse::<Uri>() {
        Ok(uri) => redact_endpoint_uri(&uri),
        Err(_) => "[REDACTED]".to_string(),
    }
}

/// Constructs the RFC 8292 VAPID `aud` origin (`scheme://host[:port]`) for a URI.
///
/// Normalizes scheme and host to ASCII lowercase, validates any explicit port,
/// omits default ports (`443` for `https`, `80` for `http`), and preserves valid
/// non-default ports. Never panics on malformed URIs.
pub(crate) fn origin_for_vapid(uri: &Uri) -> Result<String, WebPushError> {
    let scheme = uri.scheme_str().ok_or(WebPushError::InvalidUri)?;
    let authority = uri.authority().ok_or(WebPushError::InvalidUri)?;
    let host = uri.host().ok_or(WebPushError::InvalidUri)?;
    if host.is_empty() {
        return Err(WebPushError::InvalidUri);
    }

    let port = validate_explicit_port(authority)?;
    let scheme_lower = scheme.to_ascii_lowercase();
    let host_lower = host.to_ascii_lowercase();
    let default_port = match scheme_lower.as_str() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };

    match port {
        Some(port) if Some(port) != default_port => Ok(format!("{scheme_lower}://{host_lower}:{port}")),
        _ => Ok(format!("{scheme_lower}://{host_lower}")),
    }
}

fn validate_public_host(host: &str) -> Result<(), WebPushError> {
    // Handle bracketed IPv6 literals returned by `http::Uri::host()`.
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        // Any zone identifier (e.g. `%eth0` or `%25eth0`) indicates a scoped/link-local address.
        if inner.contains('%') {
            return Err(WebPushError::InvalidUri);
        }
        let ipv6: Ipv6Addr = inner.parse().map_err(|_| WebPushError::InvalidUri)?;
        if is_disallowed_ipv6(ipv6) {
            return Err(WebPushError::InvalidUri);
        }
        return Ok(());
    }

    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(WebPushError::InvalidUri);
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Err(WebPushError::InvalidUri);
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        let disallowed = match ip {
            IpAddr::V4(v4) => is_disallowed_ipv4(v4),
            IpAddr::V6(v6) => is_disallowed_ipv6(v6),
        };
        if disallowed {
            return Err(WebPushError::InvalidUri);
        }
        return Ok(());
    }

    // Reject shorthand/non-canonical numeric IPv4 literals (e.g. `127.1`, `0177.0.0.1`,
    // `2130706433`, `0x7f000001`). Valid DNS TLDs cannot be purely numeric or hex-prefixed.
    if is_shorthand_numeric_host(&lower) {
        return Err(WebPushError::InvalidUri);
    }

    Ok(())
}

fn is_shorthand_numeric_host(lower_host: &str) -> bool {
    let last_label = lower_host.rsplit('.').next().unwrap_or("");
    if last_label.is_empty() {
        return true;
    }

    if last_label.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }

    if let Some(hex_part) = last_label.strip_prefix("0x") {
        if !hex_part.is_empty() && hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return true;
        }
    }

    false
}

/// Returns `true` if `ip` is permitted by the default endpoint IP policy.
#[cfg(any(feature = "hyper-client", feature = "hyper-native-tls", test))]
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !is_disallowed_ipv4(v4),
        IpAddr::V6(v6) => !is_disallowed_ipv6(v6),
    }
}

fn is_disallowed_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    // 0.0.0.0/8 ("this network" / unspecified)
    if a == 0 {
        return true;
    }
    // RFC 1918 private, loopback, link-local (169.254.0.0/16), documentation, multicast, broadcast
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_documentation()
        || ip.is_multicast()
        || ip.is_broadcast()
    {
        return true;
    }
    // 100.64.0.0/10 (RFC 6598 CGNAT / shared address space)
    if a == 100 && (b & 0xc0) == 64 {
        return true;
    }
    // 192.0.0.0/24 (IETF protocol assignments)
    if a == 192 && b == 0 && c == 0 {
        return true;
    }
    // 192.88.99.0/24 (deprecated 6to4 relay anycast, RFC 7526)
    if a == 192 && b == 88 && c == 99 {
        return true;
    }
    // 198.18.0.0/15 (RFC 2544 benchmarking)
    if a == 198 && (b & 0xfe) == 18 {
        return true;
    }
    // 240.0.0.0/4 (reserved for future use, including 255.255.255.255)
    if a >= 240 {
        return true;
    }

    false
}

fn is_disallowed_ipv6(ip: Ipv6Addr) -> bool {
    // 1. Check IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) against IPv4 rules.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_disallowed_ipv4(v4);
    }

    let s = ip.segments();

    // 2. NAT64 well-known prefix (`64:ff9b::/96`) embeds an IPv4 address in the low 32 bits.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let embedded_v4 = Ipv4Addr::from(((s[6] as u32) << 16) | (s[7] as u32));
        return is_disallowed_ipv4(embedded_v4);
    }

    // 3. Require Global Unicast (`2000::/3`).
    // Blocks `::/96`, `::1`, `::ffff:0:0:0/96`, `100::/64`, `100:0:0:1::/64`,
    // `64:ff9b:1::/48`, `5f00::/16`, `fc00::/7`, `fe80::/10`, `fec0::/10`,
    // `ff00::/8`, and all reserved / unallocated space.
    if (s[0] & 0xe000) != 0x2000 {
        return true;
    }

    // 4. Within `2000::/3`, reject selected special-purpose and transition ranges:
    // - `2001::/32` (Teredo, RFC 4380)
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return true;
    }
    // - `2001:2::/48` (Benchmarking, RFC 5180)
    if s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0 {
        return true;
    }
    // - `2001:3::/32` (AMT, RFC 7450)
    if s[0] == 0x2001 && s[1] == 0x0003 {
        return true;
    }
    // - `2001:10::/28` (ORCHID), `2001:20::/28` (ORCHIDv2), `2001:30::/28` (Drone Remote ID)
    if s[0] == 0x2001 && ((s[1] & 0xfff0) == 0x0010 || (s[1] & 0xfff0) == 0x0020 || (s[1] & 0xfff0) == 0x0030) {
        return true;
    }
    // - `2001:db8::/32` (Documentation, RFC 3849)
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return true;
    }
    // - `2002::/16` (6to4, RFC 3056 / deprecated RFC 7526)
    if s[0] == 0x2002 {
        return true;
    }
    // - `3fff::/20` (Documentation, RFC 9637)
    if s[0] == 0x3fff && (s[1] & 0xf000) == 0x0000 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_valid_https_endpoints() {
        for url in [
            "https://updates.push.services.mozilla.com/wpush/v2/abc",
            "https://fcm.googleapis.com/fcm/send/token",
            "HTTPS://web.push.apple.com/token",
            "https://push.example.com:8443/send",
            "https://8.8.8.8/push",
            "https://[2606:4700:4700::1111]/push",
            "https://[::ffff:8.8.8.8]/push",
            "https://[64:ff9b::8.8.8.8]/push",
        ] {
            assert!(validate_endpoint(url, false).is_ok(), "expected valid: {url}");
        }
    }

    #[test]
    fn rejects_non_https_and_malformed_endpoints_by_default() {
        for url in [
            "",
            "/relative/path",
            "push.example.com",
            "http://updates.push.services.mozilla.com/wpush/v2/abc",
            "ftp://example.com/push",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user:pass@updates.push.services.mozilla.com/wpush",
            "https://user@updates.push.services.mozilla.com/wpush",
            "https:///no-host",
            // Invalid explicit ports (zero, out-of-range, signed, empty)
            "https://push.example.com:0/send",
            "https://push.example.com:99999/send",
            "https://push.example.com:+443/send",
            "https://push.example.com:-1/send",
            "https://push.example.com:/send",
            "https://[2606:4700:4700::1111]:0/push",
            "https://[2606:4700:4700::1111]:99999/push",
            "https://[2606:4700:4700::1111]:+443/push",
            "https://[2606:4700:4700::1111]:/push",
        ] {
            assert!(
                matches!(validate_endpoint(url, false), Err(WebPushError::InvalidUri)),
                "expected InvalidUri for: {url}"
            );
        }

        // Non-canonical scheme built via Uri::builder().scheme("HTTPS") must be rejected.
        let non_canonical = Uri::builder()
            .scheme("HTTPS")
            .authority("push.example.com")
            .path_and_query("/send")
            .build()
            .unwrap();
        assert!(matches!(
            validate_uri(&non_canonical, false),
            Err(WebPushError::InvalidUri)
        ));
        assert!(matches!(
            validate_uri(&non_canonical, true),
            Err(WebPushError::InvalidUri)
        ));
    }

    #[test]
    fn rejects_localhost_and_non_public_ips_by_default() {
        for url in [
            "https://localhost/push",
            "https://LOCALHOST/push",
            "https://localhost./push",
            "https://sub.localhost/push",
            "https://sub.localhost./push",
            "https://127.0.0.1/push",
            "https://127.0.0.1./push",
            "https://127.255.255.254/push",
            "https://10.0.0.1/push",
            "https://172.16.0.1/push",
            "https://172.31.255.255/push",
            "https://192.168.1.1/push",
            "https://169.254.169.254/latest/meta-data/",
            "https://100.64.0.1/push",
            "https://100.127.255.254/push",
            "https://0.0.0.0/push",
            "https://0.1.2.3/push",
            "https://224.0.0.1/push",
            "https://240.0.0.1/push",
            "https://255.255.255.255/push",
            "https://192.0.0.1/push",
            "https://192.0.2.1/push",
            "https://192.88.99.1/push",
            "https://198.18.0.1/push",
            "https://198.51.100.1/push",
            "https://203.0.113.1/push",
            "https://[::1]/push",
            "https://[::]/push",
            "https://[fc00::1]/push",
            "https://[fd12:3456:789a::1]/push",
            "https://[fe80::1]/push",
            "https://[fe80::1%25eth0]/push",
            "https://[fec0::1]/push",
            "https://[ff02::1]/push",
            "https://[2001::1]/push",
            "https://[2001:2::1]/push",
            "https://[2001:3::1]/push",
            "https://[2001:10::1]/push",
            "https://[2001:20::1]/push",
            "https://[2001:30::1]/push",
            "https://[2001:db8::1]/push",
            "https://[2002:7f00:0001::1]/push",
            "https://[2002:a9fe:a9fe::1]/push",
            "https://[3fff::1]/push",
            "https://[0200::1]/push",
            "https://[4000::1]/push",
            "https://[8000::1]/push",
            "https://[100::1]/push",
            "https://[::ffff:127.0.0.1]/push",
            "https://[::ffff:7f00:1]/push",
            "https://[::ffff:0:127.0.0.1]/push",
            "https://[::ffff:169.254.169.254]/push",
            "https://[::ffff:10.0.0.1]/push",
            "https://[64:ff9b::127.0.0.1]/push",
            "https://[64:ff9b:1::1]/push",
            // Shorthand / non-canonical IPv4 literals
            "https://127.1/push",
            "https://0177.0.0.1/push",
            "https://2130706433/push",
            "https://0x7f000001/push",
            "https://0x7f.0.0.1/push",
            "https://127.0.0.0x1/push",
        ] {
            assert!(
                matches!(validate_endpoint(url, false), Err(WebPushError::InvalidUri)),
                "expected InvalidUri for: {url}"
            );
        }
    }

    #[test]
    fn allow_insecure_permits_http_and_loopback_but_still_rejects_malformed() {
        for url in [
            "http://127.0.0.1:8080/push",
            "http://localhost:3000/push",
            "http://[::1]:8080/push",
            "https://127.0.0.1:8443/push",
            "http://10.0.0.1/push",
        ] {
            assert!(validate_endpoint(url, true).is_ok(), "expected allowed: {url}");
        }

        for url in [
            "/relative",
            "localhost:8080",
            "ftp://127.0.0.1/push",
            "file:///etc/passwd",
            "http://user:pass@127.0.0.1/push",
            "http://127.0.0.1:0/push",
            "http://127.0.0.1:99999/push",
            "http://127.0.0.1:+8080/push",
            "http://127.0.0.1:-1/push",
            "http://127.0.0.1:/push",
        ] {
            assert!(
                matches!(validate_endpoint(url, true), Err(WebPushError::InvalidUri)),
                "expected InvalidUri even with allow_insecure: {url}"
            );
        }
    }

    #[test]
    fn origin_for_vapid_handles_ports_case_and_invalid_uris() {
        assert_eq!(
            origin_for_vapid(
                &"https://updates.push.services.mozilla.com/wpush/v2/abc"
                    .parse()
                    .unwrap()
            )
            .unwrap(),
            "https://updates.push.services.mozilla.com"
        );
        assert_eq!(
            origin_for_vapid(&"HTTPS://PUSH.EXAMPLE.COM/send".parse().unwrap()).unwrap(),
            "https://push.example.com"
        );
        assert_eq!(
            origin_for_vapid(&"https://[2606:4700:4700::ABCD]:8443/send".parse().unwrap()).unwrap(),
            "https://[2606:4700:4700::abcd]:8443"
        );
        assert_eq!(
            origin_for_vapid(&"https://push.example.com:443/send".parse().unwrap()).unwrap(),
            "https://push.example.com"
        );
        assert_eq!(
            origin_for_vapid(&"https://push.example.com:8443/send".parse().unwrap()).unwrap(),
            "https://push.example.com:8443"
        );
        assert_eq!(
            origin_for_vapid(&"http://localhost:80/send".parse().unwrap()).unwrap(),
            "http://localhost"
        );
        assert_eq!(
            origin_for_vapid(&"http://localhost:8080/send".parse().unwrap()).unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            origin_for_vapid(&"https://[::1]:8443/send".parse().unwrap()).unwrap(),
            "https://[::1]:8443"
        );
        for bad in [
            "/relative/path",
            "push.example.com",
            "https://push.example.com:0/send",
            "https://push.example.com:99999/send",
            "https://push.example.com:+443/send",
            "https://push.example.com:-1/send",
            "https://push.example.com:/send",
            "https://[::1]:99999/send",
            "https://[::1]:+443/send",
        ] {
            if let Ok(uri) = bad.parse::<Uri>() {
                assert!(
                    matches!(origin_for_vapid(&uri), Err(WebPushError::InvalidUri)),
                    "expected InvalidUri from origin_for_vapid for: {bad}"
                );
            }
        }
        // `http::Uri` accepts `:+443` during parsing, so assert origin_for_vapid explicitly rejects it.
        let plus_port_uri: Uri = "https://push.example.com:+443/send".parse().unwrap();
        assert!(matches!(
            origin_for_vapid(&plus_port_uri),
            Err(WebPushError::InvalidUri)
        ));
    }

    #[test]
    fn is_public_ip_matches_policy() {
        for allowed in ["8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::8.8.8.8"] {
            assert!(is_public_ip(allowed.parse().unwrap()), "expected public: {allowed}");
        }
        for blocked in [
            "127.0.0.1",
            "169.254.169.254",
            "192.88.99.1",
            "::1",
            "2001::1",
            "2002:7f00:0001::1",
            "3fff::1",
            "::ffff:0:127.0.0.1",
            "0200::1",
            "4000::1",
            "64:ff9b:1::1",
        ] {
            assert!(!is_public_ip(blocked.parse().unwrap()), "expected blocked: {blocked}");
        }
    }
}
