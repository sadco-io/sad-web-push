//! Functions used to send and consume push http messages.
//! This module can be used to build custom clients.

use std::time::Duration;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use http::{
    header::{HeaderValue, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    Request, StatusCode,
};

use crate::{
    error::{ErrorInfo, RetryAfter, WebPushError},
    http_ece::{vapid_authorization_header, ContentEncoding},
    message::WebPushMessage,
};

/// Splits `input` on `delimiter` bytes occurring outside RFC 7230 §3.2.6 quoted strings,
/// respecting `\`-escaped characters inside `"..."`. Returns `Err(WebPushError::Unspecified)`
/// if a quoted string is unclosed.
fn split_outside_quotes(input: &str, delimiter: u8) -> Result<Vec<&str>, WebPushError> {
    let bytes = input.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;

    for (i, &b) in bytes.iter().enumerate() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_quotes = false;
            }
        } else if b == b'"' {
            in_quotes = true;
        } else if b == delimiter {
            parts.push(&input[start..i]);
            start = i + 1;
        }
    }

    if in_quotes {
        return Err(WebPushError::Unspecified);
    }

    parts.push(&input[start..]);
    Ok(parts)
}

/// Strips any `p256ecdsa` parameter (case-insensitive) from every semicolon-separated
/// parameter list within each comma-separated element of a legacy `aesgcm` `Crypto-Key`
/// header value (`draft-ietf-httpbis-encryption-encoding-03` §4), preserving RFC 7230
/// quoted-string parameter values intact. Returns `Ok(None)` if no non-empty elements remain,
/// or `Err(WebPushError::Unspecified)` if a quoted string is unclosed.
fn strip_aesgcm_p256ecdsa(existing: &str) -> Result<Option<String>, WebPushError> {
    let mut elements = Vec::new();
    for elem in split_outside_quotes(existing, b',')? {
        let params: Vec<&str> = split_outside_quotes(elem, b';')?
            .into_iter()
            .map(str::trim)
            .filter(|part| {
                !part.is_empty()
                    && !part
                        .split_once('=')
                        .map_or(*part, |(k, _)| k)
                        .trim()
                        .eq_ignore_ascii_case("p256ecdsa")
            })
            .collect();
        if !params.is_empty() {
            elements.push(params.join("; "));
        }
    }

    if elements.is_empty() {
        Ok(None)
    } else {
        Ok(Some(elements.join(", ")))
    }
}

/// Fallibly builds the HTTP request to send to the push service.
///
/// Unlike [`build_request`], this function returns an error instead of panicking
/// if a manually constructed [`WebPushMessage`] (or a manually constructed
/// [`crate::VapidSignature`]) contains invalid HTTP header values. Messages
/// created via [`crate::WebPushMessageBuilder::build`] using signatures produced
/// by [`crate::VapidSignatureBuilder::build`] are guaranteed to produce valid
/// headers.
///
/// When [`WebPushMessage::vapid_signature`] is `Some`, it is authoritative: any
/// stale `Authorization` entry in `payload.crypto_headers` is replaced, and for
/// legacy [`ContentEncoding::AesGcm`] payloads any stale `p256ecdsa` parameters
/// are stripped across all `Crypto-Key` header entries and list elements before
/// emitting the matching `p256ecdsa` parameter exactly once.
pub fn try_build_request<T>(message: WebPushMessage) -> Result<Request<T>, WebPushError>
where
    T: From<Vec<u8>> + From<&'static str>,
{
    let mut builder = Request::builder()
        .method("POST")
        .uri(message.endpoint)
        .header("TTL", format!("{}", message.ttl).as_bytes());

    if let Some(urgency) = message.urgency {
        builder = builder.header("Urgency", urgency.to_string());
    }

    if let Some(topic) = message.topic {
        builder = builder.header("Topic", topic);
    }

    if let Some(payload) = message.payload {
        let mut emitted_p256ecdsa = false;
        let encoded_vapid_k = match message.vapid_signature.as_ref() {
            Some(vapid) if payload.content_encoding == ContentEncoding::AesGcm => Some(
                Base64UrlSafeNoPadding::encode_to_string(&vapid.auth_k).map_err(|_| WebPushError::InvalidCryptoKeys)?,
            ),
            _ => None,
        };

        for (k, v) in payload.crypto_headers.into_iter() {
            if message.vapid_signature.is_some() && k.eq_ignore_ascii_case(AUTHORIZATION.as_str()) {
                // `message.vapid_signature` is authoritative; skip any stale Authorization header.
                continue;
            }

            if let Some(encoded_k) = encoded_vapid_k.as_deref() {
                if k.eq_ignore_ascii_case("crypto-key") {
                    if let Some(cleaned) = strip_aesgcm_p256ecdsa(&v)? {
                        let value = if !emitted_p256ecdsa {
                            emitted_p256ecdsa = true;
                            format!("{cleaned}; p256ecdsa={encoded_k}")
                        } else {
                            cleaned
                        };
                        let header_val = HeaderValue::from_str(&value).map_err(|_| WebPushError::Unspecified)?;
                        builder = builder.header(k, header_val);
                    }
                    continue;
                }
            }

            let mut header_val = HeaderValue::from_str(&v).map_err(|_| WebPushError::Unspecified)?;
            if k.eq_ignore_ascii_case(AUTHORIZATION.as_str()) {
                header_val.set_sensitive(true);
            }
            builder = builder.header(k, header_val);
        }

        if let Some(vapid) = message.vapid_signature.as_ref() {
            if let Some(encoded_k) = encoded_vapid_k.as_deref() {
                if !emitted_p256ecdsa {
                    let value = format!("p256ecdsa={encoded_k}");
                    let header_val = HeaderValue::from_str(&value).map_err(|_| WebPushError::Unspecified)?;
                    builder = builder.header("Crypto-Key", header_val);
                }
            }
            let (k, v) = vapid_authorization_header(vapid)?;
            let mut header_val = HeaderValue::from_str(&v).map_err(|_| WebPushError::Unspecified)?;
            header_val.set_sensitive(true);
            builder = builder.header(k, header_val);
        }

        if payload.content.is_empty() {
            builder = builder.header(CONTENT_LENGTH, "0");
            builder.body("".into()).map_err(|_| WebPushError::Unspecified)
        } else {
            builder = builder
                .header(CONTENT_ENCODING, payload.content_encoding.to_str())
                .header(CONTENT_LENGTH, format!("{}", payload.content.len() as u64).as_bytes())
                .header(CONTENT_TYPE, "application/octet-stream");
            builder
                .body(payload.content.into())
                .map_err(|_| WebPushError::Unspecified)
        }
    } else {
        if let Some(vapid) = message.vapid_signature.as_ref() {
            let (k, v) = vapid_authorization_header(vapid)?;
            let mut header_val = HeaderValue::from_str(&v).map_err(|_| WebPushError::Unspecified)?;
            header_val.set_sensitive(true);
            builder = builder.header(k, header_val);
        }
        builder = builder.header(CONTENT_LENGTH, "0");
        builder.body("".into()).map_err(|_| WebPushError::Unspecified)
    }
}

/// Builds the request to send to the push service.
///
/// This function is generic over the request body, this means that you can swap out client implementations
/// even if they use different body types.
///
/// # Panics
///
/// Panics if a hand-constructed [`WebPushMessage`] (or a manually constructed
/// [`crate::VapidSignature`]) contains invalid HTTP header values. Messages
/// constructed via [`crate::WebPushMessageBuilder::build`] with signatures
/// produced by [`crate::VapidSignatureBuilder::build`] will not panic here;
/// use [`try_build_request`] for a fallible alternative.
///
/// # Example
///
/// ```no_run
/// # use sad_web_push::{SubscriptionInfo, WebPushMessageBuilder};
/// # use sad_web_push::request_builder::build_request;
/// let info = SubscriptionInfo::new(
///     "https://updates.push.services.mozilla.com/wpush/v1/...",
///     "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
///     "xS03Fi5ErfTNH_l9WHE9Ig",
/// );
///
/// let builder = WebPushMessageBuilder::new(&info);
///
/// // Build an `http::Request<Vec<u8>>` (or any body type implementing
/// // `From<Vec<u8>> + From<&'static str>`, e.g. `http_body_util::Full<bytes::Bytes>`).
/// let request = build_request::<Vec<u8>>(builder.build().unwrap());
/// # let _ = request;
/// ```
pub fn build_request<T>(message: WebPushMessage) -> Request<T>
where
    T: From<Vec<u8>> + From<&'static str>,
{
    try_build_request(message).expect("valid web push message headers and URI")
}

/// Parses an HTTP `Retry-After` header value (numeric seconds or RFC 7231 HTTP-date)
/// into a bounded [`Duration`].
pub fn parse_retry_after(header_value: &str) -> Option<Duration> {
    RetryAfter::from_str(header_value)
}

/// Parses the response from the push service, and will return `Err` if the request was bad.
pub fn parse_response(response_status: StatusCode, body: Vec<u8>) -> Result<(), WebPushError> {
    if response_status.is_success() {
        return Ok(());
    }

    let info: ErrorInfo = serde_json::from_slice(&body).unwrap_or_else(|_| ErrorInfo {
        code: response_status.as_u16(),
        errno: 999,
        error: "unknown error".into(),
        message: String::from_utf8(body).unwrap_or_else(|_| "-".into()),
    });

    match response_status {
        StatusCode::UNAUTHORIZED => Err(WebPushError::Unauthorized(info)),
        StatusCode::GONE => Err(WebPushError::EndpointNotValid(info)),
        StatusCode::NOT_FOUND => Err(WebPushError::EndpointNotFound(info)),
        StatusCode::PAYLOAD_TOO_LARGE => Err(WebPushError::PayloadTooLarge),
        StatusCode::BAD_REQUEST => Err(WebPushError::BadRequest(info)),
        StatusCode::TOO_MANY_REQUESTS => Err(WebPushError::TooManyRequests {
            retry_after: None,
            info,
        }),
        status if status.is_server_error() => Err(WebPushError::ServerError {
            retry_after: None,
            info,
        }),
        _ => Err(WebPushError::Other(info)),
    }
}

#[cfg(test)]
mod tests {
    use http::Uri;

    use crate::{
        clients::request_builder::*, error::WebPushError, http_ece::ContentEncoding, message::WebPushMessageBuilder,
        SubscriptionInfo, Urgency, VapidSignature, WebPushMessage,
    };

    #[test]
    fn builds_a_correct_request_with_empty_payload() {
        let sub = serde_json::json!({"endpoint":"https://fcm.googleapis.com/fcm/send/synthetic-test-token-000000000000",
            "expirationTime":null,
            "keys":{"p256dh":
                "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU",
                "auth":"EvcWjEgzr4rbvhfi3yds0A"}
        });

        let info = serde_json::from_value(sub).unwrap();

        let mut builder = WebPushMessageBuilder::new(&info);

        builder.set_ttl(420);
        builder.set_urgency(Urgency::VeryLow);
        builder.set_topic("some-topic".into());

        let request = build_request::<Vec<u8>>(builder.build().unwrap());
        let ttl = request.headers().get("TTL").unwrap().to_str().unwrap();
        let urgency = request.headers().get("Urgency").unwrap().to_str().unwrap();
        let topic = request.headers().get("Topic").unwrap().to_str().unwrap();
        let expected_uri: Uri = "fcm.googleapis.com".parse().unwrap();

        assert_eq!("420", ttl);
        assert_eq!("very-low", urgency);
        assert_eq!("some-topic", topic);
        assert_eq!(expected_uri.host(), request.uri().host());
        assert_eq!(request.headers().get(CONTENT_LENGTH).unwrap(), "0");
    }

    #[test]
    fn builds_a_correct_request_with_payload() {
        let sub = serde_json::json!({"endpoint":"https://fcm.googleapis.com/fcm/send/synthetic-test-token-000000000000",
            "expirationTime":null,
            "keys":{"p256dh":
                "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU",
                "auth":"EvcWjEgzr4rbvhfi3yds0A"}
        });

        let info = serde_json::from_value(sub).unwrap();

        let mut builder = WebPushMessageBuilder::new(&info);

        builder.set_payload(ContentEncoding::Aes128Gcm, "test".as_bytes());

        let request = build_request::<Vec<u8>>(builder.build().unwrap());

        let encoding = request.headers().get("Content-Encoding").unwrap().to_str().unwrap();

        let length = request.headers().get("Content-Length").unwrap();
        let expected_uri: Uri = "fcm.googleapis.com".parse().unwrap();

        // 86-byte aes128gcm header + 4-byte plaintext + 1-byte delimiter + 16-byte GCM tag = 107 bytes
        assert_eq!("107", length);
        assert_eq!("aes128gcm", encoding);
        assert_eq!(expected_uri.host(), request.uri().host());
    }

    #[test]
    fn builds_empty_payload_request_with_vapid_headers() {
        let info = SubscriptionInfo::new(
            "https://updates.push.services.mozilla.com/wpush/v2/token",
            "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU",
            "EvcWjEgzr4rbvhfi3yds0A",
        );

        let mut builder = WebPushMessageBuilder::new(&info);
        builder.set_vapid_signature(VapidSignature {
            auth_t: "jwt.token.value".into(),
            auth_k: vec![4, 1, 2, 3],
        });

        let msg = builder.build().unwrap();
        assert!(msg.payload.is_none());
        assert!(msg.vapid_signature.is_some());

        let request = try_build_request::<Vec<u8>>(msg).unwrap();
        let auth_headers: Vec<_> = request.headers().get_all(AUTHORIZATION).iter().collect();
        assert_eq!(auth_headers.len(), 1);
        assert!(
            auth_headers[0].is_sensitive(),
            "Authorization header must be marked sensitive"
        );
        assert!(auth_headers[0]
            .to_str()
            .unwrap()
            .starts_with("vapid t=jwt.token.value, k="));
        assert_eq!(request.headers().get(CONTENT_LENGTH).unwrap(), "0");
        assert!(request.headers().get(CONTENT_ENCODING).is_none());
        assert!(request.headers().get(CONTENT_TYPE).is_none());
        assert!(request.body().is_empty());
    }

    #[test]
    fn emits_single_authorization_header_and_respects_mutated_vapid_signature() {
        let info = SubscriptionInfo::new(
            "https://updates.push.services.mozilla.com/wpush/v2/token",
            "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU",
            "EvcWjEgzr4rbvhfi3yds0A",
        );
        let old_sig = VapidSignature {
            auth_t: "old.jwt.token".into(),
            auth_k: vec![4, 1, 2, 3],
        };
        let new_sig = VapidSignature {
            auth_t: "fresh.jwt.token".into(),
            auth_k: vec![4, 9, 8, 7],
        };
        let new_k_b64 = Base64UrlSafeNoPadding::encode_to_string(&new_sig.auth_k).unwrap();

        // Case 1: payload + vapid via builder -> single sensitive Authorization header
        let mut builder = WebPushMessageBuilder::new(&info);
        builder.set_payload(ContentEncoding::Aes128Gcm, b"hello");
        builder.set_vapid_signature(old_sig.clone());
        let req = try_build_request::<Vec<u8>>(builder.build().unwrap()).unwrap();
        assert_eq!(req.headers().get_all(AUTHORIZATION).iter().count(), 1);
        assert!(req.headers().get(AUTHORIZATION).unwrap().is_sensitive());

        // Case 2: mutating msg.vapid_signature post-build overrides stale Authorization on Aes128Gcm
        let mut builder = WebPushMessageBuilder::new(&info);
        builder.set_payload(ContentEncoding::Aes128Gcm, b"hello");
        builder.set_vapid_signature(old_sig.clone());
        let mut msg = builder.build().unwrap();
        msg.vapid_signature = Some(new_sig.clone());
        let req = try_build_request::<Vec<u8>>(msg).unwrap();
        let auths: Vec<_> = req.headers().get_all(AUTHORIZATION).iter().collect();
        assert_eq!(auths.len(), 1);
        assert!(auths[0].is_sensitive());
        assert_eq!(
            auths[0].to_str().unwrap(),
            format!("vapid t=fresh.jwt.token, k={new_k_b64}")
        );

        // Case 3: mutating msg.vapid_signature post-build on AesGcm updates both Authorization and Crypto-Key p256ecdsa
        let mut builder = WebPushMessageBuilder::new(&info);
        builder.set_payload(ContentEncoding::AesGcm, b"hello");
        builder.set_vapid_signature(old_sig);
        let mut msg = builder.build().unwrap();
        msg.vapid_signature = Some(new_sig.clone());
        let req = try_build_request::<Vec<u8>>(msg).unwrap();
        let auths: Vec<_> = req.headers().get_all(AUTHORIZATION).iter().collect();
        assert_eq!(auths.len(), 1);
        assert_eq!(
            auths[0].to_str().unwrap(),
            format!("vapid t=fresh.jwt.token, k={new_k_b64}")
        );
        let crypto_key = req.headers().get("Crypto-Key").unwrap().to_str().unwrap();
        assert!(crypto_key.starts_with("dh="));
        assert!(crypto_key.contains(&format!("; p256ecdsa={new_k_b64}")));
        assert_eq!(crypto_key.matches("p256ecdsa=").count(), 1);

        // Case 4: manually attaching msg.vapid_signature to an AesGcm message built without VAPID
        let mut builder = WebPushMessageBuilder::new(&info);
        builder.set_payload(ContentEncoding::AesGcm, b"hello");
        let mut msg = builder.build().unwrap();
        msg.vapid_signature = Some(new_sig);
        let req = try_build_request::<Vec<u8>>(msg).unwrap();
        let auths: Vec<_> = req.headers().get_all(AUTHORIZATION).iter().collect();
        assert_eq!(auths.len(), 1);
        assert!(auths[0].is_sensitive());
        assert_eq!(
            auths[0].to_str().unwrap(),
            format!("vapid t=fresh.jwt.token, k={new_k_b64}")
        );
        let crypto_key = req.headers().get("Crypto-Key").unwrap().to_str().unwrap();
        assert!(crypto_key.starts_with("dh="));
        assert!(crypto_key.contains(&format!("; p256ecdsa={new_k_b64}")));
    }

    #[test]
    fn aesgcm_crypto_key_rewrite_handles_comma_lists_and_multiple_headers() {
        use crate::WebPushPayload;

        let endpoint: Uri = "https://updates.push.services.mozilla.com/wpush/v2/token"
            .parse()
            .unwrap();
        let new_sig = VapidSignature {
            auth_t: "fresh.jwt.token".into(),
            auth_k: vec![4, 9, 8, 7],
        };
        let new_k_b64 = Base64UrlSafeNoPadding::encode_to_string(&new_sig.auth_k).unwrap();

        // Case 1: comma-separated list with standalone stale p256ecdsa element
        let msg = WebPushMessage {
            endpoint: endpoint.clone(),
            ttl: 60,
            urgency: None,
            topic: None,
            payload: Some(WebPushPayload {
                content: vec![1, 2, 3],
                crypto_headers: vec![
                    ("Crypto-Key", "dh=abc, p256ecdsa=stale".into()),
                    ("Encryption", "salt=xyz".into()),
                ],
                content_encoding: ContentEncoding::AesGcm,
            }),
            vapid_signature: Some(new_sig.clone()),
        };
        let req = try_build_request::<Vec<u8>>(msg).unwrap();
        let ck_vals: Vec<&str> = req
            .headers()
            .get_all("Crypto-Key")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(ck_vals, vec![format!("dh=abc; p256ecdsa={new_k_b64}")]);

        // Case 2: comma-separated list with semicolon-attached stale p256ecdsa and second record
        let msg = WebPushMessage {
            endpoint: endpoint.clone(),
            ttl: 60,
            urgency: None,
            topic: None,
            payload: Some(WebPushPayload {
                content: vec![1, 2, 3],
                crypto_headers: vec![
                    ("Crypto-Key", "dh=abc;p256ecdsa=stale, keyid=1".into()),
                    ("Encryption", "salt=xyz".into()),
                ],
                content_encoding: ContentEncoding::AesGcm,
            }),
            vapid_signature: Some(new_sig.clone()),
        };
        let req = try_build_request::<Vec<u8>>(msg).unwrap();
        let ck_vals: Vec<&str> = req
            .headers()
            .get_all("Crypto-Key")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(ck_vals, vec![format!("dh=abc, keyid=1; p256ecdsa={new_k_b64}")]);
        assert!(!ck_vals[0].contains("stale"));
        assert_eq!(ck_vals[0].matches("p256ecdsa=").count(), 1);

        // Case 3: multiple Crypto-Key headers (including p256ecdsa-only header and mixed-case key)
        let msg = WebPushMessage {
            endpoint: endpoint.clone(),
            ttl: 60,
            urgency: None,
            topic: None,
            payload: Some(WebPushPayload {
                content: vec![1, 2, 3],
                crypto_headers: vec![
                    ("Crypto-Key", "p256ecdsa=stale0".into()),
                    ("Crypto-Key", "dh=abc; P256ECDSA=stale1".into()),
                    ("Crypto-Key", "keyid=1; p256ecdsa=stale2".into()),
                    ("Encryption", "salt=xyz".into()),
                ],
                content_encoding: ContentEncoding::AesGcm,
            }),
            vapid_signature: Some(new_sig.clone()),
        };
        let req = try_build_request::<Vec<u8>>(msg).unwrap();
        let ck_vals: Vec<&str> = req
            .headers()
            .get_all("Crypto-Key")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            ck_vals,
            vec![format!("dh=abc; p256ecdsa={new_k_b64}"), "keyid=1".to_string()]
        );
        let joined = ck_vals.join(",");
        assert!(!joined.contains("stale"));
        assert_eq!(joined.matches("p256ecdsa=").count(), 1);

        // Case 4: all existing Crypto-Key headers contained only p256ecdsa -> emits exactly one
        let msg = WebPushMessage {
            endpoint: endpoint.clone(),
            ttl: 60,
            urgency: None,
            topic: None,
            payload: Some(WebPushPayload {
                content: vec![1, 2, 3],
                crypto_headers: vec![
                    ("Crypto-Key", "p256ecdsa=stale1".into()),
                    ("Crypto-Key", "P256ECDSA=stale2".into()),
                ],
                content_encoding: ContentEncoding::AesGcm,
            }),
            vapid_signature: Some(new_sig.clone()),
        };
        let req = try_build_request::<Vec<u8>>(msg).unwrap();
        let ck_vals: Vec<&str> = req
            .headers()
            .get_all("Crypto-Key")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(ck_vals, vec![format!("p256ecdsa={new_k_b64}")]);

        // Case 5: quoted-string parameter values with commas, semicolons, and escaped quotes are preserved verbatim
        let msg = WebPushMessage {
            endpoint: endpoint.clone(),
            ttl: 60,
            urgency: None,
            topic: None,
            payload: Some(WebPushPayload {
                content: vec![1, 2, 3],
                crypto_headers: vec![
                    (
                        "Crypto-Key",
                        r#"keyid="a,b"; p256ecdsa="stale;x", keyid="c\"d,e;f"; dh=abc"#.into(),
                    ),
                    ("Encryption", r#"keyid="a,b"; salt=xyz"#.into()),
                ],
                content_encoding: ContentEncoding::AesGcm,
            }),
            vapid_signature: Some(new_sig.clone()),
        };
        let req = try_build_request::<Vec<u8>>(msg).unwrap();
        let ck_vals: Vec<&str> = req
            .headers()
            .get_all("Crypto-Key")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            ck_vals,
            vec![format!(
                r#"keyid="a,b", keyid="c\"d,e;f"; dh=abc; p256ecdsa={new_k_b64}"#
            )]
        );
        assert!(!ck_vals[0].contains("stale"));
        assert_eq!(ck_vals[0].matches("p256ecdsa=").count(), 1);

        // Case 6: unclosed quoted-string fails closed instead of smuggling a stale p256ecdsa
        let msg = WebPushMessage {
            endpoint,
            ttl: 60,
            urgency: None,
            topic: None,
            payload: Some(WebPushPayload {
                content: vec![1, 2, 3],
                crypto_headers: vec![("Crypto-Key", r#"keyid="unclosed, p256ecdsa=stale"#.into())],
                content_encoding: ContentEncoding::AesGcm,
            }),
            vapid_signature: Some(new_sig),
        };
        assert!(matches!(
            try_build_request::<Vec<u8>>(msg),
            Err(WebPushError::Unspecified)
        ));
    }

    #[test]
    fn try_build_request_rejects_invalid_header_values_without_panicking() {
        let msg = WebPushMessage {
            endpoint: "https://updates.push.services.mozilla.com/wpush/v2/token"
                .parse()
                .unwrap(),
            ttl: 60,
            urgency: None,
            topic: Some("bad\r\ntopic".into()),
            payload: None,
            vapid_signature: None,
        };
        assert!(try_build_request::<Vec<u8>>(msg).is_err());
    }

    #[test]
    fn parses_a_successful_response_correctly() {
        assert!(matches!(parse_response(StatusCode::OK, vec![]), Ok(())));
    }

    #[test]
    fn parses_an_unauthorized_response_correctly() {
        assert!(matches!(
            parse_response(StatusCode::UNAUTHORIZED, vec![]),
            Err(WebPushError::Unauthorized(_))
        ));
    }

    #[test]
    fn parses_a_gone_response_correctly() {
        assert!(matches!(
            parse_response(StatusCode::GONE, vec![]),
            Err(WebPushError::EndpointNotValid(_))
        ));
    }

    #[test]
    fn parses_a_not_found_response_correctly() {
        assert!(matches!(
            parse_response(StatusCode::NOT_FOUND, vec![]),
            Err(WebPushError::EndpointNotFound(_))
        ));
    }

    #[test]
    fn parses_a_payload_too_large_response_correctly() {
        assert!(matches!(
            parse_response(StatusCode::PAYLOAD_TOO_LARGE, vec![]),
            Err(WebPushError::PayloadTooLarge)
        ));
    }

    #[test]
    fn parses_a_server_error_response_correctly() {
        assert!(matches!(
            parse_response(StatusCode::INTERNAL_SERVER_ERROR, vec![]),
            Err(WebPushError::ServerError { .. })
        ));
    }

    #[test]
    fn parses_a_too_many_requests_response_distinctly() {
        assert!(matches!(
            parse_response(StatusCode::TOO_MANY_REQUESTS, vec![]),
            Err(WebPushError::TooManyRequests { retry_after: None, .. })
        ));
    }

    #[test]
    fn parses_a_bad_request_response_with_no_body_correctly() {
        assert!(matches!(
            parse_response(StatusCode::BAD_REQUEST, vec![]),
            Err(WebPushError::BadRequest(_))
        ));
    }

    #[test]
    fn parses_a_bad_request_response_with_body_correctly() {
        let json = r#"
            {
                "code": 400,
                "errno": 103,
                "error": "FooBar",
                "message": "No message found"
            }
        "#;

        assert!(matches!(
            parse_response(StatusCode::BAD_REQUEST, json.as_bytes().to_vec()),
            Err(WebPushError::BadRequest(ErrorInfo {
                code: 400,
                errno: 103,
                error: _,
                message: _,
            })),
        ));
    }
}
