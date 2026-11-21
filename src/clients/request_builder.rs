//! Functions used to send and consume push http messages.
//! This module can be used to build custom clients.

use std::time::Duration;

use http::{
    header::{HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    Request, StatusCode,
};

use crate::{
    error::{ErrorInfo, RetryAfter, WebPushError},
    message::WebPushMessage,
};

/// Fallibly builds the HTTP request to send to the push service.
///
/// Unlike [`build_request`], this function returns an error instead of panicking
/// if a manually constructed [`WebPushMessage`] (or a manually constructed
/// [`crate::VapidSignature`]) contains invalid HTTP header values. Messages
/// created via [`crate::WebPushMessageBuilder::build`] using signatures produced
/// by [`crate::VapidSignatureBuilder::build`] are guaranteed to produce valid
/// headers.
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
        for (k, v) in payload.crypto_headers.into_iter() {
            let mut header_val = HeaderValue::from_str(&v).map_err(|_| WebPushError::Unspecified)?;
            if k.eq_ignore_ascii_case("authorization") {
                header_val.set_sensitive(true);
            }
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
///  "https://updates.push.services.mozilla.com/wpush/v1/...",
///  "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
///  "xS03Fi5ErfTNH_l9WHE9Ig",
///  );
///
///  let builder = WebPushMessageBuilder::new(&info);
///
///  // Build the request for isahc
///  # #[cfg(feature = "isahc-client")]
///  let request = build_request::<isahc::Body>(builder.build().unwrap());
///  // Send using a http client
/// ```
pub fn build_request<T>(message: WebPushMessage) -> Request<T>
where
    T: From<Vec<u8>> + From<&'static str>, //This bound can be reduced to a &[u8] instead of str if needed
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
        StatusCode::TOO_MANY_REQUESTS => Err(WebPushError::ServerError {
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
    #[cfg(feature = "isahc-client")]
    use http::Uri;

    use crate::{
        clients::request_builder::*, error::WebPushError, message::WebPushMessageBuilder, SubscriptionInfo,
        VapidSignature, WebPushMessage,
    };
    #[cfg(feature = "isahc-client")]
    use crate::{http_ece::ContentEncoding, Urgency};

    #[cfg(feature = "isahc-client")]
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

        let request = build_request::<isahc::Body>(builder.build().unwrap());
        let ttl = request.headers().get("TTL").unwrap().to_str().unwrap();
        let urgency = request.headers().get("Urgency").unwrap().to_str().unwrap();
        let topic = request.headers().get("Topic").unwrap().to_str().unwrap();
        let expected_uri: Uri = "fcm.googleapis.com".parse().unwrap();

        assert_eq!("420", ttl);
        assert_eq!("very-low", urgency);
        assert_eq!("some-topic", topic);
        assert_eq!(request.headers().get(CONTENT_LENGTH).unwrap(), "0");
        assert_eq!(expected_uri.host(), request.uri().host());
    }

    #[cfg(feature = "isahc-client")]
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

        let request = build_request::<isahc::Body>(builder.build().unwrap());

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

        let request = try_build_request::<Vec<u8>>(builder.build().unwrap()).unwrap();
        let auth = request.headers().get("Authorization").unwrap();
        assert!(auth.is_sensitive(), "Authorization header must be marked sensitive");
        assert_eq!(request.headers().get(CONTENT_LENGTH).unwrap(), "0");
        assert!(request.headers().get(CONTENT_ENCODING).is_none());
        assert!(request.headers().get(CONTENT_TYPE).is_none());
        assert!(request.body().is_empty());

        // Non-VAPID empty push also sets Content-Length: 0.
        let empty_req = try_build_request::<Vec<u8>>(WebPushMessageBuilder::new(&info).build().unwrap()).unwrap();
        assert_eq!(empty_req.headers().get(CONTENT_LENGTH).unwrap(), "0");
        assert!(empty_req.body().is_empty());
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
    fn parses_a_too_many_requests_response_as_server_error() {
        assert!(matches!(
            parse_response(StatusCode::TOO_MANY_REQUESTS, vec![]),
            Err(WebPushError::ServerError { retry_after: None, .. })
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
