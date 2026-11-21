use std::{
    convert::From,
    error::Error,
    fmt,
    io::Error as IoError,
    string::FromUtf8Error,
    time::{Duration, SystemTime},
};

use http::uri::InvalidUri;
use serde::{Deserialize, Serialize};
use serde_json::error::Error as JsonError;

/// Maximum `Retry-After` duration accepted (365 days) to prevent arithmetic
/// overflows when callers add the returned `Duration` to an `Instant` or `SystemTime`.
const MAX_RETRY_AFTER_SECS: u64 = 365 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: u16,
    pub errno: u16,
    pub error: String,
    pub message: String,
}

impl fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "code {}, errno {}: {} ({})",
            self.code, self.errno, self.error, self.message
        )
    }
}

#[derive(Debug)]
pub enum WebPushError {
    /// An unknown error happened while encrypting or sending the message
    Unspecified,
    /// Please provide valid credentials to send the notification
    Unauthorized(ErrorInfo),
    /// Request was badly formed
    BadRequest(ErrorInfo),
    /// The push service returned HTTP 429 Too Many Requests.
    /// Contains an optional `Duration` indicating when the request can be retried.
    TooManyRequests {
        retry_after: Option<Duration>,
        info: ErrorInfo,
    },
    /// The push service returned a 5xx server error.
    /// Contains an optional `Duration` indicating when the request can be retried.
    ServerError {
        retry_after: Option<Duration>,
        info: ErrorInfo,
    },
    /// The push request or connection timed out.
    Timeout,
    /// The feature is not implemented yet
    NotImplemented(ErrorInfo),
    /// The provided URI is invalid or disallowed by endpoint security policy
    InvalidUri,
    /// The URL specified is no longer valid and should no longer be used
    EndpointNotValid(ErrorInfo),
    /// The URL specified is invalid and should not be used again
    EndpointNotFound(ErrorInfo),
    /// Maximum allowed payload size exceeded (3993 bytes for `aes128gcm`, 3800 bytes for `aesgcm`)
    PayloadTooLarge,
    /// Error in reading a file or performing I/O
    Io(IoError),
    /// Make sure the message was addressed to a registration token whose
    /// package name matches the value passed in the request (Google).
    InvalidPackageName,
    /// The TTL value provided was not valid or was not provided
    InvalidTtl,
    /// The Topic value provided was invalid
    InvalidTopic,
    /// The request was missing required crypto keys
    MissingCryptoKeys,
    /// One or more of the crypto key elements are invalid.
    InvalidCryptoKeys,
    /// Corrupted response data
    InvalidResponse,
    /// A claim had invalid data
    InvalidClaims,
    /// Response from push endpoint was too large
    ResponseTooLarge,
    Other(ErrorInfo),
}

impl Error for WebPushError {}

impl From<JsonError> for WebPushError {
    fn from(_: JsonError) -> WebPushError {
        WebPushError::InvalidResponse
    }
}

impl From<FromUtf8Error> for WebPushError {
    fn from(_: FromUtf8Error) -> WebPushError {
        WebPushError::InvalidResponse
    }
}

impl From<InvalidUri> for WebPushError {
    fn from(_: InvalidUri) -> WebPushError {
        WebPushError::InvalidUri
    }
}

#[cfg(any(feature = "hyper-client", feature = "hyper-native-tls"))]
impl From<hyper::Error> for WebPushError {
    fn from(_: hyper::Error) -> Self {
        Self::Unspecified
    }
}

#[cfg(any(feature = "hyper-client", feature = "hyper-native-tls"))]
impl From<hyper_util::client::legacy::Error> for WebPushError {
    fn from(err: hyper_util::client::legacy::Error) -> Self {
        use crate::clients::safe_connector::SafeConnectError;

        let mut source: Option<&(dyn Error + 'static)> = err.source();
        while let Some(cur) = source {
            if let Some(connect_err) = cur.downcast_ref::<SafeConnectError>() {
                return match connect_err {
                    SafeConnectError::DisallowedEndpoint => Self::InvalidUri,
                    SafeConnectError::TimedOut => Self::Timeout,
                    SafeConnectError::Io(_) => Self::Unspecified,
                };
            }
            source = cur.source();
        }
        Self::Unspecified
    }
}

#[cfg(feature = "isahc-client")]
impl From<isahc::Error> for WebPushError {
    fn from(err: isahc::Error) -> Self {
        match err.kind() {
            isahc::error::ErrorKind::Timeout => Self::Timeout,
            _ => Self::Unspecified,
        }
    }
}

impl From<IoError> for WebPushError {
    fn from(err: IoError) -> WebPushError {
        WebPushError::Io(err)
    }
}

impl WebPushError {
    pub fn short_description(&self) -> &'static str {
        match *self {
            WebPushError::Unspecified => "unspecified",
            WebPushError::Unauthorized(_) => "unauthorized",
            WebPushError::BadRequest(_) => "bad_request",
            WebPushError::TooManyRequests { .. } => "too_many_requests",
            WebPushError::ServerError { .. } => "server_error",
            WebPushError::Timeout => "timeout",
            WebPushError::NotImplemented(_) => "not_implemented",
            WebPushError::InvalidUri => "invalid_uri",
            WebPushError::EndpointNotValid(_) => "endpoint_not_valid",
            WebPushError::EndpointNotFound(_) => "endpoint_not_found",
            WebPushError::PayloadTooLarge => "payload_too_large",
            WebPushError::InvalidPackageName => "invalid_package_name",
            WebPushError::InvalidTtl => "invalid_ttl",
            WebPushError::InvalidTopic => "invalid_topic",
            WebPushError::InvalidResponse => "invalid_response",
            WebPushError::MissingCryptoKeys => "missing_crypto_keys",
            WebPushError::InvalidCryptoKeys => "invalid_crypto_keys",
            WebPushError::Io(_) => "io_error",
            WebPushError::Other(_) => "other",
            WebPushError::InvalidClaims => "invalidClaims",
            WebPushError::ResponseTooLarge => "response_too_large",
        }
    }
}

impl fmt::Display for WebPushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WebPushError::Unspecified => write!(f, "unspecified error"),
            WebPushError::Unauthorized(info) => write!(f, "unauthorized: {}", info),
            WebPushError::BadRequest(info) => write!(f, "bad request: {}", info),
            WebPushError::TooManyRequests { info, .. } => write!(f, "too many requests: {}", info),
            WebPushError::ServerError { info, .. } => write!(f, "server error: {}", info),
            WebPushError::Timeout => write!(f, "push request timed out"),
            WebPushError::PayloadTooLarge => {
                write!(
                    f,
                    "maximum payload size exceeded (3993 bytes for aes128gcm, 3800 bytes for aesgcm)"
                )
            }
            WebPushError::InvalidUri => write!(f, "invalid uri provided"),
            WebPushError::NotImplemented(info) => write!(f, "not implemented: {}", info),
            WebPushError::EndpointNotValid(info) => write!(f, "endpoint not valid: {}", info),
            WebPushError::EndpointNotFound(info) => write!(f, "endpoint not found: {}", info),
            WebPushError::Io(err) => write!(f, "i/o error: {}", err),
            WebPushError::InvalidPackageName => write!(
                f,
                "package name of registration token does not match package name provided in the request"
            ),
            WebPushError::InvalidTtl => write!(f, "invalid or missing ttl value"),
            WebPushError::InvalidTopic => write!(f, "invalid topic value"),
            WebPushError::InvalidResponse => write!(f, "could not parse response data"),
            WebPushError::MissingCryptoKeys => write!(f, "request is missing cryptographic keys"),
            WebPushError::InvalidCryptoKeys => write!(f, "request has invalid cryptographic keys"),
            WebPushError::Other(info) => write!(f, "other: {}", info),
            WebPushError::InvalidClaims => write!(f, "at least one jwt claim was invalid"),
            WebPushError::ResponseTooLarge => write!(f, "response from push endpoint was too large"),
        }
    }
}

pub(crate) struct RetryAfter;

impl RetryAfter {
    pub(crate) fn from_str(header_value: &str) -> Option<Duration> {
        let trimmed = header_value.trim();
        let max_duration = Duration::from_secs(MAX_RETRY_AFTER_SECS);

        if let Ok(seconds) = trimmed.parse::<u64>() {
            Some(Duration::from_secs(seconds.min(MAX_RETRY_AFTER_SECS)))
        } else {
            httpdate::parse_http_date(trimmed)
                .map(|systime| {
                    systime
                        .duration_since(SystemTime::now())
                        .unwrap_or_else(|_| Duration::new(0, 0))
                        .min(max_duration)
                })
                .ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_parses_seconds_and_clamps() {
        assert_eq!(RetryAfter::from_str("0"), Some(Duration::from_secs(0)));
        assert_eq!(RetryAfter::from_str("120"), Some(Duration::from_secs(120)));
        assert_eq!(RetryAfter::from_str("  42  "), Some(Duration::from_secs(42)));
        assert_eq!(
            RetryAfter::from_str(&u64::MAX.to_string()),
            Some(Duration::from_secs(MAX_RETRY_AFTER_SECS))
        );
    }

    #[test]
    fn retry_after_parses_http_dates() {
        // Past RFC 7231 IMF-fixdate clamps to zero.
        assert_eq!(
            RetryAfter::from_str("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(Duration::from_secs(0))
        );

        // Future date returns positive duration bounded by MAX_RETRY_AFTER_SECS.
        let future = SystemTime::now() + Duration::from_secs(600);
        let formatted = httpdate::fmt_http_date(future);
        let parsed = RetryAfter::from_str(&formatted).unwrap();
        assert!(parsed <= Duration::from_secs(600));
        assert!(parsed >= Duration::from_secs(595));

        // Far-future date clamps to MAX_RETRY_AFTER_SECS.
        assert_eq!(
            RetryAfter::from_str("Fri, 31 Dec 9999 23:59:59 GMT"),
            Some(Duration::from_secs(MAX_RETRY_AFTER_SECS))
        );
    }

    #[test]
    fn retry_after_rejects_invalid_values() {
        for bad in ["", "-5", "not-a-date", "12.5", "99999999999999999999999999999"] {
            assert_eq!(RetryAfter::from_str(bad), None, "expected None for {bad:?}");
        }
    }

    #[test]
    fn new_error_variants_have_expected_descriptions() {
        let info = ErrorInfo {
            code: 429,
            errno: 999,
            error: "rate_limited".into(),
            message: "slow down".into(),
        };
        let tmr = WebPushError::TooManyRequests {
            retry_after: Some(Duration::from_secs(30)),
            info,
        };
        assert_eq!(tmr.short_description(), "too_many_requests");
        assert!(tmr.to_string().contains("too many requests"));

        let timeout = WebPushError::Timeout;
        assert_eq!(timeout.short_description(), "timeout");
        assert!(timeout.to_string().contains("timed out"));
    }
}
