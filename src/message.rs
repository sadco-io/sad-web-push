use std::fmt::{self, Display, Formatter};

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use http::uri::Uri;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    endpoint::{redact_endpoint_str, redact_endpoint_uri, validate_endpoint},
    error::WebPushError,
    http_ece::{ContentEncoding, HttpEce},
    vapid::VapidSignature,
};

const P256DH_LEN: usize = 65;
const P256DH_B64_LEN: usize = 87;
const AUTH_LEN: usize = 16;
const AUTH_B64_LEN: usize = 22;

/// Encryption keys from the client.
#[derive(Deserialize, Serialize, Clone, Eq, PartialEq, Ord, PartialOrd, Default, Hash)]
pub struct SubscriptionKeys {
    /// The public key. Base64-encoded, URL-safe alphabet, no padding.
    pub p256dh: String,
    /// Authentication secret. Base64-encoded, URL-safe alphabet, no padding.
    pub auth: String,
}

impl fmt::Debug for SubscriptionKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionKeys")
            .field("p256dh", &self.p256dh)
            .field("auth", &"[REDACTED]")
            .finish()
    }
}

/// Client info for sending the notification. Maps the values from browser's
/// subscription info JSON data (AKA pushSubscription object).
///
/// Client pushSubscription objects can be directly deserialized into this struct using serde.
#[derive(Deserialize, Serialize, Clone, Eq, PartialEq, Ord, PartialOrd, Default, Hash)]
pub struct SubscriptionInfo {
    /// The endpoint URI for sending the notification.
    pub endpoint: String,
    /// The encryption key and secret for payload encryption.
    pub keys: SubscriptionKeys,
}

impl fmt::Debug for SubscriptionInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionInfo")
            .field("endpoint", &redact_endpoint_str(&self.endpoint))
            .field("keys", &self.keys)
            .finish()
    }
}

impl SubscriptionInfo {
    /// A constructor function to create a new `SubscriptionInfo`, if not using
    /// Serde's serialization.
    pub fn new<S>(endpoint: S, p256dh: S, auth: S) -> SubscriptionInfo
    where
        S: Into<String>,
    {
        SubscriptionInfo {
            endpoint: endpoint.into(),
            keys: SubscriptionKeys {
                p256dh: p256dh.into(),
                auth: auth.into(),
            },
        }
    }
}

/// The push content payload, already in an encrypted form.
#[derive(PartialEq)]
pub struct WebPushPayload {
    /// Encrypted content data.
    pub content: Vec<u8>,
    /// Headers depending on the authorization scheme and encryption standard.
    pub crypto_headers: Vec<(&'static str, String)>,
    /// The encryption standard.
    pub content_encoding: ContentEncoding,
}

impl fmt::Debug for WebPushPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        struct RedactedHeaders<'a>(&'a [(&'static str, String)]);

        impl fmt::Debug for RedactedHeaders<'_> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                let mut list = f.debug_list();
                for (k, v) in self.0 {
                    if k.eq_ignore_ascii_case("authorization") {
                        list.entry(&(*k, "[REDACTED]"));
                    } else {
                        list.entry(&(k, v));
                    }
                }
                list.finish()
            }
        }

        f.debug_struct("WebPushPayload")
            .field("content", &self.content)
            .field("crypto_headers", &RedactedHeaders(&self.crypto_headers))
            .field("content_encoding", &self.content_encoding)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Urgency {
    VeryLow,
    Low,
    #[default]
    Normal,
    High,
}

impl Display for Urgency {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let str = match self {
            Urgency::VeryLow => "very-low",
            Urgency::Low => "low",
            Urgency::Normal => "normal",
            Urgency::High => "high",
        };

        f.write_str(str)
    }
}

/// Everything needed to send a push notification to the user.
pub struct WebPushMessage {
    /// The endpoint URI where to send the payload.
    pub endpoint: Uri,
    /// Maximum time to live in seconds. Determines how long the message should
    /// be retained by the push server if the user is not online.
    pub ttl: u32,
    /// The urgency of the message.
    pub urgency: Option<Urgency>,
    /// The topic of the message.
    pub topic: Option<String>,
    /// The encrypted request payload, if sending any data.
    pub payload: Option<WebPushPayload>,
    /// Optional VAPID signature used to authenticate the push request, including
    /// for empty-payload pushes.
    pub vapid_signature: Option<VapidSignature>,
}

impl fmt::Debug for WebPushMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPushMessage")
            .field("endpoint", &redact_endpoint_uri(&self.endpoint))
            .field("ttl", &self.ttl)
            .field("urgency", &self.urgency)
            .field("topic", &self.topic)
            .field("payload", &self.payload)
            .field("vapid_signature", &self.vapid_signature)
            .finish()
    }
}

struct WebPushPayloadBuilder<'a> {
    pub content: &'a [u8],
    pub encoding: ContentEncoding,
}

/// The main class for creating a notification payload.
pub struct WebPushMessageBuilder<'a> {
    subscription_info: &'a SubscriptionInfo,
    payload: Option<WebPushPayloadBuilder<'a>>,
    ttl: u32,
    urgency: Option<Urgency>,
    topic: Option<String>,
    vapid_signature: Option<VapidSignature>,
    allow_insecure: bool,
}

impl<'a> WebPushMessageBuilder<'a> {
    /// Creates a builder for generating the web push payload.
    ///
    /// All parameters are from the subscription info given by browser when
    /// subscribing to push notifications.
    pub fn new(subscription_info: &'a SubscriptionInfo) -> WebPushMessageBuilder<'a> {
        WebPushMessageBuilder {
            subscription_info,
            ttl: 2_419_200,
            urgency: None,
            topic: None,
            payload: None,
            vapid_signature: None,
            allow_insecure: false,
        }
    }

    /// Allows insecure (`http://`) and loopback/private push endpoints when set
    /// to `true` (intended for local testing and mock servers).
    ///
    /// Defaults to `false`, which requires `https://` and rejects `localhost`,
    /// `*.localhost`, and non-public IP literals. Even when set to `true`, the
    /// endpoint must still be a valid `http` or `https` URI with a non-empty
    /// host and no embedded userinfo.
    pub fn allow_insecure_endpoint(&mut self, allow: bool) -> &mut Self {
        self.allow_insecure = allow;
        self
    }

    /// Maximum time to live in seconds. Determines how long the message should
    /// be retained by the push server if the user is not online for delivery.
    ///
    /// Some services may not accurately account for TTL or choose to retain
    /// messages for a shorter duration.
    ///
    /// A TTL of 0 seconds is valid and the message is delivered only if the
    /// user is immediately available for delivery.
    ///
    /// Defaults to 28 days.
    pub fn set_ttl(&mut self, seconds: u32) {
        self.ttl = seconds;
    }

    /// Urgency indicates to the push service how important a message is to the
    /// user. This can be used by the push service to help conserve the battery
    /// life of a user's device by only waking up for important messages when
    /// battery is low.
    ///
    /// Defaults to not specify an urgency.
    pub fn set_urgency(&mut self, urgency: Urgency) {
        self.urgency = Some(urgency);
    }

    /// Assign a topic to the push message. A message that has been stored
    /// by the push service can be replaced with new content if the message
    /// has been assigned a topic. If the user agent is offline during the
    /// time that the push messages are sent, updating a push message avoid
    /// the situation where outdated or redundant messages are sent to the
    /// user agent. A message with a topic replaces any outstanding push
    /// messages with an identical topic. It is an arbitrary string
    /// consisting of at most 32 base64url characters.
    ///
    /// Defaults to not specify a topic.
    pub fn set_topic(&mut self, topic: String) {
        self.topic = Some(topic);
    }

    /// Add a VAPID signature to the request. To be generated with the
    /// [`VapidSignatureBuilder`](struct.VapidSignatureBuilder.html).
    pub fn set_vapid_signature(&mut self, vapid_signature: VapidSignature) {
        self.vapid_signature = Some(vapid_signature);
    }

    /// If set, the client will get content in the notification.
    ///
    /// Has a maximum plaintext size of `3,993` bytes for [`ContentEncoding::Aes128Gcm`]
    /// (producing a 4,096-byte encoded HTTP body per RFC 8291 §4) and `3,800` bytes for
    /// legacy [`ContentEncoding::AesGcm`].
    ///
    /// `Aes128Gcm` is preferred, if the browser supports it.
    pub fn set_payload(&mut self, encoding: ContentEncoding, content: &'a [u8]) {
        self.payload = Some(WebPushPayloadBuilder { content, encoding });
    }

    /// Builds and if set, encrypts the payload.
    pub fn build(self) -> Result<WebPushMessage, WebPushError> {
        let endpoint = validate_endpoint(&self.subscription_info.endpoint, self.allow_insecure)?;
        let topic: Option<String> = self
            .topic
            .map(|topic| {
                if topic.len() > 32 {
                    Err(WebPushError::InvalidTopic)
                } else if topic.chars().all(is_base64url_char) {
                    Ok(topic)
                } else {
                    Err(WebPushError::InvalidTopic)
                }
            })
            .transpose()?;

        if let Some(payload) = self.payload {
            if self.subscription_info.keys.p256dh.len() != P256DH_B64_LEN
                || self.subscription_info.keys.auth.len() != AUTH_B64_LEN
            {
                return Err(WebPushError::InvalidCryptoKeys);
            }

            let mut p256dh = [0u8; P256DH_LEN];
            let p256dh_written = Base64UrlSafeNoPadding::decode(&mut p256dh, &self.subscription_info.keys.p256dh, None)
                .map_err(|_| WebPushError::InvalidCryptoKeys)?;
            if p256dh_written.len() != P256DH_LEN {
                return Err(WebPushError::InvalidCryptoKeys);
            }

            let mut auth = Zeroizing::new([0u8; AUTH_LEN]);
            let auth_written = Base64UrlSafeNoPadding::decode(auth.as_mut(), &self.subscription_info.keys.auth, None)
                .map_err(|_| WebPushError::InvalidCryptoKeys)?;
            if auth_written.len() != AUTH_LEN {
                return Err(WebPushError::InvalidCryptoKeys);
            }

            let http_ece = HttpEce::new(payload.encoding, &p256dh, auth.as_ref(), self.vapid_signature.clone());

            Ok(WebPushMessage {
                endpoint,
                ttl: self.ttl,
                urgency: self.urgency,
                topic,
                payload: Some(http_ece.encrypt(payload.content)?),
                vapid_signature: self.vapid_signature,
            })
        } else {
            Ok(WebPushMessage {
                endpoint,
                ttl: self.ttl,
                urgency: self.urgency,
                topic,
                payload: None,
                vapid_signature: self.vapid_signature,
            })
        }
    }
}

fn is_base64url_char(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_lowercase() || c.is_ascii_digit() || (c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_keys_debug_redacts_auth() {
        let keys = SubscriptionKeys {
            p256dh: "public-key-value".into(),
            auth: "super-secret-auth-token".into(),
        };
        let dbg = format!("{keys:?}");
        assert!(dbg.contains("public-key-value"));
        assert!(!dbg.contains("super-secret-auth-token"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn empty_payload_preserves_vapid_signature() {
        let info = SubscriptionInfo::new(
            "https://updates.push.services.mozilla.com/wpush/v2/token",
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            "xS03Fi5ErfTNH_l9WHE9Ig",
        );
        let sig = VapidSignature {
            auth_t: "header.payload.sig".into(),
            auth_k: vec![4, 1, 2, 3],
        };
        let mut builder = WebPushMessageBuilder::new(&info);
        builder.set_vapid_signature(sig.clone());

        let message = builder.build().unwrap();
        assert!(message.payload.is_none());
        assert_eq!(message.vapid_signature, Some(sig));
    }

    #[test]
    fn rejects_insecure_endpoint_unless_allowed() {
        let info = SubscriptionInfo::new(
            "http://127.0.0.1:8080/push",
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            "xS03Fi5ErfTNH_l9WHE9Ig",
        );
        assert!(matches!(
            WebPushMessageBuilder::new(&info).build(),
            Err(WebPushError::InvalidUri)
        ));

        let mut builder = WebPushMessageBuilder::new(&info);
        builder.allow_insecure_endpoint(true);
        assert!(builder.build().is_ok());
    }

    #[test]
    fn debug_redacts_endpoints_and_authorization_headers() {
        let secret_path = "super-secret-capability-token-xyz";
        let secret_auth = "xS03Fi5ErfTNH_l9WHE9Ig";
        let secret_jwt = "eyJhbGciOiJFUzI1NiJ9.super-secret-jwt-payload.signature";

        let info = SubscriptionInfo::new(
            format!("https://updates.push.services.mozilla.com:8443/wpush/v2/{secret_path}?q=1"),
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8".to_string(),
            secret_auth.to_string(),
        );

        let info_dbg = format!("{info:?}");
        assert!(info_dbg.contains("https://updates.push.services.mozilla.com:8443/[REDACTED]"));
        assert!(!info_dbg.contains(secret_path));
        assert!(!info_dbg.contains(secret_auth));

        for encoding in [Some(ContentEncoding::Aes128Gcm), Some(ContentEncoding::AesGcm), None] {
            let mut builder = WebPushMessageBuilder::new(&info);
            if let Some(enc) = encoding {
                builder.set_payload(enc, b"hello");
            }
            builder.set_vapid_signature(VapidSignature {
                auth_t: secret_jwt.into(),
                auth_k: vec![4, 1, 2, 3],
            });
            let msg = builder.build().unwrap();
            let msg_dbg = format!("{msg:?}");
            assert!(msg_dbg.contains("https://updates.push.services.mozilla.com:8443/[REDACTED]"));
            assert!(!msg_dbg.contains(secret_path));
            assert!(!msg_dbg.contains(secret_jwt));
            assert!(msg_dbg.contains("[REDACTED]"));

            if let Some(payload) = msg.payload.as_ref() {
                let payload_dbg = format!("{payload:?}");
                assert!(!payload_dbg.contains(secret_jwt));
                assert!(payload_dbg.contains("[REDACTED]"));
            }
        }
    }

    #[test]
    fn rejects_oversized_or_wrong_length_subscription_keys() {
        let valid_p256dh = "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8";
        let valid_auth = "xS03Fi5ErfTNH_l9WHE9Ig";

        let oversized_p256dh = SubscriptionInfo::new(
            "https://updates.push.services.mozilla.com/wpush/v2/token",
            &"A".repeat(1024),
            valid_auth,
        );
        let mut b = WebPushMessageBuilder::new(&oversized_p256dh);
        b.set_payload(ContentEncoding::Aes128Gcm, b"hi");
        assert!(matches!(b.build(), Err(WebPushError::InvalidCryptoKeys)));

        let oversized_auth = SubscriptionInfo::new(
            "https://updates.push.services.mozilla.com/wpush/v2/token",
            valid_p256dh,
            &"A".repeat(1024),
        );
        let mut b = WebPushMessageBuilder::new(&oversized_auth);
        b.set_payload(ContentEncoding::Aes128Gcm, b"hi");
        assert!(matches!(b.build(), Err(WebPushError::InvalidCryptoKeys)));
    }
}
