//! Smoke test verifying renamed `web-push = { package = "sad-web-push" }` usage on `0.12.x`.

pub use http::StatusCode;
pub use web_push::{
    request_builder, ContentEncoding, ErrorInfo, HyperNativeTlsWebPushClient, HyperNativeTlsWebPushClientBuilder,
    HyperWebPushClient, HyperWebPushClientBuilder, IsahcWebPushClient, IsahcWebPushClientBuilder, Notification,
    NotificationAction, PartialVapidSignatureBuilder, SubscriptionInfo, SubscriptionKeys, Urgency, VapidSignature,
    VapidSignatureBuilder, WebPushClient, WebPushError, WebPushMessage, WebPushMessageBuilder, WebPushPayload,
};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    static PRIVATE_PEM: &[u8] = include_bytes!("../../../resources/vapid_test_key.pem");
    static PRIVATE_DER: &[u8] = include_bytes!("../../../resources/vapid_test_key.der");
    static PRIVATE_BASE64: &str = "IQ9Ur0ykXoHS9gzfYX0aBjy9lvdrjx_PFUXmie9YRcY";

    fn sample_subscription() -> SubscriptionInfo {
        SubscriptionInfo::new(
            "https://updates.push.services.mozilla.com/wpush/v2/token",
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            "xS03Fi5ErfTNH_l9WHE9Ig",
        )
    }

    #[test]
    fn renamed_vapid_notification_and_encrypted_message_build() {
        let sub = sample_subscription();

        let partial: PartialVapidSignatureBuilder = VapidSignatureBuilder::from_pem_no_sub(PRIVATE_PEM).unwrap();
        assert_eq!(partial.get_public_key().len(), 65);

        let sig_pem: VapidSignature = partial.clone().add_sub_info(&sub).build().unwrap();
        let sig_der: VapidSignature = VapidSignatureBuilder::from_der(PRIVATE_DER, &sub)
            .unwrap()
            .build()
            .unwrap();
        let sig_b64: VapidSignature = VapidSignatureBuilder::from_base64(PRIVATE_BASE64, &sub)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(sig_pem.auth_k, sig_der.auth_k);
        assert!(!sig_b64.auth_t.is_empty());

        let mut notification: Notification<()> =
            Notification::new("Hello".to_string(), "https://example.com/open".to_string());
        notification.body = Some("Declarative push test".to_string());
        notification.actions = Some(vec![NotificationAction {
            title: "View".to_string(),
            action: "view".to_string(),
            navigate: "https://example.com/view".to_string(),
            icon: None,
        }]);
        let declarative_bytes = notification.to_payload().unwrap();

        for encoding in [ContentEncoding::Aes128Gcm, ContentEncoding::AesGcm] {
            let mut builder = WebPushMessageBuilder::new(&sub);
            builder.set_ttl(3600);
            builder.set_urgency(Urgency::High);
            builder.set_topic("updates".to_string());
            builder.set_payload(encoding, &declarative_bytes);
            builder.set_vapid_signature(sig_pem.clone());

            let msg: WebPushMessage = builder.build().unwrap();
            let payload: &WebPushPayload = msg.payload.as_ref().unwrap();
            assert_eq!(payload.content_encoding, encoding);
            assert_eq!(msg.vapid_signature.as_ref(), Some(&sig_pem));

            let req = request_builder::try_build_request::<Vec<u8>>(msg).unwrap();
            assert_eq!(req.headers().get("Content-Encoding").unwrap(), encoding.to_str());
            assert_eq!(req.headers().get_all("Authorization").iter().count(), 1);
        }
    }

    #[test]
    fn renamed_empty_payload_vapid_errors_and_clients_compile() {
        let sub = sample_subscription();
        let sig = VapidSignatureBuilder::from_base64(PRIVATE_BASE64, &sub)
            .unwrap()
            .build()
            .unwrap();

        let mut builder = WebPushMessageBuilder::new(&sub);
        builder.set_vapid_signature(sig);
        let msg = builder.build().unwrap();
        assert!(msg.payload.is_none());
        assert!(msg.vapid_signature.is_some());

        let req = request_builder::build_request::<Vec<u8>>(msg);
        assert_eq!(req.headers().get_all("Authorization").iter().count(), 1);
        assert_eq!(req.headers().get("Content-Length").unwrap(), "0");

        let hyper_client: HyperWebPushClient = HyperWebPushClient::with_timeout(Duration::from_secs(5)).unwrap();
        let native_tls_client: HyperNativeTlsWebPushClient =
            HyperNativeTlsWebPushClient::with_timeout(Duration::from_secs(5)).unwrap();
        let isahc_client: IsahcWebPushClient = IsahcWebPushClient::with_timeout(Duration::from_secs(5)).unwrap();

        fn assert_client<C: WebPushClient>(_: &C) {}
        assert_client(&hyper_client);
        assert_client(&native_tls_client);
        assert_client(&isahc_client);

        let keys = SubscriptionKeys {
            p256dh: "pub".into(),
            auth: "secret".into(),
        };
        assert!(!format!("{keys:?}").contains("secret"));

        let err = request_builder::parse_response(StatusCode::TOO_MANY_REQUESTS, Vec::new()).unwrap_err();
        assert!(matches!(
            err,
            WebPushError::TooManyRequests {
                info: ErrorInfo { code: 429, .. },
                ..
            }
        ));
        assert_eq!(WebPushError::Timeout.short_description(), "timeout");
    }
}
