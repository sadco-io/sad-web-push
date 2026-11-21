#![no_main]

use libfuzzer_sys::fuzz_target;
use sad_web_push::{request_builder, ContentEncoding, SubscriptionInfo, VapidSignatureBuilder, WebPushMessageBuilder};

const TEST_VAPID_B64: &str = "IQ9Ur0ykXoHS9gzfYX0aBjy9lvdrjx_PFUXmie9YRcY";

fuzz_target!(|data: &[u8]| {
    let sub: SubscriptionInfo = if let Ok(parsed) = serde_json::from_slice(data) {
        parsed
    } else if let Ok(s) = std::str::from_utf8(data) {
        let mut parts = s.splitn(3, '\n');
        SubscriptionInfo::new(
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
        )
    } else {
        return;
    };

    for allow_insecure in [false, true] {
        let mut vapid = VapidSignatureBuilder::from_base64(TEST_VAPID_B64, &sub).unwrap();
        vapid.allow_insecure_endpoint(allow_insecure);
        let sig = vapid.build().ok();

        for encoding in [ContentEncoding::Aes128Gcm, ContentEncoding::AesGcm] {
            let mut builder = WebPushMessageBuilder::new(&sub);
            builder.allow_insecure_endpoint(allow_insecure);
            builder.set_payload(encoding, b"fuzz payload");
            if let Some(ref s) = sig {
                builder.set_vapid_signature(s.clone());
            }
            if let Ok(msg) = builder.build() {
                let _ = request_builder::try_build_request::<Vec<u8>>(msg);
            }
        }
    }
});
