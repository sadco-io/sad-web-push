#![no_main]

use libfuzzer_sys::fuzz_target;
use sad_web_push::{SubscriptionInfo, VapidSignatureBuilder};

fuzz_target!(|data: &[u8]| {
    let sub = SubscriptionInfo::new(
        "https://updates.push.services.mozilla.com/wpush/v2/token",
        "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
        "xS03Fi5ErfTNH_l9WHE9Ig",
    );
    if let Ok(builder) = VapidSignatureBuilder::from_der(data, &sub) {
        let _ = builder.build();
    }
    if let Ok(partial) = VapidSignatureBuilder::from_der_no_sub(data) {
        let _ = partial.get_public_key();
    }
});
