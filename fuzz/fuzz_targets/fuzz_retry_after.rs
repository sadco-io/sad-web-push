#![no_main]

use libfuzzer_sys::fuzz_target;
use sad_web_push::request_builder;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = request_builder::parse_retry_after(s);
    }
});
