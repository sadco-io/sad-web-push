#![no_main]

use http::StatusCode;
use libfuzzer_sys::fuzz_target;
use sad_web_push::request_builder;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let code = u16::from_be_bytes([data[0], data[1]]);
    let Ok(status) = StatusCode::from_u16(code) else {
        return;
    };
    let _ = request_builder::parse_response(status, data[2..].to_vec());
});
