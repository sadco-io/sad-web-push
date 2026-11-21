#![no_main]

use libfuzzer_sys::fuzz_target;
use sad_web_push::{Notification, NotificationAction};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let mut parts = s.split('\0');
    let title = parts.next().unwrap_or("").to_string();
    let navigate = parts.next().unwrap_or("").to_string();

    let mut notification = Notification::<serde_json::Value>::new(title, navigate);
    notification.body = parts.next().map(str::to_string);
    notification.lang = parts.next().map(str::to_string);
    notification.dir = parts.next().map(str::to_string);
    notification.tag = parts.next().map(str::to_string);
    notification.image = parts.next().map(str::to_string);
    notification.icon = parts.next().map(str::to_string);
    notification.badge = parts.next().map(str::to_string);
    notification.data = parts.next().and_then(|raw| serde_json::from_str(raw).ok());
    notification.actions = parts.next().map(|action_title| {
        vec![NotificationAction {
            title: action_title.to_string(),
            action: parts.next().unwrap_or("act").to_string(),
            navigate: parts.next().unwrap_or("https://example.com").to_string(),
            icon: parts.next().map(str::to_string),
        }]
    });

    if let Ok(bytes) = notification.to_payload() {
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("to_payload must emit valid JSON");
        assert_eq!(parsed["web_push"], 8030);
    }
});
