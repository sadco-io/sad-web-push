use serde::Serialize;

/// Declarative notification that can be used to populate the payload of a web push.
///
/// See <https://webkit.org/blog/16535/meet-declarative-web-push>.
///
/// # Example
///
/// ```
/// use sad_web_push::{Notification, NotificationAction};
///
/// let mut notification: Notification<()> = Notification::new(
///     "New message".to_string(),
///     "https://example.com/inbox".to_string(),
/// );
/// notification.body = Some("You have an unread message.".to_string());
/// notification.actions = Some(vec![NotificationAction {
///     title: "Open".to_string(),
///     action: "open".to_string(),
///     navigate: "https://example.com/inbox".to_string(),
///     icon: None,
/// }]);
///
/// let payload = notification.to_payload().unwrap();
/// assert!(!payload.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notification<D: Serialize> {
    /// The notification title shown to the user.
    pub title: String,
    /// The destination URL navigated to when the notification is activated.
    pub navigate: String,

    /// Optional notification body text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,

    /// Optional BCP 47 language tag for the notification text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,

    /// Optional text direction (`"auto"`, `"ltr"`, or `"rtl"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,

    /// Optional tag used to coalesce or replace notifications with the same tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Optional URL of a large image to display in the notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Optional URL of an icon to display in the notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    /// Optional URL of a monochrome badge icon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub badge: Option<String>,

    /// Optional vibration pattern in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vibrate: Option<Vec<u32>>,

    /// Optional Unix timestamp in milliseconds representing the notification event time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,

    /// Optional flag controlling whether the user is re-notified when replacing a tagged notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renotify: Option<bool>,

    /// Optional flag suppressing sound and vibration for the notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub silent: Option<bool>,

    /// Optional flag indicating the notification should remain active until the user interacts with it.
    #[serde(skip_serializing_if = "Option::is_none", rename = "requireInteraction")]
    pub require_interaction: Option<bool>,

    /// Optional structured application data attached to the notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<D>,

    /// Optional action buttons displayed on the notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<NotificationAction>>,
}

/// An action button presented on a declarative [`Notification`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotificationAction {
    /// Label displayed on the action button.
    pub title: String,
    /// Application-defined action identifier.
    pub action: String,
    /// Destination URL navigated to when the action button is activated.
    pub navigate: String,

    /// Optional URL of an icon to display on the action button.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

impl<D: Serialize> Notification<D> {
    /// Creates a new declarative notification with the required `title` and `navigate` URL.
    pub fn new(title: String, navigate: String) -> Self {
        Notification {
            title,
            navigate,
            lang: None,
            dir: None,
            tag: None,
            body: None,
            icon: None,
            image: None,
            badge: None,
            vibrate: None,
            timestamp: None,
            renotify: None,
            silent: None,
            require_interaction: None,
            data: None,
            actions: None,
        }
    }

    /// Serializes this notification as a W3C Declarative Web Push JSON payload
    /// (`{"web_push": 8030, "notification": ...}`) suitable for
    /// [`crate::WebPushMessageBuilder::set_payload`].
    pub fn to_payload(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(&DeclarativePushPayload::new(self))
    }
}

#[derive(Debug, Serialize)]
struct DeclarativePushPayload<'a, D: Serialize> {
    web_push: u16,
    pub notification: &'a Notification<D>,
}

impl<'a, D: Serialize> DeclarativePushPayload<'a, D> {
    pub fn new(notification: &'a Notification<D>) -> Self {
        DeclarativePushPayload {
            web_push: 8030,
            notification,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use serde_json::Value;

    use super::{Notification, NotificationAction};

    fn parse_payload<D: Serialize>(notification: &Notification<D>) -> Value {
        let bytes = notification.to_payload().expect("to_payload should not fail");
        serde_json::from_slice(&bytes).expect("payload should be valid JSON")
    }

    #[test]
    fn test_new_sets_required_fields() {
        let n: Notification<()> = Notification::new("Hello".to_string(), "https://example.com/".to_string());
        assert_eq!(n.title, "Hello");
        assert_eq!(n.navigate, "https://example.com/");
    }

    #[test]
    fn test_payload_web_push_field_is_rfc8030_magic_value() {
        let n: Notification<()> = Notification::new("t".to_string(), "u".to_string());
        let v = parse_payload(&n);
        assert_eq!(v["web_push"], 8030);
    }

    #[test]
    fn test_require_interaction_serializes_as_camel_case() {
        let mut n: Notification<()> = Notification::new("t".to_string(), "u".to_string());
        n.require_interaction = Some(true);
        let v = parse_payload(&n);
        assert_eq!(v["notification"]["requireInteraction"], true);
        assert!(v["notification"].get("require_interaction").is_none());
    }

    #[test]
    fn test_payload_with_custom_data_struct() {
        #[derive(Serialize)]
        struct MyData {
            user_id: u32,
            action: String,
        }

        let mut n = Notification::new("t".to_string(), "u".to_string());
        n.data = Some(MyData {
            user_id: 42,
            action: "open".to_string(),
        });
        let v = parse_payload(&n);
        assert_eq!(v["notification"]["data"]["user_id"], 42);
        assert_eq!(v["notification"]["data"]["action"], "open");
    }

    #[test]
    fn test_payload_with_primitive_data() {
        let mut n = Notification::new("t".to_string(), "u".to_string());
        n.data = Some("just a string");
        let v = parse_payload(&n);
        assert_eq!(v["notification"]["data"], "just a string");
    }

    #[test]
    fn test_notification_actions() {
        let mut n: Notification<()> = Notification::new("t".to_string(), "u".to_string());
        n.actions = Some(vec![
            NotificationAction {
                title: "Accept".to_string(),
                action: "accept".to_string(),
                navigate: "https://example.com/accept".to_string(),
                icon: None,
            },
            NotificationAction {
                title: "Decline".to_string(),
                action: "decline".to_string(),
                navigate: "https://example.com/decline".to_string(),
                icon: Some("https://example.com/decline-icon.png".to_string()),
            },
        ]);
        let v = parse_payload(&n);
        let actions = v["notification"]["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0]["action"], "accept");
        assert!(actions[0].get("icon").is_none());
        assert_eq!(actions[1]["action"], "decline");
        assert_eq!(actions[1]["icon"], "https://example.com/decline-icon.png");
    }
}
