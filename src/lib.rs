//! # Web Push
//!
//! A library for creating and sending push notifications to a web browser. For
//! content payload encryption it uses [RFC8188](https://datatracker.ietf.org/doc/html/rfc8188)
//! and [RFC8291](https://datatracker.ietf.org/doc/html/rfc8291) implemented in pure Rust,
//! with pure-Rust ES256 VAPID authentication ([RFC8292](https://datatracker.ietf.org/doc/html/rfc8292))
//! and W3C Declarative Web Push [`Notification`] payload builders.
//!
//! By default (`hyper-client`), `HyperWebPushClient` uses `hyper 1.x` with pure-Rust TLS
//! (`hyper-rustls` + `ring`), OS root certificates, and a DNS-rebinding-safe connector with zero
//! OpenSSL or libcurl dependencies. Optional `HyperNativeTlsWebPushClient` (`hyper-native-tls`)
//! and `IsahcWebPushClient` (`isahc-client`) transports are also available.
//!
//! # Example
//!
//! ```no_run
//! # use sad_web_push::*;
//! # use std::fs::File;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
//! let endpoint = "https://updates.push.services.mozilla.com/wpush/v1/...";
//! let p256dh = "key_from_browser_as_base64";
//! let auth = "auth_from_browser_as_base64";
//!
//! // You would likely get this by deserializing a browser `pushSubscription` object.
//! let subscription_info = SubscriptionInfo::new(
//!     endpoint,
//!     p256dh,
//!     auth
//! );
//!
//! // Read signing material for payload.
//! let file = File::open("private.pem")?;
//! let sig_builder = VapidSignatureBuilder::from_pem(file, &subscription_info)?.build()?;
//!
//! // Now add payload and encrypt.
//! let mut builder = WebPushMessageBuilder::new(&subscription_info);
//! let content = "Encrypted payload to be sent in the notification".as_bytes();
//! builder.set_payload(ContentEncoding::Aes128Gcm, content);
//! builder.set_vapid_signature(sig_builder);
//!
//! # #[cfg(feature = "hyper-client")]
//! let client = HyperWebPushClient::new()?;
//!
//! // Finally, send the notification!
//! # #[cfg(feature = "hyper-client")]
//! client.send(builder.build()?).await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "hyper-client")]
pub use crate::clients::hyper_client::{HyperWebPushClient, HyperWebPushClientBuilder};
#[cfg(feature = "hyper-native-tls")]
pub use crate::clients::hyper_native_tls_client::{HyperNativeTlsWebPushClient, HyperNativeTlsWebPushClientBuilder};
#[cfg(feature = "isahc-client")]
pub use crate::clients::isahc_client::{IsahcWebPushClient, IsahcWebPushClientBuilder};
pub use crate::{
    clients::{request_builder, WebPushClient},
    error::{ErrorInfo, WebPushError},
    http_ece::ContentEncoding,
    message::{SubscriptionInfo, SubscriptionKeys, Urgency, WebPushMessage, WebPushMessageBuilder, WebPushPayload},
    notification::{Notification, NotificationAction},
    vapid::{builder::PartialVapidSignatureBuilder, VapidSignature, VapidSignatureBuilder},
};

mod clients;
mod endpoint;
mod error;
mod http_ece;
mod message;
mod notification;
mod vapid;
