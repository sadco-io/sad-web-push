//! Contains implementations of web push clients.
//!
//! [`request_builder`] contains the functions used to send and consume push HTTP messages.
//! This module can be consumed by custom clients via [`http`]'s `1.x` types.

#[cfg(any(feature = "hyper-client", feature = "hyper-native-tls", feature = "isahc-client"))]
use std::time::Duration;

use async_trait::async_trait;

use crate::{WebPushError, WebPushMessage};

pub mod request_builder;

#[cfg(any(feature = "hyper-client", feature = "hyper-native-tls"))]
pub(crate) mod safe_connector;

#[cfg(feature = "hyper-client")]
pub mod hyper_client;

#[cfg(feature = "hyper-native-tls")]
pub mod hyper_native_tls_client;

#[cfg(feature = "isahc-client")]
pub mod isahc_client;

#[cfg(any(feature = "hyper-client", feature = "hyper-native-tls", feature = "isahc-client"))]
const MAX_RESPONSE_SIZE: usize = 64 * 1024;

#[cfg(any(feature = "hyper-client", feature = "hyper-native-tls", feature = "isahc-client"))]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(any(feature = "hyper-client", feature = "hyper-native-tls", feature = "isahc-client"))]
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// An async client for sending the notification payload.
/// Other features, such as thread safety, may vary by implementation.
#[async_trait]
pub trait WebPushClient {
    /// Sends a notification.
    ///
    /// Built-in clients apply default connect (10s) and request (30s) timeouts,
    /// which can be customized via `with_timeout` or the client's `builder()`.
    async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError>;
}
