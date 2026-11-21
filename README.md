# sad-web-push

[![Build Status][gh-image]][gh-checks]
[![crates.io][cratesio-image]][cratesio]
[![Documentation][docsrs-image]][docsrs]
![Apache-2.0 licensed][license-image]
![MSRV][msrv-image]

[gh-image]: https://github.com/sadco-io/sad-web-push/actions/workflows/test.yml/badge.svg?branch=main
[gh-checks]: https://github.com/sadco-io/sad-web-push/actions/workflows/test.yml?query=branch%3Amain
[cratesio-image]: https://img.shields.io/crates/v/sad-web-push.svg
[cratesio]: https://crates.io/crates/sad-web-push
[docsrs-image]: https://docs.rs/sad-web-push/badge.svg
[docsrs]: https://docs.rs/sad-web-push
[license-image]: https://img.shields.io/badge/license-Apache--2.0-blue.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.89+-blue.svg

Web push notification client with **pure-Rust HTTP-ECE encryption** (RFC 8188 / RFC 8291 `aes128gcm`
and legacy `aesgcm`), **pure-Rust ES256 VAPID authentication**, **`hyper 1.x` + `hyper-rustls`
default transport**, **connect-time IP pinning on Hyper transports**, and **W3C Push API draft
Declarative Web Push** serialization support: a **maintained fork of
[pimeys/rust-web-push][upstream]**.

This fork replaces the upstream `ece` (`MPL-2.0` / OpenSSL), `jwt-simple` (which pulled in
`crypto-bigint 0.5.5`, referenced by `RUSTSEC-2026-0387`), `sec1_decode`, `pem`, and `chrono`
(referenced by informational `RUSTSEC-2026-0543`) dependencies, with no OpenSSL or libcurl library
dependency in the default `0.12` feature configuration.

## Which version?

* **`0.12.x`** *(recommended — receives all fixes)*: modernized release line using `http 1.x`,
  `HyperWebPushClient` (`hyper 1.x` + `hyper-rustls` + `ring` + OS native root certificates) by
  default with no OpenSSL or libcurl library dependency, connect-time IP pinning on Hyper
  transports, `WebPushError::{TooManyRequests, Timeout}`, RFC 8291 3,993-byte `aes128gcm`
  plaintext payloads, and Declarative Web Push (`Notification`). MSRV `1.89.0`.
* **`0.11.x`** *(security fixes only)*: maintenance line retaining the `http 0.2` API
  (`isahc-client` default, `hyper-client` optional) with Cargo dependency-renaming support for
  existing `web_push` imports, MSRV `1.89.0`. Use `0.11.1` or later on this line if you need
  `http 0.2`.

## Usage

```toml
[dependencies]
sad-web-push = "0.12"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

### Sending a push notification (default `HyperWebPushClient`)

```rust,no_run
use std::fs::File;
use sad_web_push::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let endpoint = "https://updates.push.services.mozilla.com/wpush/v1/...";
    let p256dh = "key_from_browser_as_base64";
    let auth = "auth_from_browser_as_base64";

    // Typically deserialized from a browser `PushSubscription` object via serde.
    let subscription_info = SubscriptionInfo::new(endpoint, p256dh, auth);

    // Read VAPID signing material.
    let file = File::open("private_key.pem")?;
    let sig_builder = VapidSignatureBuilder::from_pem(file, &subscription_info)?.build()?;

    // Add payload and encrypt in pure Rust (up to 3,993 plaintext bytes for Aes128Gcm).
    let mut builder = WebPushMessageBuilder::new(&subscription_info);
    let content = "Encrypted payload to be sent in the notification".as_bytes();
    builder.set_payload(ContentEncoding::Aes128Gcm, content);
    builder.set_vapid_signature(sig_builder);

    // hyper 1.x + hyper-rustls client with connect-time IP pinning & 30s/10s default timeouts.
    let client = HyperWebPushClient::new()?;
    client.send(builder.build()?).await?;
    Ok(())
}
```

### Declarative Web Push (`Notification`)

`Notification::to_payload` serializes a declarative push message in the W3C Push API draft format
(`{"web_push": 8030, "notification": ...}`), accepting caller-supplied field values without
browser-specific validation. For a subscription created with an `applicationServerKey`, attach a
VAPID signature made with the corresponding private key before sending:

```rust,no_run
use std::fs::File;
use sad_web_push::{
    ContentEncoding, HyperWebPushClient, Notification, NotificationAction, SubscriptionInfo,
    VapidSignatureBuilder, WebPushClient, WebPushMessageBuilder,
};

# async fn send_declarative(sub: SubscriptionInfo) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let mut notification: Notification<()> = Notification::new(
    "New message".to_string(),
    "https://example.com/inbox".to_string(),
);
notification.body = Some("You have an unread message.".to_string());
notification.actions = Some(vec![NotificationAction {
    title: "Open".to_string(),
    action: "open".to_string(),
    navigate: "https://example.com/inbox".to_string(),
    icon: None,
}]);

let file = File::open("private_key.pem")?;
let signature = VapidSignatureBuilder::from_pem(file, &sub)?.build()?;

let payload = notification.to_payload()?;
let mut builder = WebPushMessageBuilder::new(&sub);
builder.set_payload(ContentEncoding::Aes128Gcm, &payload);
builder.set_vapid_signature(signature);

let client = HyperWebPushClient::new()?;
client.send(builder.build()?).await?;
# Ok(())
# }
```

### Endpoint Policy, Timeouts & Local Testing

By default, `HyperWebPushClient` and `HyperNativeTlsWebPushClient`:
- require canonical `https` and a nonempty host, reject embedded userinfo and malformed or zero
  explicit ports, accept valid non-default ports, and block localhost names, non-canonical numeric
  IPv4 forms, and disallowed special-use IPv4/IPv6 ranges (restricting IPv6 literals to `2000::/3`
  global unicast minus selected special-purpose and transition ranges, applying IPv4 rules to
  IPv4-mapped IPv6 and the well-known NAT64 prefix, and rejecting scoped IPv6 literals and
  local-use NAT64),
- validate the URL at send time, check every DNS-resolved address against the configured IP policy
  on each new connection, and dial only those checked socket addresses directly while preserving
  URI-host TLS certificate verification and DNS-name SNI (mitigating DNS rebinding between
  validation and connection; see [SECURITY.md](SECURITY.md) for pooled connection reuse and
  deployment egress controls),
- disable HTTP redirects,
- configure a 10-second DNS/TCP connect deadline and a 30-second overall request deadline (both
  returning `WebPushError::Timeout`), and
- enforce a `65,536`-byte maximum response body size (`WebPushError::ResponseTooLarge`).

Customize timeouts or opt into `http://` / loopback endpoints for local test harnesses via the
client builder. When targeting a local mock server with builder-produced messages, also set
`.allow_insecure_endpoint(true)` on `WebPushMessageBuilder` (and `VapidSignatureBuilder` if using
VAPID):

```rust,no_run
use std::time::Duration;
use sad_web_push::HyperWebPushClient;

# fn configure() -> Result<(), sad_web_push::WebPushError> {
// Production custom timeouts (endpoint and IP policy stays enabled):
let prod_client = HyperWebPushClient::builder()
    .timeout(Duration::from_secs(15))
    .connect_timeout(Duration::from_secs(5))
    .build()?;

// Local integration tests against a loopback mock server
// (also call `.allow_insecure_endpoint(true)` on WebPushMessageBuilder / VapidSignatureBuilder):
let test_client = HyperWebPushClient::builder()
    .timeout(Duration::from_secs(5))
    .allow_insecure_endpoints(true)
    .build()?;
# let _ = (prod_client, test_client);
# Ok(())
# }
```

### Pure-Rust core without built-in HTTP clients

Disable default features to compile only the pure-Rust RFC 8291 / VAPID / `Notification` core with
`request_builder::{try_build_request, parse_response, parse_retry_after}` (`http 1.x`):

```toml
[dependencies]
sad-web-push = { version = "0.12", default-features = false }
```

## Migrating from `0.11.x` (or `web-push 0.11.0`) to `0.12.0`

If you need to stay on `http 0.2`, use `sad-web-push = "0.11"` (renamed alias:
`web-push = { package = "sad-web-push", version = "0.11" }`; receives security fixes only). To
adopt `0.12.0`:

1. **HTTP types upgraded to `http 1.x`:** Update any direct `http` imports used with
   `WebPushMessage::endpoint` or `request_builder` from `http 0.2` to `http 1`.
2. **Default client switched to `HyperWebPushClient`:** `default = ["hyper-client"]` uses
   `hyper 1.x` + `hyper-rustls` (Tokio). If you need an executor-agnostic client, enable
   `default-features = false, features = ["isahc-client"]`; if you need platform native TLS on
   `hyper 1.x`, enable `default-features = false, features = ["hyper-native-tls"]`.
3. **Fallible `HyperWebPushClient::new()`:** Handle the `Result<HyperWebPushClient, WebPushError>`
   returned by `HyperWebPushClient::new()?` and `HyperWebPushClient::with_timeout(d)?`.
4. **Distinct `429` and timeout errors:** Match `WebPushError::TooManyRequests { retry_after, info }`
   for HTTP 429 rate limits and `WebPushError::Timeout` for configured Hyper connect/request
   deadlines and mapped Isahc request/body-read timeout errors.
5. **Empty-payload VAPID field:** `WebPushMessage` now has `pub vapid_signature: Option<VapidSignature>`.
   Empty-payload pushes keep `payload: None` while storing the VAPID signature in `vapid_signature`.
   If you construct `WebPushMessage` literals manually, initialize `vapid_signature: None` (or
   `Some(sig)`).

## Crate Features

* `default`: Enables `hyper-client`.
* `hyper-client`: Async client (`HyperWebPushClient`) built on `hyper 1.x` + `hyper-rustls 0.27`
  using an explicit `ring` provider and OS native root loading (`rustls-native-certs`; Unix root
  discovery may use `openssl-probe` and honor `SSL_CERT_FILE`/`SSL_CERT_DIR`) with connect-time IP
  pinning (`SafeHttpConnector`). No OpenSSL or libcurl library dependency in this default
  configuration. Requires Tokio.
* `hyper-native-tls`: Async client (`HyperNativeTlsWebPushClient`) built on `hyper 1.x` +
  `hyper-tls 0.6` (`native-tls`: Secure Transport on macOS, SChannel on Windows, OpenSSL on other
  supported targets) with connect-time IP pinning (`SafeHttpConnector`). Requires Tokio.
* `isahc-client`: Executor-agnostic async client (`IsahcWebPushClient`) built on `isahc 2.x`
  (libcurl with `static-curl` enabled by default and a build-dependent TLS backend). Enforces
  send-time URL validation and per-request `RedirectPolicy::None`, but delegates DNS and proxy
  handling to Isahc; see [SECURITY.md](SECURITY.md) for residual risk notes.

## VAPID Keys

VAPID authentication identifies your application server to push services and is used for
application-server-restricted subscriptions created with an `applicationServerKey`.

Generate a P-256 private key in SEC1 PEM format with OpenSSL:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
```

Derive the uncompressed URL-safe base64 public key for the browser (`applicationServerKey`):

```bash
openssl ec -in private_key.pem -pubout -outform DER | tail -c 65 | base64 | tr '/+' '_-' | tr -d '\n='
```

Extract the raw 32-byte URL-safe base64 private key for `VapidSignatureBuilder::from_base64` /
`from_base64_no_sub` (see `rust-web-push#74`; applies specifically to SEC1 keys generated by the
`openssl ecparam` command above, not PKCS#8 keys from `openssl genpkey`):

```bash
openssl ec -in private_key.pem -outform DER | tail -c +8 | head -c 32 | base64 | tr '/+' '_-' | tr -d '\n='
```

## Example Program

Store a browser `PushSubscription` JSON object in `test.json` and run:

```bash
cd examples/simple-send && cargo run -- -v ../../private_key.pem -f ../../test.json -p "It works!"
```

## License & Attribution

`sad-web-push` is licensed under the [Apache License, Version 2.0](LICENSE).

See [NOTICE](NOTICE) for upstream copyright attribution (`Copyright 2017 Julius de Bruijn`, with
additional contributors at [pimeys/rust-web-push][upstream]) and a summary of modifications,
[CHANGELOG.md](CHANGELOG.md) for release notes, and [SECURITY.md](SECURITY.md) for our threat model,
zeroization/redaction scope, transport security boundaries, and vulnerability disclosure process.

[upstream]: https://github.com/pimeys/rust-web-push
