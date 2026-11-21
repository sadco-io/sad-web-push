# sad-web-push

[![Build Status][gh-image]][gh-checks]
[![crates.io][cratesio-image]][cratesio]
[![Documentation][docsrs-image]][docsrs]
![Apache-2.0 licensed][license-image]
![MSRV][msrv-image]

[gh-image]: https://github.com/sadco-io/sad-web-push/actions/workflows/test.yml/badge.svg?branch=0.11.x
[gh-checks]: https://github.com/sadco-io/sad-web-push/actions/workflows/test.yml?query=branch%3A0.11.x
[cratesio-image]: https://img.shields.io/crates/v/sad-web-push.svg
[cratesio]: https://crates.io/crates/sad-web-push
[docsrs-image]: https://docs.rs/sad-web-push/badge.svg
[docsrs]: https://docs.rs/sad-web-push
[license-image]: https://img.shields.io/badge/license-Apache--2.0-blue.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.89+-blue.svg

Web push notification client with **pure-Rust HTTP-ECE encryption** (RFC 8188 / RFC 8291 `aes128gcm`
and legacy `aesgcm`) and **pure-Rust ES256 VAPID authentication**: a **maintained, API-compatible
fork of [pimeys/rust-web-push][upstream]** carrying security, cryptographic, protocol, and transport
hardening fixes.

This release replaces the upstream `ece` (`MPL-2.0` / OpenSSL), `jwt-simple` (which pulled in
`crypto-bigint 0.5.5`, referenced by `RUSTSEC-2026-0387`), `sec1_decode`, `pem`, and `chrono`
(referenced by informational `RUSTSEC-2026-0543`) dependencies while retaining the `http 0.2` API
and Cargo dependency-renaming compatibility with `web-push 0.11.0`.

## Which version?

* **`0.12.x`** *(recommended — receives all fixes)*: modernized release line targeting `http 1.x`,
  modern HTTP clients with pure-Rust TLS default (`hyper-rustls`), connect-time IP pinning on Hyper
  transports, and Declarative Web Push serialization support.
* **`0.11.x`** *(security fixes only)*: maintenance line retaining the `http 0.2` API
  (`isahc-client` default, `hyper-client` optional), MSRV `1.89.0`. Use `0.11.1` or later on this
  line if you need `http 0.2`.

## Usage

### Renamed usage (for migrating existing `web-push 0.11` code)

Switch existing `web-push 0.11` code without changing `use web_push::...` imports (note the
behavior, endpoint policy, timeout, payload limit, and MSRV changes listed below):

```toml
[dependencies]
web-push = { package = "sad-web-push", version = "0.11" }
```

### Direct usage

```toml
[dependencies]
sad-web-push = "0.11"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

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

    // Add payload and encrypt in pure Rust.
    let mut builder = WebPushMessageBuilder::new(&subscription_info);
    let content = "Encrypted payload to be sent in the notification".as_bytes();
    builder.set_payload(ContentEncoding::Aes128Gcm, content);
    builder.set_vapid_signature(sig_builder);

    let client = IsahcWebPushClient::new()?;
    client.send(builder.build()?).await?;
    Ok(())
}
```

### Pure-Rust core (no OpenSSL / no C dependencies)

When building with `--no-default-features`, `sad-web-push` compiles in pure Rust with zero OpenSSL
or libcurl dependencies. You can pair `request_builder::try_build_request` and
`request_builder::parse_response` with any HTTP client.

```toml
[dependencies]
sad-web-push = { version = "0.11", default-features = false }
```

## Compatibility & Differences from `web-push 0.11.0`

`sad-web-push 0.11.1` retains the `http 0.2` API and supports Cargo dependency renaming for
existing `web_push` imports (API compatibility verified with `cargo-semver-checks`), while making
deliberate security and correctness changes to endpoint policy, timeouts, payload limits, and MSRV:

* **Default builder endpoint policy:** `WebPushMessageBuilder::build()` and
  `VapidSignatureBuilder::build()` require canonical `https` and a nonempty host, reject embedded
  userinfo and malformed or zero explicit ports, accept valid non-default ports, and block
  localhost names, non-canonical numeric IPv4 forms, and disallowed special-use IPv4/IPv6 ranges
  (restricting IPv6 literals to `2000::/3` global unicast minus selected special-purpose and transition
  ranges, applying IPv4 rules to IPv4-mapped IPv6 and the well-known NAT64 prefix, and rejecting
  scoped IPv6 literals and local-use NAT64). For local testing or mock servers, call
  `.allow_insecure_endpoint(true)` on either builder. On `0.11.x`, built-in clients do not repeat
  this check in `send` and do not filter post-DNS IP addresses; see [SECURITY.md](SECURITY.md).
* **Default HTTP timeouts & redirect protection:** `IsahcWebPushClient::new()` and
  `HyperWebPushClient::new()` configure a 30-second overall request deadline and 10-second connect
  timeout (`with_timeout(d)` sets connect timeout to `min(10s, d)`). `HyperWebPushClient::from`
  adds the 30-second request deadline and keeps the supplied connector configuration;
  `IsahcWebPushClient::from` keeps the supplied client configuration while `send` enforces
  `RedirectPolicy::None` per request.
* **Consistent payload size limit:** Maximum unencrypted payload size is consistently enforced and
  documented as `3,800` bytes across `aes128gcm` and `aesgcm`. Legacy `aesgcm` rejects 0-byte
  plaintext (`InvalidCryptoKeys`) for compatibility with `ece`/Firefox.
* **VAPID headers on empty-payload pushes:** `WebPushMessageBuilder::build()` preserves the
  `Authorization: vapid ...` header even when no payload is attached, and `try_build_request` sets
  `Content-Length: 0` on all empty-body pushes.
* **HTTP 429 `Retry-After`:** `429 Too Many Requests` responses map to `WebPushError::ServerError`
  with the parsed `Retry-After` duration attached (capped at `31,536,000` seconds).
* **Additive public APIs:** Re-exported `ErrorInfo` at the crate root; added
  `request_builder::try_build_request`, `request_builder::parse_retry_after`,
  `allow_insecure_endpoint(bool)`, and client `with_timeout(Duration)`.
* **MSRV:** Rust `1.89.0` (driven by `aes 0.9.4`; `sha2 0.11.1` requires Rust `1.88`).

## Security & Hardening Summary

| Area | Upstream `web-push 0.11.0` | `sad-web-push 0.11.1` |
|---|---|---|
| Cryptography & Dependencies | `ece` (`MPL-2.0`, OpenSSL), `jwt-simple` (`RUSTSEC-2026-0387`), `sec1_decode`, `pem` | Pure-Rust `p256 0.14`, `aes-gcm 0.11`, `hkdf 0.13`, `sha2 0.11`, `pem-rfc7468 1.0`, `zeroize 1.8` |
| `Retry-After` Parsing | `chrono` (`RUSTSEC-2026-0543`), RFC 2822 only | Zero-dep `httpdate 1.0`, numeric seconds + RFC 7231 HTTP-dates capped at `31,536,000` seconds |
| Base64 VAPID Key Panic | Panics on non-32-byte keys (`rust-web-push#73`) | Pre-decode length check (43 chars / 32 bytes) returning `Err(WebPushError::InvalidCryptoKeys)` |
| Endpoint Validation & Request Building | Accepts `http://`, private/special-use IPs; unwraps URI parts | Builder HTTPS + IP/hostname/port policy (opt-in `allow_insecure_endpoint(true)`); fallible `try_build_request` (`build_request` remains panicking for compatibility) |
| Key & Response Bounds | Unbounded key reads; Hyper extended body before cap check | `65,536`-byte cap on PEM/DER reads; `65,536`-byte response cap (Hyper pre-append check; Isahc reads up to `65,537` bytes) |
| Secret Handling | Logged raw `Authorization` header at `DEBUG`; no zeroization | Redacted `Debug` for `VapidSignature`, `SubscriptionKeys`, `SubscriptionInfo`, `WebPushPayload`, and `WebPushMessage`; sensitive `Authorization` header; metadata-only built-in logs (host/TTL/status); `Zeroizing` library-owned buffers |
| Timeouts & Redirects | No timeouts | 30s request / 10s connect defaults + `with_timeout(Duration)`; redirects disabled |

See [SECURITY.md](SECURITY.md) for the full threat model, zeroization/redaction scope, `0.11.x`
SSRF residual risks, and vulnerability disclosure instructions.

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

## Crate Features

* `default`: Enables `isahc-client`.
* `isahc-client`: Async client built on `isahc` (executor-agnostic; uses libcurl with `static-curl`
  enabled by default and a build-dependent TLS backend).
* `hyper-client`: Async client built on `hyper 0.14` + `hyper-tls` (Tokio-only; uses platform
  `native-tls`).

## License & Attribution

`sad-web-push` is licensed under the [Apache License, Version 2.0](LICENSE).

See [NOTICE](NOTICE) for upstream copyright attribution (`Copyright 2017 Julius de Bruijn`, with
additional contributors at [pimeys/rust-web-push][upstream]) and a summary of modifications,
[CHANGELOG.md](CHANGELOG.md) for release notes, and [SECURITY.md](SECURITY.md) to report a
vulnerability.

[upstream]: https://github.com/pimeys/rust-web-push
