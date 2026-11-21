ChangeLog for sad-web-push
==========================

`sad-web-push` is a maintained fork of
[pimeys/rust-web-push](https://github.com/pimeys/rust-web-push). Upstream issue
and pull request references use the form `rust-web-push#NN`.

## sad-web-push 0.12.0

Modernized release line built on `http 1.x`, `hyper 1.x`, and Rustls by default,
with connect-time IP pinning on Hyper transports and W3C Push API draft
Declarative Web Push serialization support. No OpenSSL or libcurl library
dependency in the default `0.12` feature configuration.

### Breaking Changes

* **Upgraded to `http 1.x`:** `WebPushMessage::endpoint`,
  `request_builder::{build_request, try_build_request, parse_response}`, and all
  built-in transports now use `http 1.x` (`http::Uri`, `http::Request`,
  `http::StatusCode`).
* **Pure-Rust `hyper-client` is now the default feature:** `default = ["hyper-client"]`
  replaces `isahc-client`. `HyperWebPushClient` is built on `hyper 1.x`,
  `hyper-util`, `http-body-util`, and `hyper-rustls 0.27` (`ring` + OS native
  root certificates via `rustls-native-certs`; Unix root discovery may use
  `openssl-probe` and honor `SSL_CERT_FILE`/`SSL_CERT_DIR`), with no OpenSSL or
  libcurl library dependency in the default `0.12` feature configuration.
* **Fallible `HyperWebPushClient` constructors:** `HyperWebPushClient::new()`
  and `HyperWebPushClient::with_timeout(Duration)` now return
  `Result<Self, WebPushError>` (replacing `Default` and `From<hyper::Client>`).
  Use `HyperWebPushClient::builder()` to configure timeouts or opt into insecure
  local test endpoints.
* **`WebPushMessage::vapid_signature` field:** Added
  `pub vapid_signature: Option<VapidSignature>` directly on `WebPushMessage`.
  Empty-payload pushes with VAPID keep `message.payload = None` and carry the
  signature in `message.vapid_signature` instead of synthesizing an empty
  `WebPushPayload`. When set, `message.vapid_signature` is authoritative in
  `try_build_request` (replacing any stale `Authorization` header and stripping
  stale `p256ecdsa` parameters across legacy `AesGcm` `Crypto-Key` headers/lists
  before emitting the matching `p256ecdsa` parameter once).
* **Distinct `WebPushError` variants for HTTP 429 and timeouts:**
  * Added `WebPushError::TooManyRequests { retry_after: Option<Duration>, info: ErrorInfo }`
    for HTTP `429 Too Many Requests` (distinct from 5xx `WebPushError::ServerError`).
  * Added `WebPushError::Timeout`. On Hyper clients, both the 10-second DNS/TCP
    connector deadline and the 30-second overall request deadline (covering DNS,
    TCP, TLS, and response body reading) return `WebPushError::Timeout`. On
    `IsahcWebPushClient`, both `send_async` timeouts and response body-read
    timeouts map to `WebPushError::Timeout`. `with_timeout(d)` sets the connect
    timeout to `min(10s, d)`, and the client builders allow setting both
    deadlines independently.

### New Features

* **Declarative Web Push (`rust-web-push#72`, Daniel Dickison):** Added
  `Notification<D>` and `NotificationAction` builders serializing the W3C Push
  API draft JSON format (`{"web_push": 8030, "notification": ...}`) via
  `Notification::to_payload()`, deriving `Debug`, `Clone`, `PartialEq`, `Eq`,
  and `Serialize` (caller-supplied field values are serialized without
  browser-specific validation).
* **Optional `hyper-native-tls` transport (`HyperNativeTlsWebPushClient`):**
  Added a `hyper 1.x` client backed by `hyper-tls 0.6` (platform `native-tls`:
  Secure Transport on macOS, SChannel on Windows, OpenSSL on other supported
  targets) while keeping connect-time IP pinning via `SafeHttpConnector`.
* **Upgraded optional `isahc-client` transport to `isahc 2.x`:** Keeps
  executor-agnostic `IsahcWebPushClient` aligned with `http 1.x` (libcurl with
  `static-curl` enabled by default and build-dependent TLS), adding
  `IsahcWebPushClient::builder()`, send-time URL validation, and per-request
  `RedirectPolicy::None` enforcement.
* **RFC 8291 3,993-byte plaintext limit for `aes128gcm`:** Raised the plaintext
  limit for `ContentEncoding::Aes128Gcm` from `3,800` to `3,993` bytes; at that
  limit the complete encoded HTTP body is `4,096` bytes per RFC 8291 §4
  (86-byte header + 3,993-byte plaintext + 1-byte final-record delimiter +
  16-byte GCM authentication tag; `rs = 4,096`, encrypted record + tag = 4,010
  bytes). Legacy `ContentEncoding::AesGcm` remains at `3,800` plaintext bytes
  (3,818-byte encoded HTTP body) and rejects 0-byte plaintext
  (`InvalidCryptoKeys`) for compatibility with `ece`/Firefox. Added
  `ContentEncoding::max_payload_size()`.

### Security Hardening & Dependency Modernization

* **Connect-time IP pinning on Hyper transports (`SafeHttpConnector`):**
  `HyperWebPushClient` and `HyperNativeTlsWebPushClient` validate endpoint URIs
  at send time (including hand-constructed `WebPushMessage` values), check
  every address returned by `tokio::net::lookup_host` against the configured IP
  policy on each new connection (rejecting mixed results containing any denied
  address with `WebPushError::InvalidUri`), and dial only checked socket
  addresses directly (interleaving IPv6/IPv4 with fair per-attempt time budgets)
  while preserving URI-host TLS verification and DNS-name SNI, mitigating DNS
  rebinding between validation and connection. Default clients do not follow
  HTTP redirects. Local testing can opt in via `.allow_insecure_endpoints(true)`
  on the client builder (and `.allow_insecure_endpoint(true)` on message/VAPID
  builders). See `SECURITY.md` for pooled connection reuse, deployment egress
  controls, and `IsahcWebPushClient`/`request_builder` boundaries.
* **Explicit `rustls` `CryptoProvider`:** `HyperWebPushClient` constructs its
  `rustls::ClientConfig` with an explicit `Arc::new(rustls::crypto::ring::default_provider())`
  and OS root certificates (`rustls-native-certs`), without relying on the
  process-global provider.
* **Permissive-only dependency graph:** Uses `rustls-native-certs` (avoiding
  `webpki-roots` / `CDLA-Permissive-2.0`). `cargo deny --all-features check`
  and `cargo audit` passed cleanly as of 2026-11-20.
* **MSRV:** Declared `rust-version = "1.89.0"` (driven by `aes 0.9.4`; `sha2 0.11.1`
  requires Rust 1.88). Verified in Linux CI across `--no-default-features`,
  default (`hyper-client`), `hyper-native-tls`, `isahc-client`, and
  `--all-features`.

## sad-web-push 0.11.1

Initial `sad-web-push` maintenance release, based on `web-push 0.11.0` (commit
`8de73e2e`) plus cherry-picked documentation improvements from `d4d339b4` (Niklas
Fiekas, `rust-web-push#77`). Retains the `http 0.2` API and supports Cargo
dependency renaming for existing `web_push` imports (API compatibility verified
with `cargo-semver-checks`), keeping `isahc-client` (default) and `hyper-client`
features. Endpoint policy, timeouts, payload limits, and the minimum Rust
version have changed as detailed below.

### Pure-Rust Cryptography & Dependency Cleanup

* **Replaced `ece` (`MPL-2.0` / OpenSSL):** Implemented RFC 8188 / RFC 8291
  (`aes128gcm`) and legacy draft-ietf-webpush-encryption-04 (`aesgcm`) content
  encryption directly in pure Rust using `p256 0.14`, `aes-gcm 0.11`,
  `hkdf 0.13`, `sha2 0.11`, `getrandom 0.4`, and `zeroize 1.8`. Verified
  byte-for-byte against RFC 8291 Appendix A, draft-04 Section 5 test vectors,
  and wire-interoperability checks against `ece 2.4.2`. Legacy `AesGcm` rejects
  0-byte plaintext (`InvalidCryptoKeys`) for compatibility with `ece`/Firefox,
  while `Aes128Gcm` supports 0-byte plaintext.
* **Replaced `jwt-simple`, `sec1_decode`, and `pem`:** Implemented pure-Rust
  ES256 VAPID JWT signing with `p256::ecdsa::SigningKey` and bounded SEC1 /
  PKCS#8 PEM, DER, and raw base64url key parsing using `pem-rfc7468 1.0`.
  Removes the upstream `jwt-simple 0.12` dependency (which pulled in
  `crypto-bigint 0.5.5`, referenced by `RUSTSEC-2026-0387`), unmaintained
  `sec1_decode 0.1.0`, and unused transitive cryptography (`rsa`, `ml-dsa`,
  `k256`, `p384`, `ed25519-compact`).
* **Replaced `chrono`:** Replaced the RFC 2822 date parse in `RetryAfter` with
  zero-dependency `httpdate 1.0`, removing the upstream `chrono` dependency
  (referenced by informational `RUSTSEC-2026-0543`) and supporting RFC 7231
  HTTP-dates alongside numeric seconds (capped at 31,536,000 seconds / 365 days).
* **Serde `derive` feature:** Enabled `serde = { version = "1.0", features = ["derive"] }`
  in place of a direct `serde_derive` dependency and dropped unused
  `extern crate` macros.
* **Pure-Rust core (`--no-default-features`):** Building with
  `--no-default-features` has zero C, OpenSSL, or libcurl dependencies.
* **MSRV:** Declared `rust-version = "1.89.0"` (driven by `aes 0.9.4`; `sha2 0.11.1`
  requires Rust 1.88).

### Security & Robustness Hardening

* **Default builder endpoint policy:** `WebPushMessageBuilder::build` and
  `VapidSignatureBuilder::build` require canonical `https` and a nonempty host,
  reject embedded userinfo and malformed or zero explicit ports, accept valid
  non-default ports, and block localhost names, non-canonical numeric IPv4
  forms, and disallowed special-use IPv4/IPv6 ranges (restricting IPv6 literals
  to `2000::/3` global unicast minus selected special-purpose and transition
  ranges, applying IPv4 rules to IPv4-mapped IPv6 and the well-known NAT64
  prefix, and rejecting scoped IPv6 literals and local-use NAT64). Added opt-in
  `allow_insecure_endpoint(bool)` on both builders for local testing.
* **Fixed base64 VAPID private key panic ([rust-web-push#73](https://github.com/pimeys/rust-web-push/issues/73),
  reported by a-kolechko):** `VapidSignatureBuilder::from_base64` and `from_base64_no_sub`
  validate exact base64url encoded length (43 characters / 32 bytes) before
  decoding into a fixed-size zeroizing buffer and return
  `Err(WebPushError::InvalidCryptoKeys)` instead of panicking. Subscription
  `p256dh` (87 characters / 65 bytes) and `auth` (22 characters / 16 bytes)
  fields are likewise length-checked before fixed-buffer decoding.
* **Fallible URI parsing, request construction & claim type checks:**
  `VapidSigner::sign` returns errors instead of unwrapping missing URI schemes
  or hosts, canonicalizes the default `aud` origin to lowercase host/scheme
  while preserving valid non-default ports, and validates custom VAPID claim
  types (`aud` and `sub` must be JSON strings; `exp` must be an unsigned
  integer; callers supplying overrides remain responsible for RFC 8292 claim
  values). Added fallible `request_builder::try_build_request` (returning
  `WebPushError::Unspecified` on invalid headers); the compatibility helper
  `request_builder::build_request` delegates to it and documents `# Panics`.
* **Bounded key & response reads:** Capped `VapidSignatureBuilder::from_pem`,
  `from_pem_no_sub`, `from_der`, and `from_der_no_sub` `Read` inputs at 65,536
  bytes (`InvalidCryptoKeys` on overflow; `MissingCryptoKeys` if a PEM has no
  recognized private-key block). Capped built-in client response body reads at
  65,536 bytes (`ResponseTooLarge` on overflow; Hyper checks before appending
  each chunk; Isahc reads up to 65,537 bytes to detect overflow).
* **Secret redaction & zeroization:** Custom `Debug` implementations redact
  `VapidSignature::auth_t`, `SubscriptionKeys::auth`, `WebPushPayload`
  `Authorization` headers, and `WebPushMessage`/`SubscriptionInfo` endpoint
  paths/queries (`<scheme>://<host>[:<port>]/[REDACTED]`). `try_build_request`
  marks `Authorization` headers sensitive. Built-in client logs omit request
  headers and endpoint paths. Selected library-owned buffers are zeroized on
  drop; see `SECURITY.md` for exact scope.

### Protocol & Transport Fixes

* **VAPID headers preserved on empty-payload pushes & `Content-Length: 0`:**
  `WebPushMessageBuilder::build` preserves the `Authorization: vapid ...`
  header when `vapid_signature` is set without a payload, and
  `try_build_request` emits `Content-Length: 0` on all empty-body pushes
  without `Content-Encoding` or `Content-Type`.
* **HTTP 429 `Retry-After` support:** `request_builder::parse_response` maps
  `429 Too Many Requests` to `WebPushError::ServerError` on `0.11.x` (upgraded
  to `WebPushError::TooManyRequests` in `0.12.0`), allowing built-in clients to
  attach the parsed `Retry-After` duration.
* **Default HTTP timeouts & redirect protection:** Configured 30-second overall
  request and 10-second connect timeouts by default (`with_timeout(d)` sets
  connect timeout to `min(10s, d)`), and enforced per-request
  `RedirectPolicy::None` on `IsahcWebPushClient`.
* **Reconciled payload size limit:** Standardized `MAX_PAYLOAD_SIZE` to `3,800`
  bytes on `0.11.x` (raised to `3,993` bytes for `aes128gcm` in `0.12.0`).
* **Additive public API exports:** Re-exported `ErrorInfo` at the crate root
  and exposed `request_builder::try_build_request` and
  `request_builder::parse_retry_after`.
* **Clean feature matrix:** Zero compiler or Clippy warnings across all feature
  combinations.
* **Documentation (`rust-web-push#77`, Niklas Fiekas; `rust-web-push#74`,
  luveti):** Included upstream `WebPushMessageBuilder` documentation
  improvements and added SEC1 OpenSSL raw base64 VAPID private key extraction
  instructions to `README.md`.
