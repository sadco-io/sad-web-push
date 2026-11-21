ChangeLog for sad-web-push
==========================

`sad-web-push` is a maintained fork of
[pimeys/rust-web-push](https://github.com/pimeys/rust-web-push). Upstream issue
and pull request references use the form `rust-web-push#NN`.

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
  `cargo deny --all-features check` and `cargo audit` passed cleanly as of
  2026-11-20.
* **MSRV:** Declared `rust-version = "1.89.0"` (driven by `aes 0.9.4`; `sha2 0.11.1`
  requires Rust 1.88). Linux CI checks the library on Rust 1.89.0 across the
  configured feature combinations.

### Security & Robustness Hardening

* **Default builder endpoint policy:** `WebPushMessageBuilder::build` and
  `VapidSignatureBuilder::build` now require canonical `https` and a nonempty
  host, reject embedded userinfo and malformed or zero explicit ports, accept
  valid non-default ports, and block localhost names, non-canonical numeric
  IPv4 forms, and disallowed special-use IPv4/IPv6 ranges (restricting IPv6
  literals to `2000::/3` global unicast minus selected special-purpose and
  transition ranges, applying IPv4 rules to IPv4-mapped IPv6 and the well-known
  NAT64 prefix, and rejecting scoped IPv6 literals and local-use NAT64). Added
  opt-in `allow_insecure_endpoint(bool)` on both builders for local testing.
  On `0.11.x`, the built-in clients do not repeat this check in `send` and do
  not filter post-DNS IP addresses; see `SECURITY.md`.
* **Fixed base64 VAPID private key panic ([rust-web-push#73](https://github.com/pimeys/rust-web-push/issues/73),
  reported by a-kolechko):** `VapidSignatureBuilder::from_base64` and `from_base64_no_sub`
  now validate exact base64url encoded length (43 characters / 32 bytes) before
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
  headers and endpoint paths. Selected library-owned buffers (PEM/DER reads,
  decoded private keys, signing keys, ECDH secrets, decoded `auth`, IKM, CEK,
  nonce, and plaintext records) are zeroized on drop; see `SECURITY.md` for
  exact scope.

### Protocol & Transport Fixes

* **VAPID headers preserved on empty-payload pushes & `Content-Length: 0`:**
  `WebPushMessageBuilder::build` preserves the `Authorization: vapid ...`
  header when `vapid_signature` is set without a payload, and
  `try_build_request` emits `Content-Length: 0` on all empty-body pushes
  without `Content-Encoding` or `Content-Type`.
* **HTTP 429 `Retry-After` support:** `request_builder::parse_response` maps
  `429 Too Many Requests` to `WebPushError::ServerError`, allowing both
  `IsahcWebPushClient` and `HyperWebPushClient` to attach the parsed
  `Retry-After` duration.
* **Default HTTP timeouts & redirect protection:** `IsahcWebPushClient::new`
  and `HyperWebPushClient::new` configure a 30-second overall request deadline
  and a 10-second connect timeout (TCP connect on Hyper; `with_timeout(d)` sets
  connect timeout to `min(10s, d)`). `HyperWebPushClient::from` adds the
  30-second request deadline while keeping the supplied connector
  configuration; `IsahcWebPushClient::from` keeps the supplied client
  configuration while `send` enforces `RedirectPolicy::None` per request.
  `IsahcWebPushClient` maps request timeouts to `WebPushError::Io(TimedOut)`
  consistent with `HyperWebPushClient`.
* **Reconciled payload size limit:** Standardized `MAX_PAYLOAD_SIZE` to `3800`
  bytes consistently across `http_ece`, error messages, documentation, and
  boundary tests.
* **Additive public API exports:** Re-exported `ErrorInfo` at the crate root
  and exposed `request_builder::try_build_request` and
  `request_builder::parse_retry_after`.
* **Clean feature matrix:** Zero compiler or Clippy warnings across all feature
  combinations (`--no-default-features`, default `isahc-client`,
  `hyper-client`, and `--all-features`).
* **Documentation (`rust-web-push#77`, Niklas Fiekas; `rust-web-push#74`,
  luveti):** Included upstream `WebPushMessageBuilder` documentation
  improvements and added SEC1 OpenSSL raw base64 VAPID private key extraction
  instructions to `README.md`.
