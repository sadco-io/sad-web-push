# Security Policy

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| `0.12.x` | Recommended (all fixes) | Recommended release line (`http 1.x`, modern HTTP clients, pure-Rust TLS default, connect-time IP pinning on Hyper clients). |
| `0.11.x` | Security fixes only | Maintenance line retaining the `http 0.2` API (`isahc-client` default, `hyper-client` optional). Use `0.11.1` or later on this line if you need `http 0.2`. |
| `< 0.11.1` | No | This policy covers `sad-web-push`. Report upstream `web-push` issues to upstream maintainers. |

## Scope & Threat Model

`sad-web-push` processes untrusted and security-sensitive inputs from browsers, push services, and
application configuration:

- **Untrusted subscription objects (`SubscriptionInfo`):** JSON deserialization, push endpoint URI
  parsing and scheme/host/port validation, `p256dh` public keys (exact 87-character base64url /
  65-byte uncompressed P-256 point), and `auth` secrets (exact 22-character base64url / 16 bytes).
- **VAPID key material:** PEM (SEC1 / PKCS#8, including multi-block), DER, and raw base64url
  private keys. PEM/DER `Read` inputs (including `_no_sub` variants) are capped at 65,536 bytes
  (returning `InvalidCryptoKeys` on overflow and `MissingCryptoKeys` if a PEM has no recognized
  private-key block). Raw base64url keys are length-checked (43 characters / 32 bytes) before
  decoding into a fixed-size zeroizing buffer, returning `InvalidCryptoKeys` on invalid input.
- **Payload encryption, declarative payloads & JWT signing:** Pure-Rust RFC 8188 / RFC 8291
  (`aes128gcm`), legacy draft-04 (`aesgcm`), W3C Push API draft `Notification` JSON serialization,
  and ES256 VAPID JWT signing. Custom VAPID `aud` and `sub` overrides are checked for JSON string
  type and `exp` for unsigned integer type; callers supplying overrides are responsible for RFC 8292
  claim values and expiry windows.
- **Untrusted push service responses:** HTTP status handling, `Retry-After` parsing (capped at
  31,536,000 seconds / 365 days), JSON `ErrorInfo` parsing, and a 65,536-byte response body cap
  (`ResponseTooLarge` on overflow; Hyper checks before appending each received chunk, while Isahc
  reads up to 65,537 bytes to detect overflow; the public `parse_response` helper accepts an already
  allocated body without an independent size cap).
- **Outbound push connections:** Endpoint validation and connect-time IP pinning in the built-in
  `hyper 1.x` transports.

Panics, unbounded memory/CPU consumption, cryptographic weaknesses, secret disclosure in logs or
`Debug` output, or validation bypasses reachable from these inputs are in scope.

### Zeroization & Redaction Scope

The library clears selected library-owned secrets on drop, including PEM/DER read buffers, decoded
raw private-key buffers, RustCrypto signing keys and ECDH shared secrets, decoded subscription
`auth` buffers, and explicit IKM, CEK, nonce, and plaintext-record buffers. Caller-owned input,
stored `SubscriptionKeys::auth` strings, JWT and header strings, and intermediate copies are
outside that guarantee.

`Debug` implementations redact `SubscriptionKeys::auth`, `VapidSignature::auth_t`, `WebPushPayload`
`Authorization` header values, and `WebPushMessage`/`SubscriptionInfo` endpoint paths and queries
(formatting only `<scheme>://<host>[:<port>]/[REDACTED]`). `request_builder::try_build_request`
marks `Authorization` header values as sensitive, and built-in client logs record only host, TTL,
and HTTP status. Callers should still treat subscription URLs, response error details (`ErrorInfo`),
and transport wire traces as sensitive.

### Endpoint Policy, Connect-Time IP Pinning & Residual Risks

By default, `WebPushMessageBuilder::build()`, `VapidSignatureBuilder::build()`, and all built-in
clients require canonical `https` and a nonempty host, reject embedded userinfo and malformed or
zero explicit ports, accept valid non-default ports, and block localhost names, non-canonical
numeric IPv4 forms, and disallowed IP ranges:

- **IPv4:** unspecified / "this network", RFC 1918 private, loopback, link-local, CGNAT,
  documentation, IETF protocol assignments, deprecated 6to4 relay anycast, benchmarking, multicast,
  and reserved/broadcast ranges.
- **IPv6:** restricted to global unicast (`2000::/3`) minus selected special-purpose and transition
  ranges (Teredo, benchmarking, AMT, ORCHID, ORCHIDv2, Drone Remote ID, documentation, and 6to4).
  IPv4 rules are applied to IPv4-mapped IPv6 and the well-known NAT64 prefix; scoped IPv6 literals
  and the local-use NAT64 prefix are rejected.

Explicitly opting out (`allow_insecure_endpoint(true)` on builders and
`allow_insecure_endpoints(true)` on clients) permits canonical `http` and skips the host/IP policy
while retaining nonempty-host, valid-port, and no-userinfo requirements.

Transport-specific boundaries and residual risks:

- **`HyperWebPushClient` (default `hyper-client`) and `HyperNativeTlsWebPushClient`
  (`hyper-native-tls`):** Validate the endpoint URL at send time (including hand-constructed
  `WebPushMessage` values). On each new connection they check every returned DNS address against the
  configured IP policy (rejecting mixed results containing any denied address with
  `WebPushError::InvalidUri`) and dial only those checked socket addresses directly, mitigating DNS
  rebinding between validation and connection. HTTPS still verifies the original endpoint host and
  uses DNS-name SNI where applicable. An established pooled connection can be reused without another
  DNS lookup. Default clients do not follow HTTP redirects. These checks do not establish that a
  destination is external to the deployment's network; locally routed addresses and translation
  infrastructure require separate egress controls.
- **`IsahcWebPushClient` (`isahc-client`):** Validates the initial URL at send time and enforces
  `RedirectPolicy::None` per request (including when wrapping a custom `isahc::HttpClient` via
  `From`), but delegates DNS resolution, proxy behavior, and TLS to Isahc. A private destination
  reached through DNS or a configured proxy is outside that initial validation, and custom clients
  supplied via `From` keep their configured proxy, TLS, and timeout settings.
- **Custom `request_builder` callers and `0.11.x`:** The public `request_builder` helpers leave
  endpoint and transport policy to the caller. On `0.11.x`, built-in clients do not repeat builder
  validation in `send` and do not filter post-DNS IPs. Deployments using `IsahcWebPushClient`,
  custom `request_builder` callers, or `0.11.x` with untrusted subscription URLs should pair the
  crate with an approved push-service allowlist and egress controls at the network boundary.

## Advisories

For each security fix we publish a GitHub Security Advisory for `sad-web-push` and request a RustSec advisory.
We watch upstream `pimeys/rust-web-push`'s issue tracker and RustSec advisories for `web-push`, and
mirror any that affect shared code. Because `cargo audit` and `cargo deny` match advisories by
package name, an upstream `web-push` advisory will not flag `sad-web-push` on its own.

## Reporting a Vulnerability

If you have discovered a security vulnerability in this project, please report it privately.
**Do not disclose it as a public issue.** This gives us time to work with you to fix the issue
before public exposure, reducing the chance that the exploit will be used before a patch is
released.

Please disclose it via a private [GitHub Security Advisory](https://github.com/sadco-io/sad-web-push/security/advisories/new).

If the issue also affects upstream [rust-web-push](https://github.com/pimeys/rust-web-push), we will
coordinate with its maintainers where possible.

This project is maintained by a team of volunteers on a reasonable-effort basis. We ask reporters to
allow 90 days for private coordination before public disclosure.
