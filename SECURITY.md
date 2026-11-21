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
- **Payload encryption & JWT signing:** Pure-Rust RFC 8188 / RFC 8291 (`aes128gcm`), legacy
  draft-04 (`aesgcm`), and ES256 VAPID JWT signing. Custom VAPID `aud` and `sub` overrides are
  checked for JSON string type and `exp` for unsigned integer type; callers supplying overrides are
  responsible for RFC 8292 claim values and expiry windows.
- **Untrusted push service responses:** HTTP status handling, `Retry-After` parsing (capped at
  31,536,000 seconds / 365 days), JSON `ErrorInfo` parsing, and a 65,536-byte response body cap
  (`ResponseTooLarge` on overflow; Hyper checks before appending each received chunk, while Isahc
  reads up to 65,537 bytes to detect overflow; the public `parse_response` helper accepts an already
  allocated body without an independent size cap).

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

### Endpoint Policy & SSRF Residual Risks on `0.11.x`

By default, `WebPushMessageBuilder::build()` and `VapidSignatureBuilder::build()` require canonical
`https` and a nonempty host, reject embedded userinfo and malformed or zero explicit ports, accept
valid non-default ports, and block localhost names, non-canonical numeric IPv4 forms, and
disallowed IP ranges:

- **IPv4:** unspecified / "this network", RFC 1918 private, loopback, link-local, CGNAT,
  documentation, IETF protocol assignments, deprecated 6to4 relay anycast, benchmarking, multicast,
  and reserved/broadcast ranges.
- **IPv6:** restricted to global unicast (`2000::/3`) minus selected special-purpose and transition
  ranges (Teredo, benchmarking, AMT, ORCHID, ORCHIDv2, Drone Remote ID, documentation, and 6to4).
  IPv4 rules are applied to IPv4-mapped IPv6 and the well-known NAT64 prefix; scoped IPv6 literals
  and the local-use NAT64 prefix are rejected.

Explicitly opting out via `allow_insecure_endpoint(true)` permits canonical `http` and skips the
host/IP policy while retaining nonempty-host, valid-port, and no-userinfo requirements.

On the `0.11.x` release line:

- Endpoint validation runs in the message and VAPID builders. `IsahcWebPushClient` and
  `HyperWebPushClient` do **not** repeat this policy inside `send`, so applications that
  hand-construct or modify a `WebPushMessage` directly must enforce endpoint validation before
  sending.
- Neither client checks the IP address selected after DNS resolution. A DNS name that resolves to
  an internal/private IP address or performs DNS rebinding is not blocked by `sad-web-push 0.11.x`
  alone.
- Default clients do not follow HTTP redirects, and `IsahcWebPushClient::send` enforces
  `RedirectPolicy::None` per request (including when wrapping a custom `isahc::HttpClient`). Custom
  clients supplied via `From` keep their configured proxy, TLS, and (for Isahc) timeout settings.

Applications sending to untrusted subscription URLs on `0.11.x` should pair the crate with an
approved push-service allowlist and egress controls at the network boundary, or upgrade to `0.12.x`
for connect-time IP pinning on Hyper transports.

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
