use std::{collections::BTreeMap, io::Read};

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey, SecretKey};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    endpoint::validate_endpoint,
    error::WebPushError,
    message::SubscriptionInfo,
    vapid::{signer::Claims, VapidKey, VapidSignature, VapidSigner},
};

/// Maximum key input size accepted from `Read` sources (64 KiB).
const MAX_KEY_SIZE: usize = 64 * 1024;
const RAW_P256_KEY_LEN: usize = 32;
const RAW_P256_KEY_B64_LEN: usize = 43;

/// A VAPID signature builder for generating an optional signature to the
/// request. This encryption is required for payloads in all current and future browsers.
///
/// To communicate with the site, one needs to generate a private key to keep in
/// the server and derive a public key from the generated private key for the
/// client.
///
/// Private key generation:
///
/// ```bash,ignore
/// openssl ecparam -name prime256v1 -genkey -noout -out private.pem
/// ```
///
/// To derive a public key out of generated private key:
///
/// ```bash,ignore
/// openssl ec -in private.pem -pubout -out vapid_public.pem
/// ```
///
/// To get the byte form of the public key for the JavaScript client:
///
/// ```bash,ignore
/// openssl ec -in private.pem -text -noout -conv_form uncompressed
/// ```
///
/// ... or a base64-encoded string, which the client should convert into
/// byte form before using:
///
/// ```bash,ignore
/// openssl ec -in private.pem -pubout -outform DER|tail -c 65|base64|tr '/+' '_-'|tr -d '\n'
/// ```
///
/// The above commands can be done in code using [`PartialVapidSignatureBuilder::get_public_key`], then base64 URL safe
/// encoding as well.
///
/// To create a VAPID signature:
///
/// ```no_run
/// # use sad_web_push::*;
/// # use std::fs::File;
/// # fn main () {
/// //You would get this as a `pushSubscription` object from the client. They need your public key to get that object.
/// let subscription_info = SubscriptionInfo {
///     keys: SubscriptionKeys {
///         p256dh: String::from("something"),
///         auth: String::from("secret"),
///     },
///     endpoint: String::from("https://mozilla.rules/something"),
/// };
///
/// let file = File::open("private.pem").unwrap();
///
/// let mut sig_builder = VapidSignatureBuilder::from_pem(file, &subscription_info).unwrap();
///
/// //These fields are optional, and likely unneeded for most uses.
/// sig_builder.add_claim("sub", "mailto:test@example.com");
/// sig_builder.add_claim("foo", "bar");
/// sig_builder.add_claim("omg", 123);
///
/// let signature = sig_builder.build().unwrap();
/// # }
/// ```
pub struct VapidSignatureBuilder<'a> {
    claims: Claims,
    key: VapidKey,
    subscription_info: &'a SubscriptionInfo,
    allow_insecure: bool,
}

impl<'a> VapidSignatureBuilder<'a> {
    /// Creates a new builder from a PEM formatted private key.
    ///
    /// # Details
    ///
    /// The input can be either a PKCS#8 formatted PEM, denoted by a `-----BEGIN PRIVATE KEY-----`
    /// header, or a SEC1 formatted PEM, denoted by a `-----BEGIN EC PRIVATE KEY-----` header.
    /// Multi-block PEM files containing additional sections such as `EC PARAMETERS` are supported.
    pub fn from_pem<R: Read>(
        pk_pem: R,
        subscription_info: &'a SubscriptionInfo,
    ) -> Result<VapidSignatureBuilder<'a>, WebPushError> {
        let pr_key = Self::read_pem(pk_pem)?;

        Ok(Self::from_ec(pr_key, subscription_info))
    }

    /// Creates a new builder from a PEM formatted private key. This function doesn't take a subscription,
    /// allowing the reuse of one builder for multiple messages by cloning the resulting builder.
    ///
    /// # Details
    ///
    /// The input can be either a PKCS#8 formatted PEM, denoted by a `-----BEGIN PRIVATE KEY-----`
    /// header, or a SEC1 formatted PEM, denoted by a `-----BEGIN EC PRIVATE KEY-----` header.
    pub fn from_pem_no_sub<R: Read>(pk_pem: R) -> Result<PartialVapidSignatureBuilder, WebPushError> {
        let pr_key = Self::read_pem(pk_pem)?;

        Ok(PartialVapidSignatureBuilder {
            key: VapidKey::new(pr_key),
        })
    }

    /// Creates a new builder from a DER formatted private key (SEC1 or PKCS#8).
    pub fn from_der<R: Read>(
        pk_der: R,
        subscription_info: &'a SubscriptionInfo,
    ) -> Result<VapidSignatureBuilder<'a>, WebPushError> {
        let pr_key = Self::read_der(pk_der)?;

        Ok(Self::from_ec(pr_key, subscription_info))
    }

    /// Creates a new builder from a DER formatted private key (SEC1 or PKCS#8). This function doesn't take a subscription,
    /// allowing the reuse of one builder for multiple messages by cloning the resulting builder.
    pub fn from_der_no_sub<R: Read>(pk_der: R) -> Result<PartialVapidSignatureBuilder, WebPushError> {
        let pr_key = Self::read_der(pk_der)?;

        Ok(PartialVapidSignatureBuilder {
            key: VapidKey::new(pr_key),
        })
    }

    /// Creates a new builder from a raw base64-encoded private key. This isn't the base64 from a key
    /// generated by openssl, but rather the literal 32 bytes of the P-256 private scalar itself. This is the kind
    /// of key given to you by most VAPID key generator sites, and also the kind used in the API of other
    /// large web push libraries, such as PHP and Node.
    ///
    /// Base64 encoding must use URL-safe alphabet without padding.
    ///
    /// # Example
    ///
    /// ```
    /// # use sad_web_push::VapidSignatureBuilder;
    /// // Use `from_base64` here if you have a sub
    /// let builder = VapidSignatureBuilder::from_base64_no_sub("IQ9Ur0ykXoHS9gzfYX0aBjy9lvdrjx_PFUXmie9YRcY").unwrap();
    /// ```
    pub fn from_base64(
        encoded: &str,
        subscription_info: &'a SubscriptionInfo,
    ) -> Result<VapidSignatureBuilder<'a>, WebPushError> {
        let pr_key = Self::parse_base64(encoded)?;

        Ok(Self::from_ec(pr_key, subscription_info))
    }

    /// Creates a new builder from a raw base64-encoded private key. This function doesn't take a subscription,
    /// allowing the reuse of one builder for multiple messages by cloning the resulting builder.
    ///
    /// Base64 encoding must use URL-safe alphabet without padding.
    pub fn from_base64_no_sub(encoded: &str) -> Result<PartialVapidSignatureBuilder, WebPushError> {
        let pr_key = Self::parse_base64(encoded)?;

        Ok(PartialVapidSignatureBuilder {
            key: VapidKey::new(pr_key),
        })
    }

    /// Allows insecure (`http://`) and loopback/private push endpoints when set
    /// to `true` (intended for local testing and mock servers).
    ///
    /// Defaults to `false`, which requires `https://` and rejects `localhost`,
    /// `*.localhost`, and non-public IP literals. Even when set to `true`, the
    /// endpoint must still be a valid `http` or `https` URI with a non-empty
    /// host and no embedded userinfo.
    pub fn allow_insecure_endpoint(&mut self, allow: bool) -> &mut Self {
        self.allow_insecure = allow;
        self
    }

    /// Add a claim to the signature. Claims `aud` and `exp` are automatically
    /// added to the signature. Add them manually to override the default
    /// values.
    ///
    /// The function accepts any value that can be converted into a type JSON
    /// supports.
    pub fn add_claim<V>(&mut self, key: &'a str, val: V)
    where
        V: Into<Value>,
    {
        self.claims.insert(key.to_string(), val.into());
    }

    /// Builds a signature to be used in [WebPushMessageBuilder](struct.WebPushMessageBuilder.html).
    pub fn build(self) -> Result<VapidSignature, WebPushError> {
        let endpoint = validate_endpoint(&self.subscription_info.endpoint, self.allow_insecure)?;
        let signature = VapidSigner::sign(self.key, &endpoint, self.claims)?;

        Ok(signature)
    }

    fn from_ec(ec_key: SigningKey, subscription_info: &'a SubscriptionInfo) -> VapidSignatureBuilder<'a> {
        VapidSignatureBuilder {
            claims: BTreeMap::new(),
            key: VapidKey::new(ec_key),
            subscription_info,
            allow_insecure: false,
        }
    }

    fn read_bounded<R: Read>(input: R) -> Result<Zeroizing<Vec<u8>>, WebPushError> {
        let mut buf = Zeroizing::new(Vec::with_capacity(512));
        input.take(MAX_KEY_SIZE as u64 + 1).read_to_end(&mut buf)?;
        if buf.len() > MAX_KEY_SIZE {
            return Err(WebPushError::InvalidCryptoKeys);
        }
        Ok(buf)
    }

    fn parse_base64(encoded: &str) -> Result<SigningKey, WebPushError> {
        if encoded.len() != RAW_P256_KEY_B64_LEN {
            return Err(WebPushError::InvalidCryptoKeys);
        }
        let mut decoded = Zeroizing::new([0u8; RAW_P256_KEY_LEN]);
        let written = Base64UrlSafeNoPadding::decode(decoded.as_mut(), encoded, None)
            .map_err(|_| WebPushError::InvalidCryptoKeys)?;
        if written.len() != RAW_P256_KEY_LEN {
            return Err(WebPushError::InvalidCryptoKeys);
        }
        let secret = SecretKey::from_slice(decoded.as_ref()).map_err(|_| WebPushError::InvalidCryptoKeys)?;
        Ok(SigningKey::from(secret))
    }

    fn read_der<R: Read>(input: R) -> Result<SigningKey, WebPushError> {
        let der = Self::read_bounded(input)?;
        let secret = SecretKey::from_sec1_der(&der)
            .or_else(|_| SecretKey::from_pkcs8_der(&der))
            .map_err(|_| WebPushError::InvalidCryptoKeys)?;
        Ok(SigningKey::from(secret))
    }

    /// Reads the PEM file as either SEC1 (`EC PRIVATE KEY`) or PKCS#8 (`PRIVATE KEY`),
    /// supporting multi-block PEM inputs (e.g. `EC PARAMETERS` followed by `EC PRIVATE KEY`).
    pub(crate) fn read_pem<R: Read>(input: R) -> Result<SigningKey, WebPushError> {
        let raw = Self::read_bounded(input)?;
        let text = std::str::from_utf8(&raw).map_err(|_| WebPushError::InvalidCryptoKeys)?;

        let mut sec1_der: Option<Zeroizing<Vec<u8>>> = None;
        let mut pkcs8_der: Option<Zeroizing<Vec<u8>>> = None;

        for block in extract_pem_blocks(text) {
            let (label, der) =
                pem_rfc7468::decode_vec(block.as_bytes()).map_err(|_| WebPushError::InvalidCryptoKeys)?;
            let der = Zeroizing::new(der);
            match label {
                "EC PRIVATE KEY" if sec1_der.is_none() => sec1_der = Some(der),
                "PRIVATE KEY" if pkcs8_der.is_none() => pkcs8_der = Some(der),
                _ => {}
            }
        }

        if let Some(der) = sec1_der {
            let secret = SecretKey::from_sec1_der(&der).map_err(|_| WebPushError::InvalidCryptoKeys)?;
            Ok(SigningKey::from(secret))
        } else if let Some(der) = pkcs8_der {
            let secret = SecretKey::from_pkcs8_der(&der).map_err(|_| WebPushError::InvalidCryptoKeys)?;
            Ok(SigningKey::from(secret))
        } else {
            Err(WebPushError::MissingCryptoKeys)
        }
    }
}

/// Extracts individual `-----BEGIN ...-----` ... `-----END ...-----` blocks from a PEM document.
fn extract_pem_blocks(input: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut rest = input;

    while let Some(begin_pos) = rest.find("-----BEGIN ") {
        let candidate = &rest[begin_pos..];
        let Some(begin_line_end) = candidate.find('\n') else {
            // Unclosed or single-line malformed BEGIN header; pass through so pem_rfc7468 rejects it.
            blocks.push(candidate);
            break;
        };

        let header = candidate[..begin_line_end].trim_end_matches('\r');
        let Some(label) = header.strip_prefix("-----BEGIN ").and_then(|s| s.strip_suffix("-----")) else {
            blocks.push(candidate);
            break;
        };

        let end_marker = format!("-----END {label}-----");
        if let Some(end_rel) = candidate[begin_line_end + 1..].find(&end_marker) {
            let end_pos = begin_line_end + 1 + end_rel + end_marker.len();
            blocks.push(&candidate[..end_pos]);
            rest = &candidate[end_pos..];
        } else {
            // Unterminated PEM block; pass through so pem_rfc7468 rejects it as invalid.
            blocks.push(candidate);
            break;
        }
    }

    blocks
}

/// A [`VapidSignatureBuilder`] without VAPID subscription info.
///
/// # Example
///
/// ```no_run
/// use sad_web_push::{VapidSignatureBuilder, SubscriptionInfo};
///
/// let builder = VapidSignatureBuilder::from_pem_no_sub("Some PEM".as_bytes()).unwrap();
///
/// //Clone builder for each use of the same private key
/// {
///     //Pretend this changes for each connection
///     let subscription_info = SubscriptionInfo::new(
///     "https://updates.push.services.mozilla.com/wpush/v1/...",
///     "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
///     "xS03Fi5ErfTNH_l9WHE9Ig"
///     );
///
///     let builder = builder.clone();
///     let sig = builder.add_sub_info(&subscription_info).build();
///     //Sign message etc.
/// }
///
/// ```
#[derive(Clone)]
pub struct PartialVapidSignatureBuilder {
    key: VapidKey,
}

impl PartialVapidSignatureBuilder {
    /// Adds the VAPID subscription info for a particular client.
    pub fn add_sub_info(self, subscription_info: &SubscriptionInfo) -> VapidSignatureBuilder<'_> {
        VapidSignatureBuilder {
            key: self.key,
            claims: BTreeMap::new(),
            subscription_info,
            allow_insecure: false,
        }
    }

    /// Gets the uncompressed public key bytes derived from the private key used for this VAPID signature.
    ///
    /// Base64 encode these bytes to get the key to send to the client.
    pub fn get_public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }
}

#[cfg(test)]
mod tests {
    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
    use p256::{
        pkcs8::{EncodePrivateKey, LineEnding},
        SecretKey,
    };

    use crate::{error::WebPushError, message::SubscriptionInfo, vapid::VapidSignatureBuilder};

    static PRIVATE_PEM: &[u8] = include_bytes!("../../resources/vapid_test_key.pem");
    static PRIVATE_DER: &[u8] = include_bytes!("../../resources/vapid_test_key.der");
    static PRIVATE_BASE64: &str = "IQ9Ur0ykXoHS9gzfYX0aBjy9lvdrjx_PFUXmie9YRcY";

    fn example_subscription_info() -> SubscriptionInfo {
        serde_json::from_value(serde_json::json!({
            "endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABaso4Vajy4STM25r5y5oFfyN451rUmES6mhQngxABxbZB5q_o75WpG25oKdrlrh9KdgWFKdYBc-buLPhvCTqR5KdsK8iCZHQume-ndtZJWKOgJbQ20GjbxHmAT1IAv8AIxTwHO-JTQ2Np2hwkKISp2_KUtpnmwFzglLP7vlCd16hTNJ2I",
            "keys": {
                "auth": "sBXU5_tIYz-5w7G2B25BEw",
                "p256dh": "BH1HTeKM7-NwaLGHEqxeu2IamQaVVLkcsFHPIHmsCnqxcBHPQBprF41bEMOr3O1hUQ2jU1opNEm1F_lZV_sxMP8"
            }
        }))
        .unwrap()
    }

    #[test]
    fn test_builder_from_pem() {
        let subscription_info = example_subscription_info();
        let builder = VapidSignatureBuilder::from_pem(PRIVATE_PEM, &subscription_info).unwrap();
        let signature = builder.build().unwrap();

        assert_eq!(
            "BMo1HqKF6skMZYykrte9duqYwBD08mDQKTunRkJdD3sTJ9E-yyN6sJlPWTpKNhp-y2KeS6oANHF-q3w37bClb7U",
            Base64UrlSafeNoPadding::encode_to_string(&signature.auth_k).unwrap()
        );

        assert!(!signature.auth_t.is_empty());
    }

    #[test]
    fn test_builder_from_multi_block_pem() {
        let subscription_info = example_subscription_info();
        let mut combined = b"-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n".to_vec();
        combined.extend_from_slice(PRIVATE_PEM);

        let builder = VapidSignatureBuilder::from_pem(combined.as_slice(), &subscription_info).unwrap();
        let signature = builder.build().unwrap();
        assert_eq!(
            "BMo1HqKF6skMZYykrte9duqYwBD08mDQKTunRkJdD3sTJ9E-yyN6sJlPWTpKNhp-y2KeS6oANHF-q3w37bClb7U",
            Base64UrlSafeNoPadding::encode_to_string(&signature.auth_k).unwrap()
        );
    }

    #[test]
    fn test_builder_from_pkcs8_pem_and_der() {
        let subscription_info = example_subscription_info();
        let secret = SecretKey::from_sec1_der(PRIVATE_DER).unwrap();
        let pkcs8_pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let pkcs8_der = secret.to_pkcs8_der().unwrap();

        let sig_pem = VapidSignatureBuilder::from_pem(pkcs8_pem.as_bytes(), &subscription_info)
            .unwrap()
            .build()
            .unwrap();
        let sig_der = VapidSignatureBuilder::from_der(pkcs8_der.as_bytes(), &subscription_info)
            .unwrap()
            .build()
            .unwrap();

        let expected = "BMo1HqKF6skMZYykrte9duqYwBD08mDQKTunRkJdD3sTJ9E-yyN6sJlPWTpKNhp-y2KeS6oANHF-q3w37bClb7U";
        assert_eq!(
            expected,
            Base64UrlSafeNoPadding::encode_to_string(&sig_pem.auth_k).unwrap()
        );
        assert_eq!(
            expected,
            Base64UrlSafeNoPadding::encode_to_string(&sig_der.auth_k).unwrap()
        );
    }

    #[test]
    fn test_builder_from_der() {
        let subscription_info = example_subscription_info();
        let builder = VapidSignatureBuilder::from_der(PRIVATE_DER, &subscription_info).unwrap();
        let signature = builder.build().unwrap();

        assert_eq!(
            "BMo1HqKF6skMZYykrte9duqYwBD08mDQKTunRkJdD3sTJ9E-yyN6sJlPWTpKNhp-y2KeS6oANHF-q3w37bClb7U",
            Base64UrlSafeNoPadding::encode_to_string(&signature.auth_k).unwrap()
        );

        assert!(!signature.auth_t.is_empty());
    }

    #[test]
    fn test_builder_from_base64() {
        let subscription_info = example_subscription_info();
        let builder = VapidSignatureBuilder::from_base64(PRIVATE_BASE64, &subscription_info).unwrap();
        let signature = builder.build().unwrap();

        assert_eq!(
            "BMjQIp55pdbU8pfCBKyXcZjlmER_mXt5LqNrN1hrXbdBS5EnhIbMu3Au-RV53iIpztzNXkGI56BFB1udQ8Bq_H4",
            Base64UrlSafeNoPadding::encode_to_string(&signature.auth_k).unwrap()
        );

        assert!(!signature.auth_t.is_empty());
    }

    /// Regression test for upstream Issue #73: 31-byte or wrong-length base64 private key
    /// must return `Err(WebPushError::InvalidCryptoKeys)` instead of panicking.
    #[test]
    fn test_from_base64_rejects_wrong_lengths_without_panicking() {
        let subscription_info = example_subscription_info();
        let key_31 = Base64UrlSafeNoPadding::encode_to_string([1u8; 31]).unwrap();
        let key_33 = Base64UrlSafeNoPadding::encode_to_string([1u8; 33]).unwrap();
        let key_zero = Base64UrlSafeNoPadding::encode_to_string([0u8; 32]).unwrap();
        let key_ff = Base64UrlSafeNoPadding::encode_to_string([0xffu8; 32]).unwrap();
        // Exact NIST P-256 curve order `n` (invalid scalar: must be 1 <= d < n).
        let curve_order_n: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6,
            0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ];
        let key_order_n = Base64UrlSafeNoPadding::encode_to_string(curve_order_n).unwrap();
        let oversized = "A".repeat(4096);

        for bad in [
            "",
            "not!valid!base64",
            key_31.as_str(),
            key_33.as_str(),
            key_zero.as_str(),
            key_ff.as_str(),
            key_order_n.as_str(),
            oversized.as_str(),
        ] {
            assert!(
                matches!(
                    VapidSignatureBuilder::from_base64(bad, &subscription_info),
                    Err(WebPushError::InvalidCryptoKeys)
                ),
                "expected InvalidCryptoKeys for {bad:?}"
            );
            assert!(
                matches!(
                    VapidSignatureBuilder::from_base64_no_sub(bad),
                    Err(WebPushError::InvalidCryptoKeys)
                ),
                "expected InvalidCryptoKeys for {bad:?}"
            );
        }

        // Valid 32-byte scalar with a leading zero byte must succeed.
        let mut leading_zero = [0u8; 32];
        leading_zero[31] = 1;
        let leading_zero_b64 = Base64UrlSafeNoPadding::encode_to_string(leading_zero).unwrap();
        assert!(VapidSignatureBuilder::from_base64(&leading_zero_b64, &subscription_info).is_ok());
    }

    #[test]
    fn test_pem_missing_and_oversized_keys() {
        let subscription_info = example_subscription_info();

        assert!(matches!(
            VapidSignatureBuilder::from_pem(&b"no pem blocks here"[..], &subscription_info),
            Err(WebPushError::MissingCryptoKeys)
        ));

        // Public-only PEM has no private key block -> MissingCryptoKeys.
        let public_only_pem =
            b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n";
        assert!(matches!(
            VapidSignatureBuilder::from_pem(public_only_pem.as_slice(), &subscription_info),
            Err(WebPushError::MissingCryptoKeys)
        ));

        // Unterminated BEGIN without END -> InvalidCryptoKeys.
        let unterminated_pem = b"-----BEGIN PRIVATE KEY-----\nAAAA\n";
        assert!(matches!(
            VapidSignatureBuilder::from_pem(unterminated_pem.as_slice(), &subscription_info),
            Err(WebPushError::InvalidCryptoKeys)
        ));

        // Non-P-256 (Ed25519 PKCS#8) PEM and DER -> InvalidCryptoKeys.
        let ed25519_der: &[u8] = &[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        assert!(matches!(
            VapidSignatureBuilder::from_der(ed25519_der, &subscription_info),
            Err(WebPushError::InvalidCryptoKeys)
        ));
        let ed25519_pem = pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, ed25519_der).unwrap();
        assert!(matches!(
            VapidSignatureBuilder::from_pem(ed25519_pem.as_bytes(), &subscription_info),
            Err(WebPushError::InvalidCryptoKeys)
        ));

        let oversized = vec![b'A'; 65 * 1024];
        assert!(matches!(
            VapidSignatureBuilder::from_pem(oversized.as_slice(), &subscription_info),
            Err(WebPushError::InvalidCryptoKeys)
        ));
        assert!(matches!(
            VapidSignatureBuilder::from_der(oversized.as_slice(), &subscription_info),
            Err(WebPushError::InvalidCryptoKeys)
        ));
    }

    #[test]
    fn test_builder_endpoint_validation_and_insecure_opt_in() {
        let local_sub = SubscriptionInfo::new(
            "http://127.0.0.1:8080/push",
            "BH1HTeKM7-NwaLGHEqxeu2IamQaVVLkcsFHPIHmsCnqxcBHPQBprF41bEMOr3O1hUQ2jU1opNEm1F_lZV_sxMP8",
            "sBXU5_tIYz-5w7G2B25BEw",
        );

        assert!(matches!(
            VapidSignatureBuilder::from_base64(PRIVATE_BASE64, &local_sub)
                .unwrap()
                .build(),
            Err(WebPushError::InvalidUri)
        ));

        let mut builder = VapidSignatureBuilder::from_base64(PRIVATE_BASE64, &local_sub).unwrap();
        builder.allow_insecure_endpoint(true);
        assert!(builder.build().is_ok());
    }
}
