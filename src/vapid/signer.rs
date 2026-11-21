use std::{
    collections::BTreeMap,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use http::uri::Uri;
use p256::ecdsa::{signature::Signer, Signature};
use serde_json::Value;

use crate::{endpoint::origin_for_vapid, error::WebPushError, vapid::VapidKey};

const DEFAULT_EXPIRY_SECS: u64 = 12 * 60 * 60;
const JWS_HEADER_JSON: &[u8] = br#"{"typ":"JWT","alg":"ES256"}"#;

/// A struct representing a VAPID signature. Should be generated using the
/// [VapidSignatureBuilder](struct.VapidSignatureBuilder.html).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VapidSignature {
    /// The signed JWT, base64-encoded
    pub auth_t: String,
    /// The public key bytes
    pub auth_k: Vec<u8>,
}

impl fmt::Debug for VapidSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VapidSignature")
            .field("auth_t", &"[REDACTED]")
            .field("auth_k", &self.auth_k)
            .finish()
    }
}

/// JWT claims map.
pub(crate) type Claims = BTreeMap<String, Value>;

pub(crate) struct VapidSigner {}

impl VapidSigner {
    /// Create a signature with a given key. Sets the default audience from the
    /// endpoint origin and sets the expiry in twelve hours. Values can be
    /// overwritten by adding the `aud` and `exp` claims.
    pub(crate) fn sign(key: VapidKey, endpoint: &Uri, mut claims: Claims) -> Result<VapidSignature, WebPushError> {
        if let Some(aud) = claims.get("aud") {
            if aud.as_str().is_none() {
                return Err(WebPushError::InvalidClaims);
            }
        } else {
            let audience = origin_for_vapid(endpoint)?;
            claims.insert("aud".to_string(), Value::String(audience));
        }

        if let Some(exp) = claims.get("exp") {
            if exp.as_u64().is_none() {
                return Err(WebPushError::InvalidClaims);
            }
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| WebPushError::InvalidClaims)?
                .as_secs();
            let exp = now
                .checked_add(DEFAULT_EXPIRY_SECS)
                .ok_or(WebPushError::InvalidClaims)?;
            claims.insert("exp".to_string(), Value::Number(exp.into()));
        }

        // Add default `sub` if not provided, matching upstream behavior for browsers
        // such as Firefox that require a subject claim.
        if let Some(sub) = claims.get("sub") {
            if sub.as_str().is_none() {
                return Err(WebPushError::InvalidClaims);
            }
        } else {
            claims.insert(
                "sub".to_string(),
                Value::String("mailto:example@example.com".to_string()),
            );
        }

        let header_b64 =
            Base64UrlSafeNoPadding::encode_to_string(JWS_HEADER_JSON).map_err(|_| WebPushError::InvalidClaims)?;
        let payload_json = serde_json::to_vec(&claims).map_err(|_| WebPushError::InvalidClaims)?;
        let payload_b64 =
            Base64UrlSafeNoPadding::encode_to_string(payload_json).map_err(|_| WebPushError::InvalidClaims)?;

        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature: Signature = key.0.sign(signing_input.as_bytes());
        let sig_b64 =
            Base64UrlSafeNoPadding::encode_to_string(signature.to_bytes()).map_err(|_| WebPushError::InvalidClaims)?;

        let auth_t = format!("{signing_input}.{sig_b64}");
        let auth_k = key.public_key();

        Ok(VapidSignature { auth_t, auth_k })
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use serde_json::Value;

    use super::*;

    fn test_key() -> VapidKey {
        let f = File::open("resources/vapid_test_key.pem").unwrap();
        VapidKey::new(crate::VapidSignatureBuilder::read_pem(f).unwrap())
    }

    fn verify_and_decode_jwt(sig: &VapidSignature) -> (Value, Value) {
        let parts: Vec<&str> = sig.auth_t.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated parts");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = Base64UrlSafeNoPadding::decode_to_vec(parts[2], None).unwrap();
        assert_eq!(sig_bytes.len(), 64, "ES256 raw signature must be 64 bytes (r || s)");

        let verifying_key = VerifyingKey::from_sec1_bytes(&sig.auth_k).unwrap();
        let signature = Signature::from_slice(&sig_bytes).unwrap();
        verifying_key.verify(signing_input.as_bytes(), &signature).unwrap();

        let header: Value =
            serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(parts[0], None).unwrap()).unwrap();
        let payload: Value =
            serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(parts[1], None).unwrap()).unwrap();
        (header, payload)
    }

    #[test]
    fn signs_valid_es256_jwt_with_defaults() {
        let endpoint: Uri = "https://updates.push.services.mozilla.com/wpush/v2/token"
            .parse()
            .unwrap();
        let sig = VapidSigner::sign(test_key(), &endpoint, Claims::new()).unwrap();

        let (header, payload) = verify_and_decode_jwt(&sig);
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(payload["aud"], "https://updates.push.services.mozilla.com");
        assert_eq!(payload["sub"], "mailto:example@example.com");

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let exp = payload["exp"].as_u64().unwrap();
        assert!(exp >= now + DEFAULT_EXPIRY_SECS - 5 && exp <= now + DEFAULT_EXPIRY_SECS + 5);
    }

    #[test]
    fn preserves_non_default_port_and_strips_default_port() {
        let with_port: Uri = "https://push.example.com:8443/send".parse().unwrap();
        let sig = VapidSigner::sign(test_key(), &with_port, Claims::new()).unwrap();
        let (_, payload) = verify_and_decode_jwt(&sig);
        assert_eq!(payload["aud"], "https://push.example.com:8443");

        let default_port: Uri = "https://push.example.com:443/send".parse().unwrap();
        let sig = VapidSigner::sign(test_key(), &default_port, Claims::new()).unwrap();
        let (_, payload) = verify_and_decode_jwt(&sig);
        assert_eq!(payload["aud"], "https://push.example.com");
    }

    #[test]
    fn supports_custom_claims_and_overrides() {
        let endpoint: Uri = "https://updates.push.services.mozilla.com/wpush/v2/token"
            .parse()
            .unwrap();
        let mut claims = Claims::new();
        claims.insert("aud".into(), Value::String("https://custom.example.com".into()));
        claims.insert("exp".into(), Value::from(1_900_000_000u64));
        claims.insert("sub".into(), Value::String("mailto:ops@example.com".into()));
        claims.insert("foo".into(), Value::String("bar".into()));
        claims.insert("omg".into(), Value::from(123));

        let sig = VapidSigner::sign(test_key(), &endpoint, claims).unwrap();
        let (_, payload) = verify_and_decode_jwt(&sig);
        assert_eq!(payload["aud"], "https://custom.example.com");
        assert_eq!(payload["exp"], 1_900_000_000u64);
        assert_eq!(payload["sub"], "mailto:ops@example.com");
        assert_eq!(payload["foo"], "bar");
        assert_eq!(payload["omg"], 123);
    }

    #[test]
    fn rejects_invalid_uri_and_invalid_claims_without_panicking() {
        let rel: Uri = "/relative/path".parse().unwrap();
        assert!(matches!(
            VapidSigner::sign(test_key(), &rel, Claims::new()),
            Err(WebPushError::InvalidUri)
        ));

        let authority_only: Uri = "push.example.com".parse().unwrap();
        assert!(matches!(
            VapidSigner::sign(test_key(), &authority_only, Claims::new()),
            Err(WebPushError::InvalidUri)
        ));

        let valid: Uri = "https://push.example.com/send".parse().unwrap();

        let mut bad_aud = Claims::new();
        bad_aud.insert("aud".into(), Value::from(42));
        assert!(matches!(
            VapidSigner::sign(test_key(), &valid, bad_aud),
            Err(WebPushError::InvalidClaims)
        ));

        let mut bad_exp = Claims::new();
        bad_exp.insert("exp".into(), Value::String("not-a-number".into()));
        assert!(matches!(
            VapidSigner::sign(test_key(), &valid, bad_exp),
            Err(WebPushError::InvalidClaims)
        ));

        let mut neg_exp = Claims::new();
        neg_exp.insert("exp".into(), Value::from(-10));
        assert!(matches!(
            VapidSigner::sign(test_key(), &valid, neg_exp),
            Err(WebPushError::InvalidClaims)
        ));

        let mut bad_sub = Claims::new();
        bad_sub.insert("sub".into(), Value::from(true));
        assert!(matches!(
            VapidSigner::sign(test_key(), &valid, bad_sub),
            Err(WebPushError::InvalidClaims)
        ));
    }

    #[test]
    fn vapid_signature_debug_redacts_token() {
        let sig = VapidSignature {
            auth_t: "secret.jwt.token".into(),
            auth_k: vec![4, 1, 2, 3],
        };
        let dbg = format!("{sig:?}");
        assert!(!dbg.contains("secret.jwt.token"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn normalizes_uppercase_host_in_aud_claim() {
        let endpoint: Uri = "HTTPS://PUSH.EXAMPLE.COM/send".parse().unwrap();
        let sig = VapidSigner::sign(test_key(), &endpoint, Claims::new()).unwrap();
        let (_, payload) = verify_and_decode_jwt(&sig);
        assert_eq!(payload["aud"], "https://push.example.com");
    }
}
