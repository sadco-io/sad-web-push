//! Pure-Rust HTTP Encrypted Content-Encoding (RFC 8188 / RFC 8291 `aes128gcm`
//! and legacy draft-ietf-webpush-encryption-04 `aesgcm`).

use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hkdf::Hkdf;
use p256::{
    ecdh::diffie_hellman,
    elliptic_curve::{sec1::ToSec1Point, Generate},
    PublicKey, SecretKey,
};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{error::WebPushError, message::WebPushPayload, vapid::VapidSignature};

/// Maximum unencrypted payload size for RFC 8291 `aes128gcm`, fitting within
/// RFC 8291 §4's 4,096-byte total encrypted HTTP body limit (86-byte content-coding
/// header + 3,993-byte plaintext + 1-byte final-record delimiter + 16-byte GCM
/// authentication tag = 4,096 bytes; `rs = 4096`, encrypted record + tag = 4,010 bytes).
pub(crate) const MAX_AES128GCM_PAYLOAD_SIZE: usize = 3993;

/// Maximum unencrypted payload size for legacy `aesgcm` (kept conservative at 3,800 bytes
/// so the 3,818-byte encrypted HTTP body remains well under 4,096 bytes).
pub(crate) const MAX_AESGCM_PAYLOAD_SIZE: usize = 3800;

const AES128GCM_RECORD_SIZE: u32 = 4096;
const UNCOMPRESSED_PUBKEY_LEN: usize = 65;
const AUTH_SECRET_LEN: usize = 16;
const SALT_LEN: usize = 16;
const IKM_LEN: usize = 32;
const CEK_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Content encoding profiles.
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub enum ContentEncoding {
    //Make sure this enum remains exhaustive as that allows for easier migrations to new versions.
    #[default]
    Aes128Gcm,
    /// Note: this is an older version of ECE, and should not be used unless you know for sure it is required. In all other cases, use aes128gcm.
    AesGcm,
}

impl ContentEncoding {
    /// Gets the associated string for this content encoding, as would be used in the content-encoding header.
    pub fn to_str(&self) -> &'static str {
        match &self {
            ContentEncoding::Aes128Gcm => "aes128gcm",
            ContentEncoding::AesGcm => "aesgcm",
        }
    }

    /// Returns the maximum unencrypted payload length in bytes supported by this encoding.
    pub const fn max_payload_size(self) -> usize {
        match self {
            ContentEncoding::Aes128Gcm => MAX_AES128GCM_PAYLOAD_SIZE,
            ContentEncoding::AesGcm => MAX_AESGCM_PAYLOAD_SIZE,
        }
    }
}

/// Formats the RFC 8292 `Authorization: vapid t=..., k=...` header value.
pub(crate) fn vapid_authorization_header(signature: &VapidSignature) -> Result<(&'static str, String), WebPushError> {
    let encoded_key =
        Base64UrlSafeNoPadding::encode_to_string(&signature.auth_k).map_err(|_| WebPushError::InvalidCryptoKeys)?;
    Ok((
        "Authorization",
        format!("vapid t={}, k={}", signature.auth_t, encoded_key),
    ))
}

/// Struct for handling payload encryption.
pub struct HttpEce<'a> {
    peer_public_key: &'a [u8],
    peer_secret: &'a [u8],
    encoding: ContentEncoding,
    vapid_signature: Option<VapidSignature>,
}

impl<'a> HttpEce<'a> {
    /// Create a new encryptor.
    ///
    /// `peer_public_key` is the `p256dh` and `peer_secret` the `auth` from
    /// browser subscription info.
    pub fn new(
        encoding: ContentEncoding,
        peer_public_key: &'a [u8],
        peer_secret: &'a [u8],
        vapid_signature: Option<VapidSignature>,
    ) -> HttpEce<'a> {
        HttpEce {
            peer_public_key,
            peer_secret,
            encoding,
            vapid_signature,
        }
    }

    /// Encrypts a payload.
    ///
    /// The maximum plaintext length is `3,993` bytes for [`ContentEncoding::Aes128Gcm`]
    /// (producing a 4,096-byte encoded HTTP body per RFC 8291 §4) and `3,800` bytes
    /// for legacy [`ContentEncoding::AesGcm`].
    pub fn encrypt(&self, content: &'a [u8]) -> Result<WebPushPayload, WebPushError> {
        if content.len() > self.encoding.max_payload_size() {
            return Err(WebPushError::PayloadTooLarge);
        }

        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| WebPushError::Unspecified)?;
        let as_secret = SecretKey::generate();

        // Add more encoding standards to this match as they are created.
        match self.encoding {
            ContentEncoding::Aes128Gcm => {
                let data =
                    encrypt_aes128gcm_with_inputs(self.peer_public_key, self.peer_secret, &as_secret, salt, content)?;

                let mut headers = Vec::new();
                self.add_vapid_headers(&mut headers)?;

                Ok(WebPushPayload {
                    content: data,
                    crypto_headers: headers,
                    content_encoding: self.encoding,
                })
            }
            ContentEncoding::AesGcm => {
                let (data, as_public) =
                    encrypt_aesgcm_with_inputs(self.peer_public_key, self.peer_secret, &as_secret, salt, content)?;

                let mut headers = build_aesgcm_headers(
                    &as_public,
                    &salt,
                    self.vapid_signature.as_ref().map(|v| v.auth_k.as_slice()),
                )?;
                self.add_vapid_headers(&mut headers)?;

                Ok(WebPushPayload {
                    content: data,
                    crypto_headers: headers,
                    content_encoding: self.encoding,
                })
            }
        }
    }

    /// Adds VAPID authorization header to headers, if VAPID is being used.
    fn add_vapid_headers(&self, headers: &mut Vec<(&'static str, String)>) -> Result<(), WebPushError> {
        if let Some(signature) = &self.vapid_signature {
            headers.push(vapid_authorization_header(signature)?);
        }
        Ok(())
    }
}

fn validate_peer_inputs(peer_public_key: &[u8], peer_secret: &[u8]) -> Result<PublicKey, WebPushError> {
    if peer_public_key.len() != UNCOMPRESSED_PUBKEY_LEN || peer_public_key[0] != 0x04 {
        return Err(WebPushError::InvalidCryptoKeys);
    }
    if peer_secret.len() != AUTH_SECRET_LEN {
        return Err(WebPushError::InvalidCryptoKeys);
    }
    PublicKey::from_sec1_bytes(peer_public_key).map_err(|_| WebPushError::InvalidCryptoKeys)
}

/// Deterministic RFC 8291 / RFC 8188 (`aes128gcm`) encryption helper.
fn encrypt_aes128gcm_with_inputs(
    ua_public: &[u8],
    auth_secret: &[u8],
    as_secret: &SecretKey,
    salt: [u8; SALT_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, WebPushError> {
    let ua_pk = validate_peer_inputs(ua_public, auth_secret)?;
    let as_public_point = as_secret.public_key().to_sec1_point(false);
    let as_public = as_public_point.as_bytes();
    if as_public.len() != UNCOMPRESSED_PUBKEY_LEN {
        return Err(WebPushError::InvalidCryptoKeys);
    }

    let shared_secret = diffie_hellman(as_secret.to_nonzero_scalar(), ua_pk.as_affine());

    // PRK_key = HKDF-Extract(salt = auth_secret, IKM = ecdh_secret)
    let prk_key = Hkdf::<Sha256>::new(Some(auth_secret), shared_secret.raw_secret_bytes().as_slice());

    // key_info = "WebPush: info\0" || ua_public (65) || as_public (65)
    let mut key_info = [0u8; 14 + UNCOMPRESSED_PUBKEY_LEN * 2];
    key_info[..14].copy_from_slice(b"WebPush: info\0");
    key_info[14..14 + UNCOMPRESSED_PUBKEY_LEN].copy_from_slice(ua_public);
    key_info[14 + UNCOMPRESSED_PUBKEY_LEN..].copy_from_slice(as_public);

    let mut ikm = Zeroizing::new([0u8; IKM_LEN]);
    prk_key
        .expand(&key_info, ikm.as_mut())
        .map_err(|_| WebPushError::InvalidCryptoKeys)?;

    // PRK = HKDF-Extract(salt = salt, IKM = IKM)
    let prk = Hkdf::<Sha256>::new(Some(&salt), ikm.as_ref());

    let mut cek = Zeroizing::new([0u8; CEK_LEN]);
    prk.expand(b"Content-Encoding: aes128gcm\0", cek.as_mut())
        .map_err(|_| WebPushError::InvalidCryptoKeys)?;

    let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
    prk.expand(b"Content-Encoding: nonce\0", nonce.as_mut())
        .map_err(|_| WebPushError::InvalidCryptoKeys)?;

    // Single final record: plaintext || 0x02
    let mut record = Zeroizing::new(Vec::with_capacity(plaintext.len() + 1));
    record.extend_from_slice(plaintext);
    record.push(0x02);

    let cipher = Aes128Gcm::new_from_slice(cek.as_ref()).map_err(|_| WebPushError::InvalidCryptoKeys)?;
    let nonce_arr = Zeroizing::new(Nonce::from(*nonce));
    let ciphertext = cipher
        .encrypt(&*nonce_arr, record.as_ref())
        .map_err(|_| WebPushError::Unspecified)?;

    // Wire format: salt (16) || rs (4 BE) || idlen (1 = 65) || as_public (65) || ciphertext_with_tag
    let mut output = Vec::with_capacity(SALT_LEN + 4 + 1 + UNCOMPRESSED_PUBKEY_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&AES128GCM_RECORD_SIZE.to_be_bytes());
    output.push(UNCOMPRESSED_PUBKEY_LEN as u8);
    output.extend_from_slice(as_public);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Deterministic legacy draft-ietf-webpush-encryption-04 (`aesgcm`) encryption helper.
fn encrypt_aesgcm_with_inputs(
    ua_public: &[u8],
    auth_secret: &[u8],
    as_secret: &SecretKey,
    salt: [u8; SALT_LEN],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; UNCOMPRESSED_PUBKEY_LEN]), WebPushError> {
    if plaintext.is_empty() {
        return Err(WebPushError::InvalidCryptoKeys);
    }
    let ua_pk = validate_peer_inputs(ua_public, auth_secret)?;
    let as_public_point = as_secret.public_key().to_sec1_point(false);
    let as_public_slice = as_public_point.as_bytes();
    if as_public_slice.len() != UNCOMPRESSED_PUBKEY_LEN {
        return Err(WebPushError::InvalidCryptoKeys);
    }
    let mut as_public = [0u8; UNCOMPRESSED_PUBKEY_LEN];
    as_public.copy_from_slice(as_public_slice);

    let shared_secret = diffie_hellman(as_secret.to_nonzero_scalar(), ua_pk.as_affine());

    // PRK_key = HKDF-Extract(salt = auth_secret, IKM = ecdh_secret)
    let prk_key = Hkdf::<Sha256>::new(Some(auth_secret), shared_secret.raw_secret_bytes().as_slice());

    let mut ikm = Zeroizing::new([0u8; IKM_LEN]);
    prk_key
        .expand(b"Content-Encoding: auth\0", ikm.as_mut())
        .map_err(|_| WebPushError::InvalidCryptoKeys)?;

    // context = "P-256\0" || u16_be(65) || ua_public (65) || u16_be(65) || as_public (65)
    const AESGCM_CONTEXT_LEN: usize = 6 + 2 + UNCOMPRESSED_PUBKEY_LEN + 2 + UNCOMPRESSED_PUBKEY_LEN;
    let mut context = [0u8; AESGCM_CONTEXT_LEN];
    let mut off = 0;
    context[off..off + 6].copy_from_slice(b"P-256\0");
    off += 6;
    context[off..off + 2].copy_from_slice(&(UNCOMPRESSED_PUBKEY_LEN as u16).to_be_bytes());
    off += 2;
    context[off..off + UNCOMPRESSED_PUBKEY_LEN].copy_from_slice(ua_public);
    off += UNCOMPRESSED_PUBKEY_LEN;
    context[off..off + 2].copy_from_slice(&(UNCOMPRESSED_PUBKEY_LEN as u16).to_be_bytes());
    off += 2;
    context[off..off + UNCOMPRESSED_PUBKEY_LEN].copy_from_slice(&as_public);

    let prk = Hkdf::<Sha256>::new(Some(&salt), ikm.as_ref());

    let mut cek_info = [0u8; 25 + AESGCM_CONTEXT_LEN];
    cek_info[..25].copy_from_slice(b"Content-Encoding: aesgcm\0");
    cek_info[25..].copy_from_slice(&context);
    let mut cek = Zeroizing::new([0u8; CEK_LEN]);
    prk.expand(&cek_info, cek.as_mut())
        .map_err(|_| WebPushError::InvalidCryptoKeys)?;

    let mut nonce_info = [0u8; 24 + AESGCM_CONTEXT_LEN];
    nonce_info[..24].copy_from_slice(b"Content-Encoding: nonce\0");
    nonce_info[24..].copy_from_slice(&context);
    let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
    prk.expand(&nonce_info, nonce.as_mut())
        .map_err(|_| WebPushError::InvalidCryptoKeys)?;

    // Legacy aesgcm record: u16_be(pad_len = 0) || plaintext
    let mut record = Zeroizing::new(Vec::with_capacity(2 + plaintext.len()));
    record.extend_from_slice(&0u16.to_be_bytes());
    record.extend_from_slice(plaintext);

    let cipher = Aes128Gcm::new_from_slice(cek.as_ref()).map_err(|_| WebPushError::InvalidCryptoKeys)?;
    let nonce_arr = Zeroizing::new(Nonce::from(*nonce));
    let ciphertext = cipher
        .encrypt(&*nonce_arr, record.as_ref())
        .map_err(|_| WebPushError::Unspecified)?;

    Ok((ciphertext, as_public))
}

fn build_aesgcm_headers(
    as_public: &[u8],
    salt: &[u8; SALT_LEN],
    vapid_public_key: Option<&[u8]>,
) -> Result<Vec<(&'static str, String)>, WebPushError> {
    let dh = Base64UrlSafeNoPadding::encode_to_string(as_public).map_err(|_| WebPushError::InvalidCryptoKeys)?;
    let crypto_key = match vapid_public_key {
        Some(public_key) => {
            let p256ecdsa =
                Base64UrlSafeNoPadding::encode_to_string(public_key).map_err(|_| WebPushError::InvalidCryptoKeys)?;
            format!("dh={dh}; p256ecdsa={p256ecdsa}")
        }
        None => format!("dh={dh}"),
    };
    let salt_b64 = Base64UrlSafeNoPadding::encode_to_string(salt).map_err(|_| WebPushError::InvalidCryptoKeys)?;

    Ok(vec![
        ("Crypto-Key", crypto_key),
        ("Encryption", format!("salt={salt_b64}")),
    ])
}

#[cfg(test)]
mod tests {
    use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
    use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
    use hkdf::Hkdf;
    use p256::{
        ecdh::diffie_hellman,
        elliptic_curve::{sec1::ToSec1Point, Generate},
        PublicKey, SecretKey,
    };
    use regex::Regex;
    use sha2::Sha256;

    use crate::{
        error::WebPushError,
        http_ece::{
            encrypt_aes128gcm_with_inputs, encrypt_aesgcm_with_inputs, ContentEncoding, HttpEce,
            MAX_AES128GCM_PAYLOAD_SIZE, MAX_AESGCM_PAYLOAD_SIZE, UNCOMPRESSED_PUBKEY_LEN,
        },
        VapidSignature, WebPushPayload,
    };

    fn hex_decode(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn decrypt_aes128gcm(ua_secret: &SecretKey, auth_secret: &[u8], payload: &[u8]) -> Vec<u8> {
        let salt = &payload[0..16];
        let rs = u32::from_be_bytes(payload[16..20].try_into().unwrap());
        assert_eq!(rs, 4096);
        let idlen = payload[20] as usize;
        assert_eq!(idlen, 65);
        let as_public = &payload[21..21 + 65];
        let ciphertext = &payload[21 + 65..];

        let ua_public_point = ua_secret.public_key().to_sec1_point(false);
        let ua_public = ua_public_point.as_bytes();
        let as_pk = PublicKey::from_sec1_bytes(as_public).unwrap();

        let shared = diffie_hellman(ua_secret.to_nonzero_scalar(), as_pk.as_affine());
        let prk_key = Hkdf::<Sha256>::new(Some(auth_secret), shared.raw_secret_bytes().as_slice());

        let mut key_info = Vec::with_capacity(14 + 130);
        key_info.extend_from_slice(b"WebPush: info\0");
        key_info.extend_from_slice(ua_public);
        key_info.extend_from_slice(as_public);
        let mut ikm = [0u8; 32];
        prk_key.expand(&key_info, &mut ikm).unwrap();

        let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut cek = [0u8; 16];
        prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek).unwrap();
        let mut nonce = [0u8; 12];
        prk.expand(b"Content-Encoding: nonce\0", &mut nonce).unwrap();

        let cipher = Aes128Gcm::new_from_slice(&cek).unwrap();
        let mut record = cipher.decrypt(&Nonce::from(nonce), ciphertext).unwrap();
        while record.last() == Some(&0x00) {
            record.pop();
        }
        assert_eq!(record.pop(), Some(0x02));
        record
    }

    fn decrypt_aesgcm(
        ua_secret: &SecretKey,
        auth_secret: &[u8],
        as_public: &[u8],
        salt: &[u8],
        ciphertext: &[u8],
    ) -> Vec<u8> {
        let ua_public_point = ua_secret.public_key().to_sec1_point(false);
        let ua_public = ua_public_point.as_bytes();
        let as_pk = PublicKey::from_sec1_bytes(as_public).unwrap();

        let shared = diffie_hellman(ua_secret.to_nonzero_scalar(), as_pk.as_affine());
        let prk_key = Hkdf::<Sha256>::new(Some(auth_secret), shared.raw_secret_bytes().as_slice());
        let mut ikm = [0u8; 32];
        prk_key.expand(b"Content-Encoding: auth\0", &mut ikm).unwrap();

        let mut context = Vec::with_capacity(140);
        context.extend_from_slice(b"P-256\0");
        context.extend_from_slice(&(UNCOMPRESSED_PUBKEY_LEN as u16).to_be_bytes());
        context.extend_from_slice(ua_public);
        context.extend_from_slice(&(UNCOMPRESSED_PUBKEY_LEN as u16).to_be_bytes());
        context.extend_from_slice(as_public);

        let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut cek_info = b"Content-Encoding: aesgcm\0".to_vec();
        cek_info.extend_from_slice(&context);
        let mut cek = [0u8; 16];
        prk.expand(&cek_info, &mut cek).unwrap();

        let mut nonce_info = b"Content-Encoding: nonce\0".to_vec();
        nonce_info.extend_from_slice(&context);
        let mut nonce = [0u8; 12];
        prk.expand(&nonce_info, &mut nonce).unwrap();

        let cipher = Aes128Gcm::new_from_slice(&cek).unwrap();
        let record = cipher.decrypt(&Nonce::from(nonce), ciphertext).unwrap();
        let pad_len = u16::from_be_bytes(record[0..2].try_into().unwrap()) as usize;
        assert!(record[2..2 + pad_len].iter().all(|&b| b == 0));
        record[2 + pad_len..].to_vec()
    }

    #[test]
    fn test_payload_size_boundaries() {
        let p256dh = Base64UrlSafeNoPadding::decode_to_vec(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            None,
        )
        .unwrap();
        let auth = Base64UrlSafeNoPadding::decode_to_vec("xS03Fi5ErfTNH_l9WHE9Ig", None).unwrap();

        let aes128_ece = HttpEce::new(ContentEncoding::Aes128Gcm, &p256dh, &auth, None);
        let aes128_max = aes128_ece.encrypt(&[b'a'; MAX_AES128GCM_PAYLOAD_SIZE]).unwrap();
        assert_eq!(aes128_max.content.len(), 4096);
        assert!(matches!(
            aes128_ece.encrypt(&[b'a'; MAX_AES128GCM_PAYLOAD_SIZE + 1]),
            Err(WebPushError::PayloadTooLarge)
        ));

        let aesgcm_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, None);
        let aesgcm_max = aesgcm_ece.encrypt(&[b'a'; MAX_AESGCM_PAYLOAD_SIZE]).unwrap();
        assert_eq!(aesgcm_max.content.len(), 3818);
        assert!(matches!(
            aesgcm_ece.encrypt(&[b'a'; MAX_AESGCM_PAYLOAD_SIZE + 1]),
            Err(WebPushError::PayloadTooLarge)
        ));
    }

    /// Verifies RFC 8291 Appendix A official test vector byte-for-byte.
    #[test]
    fn test_rfc8291_appendix_a_vector() {
        let as_secret_bytes = hex_decode("c9f58f89813e9f8e872e71f42aa64e1757c9254dcc62b72ddc010bb4043ea11c");
        let as_secret = SecretKey::from_slice(&as_secret_bytes).unwrap();
        let ua_public = hex_decode(
            "042571b2becdfde360551aaf1ed0f4cd366c11cebe555f89bcb7b186a53339173168ece2ebe018597bd30479b86e3c8f8eced577ca59187e9246990db682008b0e",
        );
        let auth_secret = hex_decode("05305932a1c7eabe13b6cec9fda48882");
        let salt: [u8; 16] = hex_decode("0c6bfaadad67958803092d454676f397").try_into().unwrap();
        let plaintext = b"When I grow up, I want to be a watermelon";

        let encrypted = encrypt_aes128gcm_with_inputs(&ua_public, &auth_secret, &as_secret, salt, plaintext).unwrap();

        let expected = "0c6bfaadad67958803092d454676f397000010004104fe33f4ab0dea71914db55823f73b54948f41306d920732dbb9a59a53286482200e597a7b7bc260ba1c227998580992e93973002f3012a28ae8f06bbb78e5ec0ff297de5b429bba7153d3a4ae0caa091fd425f3b4b5414add8ab37a19c1bbb05cf5cb5b2a2e0562d558635641ec52812c6c8ff42e95ccb86be7cd";
        assert_eq!(hex_encode(&encrypted), expected);

        let ua_secret_bytes = hex_decode("ab5757a70dd4a53e553a6bbf71ffefea2874ec07a6b379e3c48f895a02dc33de");
        let ua_secret = SecretKey::from_slice(&ua_secret_bytes).unwrap();
        assert_eq!(decrypt_aes128gcm(&ua_secret, &auth_secret, &encrypted), plaintext);
    }

    /// Verifies legacy IETF draft-ietf-webpush-encryption-04 Section 5 test vector byte-for-byte.
    #[test]
    fn test_draft04_aesgcm_vector() {
        let as_secret_bytes = hex_decode("9c249c7a4f90a448e638e953fab437f27673bdd3e5a9ad34672d22ea6d8e26f6");
        let as_secret = SecretKey::from_slice(&as_secret_bytes).unwrap();
        let ua_public = hex_decode(
            "042124063ccbf19dc2fa88b643ba04e6dd8da7ea7ba2c8c62e0f77a943f4c2fa914f6d44116c9fd1c40341c6a440cab3e2140a60e4378a5da735972de078005105",
        );
        let auth_secret = hex_decode("476f6f20676f6f206727206a6f6f6221");
        let salt: [u8; 16] = hex_decode("96781aadbc8a7cca22f59ef9c585e692").try_into().unwrap();
        let plaintext = b"I am the walrus";

        let (ciphertext, as_public) =
            encrypt_aesgcm_with_inputs(&ua_public, &auth_secret, &as_secret, salt, plaintext).unwrap();

        assert_eq!(
            hex_encode(&ciphertext),
            "ea7a80414304f2136ac39277925f1ca55549ca55ca62a64e7ac7991bc52e78aa40"
        );

        let ua_secret_bytes = hex_decode("f455a5d79fd05100160da0f7937979d19059409e1abb6ec5d55e05d2e2d20ff3");
        let ua_secret = SecretKey::from_slice(&ua_secret_bytes).unwrap();
        assert_eq!(
            decrypt_aesgcm(&ua_secret, &auth_secret, &as_public, &salt, &ciphertext),
            plaintext
        );
    }

    /// Tests that the content encryption is properly reversible while using aes128gcm.
    #[test]
    fn test_payload_encrypts_128() {
        let ua_secret = SecretKey::generate();
        let ua_point = ua_secret.public_key().to_sec1_point(false);
        let auth = [0x42u8; 16];

        let http_ece = HttpEce::new(ContentEncoding::Aes128Gcm, ua_point.as_bytes(), &auth, None);
        for plaintext in [&b""[..], b"Hello world!", &[b'x'; MAX_AES128GCM_PAYLOAD_SIZE]] {
            let ciphertext = http_ece.encrypt(plaintext).unwrap();
            assert!(ciphertext.content.len() >= 103);
            assert_ne!(plaintext, ciphertext.content.as_slice());
            let decrypted = decrypt_aes128gcm(&ua_secret, &auth, &ciphertext.content);
            assert_eq!(decrypted, plaintext);
        }
    }

    /// Tests that the content encryption is properly reversible while using aesgcm.
    #[test]
    fn test_payload_encrypts_aesgcm() {
        let ua_secret = SecretKey::generate();
        let ua_point = ua_secret.public_key().to_sec1_point(false);
        let auth = [0x24u8; 16];

        let http_ece = HttpEce::new(ContentEncoding::AesGcm, ua_point.as_bytes(), &auth, None);
        let plaintext = b"Hello world!";
        let payload = http_ece.encrypt(plaintext).unwrap();

        let dh_b64 = payload
            .crypto_headers
            .iter()
            .find(|(k, _)| *k == "Crypto-Key")
            .unwrap()
            .1
            .strip_prefix("dh=")
            .unwrap();
        let salt_b64 = payload
            .crypto_headers
            .iter()
            .find(|(k, _)| *k == "Encryption")
            .unwrap()
            .1
            .strip_prefix("salt=")
            .unwrap();
        let as_public = Base64UrlSafeNoPadding::decode_to_vec(dh_b64, None).unwrap();
        let salt = Base64UrlSafeNoPadding::decode_to_vec(salt_b64, None).unwrap();

        assert_ne!(plaintext, payload.content.as_slice());
        assert_eq!(
            decrypt_aesgcm(&ua_secret, &auth, &as_public, &salt, &payload.content),
            plaintext
        );
    }

    #[test]
    fn test_invalid_peer_keys_rejected() {
        let ua_secret = SecretKey::generate();
        let compressed = ua_secret.public_key().to_sec1_point(true);
        let uncompressed = ua_secret.public_key().to_sec1_point(false);
        let auth = [0x11u8; 16];

        for encoding in [ContentEncoding::Aes128Gcm, ContentEncoding::AesGcm] {
            // Compressed 33-byte public key rejected
            assert!(matches!(
                HttpEce::new(encoding, compressed.as_bytes(), &auth, None).encrypt(b"hi"),
                Err(WebPushError::InvalidCryptoKeys)
            ));
            // Wrong-length public key rejected
            assert!(matches!(
                HttpEce::new(encoding, &[0x04; 64], &auth, None).encrypt(b"hi"),
                Err(WebPushError::InvalidCryptoKeys)
            ));
            // Off-curve 65-byte point rejected
            assert!(matches!(
                HttpEce::new(encoding, &[0x04; 65], &auth, None).encrypt(b"hi"),
                Err(WebPushError::InvalidCryptoKeys)
            ));
            // Short or long auth secret rejected
            assert!(matches!(
                HttpEce::new(encoding, uncompressed.as_bytes(), &[0u8; 15], None).encrypt(b"hi"),
                Err(WebPushError::InvalidCryptoKeys)
            ));
            assert!(matches!(
                HttpEce::new(encoding, uncompressed.as_bytes(), &[0u8; 17], None).encrypt(b"hi"),
                Err(WebPushError::InvalidCryptoKeys)
            ));
        }
    }

    fn setup_payload(vapid_signature: Option<VapidSignature>, encoding: ContentEncoding) -> WebPushPayload {
        let p256dh = Base64UrlSafeNoPadding::decode_to_vec(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            None,
        )
        .unwrap();
        let auth = Base64UrlSafeNoPadding::decode_to_vec("xS03Fi5ErfTNH_l9WHE9Ig", None).unwrap();

        let http_ece = HttpEce::new(encoding, &p256dh, &auth, vapid_signature);
        let content = "Hello, world!".as_bytes();

        http_ece.encrypt(content).unwrap()
    }

    #[test]
    fn test_aes128gcm_headers_no_vapid() {
        let wp_payload = setup_payload(None, ContentEncoding::Aes128Gcm);
        assert_eq!(wp_payload.crypto_headers.len(), 0);
    }

    #[test]
    fn test_aesgcm_headers_no_vapid() {
        let wp_payload = setup_payload(None, ContentEncoding::AesGcm);
        assert_eq!(wp_payload.crypto_headers.len(), 2);
        assert_eq!(wp_payload.crypto_headers[0].0, "Crypto-Key");
        assert!(wp_payload.crypto_headers[0].1.starts_with("dh="));
        assert!(!wp_payload.crypto_headers[0].1.contains("p256ecdsa="));
        assert_eq!(wp_payload.crypto_headers[1].0, "Encryption");
        assert!(wp_payload.crypto_headers[1].1.starts_with("salt="));
    }

    #[test]
    fn test_aes128gcm_headers_vapid() {
        let auth_re = Regex::new(r"vapid t=(?P<sig_t>[^,]*), k=(?P<sig_k>[^,]*)").unwrap();
        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar").into_bytes(),
        };
        let wp_payload = setup_payload(Some(vapid_signature), ContentEncoding::Aes128Gcm);
        assert_eq!(wp_payload.crypto_headers.len(), 1);
        let auth = wp_payload.crypto_headers[0].clone();
        assert_eq!(auth.0, "Authorization");
        assert!(auth_re.captures(&auth.1).is_some());
    }

    #[test]
    fn test_aesgcm_headers_vapid() {
        let auth_re = Regex::new(r"vapid t=(?P<sig_t>[^,]*), k=(?P<sig_k>[^,]*)").unwrap();
        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar").into_bytes(),
        };
        let wp_payload = setup_payload(Some(vapid_signature), ContentEncoding::AesGcm);
        // Should have Crypto-Key, Encryption, and Authorization
        assert_eq!(wp_payload.crypto_headers.len(), 3);
        assert_eq!(wp_payload.crypto_headers[0].0, "Crypto-Key");
        assert!(wp_payload.crypto_headers[0].1.contains("; p256ecdsa="));
        assert_eq!(wp_payload.crypto_headers[1].0, "Encryption");
        let auth = wp_payload.crypto_headers[2].clone();
        assert_eq!(auth.0, "Authorization");
        assert!(auth_re.captures(&auth.1).is_some());
    }

    #[test]
    fn test_aesgcm_rejects_empty_plaintext_while_aes128gcm_accepts() {
        let ua_secret = SecretKey::generate();
        let ua_point = ua_secret.public_key().to_sec1_point(false);
        let auth = [0x33u8; 16];

        assert!(matches!(
            HttpEce::new(ContentEncoding::AesGcm, ua_point.as_bytes(), &auth, None).encrypt(b""),
            Err(WebPushError::InvalidCryptoKeys)
        ));

        let encrypted = HttpEce::new(ContentEncoding::Aes128Gcm, ua_point.as_bytes(), &auth, None)
            .encrypt(b"")
            .unwrap();
        assert_eq!(decrypt_aes128gcm(&ua_secret, &auth, &encrypted.content), b"");
    }
}
