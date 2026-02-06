use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{CryptoError, Result};

type HmacSha256 = Hmac<Sha256>;

/// HKDF key set for CRISP short link (28 bytes: 16B key + 12B nonce).
#[derive(Debug, Clone)]
pub struct HkdfKey28 {
    pub aes_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// HKDF key set for CRISP long link (56 bytes: 2x16B keys + 2x12B nonces).
#[derive(Debug, Clone)]
pub struct HkdfKey56 {
    pub encode_aes_key: Vec<u8>,
    pub encode_nonce: Vec<u8>,
    pub decode_aes_key: Vec<u8>,
    pub decode_nonce: Vec<u8>,
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt = if salt.is_empty() { &[0u8; 32] } else { salt };
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.to_vec()
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|e| CryptoError::HkdfDerive(format!("invalid PRK: {e}")))?;

    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm)
        .map_err(|e| CryptoError::HkdfDerive(format!("expand failed: {e}")))?;

    Ok(okm)
}

pub fn hkdf_extract_and_expand(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

pub fn hkdf_expand_handshake_keys(
    hash: &[u8],
    label: &str,
    context_hash: &[u8],
) -> Result<Vec<u8>> {
    let mut info = Vec::new();
    info.extend_from_slice(label.as_bytes());
    info.extend_from_slice(context_hash);
    hkdf_expand(hash, &info, 56)
}

pub fn hkdf_expand_short_keys(
    prk: &[u8],
    label: &str,
    context_hash: &[u8],
) -> Result<HkdfKey28> {
    let mut info = Vec::new();
    info.extend_from_slice(label.as_bytes());
    info.extend_from_slice(context_hash);

    let expanded = hkdf_expand(prk, &info, 28)?;
    Ok(HkdfKey28 {
        aes_key: expanded[0..16].to_vec(),
        nonce: expanded[16..28].to_vec(),
    })
}

pub fn hkdf_expand_psk(
    prk: &[u8],
    label: &str,
    context_hash: &[u8],
) -> Result<Vec<u8>> {
    let mut info = Vec::new();
    info.extend_from_slice(label.as_bytes());
    info.extend_from_slice(context_hash);
    hkdf_expand(prk, &info, 32)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let computed = hmac_sha256(key, data);
    constant_time_eq(&computed, expected)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_extract() {
        let salt = [0x0b; 32];
        let ikm = [0x42; 32];
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk.len(), 32);
    }

    #[test]
    fn test_hkdf_expand() {
        let prk = [0x42u8; 32];
        let info = b"test info";
        let okm = hkdf_expand(&prk, info, 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_hkdf_expand_handshake_keys() {
        let hash = [0xAA; 32];
        let context = [0xBB; 32];
        let keys = hkdf_expand_handshake_keys(
            &hash,
            crate::constants::LABEL_HANDSHAKE_KEY_EXPANSION,
            &context,
        )
        .unwrap();
        assert_eq!(keys.len(), 56);
    }

    #[test]
    fn test_hkdf_expand_short_keys() {
        let prk = [0xCC; 32];
        let context = [0xDD; 32];
        let keys = hkdf_expand_short_keys(
            &prk,
            crate::constants::LABEL_EARLY_DATA_KEY_EXPANSION,
            &context,
        )
        .unwrap();
        assert_eq!(keys.aes_key.len(), 16);
        assert_eq!(keys.nonce.len(), 12);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let data = b"test data";
        let mac = hmac_sha256(key, data);
        assert_eq!(mac.len(), 32);
        assert!(hmac_sha256_verify(key, data, &mac));
        assert!(!hmac_sha256_verify(key, b"wrong data", &mac));
    }

    #[test]
    fn test_hkdf_extract_and_expand() {
        let salt = [0x42; 32];
        let ikm = [0xAA; 32];
        let info = b"test context";
        let result = hkdf_extract_and_expand(&salt, &ikm, info, 48).unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_hkdf_expand_psk() {
        let prk = [0xBB; 32];
        let context = [0xCC; 32];
        let result = hkdf_expand_psk(
            &prk,
            crate::constants::LABEL_PSK_ACCESS,
            &context,
        )
        .unwrap();
        assert_eq!(result.len(), 32);
    }
}
