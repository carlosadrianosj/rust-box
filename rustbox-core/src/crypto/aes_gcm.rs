use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};

use super::{CryptoError, Result};

/// Encrypt with AES-128-GCM, returning ciphertext with appended 16-byte auth tag.
pub fn aes128_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 16,
            got: key.len(),
        });
    }
    if nonce.len() != 12 {
        return Err(CryptoError::AesGcmEncrypt(format!(
            "invalid nonce length: expected 12, got {}",
            nonce.len()
        )));
    }

    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::AesGcmEncrypt(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::AesGcmEncrypt(e.to_string()))
}

/// Decrypt AES-128-GCM ciphertext, verifying the auth tag and AAD.
pub fn aes128_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 16,
            got: key.len(),
        });
    }
    if nonce.len() != 12 {
        return Err(CryptoError::AesGcmDecrypt(format!(
            "invalid nonce length: expected 12, got {}",
            nonce.len()
        )));
    }

    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::AesGcmDecrypt(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::AesGcmDecrypt(e.to_string()))
}

/// XOR a sequence number into a 12-byte base nonce (CRISP record layer counter).
pub fn compute_nonce(base_nonce: &[u8], seq: u64) -> Vec<u8> {
    assert_eq!(base_nonce.len(), 12, "base nonce must be 12 bytes");

    let mut nonce = base_nonce.to_vec();
    let seq_bytes = seq.to_be_bytes();

    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }

    nonce
}

/// Build CRISP Additional Authenticated Data: 8-byte sequence || 5-byte record header.
pub fn build_aad(seq: u64, record_header: &[u8; 5]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.extend_from_slice(record_header);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_gcm_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let plaintext = b"Hello RustBox World!";
        let aad = b"additional data";

        let ciphertext = aes128_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        let decrypted = aes128_gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_gcm_empty_aad() {
        let key = [0xAB; 16];
        let nonce = [0xCD; 12];
        let plaintext = b"test data";

        let ciphertext = aes128_gcm_encrypt(&key, &nonce, plaintext, &[]).unwrap();
        let decrypted = aes128_gcm_decrypt(&key, &nonce, &ciphertext, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_gcm_wrong_key() {
        let key = [0x42u8; 16];
        let wrong_key = [0x43u8; 16];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret";

        let ciphertext = aes128_gcm_encrypt(&key, &nonce, plaintext, &[]).unwrap();
        let result = aes128_gcm_decrypt(&wrong_key, &nonce, &ciphertext, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_nonce() {
        let base = [0u8; 12];
        let nonce = compute_nonce(&base, 1);
        assert_eq!(nonce.len(), 12);
        assert_eq!(nonce[11], 1);
        assert_eq!(nonce[0], 0);
    }

    #[test]
    fn test_compute_nonce_xor() {
        let base = [0xFF; 12];
        let nonce = compute_nonce(&base, 0);
        assert_eq!(nonce, vec![0xFF; 12]);

        let nonce = compute_nonce(&base, 1);
        assert_eq!(nonce[11], 0xFE);
    }

    #[test]
    fn test_build_aad() {
        let header: [u8; 5] = [0x17, 0xF1, 0x03, 0x00, 0x20];
        let aad = build_aad(1, &header);
        assert_eq!(aad.len(), 13);
        assert_eq!(&aad[0..8], &1u64.to_be_bytes());
        assert_eq!(&aad[8..13], &header);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = aes128_gcm_encrypt(&[0u8; 15], &[0u8; 12], b"test", &[]);
        assert!(result.is_err());
    }
}
