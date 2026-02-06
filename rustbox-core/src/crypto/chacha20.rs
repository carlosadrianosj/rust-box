use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};

use super::{CryptoError, Result};
use crate::constants::XCHACHA20_NONCE_LEN;

/// Encrypt plaintext with XChaCha20-Poly1305.
///
/// Returns ciphertext with 16-byte authentication tag appended.
pub fn xchacha20_encrypt(
    key: &[u8; 32],
    nonce: &[u8; XCHACHA20_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(xnonce, payload)
        .map_err(|e| CryptoError::ChaCha20Encrypt(e.to_string()))
}

/// Decrypt ciphertext with XChaCha20-Poly1305 and verify authentication tag.
pub fn xchacha20_decrypt(
    key: &[u8; 32],
    nonce: &[u8; XCHACHA20_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(xnonce, payload)
        .map_err(|e| CryptoError::ChaCha20Decrypt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xchacha20_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; XCHACHA20_NONCE_LEN];
        let plaintext = b"Hello RustBox zero-knowledge!";
        let aad = b"chunk metadata";

        let ciphertext = xchacha20_encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], &plaintext[..]);

        let decrypted = xchacha20_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xchacha20_empty_aad() {
        let key = [0xAB; 32];
        let nonce = [0xCD; XCHACHA20_NONCE_LEN];
        let plaintext = b"test data without aad";

        let ciphertext = xchacha20_encrypt(&key, &nonce, plaintext, &[]).unwrap();
        let decrypted = xchacha20_decrypt(&key, &nonce, &ciphertext, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xchacha20_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0x01u8; XCHACHA20_NONCE_LEN];
        let plaintext = b"secret data";

        let ciphertext = xchacha20_encrypt(&key, &nonce, plaintext, &[]).unwrap();
        let result = xchacha20_decrypt(&wrong_key, &nonce, &ciphertext, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_xchacha20_wrong_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; XCHACHA20_NONCE_LEN];
        let plaintext = b"secret data";

        let ciphertext = xchacha20_encrypt(&key, &nonce, plaintext, b"correct aad").unwrap();
        let result = xchacha20_decrypt(&key, &nonce, &ciphertext, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_xchacha20_large_payload() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; XCHACHA20_NONCE_LEN];
        let plaintext = vec![0xAA; 1_048_576]; // 1 MB

        let ciphertext = xchacha20_encrypt(&key, &nonce, &plaintext, &[]).unwrap();
        let decrypted = xchacha20_decrypt(&key, &nonce, &ciphertext, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
