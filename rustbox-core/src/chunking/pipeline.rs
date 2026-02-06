use sha2::{Sha256, Digest};

use crate::crypto::chacha20::{xchacha20_encrypt, xchacha20_decrypt};
use crate::crypto::key_hierarchy::derive_chunk_key;
use crate::crypto::CryptoError;
use crate::traits::random::SecureRandom;
use crate::constants::XCHACHA20_NONCE_LEN;

/// An encrypted chunk with its hash, nonce, and index.
#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    pub hash: [u8; 32],
    pub encrypted_data: Vec<u8>,
    pub nonce: [u8; XCHACHA20_NONCE_LEN],
    pub index: u32,
}

/// Encrypt a chunk using XChaCha20-Poly1305.
///
/// Derives a unique key for this chunk from the file encryption key and index,
/// generates a random nonce, and computes SHA-256 over the ciphertext.
pub fn encrypt_chunk(
    file_enc_key: &[u8; 32],
    chunk_index: u32,
    plaintext: &[u8],
    rng: &dyn SecureRandom,
) -> Result<EncryptedChunk, CryptoError> {
    let chunk_key = derive_chunk_key(file_enc_key, chunk_index)?;

    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    rng.fill_bytes(&mut nonce)
        .map_err(|e| CryptoError::ChaCha20Encrypt(e.to_string()))?;

    let aad = chunk_index.to_be_bytes();
    let encrypted_data = xchacha20_encrypt(&chunk_key, &nonce, plaintext, &aad)?;

    let hash: [u8; 32] = Sha256::digest(&encrypted_data).into();

    Ok(EncryptedChunk {
        hash,
        encrypted_data,
        nonce,
        index: chunk_index,
    })
}

/// Decrypt a chunk using XChaCha20-Poly1305.
pub fn decrypt_chunk(
    file_enc_key: &[u8; 32],
    chunk_index: u32,
    encrypted_data: &[u8],
    nonce: &[u8; XCHACHA20_NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let chunk_key = derive_chunk_key(file_enc_key, chunk_index)?;
    let aad = chunk_index.to_be_bytes();
    xchacha20_decrypt(&chunk_key, nonce, encrypted_data, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RustBoxError;

    struct TestRng;
    impl SecureRandom for TestRng {
        fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RustBoxError> {
            getrandom::getrandom(dest)
                .map_err(|e| RustBoxError::Platform(e.to_string()))
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let file_key = [0x42u8; 32];
        let plaintext = b"Hello RustBox chunk encryption!";
        let rng = TestRng;

        let encrypted = encrypt_chunk(&file_key, 0, plaintext, &rng).unwrap();
        assert_eq!(encrypted.index, 0);
        assert_ne!(encrypted.encrypted_data, plaintext);

        let decrypted = decrypt_chunk(
            &file_key,
            0,
            &encrypted.encrypted_data,
            &encrypted.nonce,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonce_different_hash() {
        let file_key = [0x42u8; 32];
        let plaintext = b"same data";
        let rng = TestRng;

        let enc1 = encrypt_chunk(&file_key, 0, plaintext, &rng).unwrap();
        let enc2 = encrypt_chunk(&file_key, 0, plaintext, &rng).unwrap();

        // Random nonces should produce different ciphertexts/hashes
        assert_ne!(enc1.nonce, enc2.nonce);
        assert_ne!(enc1.hash, enc2.hash);
    }

    #[test]
    fn test_wrong_key_fails() {
        let file_key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"secret";
        let rng = TestRng;

        let encrypted = encrypt_chunk(&file_key, 0, plaintext, &rng).unwrap();
        let result = decrypt_chunk(
            &wrong_key,
            0,
            &encrypted.encrypted_data,
            &encrypted.nonce,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_index_fails() {
        let file_key = [0x42u8; 32];
        let plaintext = b"secret";
        let rng = TestRng;

        let encrypted = encrypt_chunk(&file_key, 0, plaintext, &rng).unwrap();
        let result = decrypt_chunk(
            &file_key,
            1, // wrong index
            &encrypted.encrypted_data,
            &encrypted.nonce,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_large_chunk() {
        let file_key = [0x42u8; 32];
        let plaintext = vec![0xAA; 1_048_576]; // 1 MB
        let rng = TestRng;

        let encrypted = encrypt_chunk(&file_key, 0, &plaintext, &rng).unwrap();
        let decrypted = decrypt_chunk(
            &file_key,
            0,
            &encrypted.encrypted_data,
            &encrypted.nonce,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
