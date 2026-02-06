pub mod hkdf;
pub mod aes_gcm;
pub mod ecdh;
pub mod ecdsa;
pub mod chacha20;
pub mod pbkdf2;
pub mod key_hierarchy;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("ECDH key generation failed: {0}")]
    EcdhKeyGen(String),
    #[error("ECDH shared secret computation failed: {0}")]
    EcdhSharedSecret(String),
    #[error("AES-GCM encryption failed: {0}")]
    AesGcmEncrypt(String),
    #[error("AES-GCM decryption failed: {0}")]
    AesGcmDecrypt(String),
    #[error("HKDF derivation failed: {0}")]
    HkdfDerive(String),
    #[error("ECDSA verification failed: {0}")]
    EcdsaVerify(String),
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("Invalid public key format")]
    InvalidPublicKey,
    #[error("ChaCha20-Poly1305 encryption failed: {0}")]
    ChaCha20Encrypt(String),
    #[error("ChaCha20-Poly1305 decryption failed: {0}")]
    ChaCha20Decrypt(String),
    #[error("PBKDF2 derivation failed: {0}")]
    Pbkdf2Derive(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
