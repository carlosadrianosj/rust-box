//! CRISP protocol: TLS 1.3-inspired secure channel (P-256 ECDH, AES-128-GCM, PSK resumption).

pub mod record;
pub mod handshake;
pub mod keys;
pub mod cipher;

use thiserror::Error;

/// Errors from CRISP handshake, record parsing, or session management.
#[derive(Error, Debug)]
pub enum CrispError {
    #[error("Record parse error: {0}")]
    RecordParse(String),
    #[error("Handshake error: {0}")]
    Handshake(String),
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),
    #[error("Cipher error: {0}")]
    Cipher(String),
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("Insufficient data: need {need} bytes, got {got}")]
    InsufficientData { need: usize, got: usize },
    #[error("Invalid record type: {0:#04x}")]
    InvalidRecordType(u8),
    #[error("Invalid protocol version: {0:#06x}")]
    InvalidVersion(u16),
    #[error("Session not established")]
    SessionNotEstablished,
}

/// Convenience alias for CRISP operations.
pub type Result<T> = std::result::Result<T, CrispError>;
