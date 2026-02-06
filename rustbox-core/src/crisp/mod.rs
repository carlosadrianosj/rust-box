pub mod record;
pub mod handshake;
pub mod keys;
pub mod cipher;

use thiserror::Error;

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

pub type Result<T> = std::result::Result<T, CrispError>;
