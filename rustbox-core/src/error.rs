use thiserror::Error;

#[derive(Error, Debug)]
pub enum RustBoxError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("CRISP error: {0}")]
    Crisp(#[from] crate::crisp::CrispError),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Merkle tree error: {0}")]
    Merkle(String),

    #[error("Sync error: {0}")]
    Sync(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Platform error: {0}")]
    Platform(String),
}

pub type Result<T> = std::result::Result<T, RustBoxError>;
