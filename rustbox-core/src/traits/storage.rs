use async_trait::async_trait;
use crate::error::RustBoxError;

/// Blob storage addressed by SHA-256 hash of the ciphertext (deduplication-safe).
#[async_trait(?Send)]
pub trait ContentAddressableStorage {
    /// Store a blob keyed by its SHA-256 hash.
    async fn store(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError>;
    /// Retrieve a blob by its SHA-256 hash.
    async fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError>;
    /// Check whether a blob with this hash exists locally.
    async fn exists(&self, hash: &[u8; 32]) -> Result<bool, RustBoxError>;
    /// List all locally stored blob hashes.
    async fn list_hashes(&self) -> Result<Vec<[u8; 32]>, RustBoxError>;
    /// Delete a blob by hash.
    async fn delete(&self, hash: &[u8; 32]) -> Result<(), RustBoxError>;
}

/// Key-value metadata storage (vault state, server address, manifest index).
#[async_trait(?Send)]
pub trait PersistentStorage {
    /// Store a key-value pair.
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), RustBoxError>;
    /// Retrieve a value by key, returning None if absent.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, RustBoxError>;
    /// Delete a key-value pair.
    async fn delete(&self, key: &str) -> Result<(), RustBoxError>;
    /// List all keys matching a prefix.
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, RustBoxError>;
}
