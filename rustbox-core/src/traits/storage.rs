use async_trait::async_trait;
use crate::error::RustBoxError;

#[async_trait(?Send)]
pub trait ContentAddressableStorage {
    async fn store(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError>;
    async fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError>;
    async fn exists(&self, hash: &[u8; 32]) -> Result<bool, RustBoxError>;
    async fn list_hashes(&self) -> Result<Vec<[u8; 32]>, RustBoxError>;
    async fn delete(&self, hash: &[u8; 32]) -> Result<(), RustBoxError>;
}

#[async_trait(?Send)]
pub trait PersistentStorage {
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), RustBoxError>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, RustBoxError>;
    async fn delete(&self, key: &str) -> Result<(), RustBoxError>;
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, RustBoxError>;
}
