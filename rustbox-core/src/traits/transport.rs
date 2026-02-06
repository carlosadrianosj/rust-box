use async_trait::async_trait;
use crate::error::RustBoxError;

#[async_trait(?Send)]
pub trait Transport {
    async fn upload_chunk(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError>;
    async fn download_chunk(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError>;
    async fn upload_manifest(&self, data: &[u8]) -> Result<String, RustBoxError>;
    async fn download_manifest(&self, id: &str) -> Result<Vec<u8>, RustBoxError>;
    async fn get_merkle_root(&self) -> Result<[u8; 32], RustBoxError>;
    async fn get_merkle_diff(&self, local_root: &[u8; 32]) -> Result<Vec<[u8; 32]>, RustBoxError>;
}
