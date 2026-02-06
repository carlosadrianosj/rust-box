use async_trait::async_trait;
use crate::error::RustBoxError;

/// Network transport for chunk/manifest exchange and Merkle sync.
///
/// Uses `?Send` so implementations work in both Tokio (native) and single-threaded WASM.
#[async_trait(?Send)]
pub trait Transport {
    /// Upload an encrypted chunk keyed by its SHA-256 hash.
    async fn upload_chunk(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError>;
    /// Download an encrypted chunk by its SHA-256 hash.
    async fn download_chunk(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError>;
    /// Upload an encrypted manifest envelope, returning the server-assigned ID.
    async fn upload_manifest(&self, data: &[u8]) -> Result<String, RustBoxError>;
    /// Download an encrypted manifest envelope by ID.
    async fn download_manifest(&self, id: &str) -> Result<Vec<u8>, RustBoxError>;
    /// Fetch the server's Merkle root hash for the current user.
    async fn get_merkle_root(&self) -> Result<[u8; 32], RustBoxError>;
    /// Compare local and remote Merkle trees, returning the remote leaf hashes.
    async fn get_merkle_diff(&self, local_root: &[u8; 32]) -> Result<Vec<[u8; 32]>, RustBoxError>;
}
