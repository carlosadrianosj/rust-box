use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::fs;
use tracing::debug;

use rustbox_core::error::RustBoxError;
use rustbox_core::traits::storage::ContentAddressableStorage;

/// Content-addressable blob storage backed by the local filesystem.
///
/// Blobs are stored at `.rustbox/blobs/{hex_hash}` where `hex_hash` is the
/// lowercase hex encoding of the 32-byte SHA-256 hash.
pub struct LocalFs {
    blobs_dir: PathBuf,
}

impl LocalFs {
    /// Create a new LocalFs rooted at the given blobs directory.
    pub fn new(blobs_dir: &Path) -> Self {
        Self {
            blobs_dir: blobs_dir.to_path_buf(),
        }
    }

    /// Return the filesystem path for a given hash.
    fn blob_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.blobs_dir.join(hex::encode(hash))
    }
}

#[async_trait(?Send)]
impl ContentAddressableStorage for LocalFs {
    async fn store(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError> {
        let path = self.blob_path(hash);

        // Ensure the blobs directory exists.
        fs::create_dir_all(&self.blobs_dir)
            .await
            .map_err(|e| RustBoxError::Storage(format!("create blobs dir failed: {e}")))?;

        fs::write(&path, data)
            .await
            .map_err(|e| RustBoxError::Storage(format!("write blob failed: {e}")))?;

        debug!("Stored blob {} ({} bytes)", hex::encode(hash), data.len());
        Ok(())
    }

    async fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError> {
        let path = self.blob_path(hash);

        if !path.exists() {
            return Err(RustBoxError::NotFound(format!(
                "blob not found: {}",
                hex::encode(hash)
            )));
        }

        let data = fs::read(&path)
            .await
            .map_err(|e| RustBoxError::Storage(format!("read blob failed: {e}")))?;

        debug!(
            "Retrieved blob {} ({} bytes)",
            hex::encode(hash),
            data.len()
        );
        Ok(data)
    }

    async fn exists(&self, hash: &[u8; 32]) -> Result<bool, RustBoxError> {
        let path = self.blob_path(hash);
        Ok(path.exists())
    }

    async fn list_hashes(&self) -> Result<Vec<[u8; 32]>, RustBoxError> {
        let mut hashes = Vec::new();

        if !self.blobs_dir.exists() {
            return Ok(hashes);
        }

        let mut entries = fs::read_dir(&self.blobs_dir)
            .await
            .map_err(|e| RustBoxError::Storage(format!("read blobs dir failed: {e}")))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| RustBoxError::Storage(format!("read dir entry failed: {e}")))?
        {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.len() == 64 {
                if let Ok(bytes) = hex::decode(name_str.as_ref()) {
                    if bytes.len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&bytes);
                        hashes.push(hash);
                    }
                }
            }
        }

        debug!("Listed {} blobs", hashes.len());
        Ok(hashes)
    }

    async fn delete(&self, hash: &[u8; 32]) -> Result<(), RustBoxError> {
        let path = self.blob_path(hash);

        if !path.exists() {
            return Err(RustBoxError::NotFound(format!(
                "blob not found: {}",
                hex::encode(hash)
            )));
        }

        fs::remove_file(&path)
            .await
            .map_err(|e| RustBoxError::Storage(format!("delete blob failed: {e}")))?;

        debug!("Deleted blob {}", hex::encode(hash));
        Ok(())
    }
}
