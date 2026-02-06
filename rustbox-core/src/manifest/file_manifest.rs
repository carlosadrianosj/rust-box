use serde::{Serialize, Deserialize};
use crate::constants::XCHACHA20_NONCE_LEN;

/// Metadata for a single encrypted chunk within a file manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChunkEntry {
    pub index: u32,
    pub hash: [u8; 32],
    pub nonce: [u8; XCHACHA20_NONCE_LEN],
    pub encrypted_size: u32,
    pub plaintext_size: u32,
}

/// Encrypted-at-rest descriptor of a file: name, size, and ordered chunk list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileManifest {
    pub file_id: String,
    pub filename: String,
    pub original_size: u64,
    pub mime_type: Option<String>,
    pub created_at: u64,
    pub modified_at: u64,
    pub chunks: Vec<ChunkEntry>,
    pub file_hash: [u8; 32],
}

impl FileManifest {
    /// Create an empty manifest shell; chunks are added during the upload pipeline.
    pub fn new(file_id: String, filename: String, original_size: u64) -> Self {
        Self {
            file_id,
            filename,
            original_size,
            mime_type: None,
            created_at: 0,
            modified_at: 0,
            chunks: Vec::new(),
            file_hash: [0u8; 32],
        }
    }

    /// Append an encrypted chunk entry to the manifest.
    pub fn add_chunk(&mut self, entry: ChunkEntry) {
        self.chunks.push(entry);
    }

    /// Extract ordered chunk hashes for Merkle tree construction.
    pub fn chunk_hashes(&self) -> Vec<[u8; 32]> {
        self.chunks.iter().map(|c| c.hash).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::serialization;

    #[test]
    fn test_file_manifest_serialization_roundtrip() {
        let mut manifest = FileManifest::new(
            "file-001".to_string(),
            "hello.txt".to_string(),
            1024,
        );
        manifest.created_at = 1700000000;
        manifest.modified_at = 1700000001;
        manifest.file_hash = [0xAA; 32];
        manifest.add_chunk(ChunkEntry {
            index: 0,
            hash: [0xBB; 32],
            nonce: [0xCC; XCHACHA20_NONCE_LEN],
            encrypted_size: 1040,
            plaintext_size: 1024,
        });

        let bytes = serialization::serialize(&manifest).unwrap();
        let decoded: FileManifest = serialization::deserialize(&bytes).unwrap();
        assert_eq!(decoded, manifest);
    }
}
