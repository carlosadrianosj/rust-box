use serde::{Serialize, Deserialize};

/// Pointer to a file's manifest within the sync index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileReference {
    pub file_id: String,
    pub filename: String,
    pub manifest_id: String,
    pub merkle_leaf: [u8; 32],
    pub modified_at: u64,
}

/// Per-user index of all synced files with the current Merkle root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncManifest {
    pub user_id: String,
    pub files: Vec<FileReference>,
    pub merkle_root: [u8; 32],
    pub version: u64,
    pub last_sync_at: u64,
}

impl SyncManifest {
    /// Create an empty sync manifest for a new user.
    pub fn new(user_id: String) -> Self {
        Self {
            user_id,
            files: Vec::new(),
            merkle_root: [0u8; 32],
            version: 0,
            last_sync_at: 0,
        }
    }

    /// Track a file reference in the sync index.
    pub fn add_file(&mut self, reference: FileReference) {
        self.files.push(reference);
    }

    /// Number of files tracked in this manifest.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::serialization;

    #[test]
    fn test_sync_manifest_roundtrip() {
        let mut manifest = SyncManifest::new("user-001".to_string());
        manifest.version = 1;
        manifest.merkle_root = [0xAA; 32];
        manifest.add_file(FileReference {
            file_id: "file-001".to_string(),
            filename: "test.txt".to_string(),
            manifest_id: "m-001".to_string(),
            merkle_leaf: [0xBB; 32],
            modified_at: 1700000000,
        });

        let bytes = serialization::serialize(&manifest).unwrap();
        let decoded: SyncManifest = serialization::deserialize(&bytes).unwrap();
        assert_eq!(decoded, manifest);
    }
}
