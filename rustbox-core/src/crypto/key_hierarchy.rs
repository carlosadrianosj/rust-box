use super::hkdf::{hkdf_extract, hkdf_expand};
use super::Result;
use crate::constants::*;

/// Derive file encryption key from master key and file ID.
///
/// file_enc_key = HKDF-Expand(HKDF-Extract(master_key), "rustbox-enc" || file_id, 32)
pub fn derive_file_enc_key(master_key: &[u8; 32], file_id: &str) -> Result<[u8; 32]> {
    let prk = hkdf_extract(&[], master_key);

    let mut info = Vec::new();
    info.extend_from_slice(LABEL_RUSTBOX_ENC.as_bytes());
    info.extend_from_slice(file_id.as_bytes());

    let expanded = hkdf_expand(&prk, &info, 32)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&expanded);
    Ok(key)
}

/// Derive chunk key from file encryption key and chunk index.
///
/// chunk_key = HKDF-Expand(file_enc_key, "chunk" || index_bytes, 32)
pub fn derive_chunk_key(file_enc_key: &[u8; 32], chunk_index: u32) -> Result<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(LABEL_RUSTBOX_CHUNK.as_bytes());
    info.extend_from_slice(&chunk_index.to_be_bytes());

    let expanded = hkdf_expand(file_enc_key, &info, 32)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&expanded);
    Ok(key)
}

/// Derive manifest encryption key from master key and file ID.
///
/// manifest_key = HKDF-Expand(HKDF-Extract(master_key), "rustbox-manifest" || file_id, 32)
pub fn derive_manifest_key(master_key: &[u8; 32], file_id: &str) -> Result<[u8; 32]> {
    let prk = hkdf_extract(&[], master_key);

    let mut info = Vec::new();
    info.extend_from_slice(LABEL_RUSTBOX_MANIFEST.as_bytes());
    info.extend_from_slice(file_id.as_bytes());

    let expanded = hkdf_expand(&prk, &info, 32)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&expanded);
    Ok(key)
}

/// Derive auth key from master key.
///
/// auth_key = HKDF-Expand(HKDF-Extract(master_key), "rustbox-auth", 32)
pub fn derive_auth_key(master_key: &[u8; 32]) -> Result<[u8; 32]> {
    let prk = hkdf_extract(&[], master_key);

    let info = LABEL_RUSTBOX_AUTH.as_bytes();
    let expanded = hkdf_expand(&prk, info, 32)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&expanded);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_file_enc_key_deterministic() {
        let master = [0x42u8; 32];
        let key1 = derive_file_enc_key(&master, "file-001").unwrap();
        let key2 = derive_file_enc_key(&master, "file-001").unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_file_enc_key_different_files() {
        let master = [0x42u8; 32];
        let key1 = derive_file_enc_key(&master, "file-001").unwrap();
        let key2 = derive_file_enc_key(&master, "file-002").unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_chunk_key_chain() {
        let master = [0x42u8; 32];
        let file_key = derive_file_enc_key(&master, "test-file").unwrap();

        let chunk0 = derive_chunk_key(&file_key, 0).unwrap();
        let chunk1 = derive_chunk_key(&file_key, 1).unwrap();
        let chunk2 = derive_chunk_key(&file_key, 2).unwrap();

        // Each chunk key should be unique
        assert_ne!(chunk0, chunk1);
        assert_ne!(chunk1, chunk2);
        assert_ne!(chunk0, chunk2);
        assert_eq!(chunk0.len(), 32);
    }

    #[test]
    fn test_derive_manifest_key() {
        let master = [0x42u8; 32];
        let manifest_key = derive_manifest_key(&master, "file-001").unwrap();
        let file_key = derive_file_enc_key(&master, "file-001").unwrap();

        // Manifest key and file key for the same file should differ
        assert_ne!(manifest_key, file_key);
        assert_eq!(manifest_key.len(), 32);
    }

    #[test]
    fn test_derive_auth_key() {
        let master = [0x42u8; 32];
        let auth_key = derive_auth_key(&master).unwrap();
        let file_key = derive_file_enc_key(&master, "any-file").unwrap();

        assert_ne!(auth_key, file_key);
        assert_eq!(auth_key.len(), 32);
    }

    #[test]
    fn test_key_hierarchy_isolation() {
        // Different master keys produce completely different hierarchies
        let master1 = [0x42u8; 32];
        let master2 = [0x43u8; 32];

        let file_key1 = derive_file_enc_key(&master1, "same-file").unwrap();
        let file_key2 = derive_file_enc_key(&master2, "same-file").unwrap();
        assert_ne!(file_key1, file_key2);

        let chunk1 = derive_chunk_key(&file_key1, 0).unwrap();
        let chunk2 = derive_chunk_key(&file_key2, 0).unwrap();
        assert_ne!(chunk1, chunk2);
    }
}
