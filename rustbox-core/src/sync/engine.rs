use crate::merkle::diff::{compute_missing_hashes, compute_extra_hashes};

/// The result of comparing local and remote Merkle trees.
#[derive(Debug, Clone)]
pub struct SyncPlan {
    /// Chunk hashes that need to be uploaded to the server.
    pub to_upload: Vec<[u8; 32]>,
    /// Chunk hashes that need to be downloaded from the server.
    pub to_download: Vec<[u8; 32]>,
}

impl SyncPlan {
    pub fn is_synced(&self) -> bool {
        self.to_upload.is_empty() && self.to_download.is_empty()
    }
}

/// Compute a sync plan by comparing local and remote leaf hash sets.
pub fn compute_sync_plan(
    local_leaves: &[[u8; 32]],
    remote_leaves: &[[u8; 32]],
) -> SyncPlan {
    SyncPlan {
        to_upload: compute_extra_hashes(local_leaves, remote_leaves),
        to_download: compute_missing_hashes(local_leaves, remote_leaves),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(val: u8) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = val;
        hash
    }

    #[test]
    fn test_already_synced() {
        let hashes = vec![h(1), h(2), h(3)];
        let plan = compute_sync_plan(&hashes, &hashes);
        assert!(plan.is_synced());
    }

    #[test]
    fn test_need_upload_and_download() {
        let local = vec![h(1), h(2), h(3)];
        let remote = vec![h(2), h(3), h(4)];

        let plan = compute_sync_plan(&local, &remote);
        assert_eq!(plan.to_upload.len(), 1);
        assert_eq!(plan.to_upload[0], h(1));
        assert_eq!(plan.to_download.len(), 1);
        assert_eq!(plan.to_download[0], h(4));
    }

    #[test]
    fn test_fresh_client() {
        let local = vec![];
        let remote = vec![h(1), h(2)];

        let plan = compute_sync_plan(&local, &remote);
        assert!(plan.to_upload.is_empty());
        assert_eq!(plan.to_download.len(), 2);
    }
}
