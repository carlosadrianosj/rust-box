use std::collections::HashSet;

/// Compute hashes present in `remote` but missing from `local`.
pub fn compute_missing_hashes(
    local: &[[u8; 32]],
    remote: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    let local_set: HashSet<[u8; 32]> = local.iter().copied().collect();
    remote
        .iter()
        .filter(|h| !local_set.contains(*h))
        .copied()
        .collect()
}

/// Compute hashes present in `local` but not in `remote`.
pub fn compute_extra_hashes(
    local: &[[u8; 32]],
    remote: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    let remote_set: HashSet<[u8; 32]> = remote.iter().copied().collect();
    local
        .iter()
        .filter(|h| !remote_set.contains(*h))
        .copied()
        .collect()
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
    fn test_compute_missing_hashes() {
        let local = vec![h(1), h(2), h(3)];
        let remote = vec![h(2), h(3), h(4)];

        let missing = compute_missing_hashes(&local, &remote);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], h(4));
    }

    #[test]
    fn test_compute_extra_hashes() {
        let local = vec![h(1), h(2), h(3)];
        let remote = vec![h(2), h(3), h(4)];

        let extra = compute_extra_hashes(&local, &remote);
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0], h(1));
    }

    #[test]
    fn test_identical_sets() {
        let hashes = vec![h(1), h(2), h(3)];
        assert!(compute_missing_hashes(&hashes, &hashes).is_empty());
        assert!(compute_extra_hashes(&hashes, &hashes).is_empty());
    }

    #[test]
    fn test_empty_local() {
        let remote = vec![h(1), h(2)];
        let missing = compute_missing_hashes(&[], &remote);
        assert_eq!(missing.len(), 2);
    }

    #[test]
    fn test_empty_remote() {
        let local = vec![h(1), h(2)];
        let extra = compute_extra_hashes(&local, &[]);
        assert_eq!(extra.len(), 2);
    }
}
