use sha2::{Sha256, Digest};

/// A Merkle tree built from leaf hashes using SHA-256.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    nodes: Vec<[u8; 32]>,
    leaf_count: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of leaf hashes.
    /// Returns a tree with a single zero-hash root if leaves is empty.
    pub fn from_leaves(leaves: &[[u8; 32]]) -> Self {
        if leaves.is_empty() {
            return Self {
                nodes: vec![[0u8; 32]],
                leaf_count: 0,
            };
        }

        let leaf_count = leaves.len();
        // Pad to next power of 2
        let padded_count = leaf_count.next_power_of_two();
        let total_nodes = 2 * padded_count - 1;

        let mut nodes = vec![[0u8; 32]; total_nodes];

        // Fill leaf layer (last padded_count nodes)
        let leaf_start = padded_count - 1;
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[leaf_start + i] = *leaf;
        }

        // Build internal nodes bottom-up
        for i in (0..leaf_start).rev() {
            let left = nodes[2 * i + 1];
            let right = nodes[2 * i + 2];
            nodes[i] = hash_pair(&left, &right);
        }

        Self { nodes, leaf_count }
    }

    /// Get the root hash.
    pub fn root(&self) -> [u8; 32] {
        self.nodes[0]
    }

    /// Get the leaf hashes.
    pub fn leaves(&self) -> &[[u8; 32]] {
        let padded = self.leaf_count.next_power_of_two().max(1);
        let start = padded - 1;
        &self.nodes[start..start + self.leaf_count]
    }

    /// Number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Generate an inclusion proof for the leaf at the given index.
    /// Returns the sibling hashes needed to verify inclusion.
    pub fn proof(&self, leaf_index: usize) -> Vec<[u8; 32]> {
        if leaf_index >= self.leaf_count {
            return vec![];
        }

        let padded = self.leaf_count.next_power_of_two();
        let mut proof = Vec::new();
        let mut idx = padded - 1 + leaf_index;

        while idx > 0 {
            let sibling = if idx % 2 == 1 { idx + 1 } else { idx - 1 };
            if sibling < self.nodes.len() {
                proof.push(self.nodes[sibling]);
            }
            idx = (idx - 1) / 2;
        }

        proof
    }

    /// Verify an inclusion proof for a given leaf against a known root.
    pub fn verify_proof(
        root: &[u8; 32],
        leaf: &[u8; 32],
        leaf_index: usize,
        proof: &[[u8; 32]],
        total_leaves: usize,
    ) -> bool {
        if total_leaves == 0 {
            return false;
        }

        let padded = total_leaves.next_power_of_two();
        let mut hash = *leaf;
        let mut idx = padded - 1 + leaf_index;

        for sibling_hash in proof {
            if idx % 2 == 1 {
                // Current is left child
                hash = hash_pair(&hash, sibling_hash);
            } else {
                // Current is right child
                hash = hash_pair(sibling_hash, &hash);
            }
            idx = (idx - 1) / 2;
        }

        hash == *root
    }
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaf(val: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = val;
        h
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::from_leaves(&[]);
        assert_eq!(tree.root(), [0u8; 32]);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_single_leaf() {
        let leaf = make_leaf(1);
        let tree = MerkleTree::from_leaves(&[leaf]);
        // Root = hash(leaf || [0;32])
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.leaves(), &[leaf]);
    }

    #[test]
    fn test_deterministic_root() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| make_leaf(i)).collect();
        let tree1 = MerkleTree::from_leaves(&leaves);
        let tree2 = MerkleTree::from_leaves(&leaves);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_leaves_different_root() {
        let leaves1: Vec<[u8; 32]> = (0..4).map(|i| make_leaf(i)).collect();
        let leaves2: Vec<[u8; 32]> = (10..14).map(|i| make_leaf(i)).collect();
        let tree1 = MerkleTree::from_leaves(&leaves1);
        let tree2 = MerkleTree::from_leaves(&leaves2);
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_proof_and_verify() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| make_leaf(i)).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let root = tree.root();

        for i in 0..8 {
            let proof = tree.proof(i);
            assert!(
                MerkleTree::verify_proof(&root, &leaves[i], i, &proof, 8),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn test_proof_invalid_leaf() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| make_leaf(i)).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let root = tree.root();
        let proof = tree.proof(0);

        let fake_leaf = make_leaf(99);
        assert!(!MerkleTree::verify_proof(&root, &fake_leaf, 0, &proof, 4));
    }

    #[test]
    fn test_non_power_of_two_leaves() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| make_leaf(i)).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        assert_eq!(tree.leaf_count(), 5);

        let root = tree.root();
        for i in 0..5 {
            let proof = tree.proof(i);
            assert!(MerkleTree::verify_proof(&root, &leaves[i], i, &proof, 5));
        }
    }
}
