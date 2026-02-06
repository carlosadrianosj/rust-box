# Sync Engine

The sync engine keeps a user's file collection consistent across multiple
clients and the server. It relies on SHA-256 Merkle trees to detect differences
and content-addressable storage to deduplicate blob transfers.

## Merkle Tree

Each uploaded blob has a SHA-256 hash (computed over the ciphertext, not the
plaintext). These hashes become the leaves of a Merkle tree:

```
                   root = H(H01 || H23)
                  /                      \
        H01 = H(L0 || L1)       H23 = H(L2 || L3)
        /           \            /           \
      L0            L1         L2            L3
  SHA256(blob0) SHA256(blob1) SHA256(blob2) SHA256(blob3)
```

If the leaf count is not a power of two, the tree is padded with zero-hashes.

### Construction

From `rustbox-core/src/merkle/tree.rs`:

```rust
pub fn from_leaves(leaves: &[[u8; 32]]) -> Self {
    let leaf_count = leaves.len();
    let padded_count = leaf_count.next_power_of_two();
    let total_nodes = 2 * padded_count - 1;

    let mut nodes = vec![[0u8; 32]; total_nodes];

    // Fill leaf layer
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
```

The tree is stored as a flat array using the standard binary heap layout:

```
Index:     0     1     2     3     4     5     6
Node:    root   H01   H23   L0    L1    L2    L3
```

Parent of node `i` is at `(i - 1) / 2`. Children of node `i` are at
`2*i + 1` (left) and `2*i + 2` (right).

### Inclusion Proofs

A client can prove that a specific blob belongs to the tree by providing the
sibling hashes along the path from the leaf to the root:

```
To prove L2 is in the tree:

                   root = H(H01 || H23)
                  /                      \
        [H01]                    H23 = H(L2 || [L3])
                                 /
                               L2 (target)

Proof: [L3, H01]

Verifier computes:
  step 1: H23 = H(L2 || L3)
  step 2: root' = H(H01 || H23)
  accept if root' == root
```

From the code:

```rust
pub fn verify_proof(
    root: &[u8; 32],
    leaf: &[u8; 32],
    leaf_index: usize,
    proof: &[[u8; 32]],
    total_leaves: usize,
) -> bool {
    let mut hash = *leaf;
    let mut idx = padded - 1 + leaf_index;
    for sibling_hash in proof {
        if idx % 2 == 1 {
            hash = hash_pair(&hash, sibling_hash);
        } else {
            hash = hash_pair(sibling_hash, &hash);
        }
        idx = (idx - 1) / 2;
    }
    hash == *root
}
```

## Diff Computation

The sync engine computes the difference between local and remote leaf sets
to produce a `SyncPlan`:

```rust
pub struct SyncPlan {
    pub to_upload: Vec<[u8; 32]>,    // local only (not on server)
    pub to_download: Vec<[u8; 32]>,  // remote only (not on client)
}
```

From `rustbox-core/src/sync/engine.rs`:

```rust
pub fn compute_sync_plan(
    local_leaves: &[[u8; 32]],
    remote_leaves: &[[u8; 32]],
) -> SyncPlan {
    SyncPlan {
        to_upload: compute_extra_hashes(local_leaves, remote_leaves),
        to_download: compute_missing_hashes(local_leaves, remote_leaves),
    }
}
```

The `compute_extra_hashes` and `compute_missing_hashes` functions perform set
differences using hash lookups.

### Sync Scenarios

```
Scenario 1: Client has new files
  Local:  [A, B, C, D]
  Remote: [A, B]
  Plan:   upload [C, D], download []

Scenario 2: Another client uploaded files
  Local:  [A, B]
  Remote: [A, B, C, D]
  Plan:   upload [], download [C, D]

Scenario 3: Both sides have changes
  Local:  [A, B, C]
  Remote: [B, C, D]
  Plan:   upload [A], download [D]

Scenario 4: Already in sync
  Local:  [A, B, C]
  Remote: [A, B, C]
  Plan:   upload [], download [] (is_synced = true)
```

## Content-Addressable Storage

Blobs are stored using their SHA-256 hash as the key:

```
blob_hash = SHA256(ciphertext_bytes)
```

This provides natural deduplication: if two files share identical chunks, only
one copy of each chunk is stored. The hash also serves as an integrity check;
if a blob is corrupted, its hash will not match.

The `ContentAddressableStorage` trait defines the interface:

```rust
#[async_trait(?Send)]
pub trait ContentAddressableStorage {
    async fn store(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError>;
    async fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError>;
    async fn exists(&self, hash: &[u8; 32]) -> Result<bool, RustBoxError>;
    async fn list_hashes(&self) -> Result<Vec<[u8; 32]>, RustBoxError>;
    async fn delete(&self, hash: &[u8; 32]) -> Result<(), RustBoxError>;
}
```

| Client | Implementation     | Backing Store        |
|--------|--------------------|----------------------|
| CLI    | Filesystem blobs   | Files named by hex hash |
| WASM   | IndexedDB          | Object store keyed by hash |
| Server | PostgreSQL         | `blobs` table, BYTEA column |

## Manifest System

RustBox uses two manifest types to track file metadata:

### FileManifest

Describes a single file and its encrypted chunks:

```rust
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

pub struct ChunkEntry {
    pub index: u32,
    pub hash: [u8; 32],         // SHA256 of ciphertext
    pub nonce: [u8; 24],        // XChaCha20 nonce used
    pub encrypted_size: u32,
    pub plaintext_size: u32,
}
```

The manifest is serialized with bincode and encrypted with XChaCha20-Poly1305
using the per-file manifest key. The encrypted envelope format:

```
+--------+----------------+-------------------+-----------------+
| Nonce  | file_id length | file_id (UTF-8)   | ciphertext      |
| 24B    | 4B (BE)        | variable          | variable        |
+--------+----------------+-------------------+-----------------+
```

The `file_id` is in cleartext in the envelope header so the server can index
manifests, but the filename, chunk list, and all other metadata are encrypted.

### SyncManifest

Per-user index of all synced files:

```rust
pub struct SyncManifest {
    pub user_id: String,
    pub files: Vec<FileReference>,
    pub merkle_root: [u8; 32],
    pub version: u64,
    pub last_sync_at: u64,
}

pub struct FileReference {
    pub file_id: String,
    pub filename: String,
    pub manifest_id: String,
    pub merkle_leaf: [u8; 32],
    pub modified_at: u64,
}
```

The sync manifest is also encrypted and stored on the server. It enables a
client to enumerate all files without downloading every individual manifest.

## Full Sync Flow

```
[1] Client logs in, fetches salt, derives master_key
         |
         v
[2] Client lists local blob hashes -> build local Merkle tree
         |
         v
[3] Client calls get_merkle_root() on server
         |
         v
[4] Compare roots
         |
    +----+----+
    |         |
  equal    different
    |         |
    v         v
  done    [5] Client calls get_merkle_diff(local_root)
               |
               v
          [6] Server returns remote leaf hashes
               |
               v
          [7] compute_sync_plan(local_leaves, remote_leaves)
               |
               v
          [8] Upload to_upload blobs + manifests
               |
               v
          [9] Download to_download blobs + manifests
               |
               v
         [10] Rebuild Merkle tree, verify roots match
               |
               v
             done
```

## Chunking

Files are split into fixed 1 MB chunks before encryption:

```rust
pub fn split_into_chunks(data: &[u8]) -> Vec<RawChunk> {
    data.chunks(CHUNK_SIZE)   // 1,048,576 bytes
        .enumerate()
        .map(|(i, chunk)| RawChunk { index: i as u32, data: chunk.to_vec() })
        .collect()
}
```

The last chunk may be smaller than 1 MB. Each chunk is encrypted independently
with its own derived key and random nonce, producing a self-contained blob.

### Example: 3.5 MB File

```
Original file: 3,670,016 bytes (3.5 MB)

Chunk 0: bytes [       0 .. 1,048,575]  -> 1,048,576 B
Chunk 1: bytes [1,048,576 .. 2,097,151]  -> 1,048,576 B
Chunk 2: bytes [2,097,152 .. 3,145,727]  -> 1,048,576 B
Chunk 3: bytes [3,145,728 .. 3,670,015]  ->   524,288 B

Each chunk encrypted independently:
  chunk_key[i]  = HKDF(file_enc_key, "chunk" || i)
  nonce[i]      = random 24 bytes
  ciphertext[i] = XChaCha20-Poly1305(chunk_key[i], nonce[i], chunk_data[i])
  blob_hash[i]  = SHA256(ciphertext[i])
```
