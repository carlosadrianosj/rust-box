# Architecture

RustBox is a zero-knowledge encrypted file sync system built in Rust. The server
never sees plaintext. All encryption, key derivation, chunking, and manifest
management happen on the client.

## Crate Layout

```
rustbox-core        Platform-independent crypto, traits, sync engine
rustbox-cli         Native CLI client (Tokio, QUIC, SQLite, filesystem)
rustbox-wasm        Browser client (wasm-bindgen, fetch, IndexedDB)
rustbox-server      Axum HTTP + Quinn QUIC server, PostgreSQL backend
```

The dependency graph flows in one direction:

```
                      rustbox-core
                     /             \
               rustbox-cli      rustbox-wasm
                     \             /
                      rustbox-server
```

Both clients depend on `rustbox-core`. The server is independent: it never
imports encryption functions, only stores and retrieves opaque blobs.

## Trait Abstraction

The core crate defines four async traits that decouple business logic from
platform specifics. Every trait uses `#[async_trait(?Send)]` so it compiles
under both Tokio (native, multi-threaded) and single-threaded WASM runtimes.

```
+---------------------+   +-----------------------------+
|     Transport       |   | ContentAddressableStorage   |
+---------------------+   +-----------------------------+
| upload_chunk()      |   | store(hash, data)           |
| download_chunk()    |   | get(hash)                   |
| upload_manifest()   |   | exists(hash)                |
| download_manifest() |   | list_hashes()               |
| get_merkle_root()   |   | delete(hash)                |
| get_merkle_diff()   |   +-----------------------------+
+---------------------+
                           +-----------------------------+
+---------------------+   | PersistentStorage           |
|    SecureRandom     |   +-----------------------------+
+---------------------+   | set(key, value)             |
| fill_bytes()        |   | get(key)                    |
| random_bytes()      |   | delete(key)                 |
+---------------------+   | list_keys(prefix)           |
                           +-----------------------------+
+---------------------+
|       Clock         |
+---------------------+
| now_secs()          |
| now_millis()        |
+---------------------+
```

### Implementations by Client

| Trait                      | CLI                  | WASM                  |
|----------------------------|----------------------|-----------------------|
| Transport                  | QUIC (quinn)         | HTTP fetch()          |
| ContentAddressableStorage  | Filesystem blobs     | IndexedDB             |
| PersistentStorage          | SQLite               | IndexedDB             |
| SecureRandom               | OsRng                | crypto.getRandomValues|
| Clock                      | SystemTime           | Date.now()            |

## Server Architecture

The server exposes two listeners on separate ports:

```
+-------------------------------------------------------+
|                   rustbox-server                       |
|                                                        |
|   :8443  Axum HTTP REST API                            |
|          POST /register, POST /login                   |
|          POST /upload/chunk, GET /download/chunk/:hash |
|          POST /upload/manifest, GET /manifest/:id      |
|          GET /merkle/root, POST /merkle/diff           |
|          GET /manifests (list), DELETE /manifest/:id    |
|          GET /status, GET /health                       |
|                                                        |
|   :4433  Quinn QUIC Binary Protocol                    |
|          Binary-framed requests over QUIC streams      |
|          Same operations, lower overhead               |
|                                                        |
|   PostgreSQL 16                                        |
|          users, salts, blobs, manifests, merkle_nodes  |
+-------------------------------------------------------+
```

The HTTP API serves the WASM client (browser fetch). The QUIC protocol serves
the CLI for bulk transfers with lower overhead and multiplexed streams.

## Zero-Knowledge Guarantee

The server stores:

1. **Opaque ciphertext blobs** keyed by SHA-256 hash
2. **Encrypted manifest envelopes** (XChaCha20-Poly1305)
3. **Merkle tree nodes** (hashes of hashes)
4. **Per-user salt** (PBKDF2, generated server-side)
5. **Auth tokens** (derived from master key, not the password itself)

The server never stores, receives, or derives:

- Plaintext file content
- Filenames (inside encrypted manifests)
- Master keys or file encryption keys
- User passwords

Even if the server database is fully compromised, an attacker obtains only
ciphertext and hashes. Without the user's password, no key can be reconstructed.

## Data Flow: Upload

```
User file (plaintext)
    |
    v
[1] Split into 1 MB chunks
    |
    v
[2] For each chunk i:
      chunk_key = HKDF(file_enc_key, "chunk" || i)
      nonce     = random 24 bytes
      ciphertext = XChaCha20-Poly1305(chunk_key, nonce, chunk_data)
      blob_hash  = SHA-256(ciphertext)
    |
    v
[3] Upload each blob (keyed by blob_hash)
    |
    v
[4] Build FileManifest (file_id, filename, chunk list with hashes/nonces)
    |
    v
[5] Serialize manifest (bincode), encrypt with manifest_key
      envelope = [nonce (24B) | file_id_len (4B BE) | file_id (UTF-8) | ciphertext]
    |
    v
[6] Upload encrypted manifest envelope
    |
    v
[7] Update SyncManifest: add FileReference, recompute Merkle root
```

## Data Flow: Download

```
[1] Fetch manifest envelope by ID from server
    |
    v
[2] Decrypt envelope with manifest_key -> FileManifest
    |
    v
[3] For each ChunkEntry in manifest:
      Download blob by hash
      Derive chunk_key from file_enc_key + index
      Decrypt with XChaCha20-Poly1305 using stored nonce
    |
    v
[4] Reassemble chunks in order -> original file
```

## Data Flow: Sync

```
[1] Client builds local Merkle tree from stored blob hashes
    |
    v
[2] Compare local Merkle root with server Merkle root
    |
    v
[3] If roots differ:
      Fetch remote leaf hashes via get_merkle_diff()
      Compute SyncPlan:
        to_upload   = local hashes not in remote set
        to_download = remote hashes not in local set
    |
    v
[4] Execute plan:
      Upload missing blobs + manifests
      Download missing blobs + manifests
    |
    v
[5] Verify: rebuild Merkle tree, confirm roots match
```

## Cross-Client Identity

Both CLI and WASM clients produce identical ciphertext for the same file and
password. This is guaranteed by:

1. **Server-stored salt**: the server generates and stores a unique 32-byte salt
   per username at registration. All clients fetch this salt before key derivation.

2. **Deterministic key hierarchy**: `PBKDF2(password, salt)` always produces the
   same master key. `HKDF(master_key, label || file_id)` always produces the same
   file key. The chain is fully deterministic given the same inputs.

3. **Shared core crate**: both clients link against `rustbox-core`, which contains
   all crypto and manifest logic. There is no duplicated implementation.

A file uploaded from the CLI can be downloaded from the browser and vice versa,
because both clients derive identical keys and produce identical manifest formats.
