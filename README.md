<p align="center">
  <img src="assets/rust_box_v4.png" alt="RustBox" width="280" />
</p>

<h1 align="center">RustBox</h1>

<p align="center">
  <strong>Zero-Knowledge Encrypted File Sync</strong><br/>
  <sub>One Core, Two Clients, A Blind Server.</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust" />
  <img src="https://img.shields.io/badge/crypto-XChaCha20--Poly1305-blue?style=flat-square" alt="Crypto" />
  <img src="https://img.shields.io/badge/transport-QUIC-green?style=flat-square" alt="QUIC" />
  <img src="https://img.shields.io/badge/targets-CLI%20%7C%20WASM-purple?style=flat-square" alt="Targets" />
  <img src="https://img.shields.io/badge/tests-88%20passing-brightgreen?style=flat-square" alt="Tests" />
  <img src="https://img.shields.io/badge/status-Proof%20of%20Concept-yellow?style=flat-square" alt="Status" />
</p>

---

## Overview

RustBox is a proof of concept for a cloud storage system where **the server is blind**. It stores encrypted data and has no ability to read, decrypt, or understand the files users upload. The server knows a file exists, it knows a timestamp, it knows how many encrypted chunks make up that file. But it cannot see filenames, file contents, file types, or any meaningful metadata. Everything is encrypted client-side before it ever leaves the user's machine.

This is not "we promise we won't look at your data." This is **"we mathematically cannot, even if compelled by a court order."**

The goal was to prove that zero-knowledge encryption is practical for real file sync -- not just a theoretical exercise -- and that a single Rust codebase can power CLI and Web (WASM) clients simultaneously.

---

## One Core: The Trait Architecture

The primary engineering challenge was not encryption itself. Established algorithms exist. The real challenge was: **how do you write one Rust library that compiles to native x86/ARM and to WebAssembly, when the two targets disagree on everything?**

| | Native (CLI) | Browser (WASM) |
|---|---|---|
| **Async runtime** | Tokio, multi-threaded | Single-threaded JS event loop |
| **Thread safety** | `Send + Sync` required | `!Send` (no threads exist) |
| **Random bytes** | OS CSPRNG (`getrandom`) | `crypto.getRandomValues()` |
| **Storage** | SQLite + filesystem | IndexedDB |
| **Network** | QUIC over UDP | HTTP `fetch()` |
| **Clock** | `std::time::SystemTime` | `js_sys::Date::now()` |

The answer is **traits**. `rustbox-core` defines five traits that abstract every platform-dependent operation. The core never calls the OS, never opens a socket, never touches a filesystem. It only calls trait methods. Each client crate plugs in its own implementations.

### The Five Traits

```rust
// rustbox-core/src/traits/transport.rs
#[async_trait(?Send)]
pub trait Transport {
    async fn upload_chunk(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError>;
    async fn download_chunk(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError>;
    async fn upload_manifest(&self, data: &[u8]) -> Result<String, RustBoxError>;
    async fn download_manifest(&self, id: &str) -> Result<Vec<u8>, RustBoxError>;
    async fn get_merkle_root(&self) -> Result<[u8; 32], RustBoxError>;
    async fn get_merkle_diff(&self, local_root: &[u8; 32]) -> Result<Vec<[u8; 32]>, RustBoxError>;
}

// rustbox-core/src/traits/storage.rs
#[async_trait(?Send)]
pub trait ContentAddressableStorage {
    async fn store(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError>;
    async fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError>;
    async fn exists(&self, hash: &[u8; 32]) -> Result<bool, RustBoxError>;
    async fn list_hashes(&self) -> Result<Vec<[u8; 32]>, RustBoxError>;
    async fn delete(&self, hash: &[u8; 32]) -> Result<(), RustBoxError>;
}

#[async_trait(?Send)]
pub trait PersistentStorage {
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), RustBoxError>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, RustBoxError>;
    async fn delete(&self, key: &str) -> Result<(), RustBoxError>;
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, RustBoxError>;
}

// rustbox-core/src/traits/random.rs
pub trait SecureRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RustBoxError>;
    fn random_bytes(&self, len: usize) -> Result<Vec<u8>, RustBoxError>;
}

// rustbox-core/src/traits/clock.rs
pub trait Clock {
    fn now_secs(&self) -> Result<u64, RustBoxError>;
    fn now_millis(&self) -> Result<u64, RustBoxError>;
}
```

The critical detail is `#[async_trait(?Send)]`. Standard Rust async traits require futures to be `Send` (transferable across threads). WASM has no threads, so its futures are `!Send`. The `?Send` bound removes that requirement, allowing the same trait definition to compile under both Tokio (multi-threaded) and the browser's single-threaded event loop.

### How the CLI Implements Them

The CLI (`rustbox-cli`) runs on Tokio with full OS access. Its implementations use native system calls:

```rust
// rustbox-cli/src/platform/native_random.rs
impl SecureRandom for NativeRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RustBoxError> {
        getrandom::getrandom(dest)                 // OS CSPRNG (urandom / CryptGenRandom)
            .map_err(|e| RustBoxError::Platform(format!("getrandom failed: {e}")))
    }
}

// rustbox-cli/src/platform/native_clock.rs
impl Clock for NativeClock {
    fn now_secs(&self) -> Result<u64, RustBoxError> {
        SystemTime::now()                           // std::time::SystemTime
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| RustBoxError::Platform(format!("SystemTime error: {e}")))
    }
}
```

For transport, the CLI opens QUIC streams over UDP using `quinn`. For storage, it writes blobs as files to disk (named by hex hash) and metadata to SQLite.

| Trait | CLI Implementation | Backing System |
|---|---|---|
| `Transport` | `QuicTransport` | Quinn QUIC, UDP :4433 |
| `ContentAddressableStorage` | `LocalFsStorage` | Filesystem, one file per blob |
| `PersistentStorage` | `SqliteMeta` | SQLite database |
| `SecureRandom` | `NativeRandom` | `getrandom` (OS CSPRNG) |
| `Clock` | `NativeClock` | `std::time::SystemTime` |

### How WASM Implements Them

The WASM client (`rustbox-wasm`) runs inside a browser. There is no filesystem, no UDP, no system clock. Every implementation delegates to a browser API:

```rust
// rustbox-wasm/src/platform/wasm_random.rs
impl SecureRandom for WasmRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RustBoxError> {
        getrandom::getrandom(dest)                 // delegates to crypto.getRandomValues()
            .map_err(|e| RustBoxError::Platform(format!("getrandom failed: {}", e)))
    }
}

// rustbox-wasm/src/platform/wasm_clock.rs
impl Clock for WasmClock {
    fn now_secs(&self) -> Result<u64, RustBoxError> {
        let ms = js_sys::Date::now();              // JavaScript Date.now()
        Ok((ms / 1000.0) as u64)
    }
}
```

For transport, the WASM client uses the browser Fetch API over HTTP. For storage, it uses IndexedDB (two object stores: `"blobs"` for chunks, `"metadata"` for key-value pairs).

| Trait | WASM Implementation | Backing System |
|---|---|---|
| `Transport` | `FetchTransport` | Browser `fetch()`, HTTP :8443 |
| `ContentAddressableStorage` | `IndexedDbStorage` | IndexedDB `"blobs"` store |
| `PersistentStorage` | `IndexedDbStorage` | IndexedDB `"metadata"` store |
| `SecureRandom` | `WasmRandom` | `crypto.getRandomValues()` |
| `Clock` | `WasmClock` | `js_sys::Date::now()` |

### What the Core Never Touches

`rustbox-core` has **zero platform imports**. It never calls `std::fs`, `std::net`, `std::time`, `tokio`, `js_sys`, or `web_sys`. Every byte of randomness comes through `SecureRandom`. Every network call goes through `Transport`. Every timestamp comes from `Clock`. This is why the same 3,000 lines of crypto code compile identically to x86, ARM, and `wasm32-unknown-unknown`.

The cryptographic pipeline (PBKDF2, HKDF, XChaCha20-Poly1305, Merkle trees, chunking) is pure computation. Same inputs produce the same outputs on every platform. A file uploaded from the CLI can be downloaded and decrypted from the browser with zero compatibility issues, because both clients share the exact same core library and differ only in their trait implementations.

---

## Architecture

```
                    rustbox-core (~3,000 LOC, 88 tests)
                   /          \
          rustbox-cli     rustbox-wasm
          (~2,100 LOC)    (~2,600 LOC)
              |               |
              v               v
         Terminal        Browser (WASM)
              \               |
               \              |
           QUIC :4433    HTTP :8443
                \             |
                 v            v
                   rustbox-server (~2,000 LOC)
                          |
                   PostgreSQL 16
```

> **~9,700 lines of Rust | ~2,200 lines of JS/HTML/CSS | 88 unit tests | 4 crates**

The `rustbox-ui/` directory contains a shared HTML/CSS/JS frontend used by the WASM build (served as a static page). An adapter layer (`adapter.js`) wraps the WASM backend: calls go through `wasm-bindgen`.

---

## Cryptographic Design

### Key Hierarchy

RustBox uses a deterministic key hierarchy. Given the same username and password on any client, the exact same keys are derived. This is what makes cross-client sync work without the server ever seeing a key.

```
password + salt (32 bytes, stored on server per username)
    |
    v
PBKDF2-HMAC-SHA256 (100,000 iterations)
    |
    v
master_key (256 bits)
    |
    +---> HKDF-SHA256(master_key, "rustbox-auth")
    |         --> auth_key --> SHA256(auth_key) = server identity
    |
    +---> HKDF-SHA256(master_key, "rustbox-enc" || file_id)
    |         --> file_enc_key (unique per file)
    |               |
    |               +---> HKDF-SHA256(file_enc_key, "chunk" || index)
    |                         --> chunk_key (unique per chunk)
    |
    +---> HKDF-SHA256(master_key, "rustbox-manifest" || file_id)
              --> manifest_key (unique per file)
```

**PBKDF2** (100,000 iterations) provides brute-force resistance for the master key derivation. **HKDF-SHA256** (HMAC-based Key Derivation Function) expands the master key into purpose-specific subkeys. Each file gets its own encryption key. Each chunk within a file gets its own key derived from the file key plus the chunk index. This means no two chunks in the entire system share a key, even across files.

---

### Encryption: XChaCha20-Poly1305

All encryption uses **XChaCha20-Poly1305**, a modern AEAD (Authenticated Encryption with Associated Data) cipher.

| Data | Algorithm | Key | Nonce |
|------|-----------|-----|-------|
| File chunks | XChaCha20-Poly1305 | chunk_key (unique per chunk) | 24 bytes, random |
| File manifests | XChaCha20-Poly1305 | manifest_key (unique per file) | 24 bytes, random |
| Vault verifier | XChaCha20-Poly1305 | master_key | 24 bytes, random |

**Why XChaCha20 instead of AES-GCM?**

- **24-byte nonces** (vs AES-GCM's 12 bytes): with random nonces, the probability of collision is negligible even across billions of operations. AES-GCM's 12-byte nonce makes random generation risky at scale.
- **No hardware dependency**: XChaCha20 performs consistently on all platforms (including WASM in browsers without AES-NI).
- **Poly1305 authentication**: any tampering with ciphertext is detected on decryption. Chunk AAD (Additional Authenticated Data) includes the chunk index, preventing reordering attacks.

---

### What the Server Sees vs. What It Cannot See

| Server stores | Server cannot see |
|---------------|-------------------|
| Encrypted blob (ciphertext) | File contents |
| SHA-256(ciphertext) as blob ID | Original filename |
| Encrypted manifest envelope | File size, type, metadata |
| Timestamp of upload | Relationship between chunks |
| Number of chunks | Which chunks belong to which file |
| SHA-256(auth_key) for identity | Password, master key, any key |

The server is a **content-addressable blob store** that speaks a binary protocol. It has zero imports from the crypto modules. It cannot decrypt anything even with full database access.

---

### Cross-Client Identity

The first client to log in with a username generates a random 32-byte salt and registers it on the server along with `SHA256(auth_key)` as a public identity. Subsequent clients for the same username fetch this salt, derive the same master key from the same password, and produce the same identity hash:

```
Client A (first login):
  1. GET salt("alice")  --> not found
  2. Generate random 32-byte salt
  3. master_key = PBKDF2(password, salt, 100K)
  4. Register: { username, salt, SHA256(HKDF(master_key, "rustbox-auth")) }
  5. Server stores salt + identity hash, returns user_id

Client B (any other client, same user):
  1. GET salt("alice")  --> returns stored salt
  2. master_key = PBKDF2(password, stored_salt, 100K)   [identical key]
  3. Register: { username, SHA256(HKDF(master_key, "rustbox-auth")) }
  4. Server verifies identity matches, returns same user_id
```

No password or key ever leaves the client. The server stores only the salt (public, not secret) and a hash of a derived auth key (one-way, cannot be reversed).

---

## The CRISP Protocol

`rustbox-core` includes an implementation of the **CRISP** (Crypto Record Interchange Security Protocol) -- a custom protocol inspired by TLS 1.3, designed for lightweight secure channels.

### What CRISP Provides

CRISP implements a handshake and record protocol using:

- **P-256 ECDH** (Elliptic Curve Diffie-Hellman) for key exchange
- **AES-128-GCM** for record encryption
- **HKDF-SHA256** for key derivation
- **PSK (Pre-Shared Key) resumption** for fast reconnections

The handshake flow mirrors TLS 1.3:

```
Client                              Server
  |                                    |
  |--- ClientHello (ECDH pubkey) ---->|
  |                                    |
  |<-- ServerHello (ECDH pubkey) -----|
  |<-- EncryptedExtensions -----------|
  |<-- Finished (HMAC) ---------------|
  |                                    |
  |--- Finished (HMAC) -------------->|
  |                                    |
  [symmetric keys established]
  |                                    |
  |=== Application Data (AES-GCM) ===>|
  |<=== Application Data (AES-GCM) ===|
```

After the initial handshake, a **PSK ticket** is issued. Subsequent connections use **short-link mode** (0-RTT style) that skips the full ECDH exchange and derives session keys from the PSK, dramatically reducing latency.

### How CRISP Relates to RustBox Transport

RustBox's QUIC transport (CLI) relies on **QUIC's built-in TLS 1.3** for transport encryption. The CRISP protocol in `rustbox-core` provides an **application-layer security option** -- it can establish encrypted channels independently of the transport layer, useful when QUIC/TLS is not available or when an additional encryption layer is desired.

The CRISP code shares the same HKDF, ECDH, and key derivation infrastructure used by the file encryption pipeline, demonstrating the versatility of the core library.

---

## Transport Layer

### QUIC Binary Protocol (CLI)

The CLI client communicates with the server over **QUIC** (RFC 9000) using the `quinn` crate. QUIC provides:

1. **Built-in TLS 1.3 encryption** -- every stream is encrypted
2. **Multiplexed streams** -- multiple uploads/downloads in parallel, no head-of-line blocking
3. **0-RTT reconnection** -- subsequent connections complete in zero round-trips
4. **UDP-based** -- lower latency than TCP, works through NATs

Each command opens a bidirectional QUIC stream with a compact binary protocol:

```
Request:  [cmd: 1 byte] [payload_len: 4 bytes BE] [payload]
Response: [status: 1 byte] [payload_len: 4 bytes BE] [payload]
```

| Command | Code | Description |
|---------|------|-------------|
| UPLOAD_CHUNK | 0x01 | Store encrypted blob by SHA-256 hash |
| DOWNLOAD_CHUNK | 0x02 | Retrieve blob by hash |
| UPLOAD_MANIFEST | 0x03 | Store encrypted manifest envelope |
| DOWNLOAD_MANIFEST | 0x04 | Retrieve manifest by UUID |
| GET_ROOT | 0x05 | Get user's Merkle root (32 bytes) |
| GET_DIFF | 0x06 | Compare Merkle trees for sync |
| REGISTER | 0x10 | Register/login with username + salt + auth hash |
| GET_SALT | 0x11 | Fetch per-username salt |
| LIST_MANIFESTS | 0x12 | List all manifests for a user |
| DELETE_MANIFEST | 0x13 | Delete a manifest |
| DB_OVERVIEW | 0x14 | Get storage statistics |

### HTTP REST API (WASM / Browser)

Browsers cannot open raw QUIC connections (yet). The WASM client uses standard HTTP `fetch()` against the server's Axum REST API on port 8443. The endpoints mirror the QUIC commands:

- `POST /api/auth/register`, `GET /api/auth/salt/:username`
- `POST /api/blobs`, `GET /api/blobs/:hash`
- `POST /api/manifests`, `GET /api/manifests/:id`, `DELETE /api/manifests/:id`
- `GET /api/manifests` (list), `GET /api/db/overview`

Both transports share the same PostgreSQL backend. The protocol is just a delivery mechanism -- the encrypted payloads are identical regardless of transport.

### Future: WebTransport

WebTransport (W3C spec, supported in Chrome 97+, Firefox 114+) will enable browsers to open QUIC connections directly. When adopted:

1. The Web client switches from HTTP fetch to WebTransport QUIC
2. Both clients use the same binary protocol
3. The HTTP API layer can be removed entirely
4. Single port deployment (4433 only)

---

## File Upload / Download Pipeline

### Upload

```
1. Read file, split into 1 MB chunks
2. For each chunk[i]:
   a. chunk_key = HKDF(file_enc_key, "chunk", i)
   b. nonce = random 24 bytes
   c. ciphertext = XChaCha20-Poly1305(chunk_key, nonce, plaintext, AAD=i)
   d. blob_id = SHA256(ciphertext)           [content-addressable]
   e. Upload (blob_id, ciphertext) to server
3. Build Merkle tree from blob hashes
4. Build FileManifest { filename, size, chunks[], merkle_root }
5. Serialize with bincode, encrypt with manifest_key
6. Envelope: [nonce 24B | file_id_len 4B BE | file_id UTF-8 | ciphertext]
7. Upload encrypted manifest to server
```

### Download

```
1. Download encrypted manifest by ID
2. Parse envelope, derive manifest_key, decrypt, deserialize
3. For each ChunkEntry in manifest:
   a. Download blob by hash
   b. Derive chunk_key from file_enc_key + index
   c. Decrypt with stored nonce
   d. Verify: SHA256(downloaded_ciphertext) == expected hash
4. Concatenate plaintext chunks -> original file
```

---

## Content-Addressable Storage and Merkle Sync

Blobs are stored by their **SHA-256 hash** (of the ciphertext). This provides:

1. **Deduplication**: identical encrypted chunks stored only once
2. **Integrity verification**: any blob can be verified by recomputing its hash
3. **Efficient sync**: the Merkle tree root is a single 32-byte fingerprint for all user data

The sync algorithm is simple:

```
1. Client computes local Merkle root from local blob hashes
2. Server returns its Merkle root for the user
3. If roots match -> fully synced, done
4. If roots differ -> server returns list of leaf hashes
5. Client computes: to_upload = local - remote, to_download = remote - local
6. Transfer only the missing blobs
```

This avoids downloading or re-uploading anything that already exists on both sides.

---

## AWS Cost Analysis

A zero-knowledge architecture is not just more secure -- it is **cheaper to operate**. The server does zero encryption. No CPU cycles spent on crypto. All cryptographic work is offloaded to clients. Server compute is dominated by network I/O and simple database queries.

### Per-User Monthly Cost (5 GB stored, 2 GB transfer)

| Component | Unit Cost | Per User |
|-----------|-----------|----------|
| S3 Standard storage | $0.023/GB/month | $0.115 |
| S3 PUT requests | $0.005/1000 | $0.025 |
| S3 GET requests | $0.0004/1000 | $0.004 |
| Data transfer out | $0.09/GB (first 10 TB) | $0.180 |
| **Storage subtotal** | | **$0.324** |

### Compute (Shared)

| Users | Instance | Monthly Cost | Per User |
|-------|----------|-------------|----------|
| 10,000 | c6g.xlarge | $98 | $0.0098 |
| 50,000 | c6g.2xlarge | $196 | $0.0039 |
| 1,000,000 | 4x c6g.4xlarge | $1,568 | $0.0016 |

QUIC multiplexing means a single server handles thousands of concurrent connections. No encryption CPU overhead on the server side.

### Total Cost at Scale

| Scale | Storage | Compute | DB (RDS) | Total | vs Dropbox ($11.99) |
|-------|---------|---------|----------|-------|---------------------|
| 10K users | $0.324 | $0.010 | $0.036 | **$0.37/user** | 97% cheaper |
| 50K users | $0.324 | $0.004 | $0.014 | **$0.34/user** | 97% cheaper |
| 1M users | $0.324 | $0.002 | $0.004 | **$0.33/user** | 97% cheaper |

### Revenue Model at $3.99/month

| Scale | Revenue/month | AWS Cost/month | Gross Margin |
|-------|--------------|----------------|-------------|
| 10K users | $39,900 | $3,700 | 90.7% |
| 50K users | $199,500 | $17,000 | 91.5% |
| 1M users | $3,990,000 | $330,000 | 91.7% |

At scale, cost is dominated by storage and data transfer. Compute is negligible because the server does no encryption.

---

## Performance

Measured on localhost with the QUIC transport:

| Operation | File Size | Time | Throughput |
|-----------|----------|------|------------|
| Upload (encrypt + chunk + send) | 309 MB | ~7 sec | ~44 MB/s |
| Download (recv + decrypt + reassemble) | 309 MB | ~4 sec | ~75 MB/s |
| Chunk encryption | 1 MB | <1 ms | >1 GB/s |
| PBKDF2 key derivation | -- | ~200 ms | -- |

---

## Getting Started

### Prerequisites

```
Rust 1.75+
PostgreSQL 16 (via Docker)
wasm-pack (for Web build)
```

### Quick Start

```bash
# Start everything (PostgreSQL + Server + Web UI)
./test/start-dev.sh

# Open Web UI
open http://localhost:8080/serve.html

# Test CLI (single-user)
./test/test-cli.sh

# Test CLI (multi-user isolation)
./test/test-cli.sh sync

# Stop everything
./test/stop-dev.sh
```

### CLI Usage

After `./test/start-dev.sh`, the `rustbox` binary is available at the project root:

```bash
# Login (creates vault + registers with server)
RUSTBOX_USERNAME=user01 RUSTBOX_PASSWORD=password \
  ./rustbox login --server 127.0.0.1:4433

# Upload a file (--server not needed after login, stored automatically)
RUSTBOX_PASSWORD=password ./rustbox upload photo.png

# List all files on server
RUSTBOX_PASSWORD=password ./rustbox files

# Download a file by manifest ID
RUSTBOX_PASSWORD=password ./rustbox download <manifest-id> output.png

# Delete a file by manifest ID
RUSTBOX_PASSWORD=password ./rustbox delete <manifest-id>
RUSTBOX_PASSWORD=password ./rustbox delete <manifest-id> --yes   # skip confirm

# Sync (Merkle-based)
RUSTBOX_PASSWORD=password ./rustbox sync

# Show vault status
./rustbox status
```

### Default Test Credentials

```
Username: user01
Password: password
Server:   127.0.0.1:4433
```

---

## Project Structure

```
rust-box/
    rustbox-core/              Shared cryptographic core (88 tests)
        src/
            crypto/            PBKDF2, HKDF, XChaCha20-Poly1305, key hierarchy
            chunking/          1 MB splitter, encrypt/decrypt pipeline
            merkle/            SHA-256 Merkle tree with inclusion proofs
            manifest/          FileManifest + ChunkEntry (bincode serialization)
            sync/              Diff engine (compare Merkle roots)
            crisp/             CRISP protocol (ECDH, AES-GCM, PSK)
            traits/            Transport, Storage, Clock, SecureRandom
    rustbox-server/            Axum HTTP + Quinn QUIC server
        src/
            api/               REST endpoints
            quic/              Binary protocol handler (11 commands)
            db/                PostgreSQL queries
    rustbox-cli/               Terminal client (clap, QUIC, SQLite)
    rustbox-wasm/              WebAssembly client (wasm-bindgen, fetch, IndexedDB)
    rustbox-ui/                Shared HTML/CSS/JS frontend
        js/
            adapter.js         WASM backend adapter
            app.js             Application state machine
            auth.js            Login flow + session persistence
            file-manager.js    Upload, download, delete UI
            auto-sync.js       4-second manifest polling
            database.js        Server storage inspector
    docs/                      Technical documentation
        architecture.md        Crate layout, traits, data flow
        cryptography.md        Key hierarchy, ciphers, HKDF labels
        crisp-protocol.md      Handshake, PSK, record format
        sync-engine.md         Merkle trees, chunking, manifests
        transport.md           QUIC protocol, HTTP API, dispatch
    test/
        start-dev.sh           Launch all services
        stop-dev.sh            Stop all services
        test-cli.sh            Integration tests
    migrations/                PostgreSQL schema
    docker-compose.yml         PostgreSQL 16 container
```

---

## What This Proves

1. **Zero-knowledge encryption is practical for file sync**, not just theoretical. Files are uploaded, synced, and downloaded across different client types with full encryption.

2. **A single Rust core can target CLI and WebAssembly simultaneously.** The same 3,000 lines of crypto code compile to x86, ARM, and WASM with zero platform-specific branches.

3. **QUIC provides real advantages over HTTP** for file transfer: multiplexed streams, lower overhead, 0-RTT reconnection, and native UDP efficiency.

4. **A blind server is cheaper to run.** Zero encryption on the server side means near-zero CPU cost. At scale, the per-user cost is ~$0.33/month with 91%+ gross margin at $3.99 pricing.

5. **Content-addressable storage with Merkle trees** enables efficient sync without trusting the server. Only missing chunks are transferred.

6. **The CRISP protocol demonstrates** that custom secure channel establishment (ECDH + AES-GCM + PSK resumption) can be implemented alongside standard QUIC/TLS in a shared core library.

---

<sub>This is a proof of concept, not production software. It lacks features like file versioning, sharing, folder sync, conflict resolution, rate limiting, and proper certificate management. But the cryptographic foundation is sound, the cross-client architecture works, and the performance is more than adequate for a real product.</sub>
