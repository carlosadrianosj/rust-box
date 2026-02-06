# Cryptography

RustBox uses a layered cryptographic design. Password-based key derivation
produces a master key. HKDF expands the master key into per-file and per-chunk
keys. File content is encrypted with XChaCha20-Poly1305. The CRISP transport
protocol uses AES-128-GCM. All primitives come from audited Rust crates.

## Key Hierarchy

```
password (user input) + salt (server-stored, 32 bytes)
    |
    v
PBKDF2-HMAC-SHA256 (100,000 iterations)
    |
    v
master_key (32 bytes)
    |
    +---> HKDF-Extract([], master_key)
    |         |
    |         +---> HKDF-Expand(prk, "rustbox-enc" || file_id, 32)
    |         |         |
    |         |         v
    |         |     file_enc_key (32 bytes)
    |         |         |
    |         |         +---> HKDF-Expand(file_enc_key, "chunk" || index_be32, 32)
    |         |                   |
    |         |                   v
    |         |               chunk_key[i] (32 bytes)
    |         |
    |         +---> HKDF-Expand(prk, "rustbox-manifest" || file_id, 32)
    |         |         |
    |         |         v
    |         |     manifest_key (32 bytes)
    |         |
    |         +---> HKDF-Expand(prk, "rustbox-auth", 32)
    |                   |
    |                   v
    |               auth_key (32 bytes)
    |
    v
(used for vault verification)
```

### Code Example: Deriving a Chunk Key

From `rustbox-core/src/crypto/key_hierarchy.rs`:

```rust
pub fn derive_file_enc_key(master_key: &[u8; 32], file_id: &str) -> Result<[u8; 32]> {
    let prk = hkdf_extract(&[], master_key);
    let mut info = Vec::new();
    info.extend_from_slice(LABEL_RUSTBOX_ENC.as_bytes());  // "rustbox-enc"
    info.extend_from_slice(file_id.as_bytes());
    let expanded = hkdf_expand(&prk, &info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&expanded);
    Ok(key)
}

pub fn derive_chunk_key(file_enc_key: &[u8; 32], chunk_index: u32) -> Result<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(LABEL_RUSTBOX_CHUNK.as_bytes()); // "chunk"
    info.extend_from_slice(&chunk_index.to_be_bytes());
    let expanded = hkdf_expand(file_enc_key, &info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&expanded);
    Ok(key)
}
```

The chain is deterministic: the same password, salt, file_id, and chunk index
always produce the same chunk key on any client.

## PBKDF2

**Purpose:** Slow password stretching to resist brute-force attacks.

| Parameter  | Value              |
|------------|--------------------|
| Algorithm  | PBKDF2-HMAC-SHA256 |
| Iterations | 100,000            |
| Salt       | 32 bytes (server)  |
| Output     | 32 bytes           |

From `rustbox-core/src/crypto/pbkdf2.rs`:

```rust
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; MASTER_KEY_LEN]> {
    if salt.len() < PBKDF2_SALT_LEN {
        return Err(CryptoError::Pbkdf2Derive(/* ... */));
    }
    let mut output = [0u8; MASTER_KEY_LEN];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut output)?;
    Ok(output)
}
```

The salt is generated once at registration and stored server-side. Every client
fetches it before deriving keys. This ensures cross-client key agreement.

## HKDF-SHA256

**Purpose:** Expand a master key into multiple domain-separated subkeys.

RustBox uses HKDF in two steps:

1. **Extract:** `prk = HMAC-SHA256(salt=[], ikm=master_key)` collapses the
   master key into a pseudorandom key.

2. **Expand:** `okm = HKDF-Expand(prk, info, length)` produces output keying
   material. The `info` parameter acts as a domain separator.

### HKDF Labels

| Constant                       | Label String                      | Purpose                     |
|--------------------------------|-----------------------------------|-----------------------------|
| LABEL_RUSTBOX_ENC              | "rustbox-enc"                     | Per-file encryption key     |
| LABEL_RUSTBOX_MANIFEST         | "rustbox-manifest"                | Per-file manifest key       |
| LABEL_RUSTBOX_AUTH             | "rustbox-auth"                    | Authentication key          |
| LABEL_RUSTBOX_CHUNK            | "chunk"                           | Per-chunk key               |
| LABEL_HANDSHAKE_KEY_EXPANSION  | "handshake key expansion"         | CRISP handshake keys        |
| LABEL_EARLY_DATA_KEY_EXPANSION | "early data key expansion"        | CRISP short-link keys       |
| LABEL_PSK_ACCESS               | "PSK_ACCESS"                      | PSK session access key      |
| LABEL_PSK_REFRESH              | "PSK_REFRESH"                     | PSK ticket rotation key     |
| LABEL_SERVER_FINISHED          | "server finished"                 | Server Finished HMAC key    |
| LABEL_CLIENT_FINISHED          | "client finished"                 | Client Finished HMAC key    |
| LABEL_EXPANDED_SECRET          | "expanded secret"                 | Key material expansion      |
| LABEL_APP_DATA_KEY_EXPANSION   | "application data key expansion"  | Application data keys       |

## XChaCha20-Poly1305

**Purpose:** Encrypt file chunks (client-side, AEAD).

| Parameter    | Value               |
|--------------|---------------------|
| Key size     | 32 bytes            |
| Nonce size   | 24 bytes            |
| Auth tag     | 16 bytes (appended) |

XChaCha20-Poly1305 was chosen for file encryption because the 24-byte nonce
eliminates collision risk when nonces are generated randomly. AES-GCM's 12-byte
nonce limits safe random usage to approximately 2^32 messages per key, which is
insufficient for a file sync system that may process millions of chunks.

From `rustbox-core/src/crypto/chacha20.rs`:

```rust
pub fn xchacha20_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);
    let payload = Payload { msg: plaintext, aad };
    cipher.encrypt(xnonce, payload)
        .map_err(|e| CryptoError::ChaCha20Encrypt(e.to_string()))
}
```

## AES-128-GCM

**Purpose:** Encrypt CRISP protocol records (transport layer).

| Parameter    | Value                        |
|--------------|------------------------------|
| Key size     | 16 bytes                     |
| Nonce size   | 12 bytes (computed per-record)|
| Auth tag     | 16 bytes (appended)          |

The nonce is computed deterministically from a base nonce and a per-direction
sequence counter:

```
computed_nonce[i] = base_nonce XOR pad_left(sequence_number, 12)
```

This construction is safe because each (key, sequence) pair is unique within a
session, and keys are rotated on every handshake.

## P-256 ECDH

**Purpose:** Key agreement during the CRISP handshake.

The client generates an ephemeral P-256 key pair and sends the public key in
the ClientHello. The server generates its own ephemeral key pair and responds
with its public key in the ServerHello. Both sides compute:

```
shared_secret = ECDH(own_private, peer_public)
```

The shared secret is hashed and fed into HKDF to derive session keys. Neither
side transmits the shared secret; it exists only in memory.

## P-256 ECDSA

**Purpose:** Server identity verification during the CRISP handshake.

The server signs its handshake transcript with a long-lived ECDSA key. The
client verifies the signature against the server's known public key. This
prevents man-in-the-middle attacks by binding the handshake to a specific server
identity.

## Vault Verification

At vault initialization, the client encrypts a known constant
(`RUSTBOX_VAULT_OK`, 16 bytes) with XChaCha20-Poly1305 using the master key.
On subsequent logins, it decrypts this blob. If decryption succeeds and the
plaintext matches the constant, the password is correct. This avoids storing
any password hash.

## Crate Dependencies

| Algorithm              | Crate                  | Version |
|------------------------|------------------------|---------|
| AES-128-GCM            | aes-gcm                | 0.10    |
| XChaCha20-Poly1305     | chacha20poly1305       | 0.10    |
| HKDF-SHA256            | hkdf + sha2            | 0.12    |
| PBKDF2-HMAC-SHA256     | pbkdf2 + hmac + sha2   | 0.12    |
| P-256 ECDH             | p256 + elliptic-curve  | 0.13    |
| P-256 ECDSA            | p256 + ecdsa           | 0.16    |
| SHA-256                | sha2                   | 0.10    |
| Bincode serialization  | bincode                | 1.x     |
