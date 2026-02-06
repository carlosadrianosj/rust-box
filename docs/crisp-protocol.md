# CRISP Protocol

CRISP (Crypto Record Interchange Security Protocol) is a custom TLS 1.3-inspired
binary protocol used for transport security between RustBox clients and the
server. It provides confidentiality, integrity, and server authentication over
any reliable byte stream.

## Overview

CRISP operates in two modes:

1. **Full Handshake**: Ephemeral ECDH key agreement, ECDSA server verification,
   session key derivation, and session ticket issuance.

2. **Short-Link (PSK Resumption)**: Reuses a previously negotiated PSK to
   encrypt requests without a new ECDH exchange. Reduces round trips from 2
   to 1.

## Record Format

Every CRISP message is framed as one or more records:

```
+------+----------+----------+-------------------+
| Type | Version  |  Length   |     Payload       |
| 1B   |  2B BE   |  2B BE   |  Length bytes      |
+------+----------+----------+-------------------+
```

| Field   | Size    | Description                              |
|---------|---------|------------------------------------------|
| Type    | 1 byte  | Record type identifier                   |
| Version | 2 bytes | Protocol version (0xF103)                |
| Length  | 2 bytes | Payload length in bytes (big-endian)     |
| Payload | N bytes | Plaintext or ciphertext depending on phase|

### Record Types

| Value | Name              | Direction | Description                 |
|-------|-------------------|-----------|-----------------------------|
| 0x15  | Alert             | Both      | Error signaling             |
| 0x16  | ServerHandshake   | S -> C    | Server handshake records    |
| 0x17  | ApplicationData   | Both      | Encrypted application data  |
| 0x19  | ClientHandshake   | C -> S    | Client handshake records    |

### Code Example: Record Parsing

From `rustbox-core/src/crisp/record.rs`:

```rust
pub fn parse_multiple(data: &[u8]) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let header = RecordHeader::deserialize(&data[offset..])?;
        offset += RecordHeader::SIZE;  // 5 bytes
        let payload = data[offset..offset + header.size as usize].to_vec();
        offset += header.size as usize;
        records.push(Record { header, payload });
    }
    Ok(records)
}
```

## Full Handshake

```
Client                                              Server
  |                                                    |
  |  [1] ClientHello (0x19)                            |
  |    random (32B), timestamp (4B)                    |
  |    ecdh_pub_key1 (65B, P-256 uncompressed)         |
  |    ecdh_pub_key2 (65B, P-256 uncompressed)         |
  |  ------------------------------------------>       |
  |                                                    |
  |  [2] ServerHello (0x16)                            |
  |    random (32B), ecdh_pub_key (65B)                |
  |  <------------------------------------------       |
  |                                                    |
  |  Both sides compute:                               |
  |    shared_secret = ECDH(own_priv, peer_pub)        |
  |    transcript    = SHA256(ServerHello payload)      |
  |    handshake_keys = HKDF(shared_secret, transcript)|
  |                                                    |
  |  [3] EncryptedExtensions (0x16, encrypted)         |
  |    Server capabilities and parameters              |
  |  <------------------------------------------       |
  |                                                    |
  |  [4] CertificateVerify (0x16, encrypted)           |
  |    ECDSA signature over handshake transcript        |
  |  <------------------------------------------       |
  |                                                    |
  |  [5] NewSessionTicket (0x16, encrypted)            |
  |    PSK ticket for future resumption                |
  |  <------------------------------------------       |
  |                                                    |
  |  [6] Finished (0x16, encrypted)                    |
  |    HMAC over full transcript                        |
  |  <------------------------------------------       |
  |                                                    |
  |  Session established: both sides hold              |
  |    psk_access_key, psk_refresh_key                 |
  |    short_encrypt/decrypt keys                      |
  +----------------------------------------------------+
```

### Key Derivation During Handshake

After the ECDH exchange, both sides derive keys using HKDF with
domain-separated labels:

```
shared_secret_hash = SHA256(ECDH_shared_secret)

handshake_keys (56 bytes) = HKDF-Expand(
    shared_secret_hash,
    "handshake key expansion" || SHA256(ServerHello),
    56
)

Layout of the 56-byte expansion:
  [ 0..16 ] encode_aes_key      (client encrypt / server decrypt)
  [16..32 ] decode_aes_key      (server encrypt / client decrypt)
  [32..44 ] encode_nonce         (12 bytes)
  [44..56 ] decode_nonce         (12 bytes)
```

These keys protect records [3] through [6].

### Session Keys

After the handshake completes, both sides derive long-term session keys:

```
psk_access_key  = HKDF-Expand(shared_secret_hash, "PSK_ACCESS"  || full_transcript, 32)
psk_refresh_key = HKDF-Expand(shared_secret_hash, "PSK_REFRESH" || full_transcript, 32)
```

The `psk_access_key` enables short-link resumption. The `psk_refresh_key` allows
ticket rotation without a new handshake.

## Short-Link (PSK Resumption)

When a client holds a valid PSK from a previous handshake, it can skip the full
ECDH exchange:

```
Client                                              Server
  |                                                    |
  |  Record 1: ClientHello (0x19)                      |
  |    Includes PSK ticket from previous session       |
  |                                                    |
  |  Record 2: Encrypted request (0x17)                |
  |    AES-128-GCM with short-link encrypt keys        |
  |                                                    |
  |  Record 3: Encrypted request continued (0x17)      |
  |                                                    |
  |  Record 4: Encrypted padding/metadata (0x17)       |
  |  ------------------------------------------>       |
  |                                                    |
  |  Server looks up PSK, derives short-link keys      |
  |                                                    |
  |  Record 1: Encrypted response (0x16)               |
  |  Record 2: Encrypted response continued (0x16)     |
  |  <------------------------------------------       |
  +----------------------------------------------------+
```

### Short-Link Key Derivation

```
client_hello_hash = SHA256(full ClientHello record bytes)

encrypt_keys (28 bytes) = HKDF-Expand(
    psk_access_key,
    "early data key expansion" || client_hello_hash,
    28
)

Layout:
  [ 0..16 ] aes_key   (16 bytes)
  [16..28 ] nonce      (12 bytes)
```

The server derives the same keys from its stored PSK and the received
ClientHello hash. Both sides use the same transcript, so the keys match.

### Dispatch Logic

The server distinguishes full handshakes from short-link requests by counting
the records in the incoming data:

| Record Count | Interpretation        |
|--------------|-----------------------|
| 1            | Full handshake        |
| 3 or more    | PSK short-link        |

## CipherState

The `CipherState` struct manages symmetric encryption for an active session:

```rust
pub struct CipherState {
    pub encrypt_key: Vec<u8>,    // 16 bytes (AES-128)
    pub encrypt_nonce: Vec<u8>,  // 12 bytes (base nonce)
    pub decrypt_key: Vec<u8>,    // 16 bytes
    pub decrypt_nonce: Vec<u8>,  // 12 bytes
    pub encrypt_seq: u64,        // incremented per encrypt
    pub decrypt_seq: u64,        // incremented per decrypt
    pub cipher_suite: CipherSuite,
}
```

Each record encryption:

1. Increments the sequence counter.
2. Computes the nonce: `base_nonce XOR pad_left(seq, 12)`.
3. Builds the AAD: `seq (8B BE) || record_header (5B)`.
4. Encrypts with AES-128-GCM, appending the 16-byte auth tag.

This construction guarantees nonce uniqueness within a session. A key rotation
(via `update_keys`) resets both sequence counters to zero.

## Cipher Suite

RustBox currently supports one cipher suite:

| Code   | Name                                  |
|--------|---------------------------------------|
| 0xC02B | ECDHE-ECDSA-WITH-AES-128-GCM-SHA256  |

This matches the TLS 1.3 cipher suite identifier and uses:

- **Key exchange:** Ephemeral P-256 ECDH
- **Authentication:** P-256 ECDSA
- **Bulk encryption:** AES-128-GCM
- **Hash:** SHA-256 (HKDF, HMAC, transcript)

## Finished Verification

Both the server and client Finished messages contain an HMAC over the full
handshake transcript:

```
server_finished_key = HKDF-Expand(psk_access_key, "server finished", 32)
client_finished_key = HKDF-Expand(psk_access_key, "client finished", 32)

finished_hmac = HMAC-SHA256(finished_key, transcript_hash)
```

The Finished HMAC binds the session to the entire handshake. If any message was
tampered with, the HMAC verification fails and the session is aborted.

## Session Lifecycle

```
+----------+    ClientHello    +-----------------+
| Initial  | ---------------> | HandshakeSent   |
+----------+                  +-----------------+
                                     |
                              Finished verified
                                     |
                                     v
                              +-----------------+
                              |  Established    |
                              +-----------------+
                                     |
                              PSK resumption
                                     |
                                     v
                              +-----------------+
                              |    Resumed      |
                              +-----------------+
                                     |
                              close / error
                                     |
                                     v
                              +-----------------+
                              |    Closed       |
                              +-----------------+
```
