# RustBox Technical Documentation

Detailed technical documentation for the RustBox zero-knowledge encrypted file
sync system.

## Documents

| Document                                  | Description                                           |
|-------------------------------------------|-------------------------------------------------------|
| [Architecture](architecture.md)           | Crate layout, trait system, data flow, zero-knowledge  |
| [Cryptography](cryptography.md)           | Key hierarchy, PBKDF2, HKDF, XChaCha20, AES-GCM      |
| [CRISP Protocol](crisp-protocol.md)       | Handshake, PSK resumption, record format, cipher state |
| [Sync Engine](sync-engine.md)             | Merkle trees, diff computation, chunking, manifests    |
| [Transport](transport.md)                 | QUIC binary protocol, HTTP REST API, server dispatch   |

## Reading Order

For a first read, start with **Architecture** to understand the overall system
design and zero-knowledge guarantee. Then read **Cryptography** for the key
hierarchy and cipher choices. **CRISP Protocol** and **Sync Engine** can be read
independently. **Transport** covers the networking layer.
