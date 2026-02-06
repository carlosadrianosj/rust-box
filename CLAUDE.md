# RustBox POC1-V2 Project Rules

## Mantras

1. **One Core, Two Products** -- `rustbox-core` is the single source of truth for crypto, sync, chunking, manifest. Never duplicate in client crates.
2. **Zero-Knowledge is Non-Negotiable** -- Server NEVER sees plaintext. All encryption is client-side. `rustbox-server` must NEVER import encryption functions.
3. **Content-Addressable Storage** -- Blobs are SHA256(ciphertext). The hash IS the address.
4. **Deterministic Key Hierarchy** -- `master_key -> file_enc_key -> chunk_key`. Same inputs = same outputs.
5. **Cross-Client Parity** -- Any feature in one client MUST work identically in all clients.
6. **Merkle-Verified Sync** -- All sync verified by Merkle tree. No blind trust.
7. **Transport Agnostic** -- Core uses traits (`Transport`, `ContentAddressableStorage`). Implementations live in client crates only.
8. **WASM-Safe Core** -- All core async traits use `#[async_trait(?Send)]`. No `Send + Sync` bounds on core traits.

## Code Rules

- No `.unwrap()` in library code; `.expect("reason")` only in main.rs
- Every module has `#[cfg(test)] mod tests`
- Commits: prefix `core:`, `cli:`, `wasm:`, `server:`, `ui:`
- Verify core WASM compat: `cargo build -p rustbox-core --target wasm32-unknown-unknown`

## Architecture

- 4 crates: `rustbox-core`, `rustbox-server`, `rustbox-cli`, `rustbox-wasm`
- UI: `rustbox-ui/` used by WASM build (serve.html)
- Server: Axum HTTP :8443 + Quinn QUIC :4433, PostgreSQL 16
- Cross-client identity: server stores salt per username, all clients fetch salt before deriving keys
- Manifest envelope: `[nonce (24B) | file_id_len (4B BE) | file_id (UTF-8) | ciphertext]`
