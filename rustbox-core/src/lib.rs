//! Platform-independent cryptographic library for zero-knowledge file sync.
//!
//! All encryption, key derivation, chunking, and sync logic lives here so that
//! CLI and WASM clients share identical byte-level behavior.

pub mod error;
pub mod constants;
pub mod traits;
pub mod crypto;
pub mod crisp;
pub mod chunking;
pub mod merkle;
pub mod manifest;
pub mod sync;
