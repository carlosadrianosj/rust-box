/// Chunk size: 1 MB.
pub const CHUNK_SIZE: usize = 1_048_576;

/// PBKDF2 iterations for master key derivation.
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// PBKDF2 salt length in bytes.
pub const PBKDF2_SALT_LEN: usize = 32;

/// Master key length in bytes.
pub const MASTER_KEY_LEN: usize = 32;

/// CRISP protocol version tag.
pub const CRISP_VERSION: u16 = 0xF103;

/// HKDF label: derive per-file encryption key from master key.
pub const LABEL_RUSTBOX_ENC: &str = "rustbox-enc";
/// HKDF label: derive per-file manifest encryption key.
pub const LABEL_RUSTBOX_MANIFEST: &str = "rustbox-manifest";
/// HKDF label: derive authentication key from master key.
pub const LABEL_RUSTBOX_AUTH: &str = "rustbox-auth";
/// HKDF label: derive per-chunk key from file key.
pub const LABEL_RUSTBOX_CHUNK: &str = "chunk";

/// HKDF label: CRISP handshake key expansion (56 bytes).
pub const LABEL_HANDSHAKE_KEY_EXPANSION: &str = "handshake key expansion";
/// HKDF label: CRISP early data (short-link) key expansion (28 bytes).
pub const LABEL_EARLY_DATA_KEY_EXPANSION: &str = "early data key expansion";
/// HKDF label: derive PSK access key for session resumption.
pub const LABEL_PSK_ACCESS: &str = "PSK_ACCESS";
/// HKDF label: derive PSK refresh key for ticket rotation.
pub const LABEL_PSK_REFRESH: &str = "PSK_REFRESH";
/// HKDF label: derive server Finished HMAC key.
pub const LABEL_SERVER_FINISHED: &str = "server finished";
/// HKDF label: derive client Finished HMAC key.
pub const LABEL_CLIENT_FINISHED: &str = "client finished";
/// HKDF label: derive expanded secret for key material generation.
pub const LABEL_EXPANDED_SECRET: &str = "expanded secret";
/// HKDF label: CRISP application data key expansion (56 bytes).
pub const LABEL_APP_DATA_KEY_EXPANSION: &str = "application data key expansion";

/// Verification constant encrypted during vault init to validate master key.
pub const VAULT_VERIFY_CONSTANT: &[u8] = b"RUSTBOX_VAULT_OK";

/// XChaCha20 nonce length (24 bytes).
pub const XCHACHA20_NONCE_LEN: usize = 24;
