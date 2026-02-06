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

// HKDF labels for RustBox key hierarchy
pub const LABEL_RUSTBOX_ENC: &str = "rustbox-enc";
pub const LABEL_RUSTBOX_MANIFEST: &str = "rustbox-manifest";
pub const LABEL_RUSTBOX_AUTH: &str = "rustbox-auth";
pub const LABEL_RUSTBOX_CHUNK: &str = "chunk";

// HKDF labels for CRISP protocol (carried from v2)
pub const LABEL_HANDSHAKE_KEY_EXPANSION: &str = "handshake key expansion";
pub const LABEL_EARLY_DATA_KEY_EXPANSION: &str = "early data key expansion";
pub const LABEL_PSK_ACCESS: &str = "PSK_ACCESS";
pub const LABEL_PSK_REFRESH: &str = "PSK_REFRESH";
pub const LABEL_SERVER_FINISHED: &str = "server finished";
pub const LABEL_CLIENT_FINISHED: &str = "client finished";
pub const LABEL_EXPANDED_SECRET: &str = "expanded secret";
pub const LABEL_APP_DATA_KEY_EXPANSION: &str = "application data key expansion";

/// Verification constant encrypted during vault init to validate master key.
pub const VAULT_VERIFY_CONSTANT: &[u8] = b"RUSTBOX_VAULT_OK";

/// XChaCha20 nonce length (24 bytes).
pub const XCHACHA20_NONCE_LEN: usize = 24;
