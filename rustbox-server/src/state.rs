use sqlx::PgPool;

use crate::session::store::SessionStore;

/// Shared application state passed to all handlers via Axum's State extractor.
#[allow(dead_code)]
pub struct AppState {
    /// PostgreSQL connection pool.
    pub pool: PgPool,
    /// Server ECDH private key bytes (P-256, 32 bytes).
    pub server_ecdh_private: Vec<u8>,
    /// Server ECDH public key bytes (P-256, uncompressed, 65 bytes).
    pub server_ecdh_public: Vec<u8>,
    /// Server ECDSA signing key bytes (P-256, 32 bytes).
    pub server_ecdsa_private: Vec<u8>,
    /// Server ECDSA verifying key bytes (P-256, uncompressed, 65 bytes).
    pub server_ecdsa_public: Vec<u8>,
    /// In-memory session store (DashMap-backed).
    pub sessions: SessionStore,
}
