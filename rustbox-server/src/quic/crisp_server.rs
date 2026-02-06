//! CRISP protocol server-side handler.
//!
//! This is a placeholder for the full CRISP handshake implementation.
//! In POC1, QUIC connections use the binary command protocol defined in handler.rs.
//! Full CRISP handshake (ECDH + AES-GCM + PSK resumption) is a stretch goal.

use std::sync::Arc;

use crate::state::AppState;

/// Placeholder CRISP server context.
///
/// Will eventually hold the server's ECDH/ECDSA keys and manage CRISP
/// handshake state machines for incoming connections.
#[allow(dead_code)]
pub struct CrispServer {
    /// Reference to shared application state.
    state: Arc<AppState>,
}

#[allow(dead_code)]
impl CrispServer {
    /// Create a new CRISP server with the shared application state.
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Get the server's ECDH public key (P-256 uncompressed, 65 bytes).
    pub fn ecdh_public_key(&self) -> &[u8] {
        &self.state.server_ecdh_public
    }

    /// Get the server's ECDSA public key (P-256 uncompressed, 65 bytes).
    pub fn ecdsa_public_key(&self) -> &[u8] {
        &self.state.server_ecdsa_public
    }

    /// Process a CRISP handshake ClientHello.
    ///
    /// Stretch goal: Full implementation would:
    /// 1. Parse the ClientHello record
    /// 2. Generate server ephemeral ECDH key pair
    /// 3. Compute shared secret via P-256 ECDH
    /// 4. Derive handshake keys via HKDF
    /// 5. Build ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished
    /// 6. Return the response records
    ///
    /// For now, returns an error indicating CRISP is not yet implemented.
    pub fn process_client_hello(&self, _client_hello: &[u8]) -> Result<Vec<u8>, String> {
        Err("CRISP handshake not yet implemented in POC1; use binary command protocol".to_string())
    }

    /// Process a CRISP PSK-based short-link request.
    ///
    /// Stretch goal: Full implementation would:
    /// 1. Parse the PSK ClientHello
    /// 2. Look up the PSK in the session store
    /// 3. Derive early data keys
    /// 4. Decrypt and process the request
    /// 5. Encrypt and return the response
    ///
    /// For now, returns an error indicating CRISP is not yet implemented.
    pub fn process_psk_request(&self, _psk_request: &[u8]) -> Result<Vec<u8>, String> {
        Err("CRISP PSK resumption not yet implemented in POC1; use binary command protocol".to_string())
    }
}
