use super::{CrispError, Result};
use crate::crypto::hkdf;
use crate::constants::*;

/// CRISP session keys derived from handshake.
#[derive(Debug, Clone)]
pub struct CrispKeys {
    pub psk_access_key: Vec<u8>,
    pub psk_refresh_key: Vec<u8>,
    pub short_encrypt_key: Vec<u8>,
    pub short_encrypt_nonce: Vec<u8>,
    pub short_decrypt_key: Vec<u8>,
    pub short_decrypt_nonce: Vec<u8>,
    pub client_seq: u32,
    pub server_seq: u32,
    pub cipher_suite: super::cipher::CipherSuite,
    pub psk_list: Vec<PskTicket>,
    pub early_data_part: Vec<u8>,
}

impl CrispKeys {
    /// Empty key set; populated during handshake or PSK resumption.
    pub fn new() -> Self {
        Self {
            psk_access_key: Vec::new(),
            psk_refresh_key: Vec::new(),
            short_encrypt_key: Vec::new(),
            short_encrypt_nonce: Vec::new(),
            short_decrypt_key: Vec::new(),
            short_decrypt_nonce: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            cipher_suite: super::cipher::CipherSuite::EcdheEcdsaWithAes128GcmSha256,
            psk_list: Vec::new(),
            early_data_part: Vec::new(),
        }
    }
}

impl Default for CrispKeys {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialized PSK ticket received from the server for session resumption.
#[derive(Debug, Clone)]
pub struct PskTicket {
    pub psk_type: u8,
    pub lifetime_hint: u32,
    pub mac_value: Vec<u8>,
    pub key_version: u32,
    pub iv: Vec<u8>,
    pub encrypted_ticket: Vec<u8>,
}

/// Derive 56-byte handshake key material from the ECDH shared secret and transcript.
pub fn derive_handshake_keys(
    ecdh_shared_secret_hash: &[u8],
    transcript_hash: &[u8],
) -> Result<hkdf::HkdfKey56> {
    let expanded = hkdf::hkdf_expand_handshake_keys(
        ecdh_shared_secret_hash,
        LABEL_HANDSHAKE_KEY_EXPANSION,
        transcript_hash,
    )
    .map_err(|e| CrispError::KeyDerivation(e.to_string()))?;

    Ok(hkdf::HkdfKey56 {
        encode_aes_key: expanded[0..16].to_vec(),
        encode_nonce: expanded[32..44].to_vec(),
        decode_aes_key: expanded[16..32].to_vec(),
        decode_nonce: expanded[44..56].to_vec(),
    })
}

/// Derive the PSK access key used for short-link encryption.
pub fn derive_psk_access_key(
    ecdh_shared_secret_hash: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    hkdf::hkdf_expand_psk(
        ecdh_shared_secret_hash,
        LABEL_PSK_ACCESS,
        transcript_hash,
    )
    .map_err(|e| CrispError::KeyDerivation(e.to_string()))
}

/// Derive the PSK refresh key used to rotate session tickets.
pub fn derive_psk_refresh_key(
    ecdh_shared_secret_hash: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    hkdf::hkdf_expand_psk(
        ecdh_shared_secret_hash,
        LABEL_PSK_REFRESH,
        transcript_hash,
    )
    .map_err(|e| CrispError::KeyDerivation(e.to_string()))
}

/// Derive client-side short-link encryption keys from the PSK and ClientHello hash.
pub fn derive_short_link_encrypt_keys(
    psk_access_key: &[u8],
    client_hello_hash: &[u8],
) -> Result<hkdf::HkdfKey28> {
    hkdf::hkdf_expand_short_keys(
        psk_access_key,
        LABEL_EARLY_DATA_KEY_EXPANSION,
        client_hello_hash,
    )
    .map_err(|e| CrispError::KeyDerivation(e.to_string()))
}

/// Derive server-side short-link response decryption keys from the PSK and transcript.
pub fn derive_short_link_decrypt_keys(
    psk_access_key: &[u8],
    transcript_hash: &[u8],
) -> Result<hkdf::HkdfKey28> {
    hkdf::hkdf_expand_short_keys(
        psk_access_key,
        LABEL_HANDSHAKE_KEY_EXPANSION,
        transcript_hash,
    )
    .map_err(|e| CrispError::KeyDerivation(e.to_string()))
}

/// Derive the key used to compute the server Finished HMAC.
pub fn derive_server_finished_key(psk_access_key: &[u8]) -> Result<Vec<u8>> {
    let info = LABEL_SERVER_FINISHED.as_bytes();
    hkdf::hkdf_expand(psk_access_key, info, 32)
        .map_err(|e| CrispError::KeyDerivation(e.to_string()))
}

/// Derive the key used to compute the client Finished HMAC.
pub fn derive_client_finished_key(psk_access_key: &[u8]) -> Result<Vec<u8>> {
    let info = LABEL_CLIENT_FINISHED.as_bytes();
    hkdf::hkdf_expand(psk_access_key, info, 32)
        .map_err(|e| CrispError::KeyDerivation(e.to_string()))
}

/// Derive 56-byte application data keys from the master secret and full transcript.
pub fn derive_application_data_keys(
    master_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<hkdf::HkdfKey56> {
    let expanded = hkdf::hkdf_expand_handshake_keys(
        master_secret,
        LABEL_APP_DATA_KEY_EXPANSION,
        transcript_hash,
    )
    .map_err(|e| CrispError::KeyDerivation(e.to_string()))?;

    Ok(hkdf::HkdfKey56 {
        encode_aes_key: expanded[0..16].to_vec(),
        encode_nonce: expanded[32..44].to_vec(),
        decode_aes_key: expanded[16..32].to_vec(),
        decode_nonce: expanded[44..56].to_vec(),
    })
}

/// Derive an expanded secret for further key material generation.
pub fn derive_expanded_secret(
    master_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    hkdf::hkdf_expand_psk(
        master_secret,
        LABEL_EXPANDED_SECRET,
        transcript_hash,
    )
    .map_err(|e| CrispError::KeyDerivation(e.to_string()))
}

/// One-shot derivation of all session keys from the ECDH output and transcript hashes.
pub fn derive_all_session_keys(
    ecdh_shared_secret_hash: &[u8],
    server_hello_hash: &[u8],
    full_transcript_hash: &[u8],
) -> Result<CrispKeys> {
    let _handshake_keys = derive_handshake_keys(
        ecdh_shared_secret_hash,
        server_hello_hash,
    )?;

    let psk_access_key = derive_psk_access_key(
        ecdh_shared_secret_hash,
        full_transcript_hash,
    )?;

    let psk_refresh_key = derive_psk_refresh_key(
        ecdh_shared_secret_hash,
        full_transcript_hash,
    )?;

    Ok(CrispKeys {
        psk_access_key,
        psk_refresh_key,
        short_encrypt_key: Vec::new(),
        short_encrypt_nonce: Vec::new(),
        short_decrypt_key: Vec::new(),
        short_decrypt_nonce: Vec::new(),
        client_seq: 0,
        server_seq: 0,
        cipher_suite: super::cipher::CipherSuite::EcdheEcdsaWithAes128GcmSha256,
        psk_list: Vec::new(),
        early_data_part: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_handshake_keys() {
        let secret_hash = [0xAA; 32];
        let transcript = [0xBB; 32];

        let keys = derive_handshake_keys(&secret_hash, &transcript).unwrap();
        assert_eq!(keys.encode_aes_key.len(), 16);
        assert_eq!(keys.decode_aes_key.len(), 16);
        assert_eq!(keys.encode_nonce.len(), 12);
        assert_eq!(keys.decode_nonce.len(), 12);
    }

    #[test]
    fn test_derive_psk_keys() {
        let secret_hash = [0xCC; 32];
        let transcript = [0xDD; 32];

        let access = derive_psk_access_key(&secret_hash, &transcript).unwrap();
        assert_eq!(access.len(), 32);

        let refresh = derive_psk_refresh_key(&secret_hash, &transcript).unwrap();
        assert_eq!(refresh.len(), 32);

        assert_ne!(access, refresh);
    }

    #[test]
    fn test_derive_short_link_keys() {
        let psk = [0xEE; 32];
        let hello_hash = [0xFF; 32];

        let keys = derive_short_link_encrypt_keys(&psk, &hello_hash).unwrap();
        assert_eq!(keys.aes_key.len(), 16);
        assert_eq!(keys.nonce.len(), 12);
    }

    #[test]
    fn test_derive_finished_keys() {
        let psk = [0x42; 32];

        let server_key = derive_server_finished_key(&psk).unwrap();
        let client_key = derive_client_finished_key(&psk).unwrap();
        assert_eq!(server_key.len(), 32);
        assert_eq!(client_key.len(), 32);
        assert_ne!(server_key, client_key);
    }

    #[test]
    fn test_derive_all_session_keys() {
        let secret = [0xAA; 32];
        let sh_hash = [0xBB; 32];
        let full_hash = [0xCC; 32];

        let keys = derive_all_session_keys(&secret, &sh_hash, &full_hash).unwrap();
        assert_eq!(keys.psk_access_key.len(), 32);
        assert_eq!(keys.psk_refresh_key.len(), 32);
    }
}
