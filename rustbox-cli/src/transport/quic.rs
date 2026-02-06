use std::sync::Arc;

use async_trait::async_trait;
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tracing::{debug, info};

use rustbox_core::error::RustBoxError;
use rustbox_core::traits::transport::Transport;

/// Wire protocol command bytes.
const CMD_UPLOAD_CHUNK: u8 = 0x01;
const CMD_DOWNLOAD_CHUNK: u8 = 0x02;
const CMD_UPLOAD_MANIFEST: u8 = 0x03;
const CMD_DOWNLOAD_MANIFEST: u8 = 0x04;
const CMD_GET_ROOT: u8 = 0x05;
const CMD_GET_DIFF: u8 = 0x06;
const CMD_REGISTER: u8 = 0x10;
const CMD_GET_SALT: u8 = 0x11;
#[allow(dead_code)]
const CMD_LIST_MANIFESTS: u8 = 0x12;
#[allow(dead_code)]
const CMD_DELETE_MANIFEST: u8 = 0x13;
#[allow(dead_code)]
const CMD_DB_OVERVIEW: u8 = 0x14;

/// Status codes returned by the server.
const STATUS_OK: u8 = 0x00;
const STATUS_CREATED: u8 = 0x01;
const STATUS_NOT_FOUND: u8 = 0x02;
#[allow(dead_code)]
const STATUS_CONFLICT: u8 = 0x03;

/// QUIC transport for RustBox using a simple binary protocol.
///
/// Wire format:
/// ```text
/// Client sends: [cmd: 1B][payload_len: 4B BE][payload]
/// Server responds: [status: 1B][payload_len: 4B BE][payload]
/// ```
///
/// Each operation opens a new bidirectional QUIC stream on a persistent connection.
pub struct QuicTransport {
    connection: Connection,
    /// User ID (UUID bytes) to send with upload commands. Set after login.
    user_id: [u8; 16],
}

impl QuicTransport {
    /// Connect to a RustBox server at the given `host:port`.
    ///
    /// Accepts self-signed certificates for development.
    pub async fn connect(server_addr: &str) -> Result<Self, RustBoxError> {
        // Install the ring crypto provider for rustls (idempotent).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let addr = server_addr
            .parse()
            .map_err(|e| RustBoxError::Transport(format!("invalid server address: {e}")))?;

        // Build a rustls client config that skips certificate verification (dev mode).
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        // Must match the server's ALPN protocol.
        crypto.alpn_protocols = vec![b"rustbox-quic".to_vec()];

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| RustBoxError::Transport(format!("quinn crypto config error: {e}")))?
        ));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().map_err(|e| {
            RustBoxError::Transport(format!("bind address error: {e}"))
        })?)
        .map_err(|e| RustBoxError::Transport(format!("endpoint creation failed: {e}")))?;

        endpoint.set_default_client_config(client_config);

        info!("Connecting to QUIC server at {server_addr}");

        let connection = endpoint
            .connect(addr, "rustbox")
            .map_err(|e| RustBoxError::Transport(format!("QUIC connect error: {e}")))?
            .await
            .map_err(|e| RustBoxError::Transport(format!("QUIC connection failed: {e}")))?;

        info!("QUIC connection established");

        Ok(Self { connection, user_id: [0u8; 16] })
    }

    /// Send a command on a new bi-directional QUIC stream and read the response.
    async fn send_command(&self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, RustBoxError> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| RustBoxError::Transport(format!("open stream failed: {e}")))?;

        // Build request: [cmd: 1B][payload_len: 4B BE][payload]
        let payload_len = payload.len() as u32;
        let mut request = Vec::with_capacity(1 + 4 + payload.len());
        request.push(cmd);
        request.extend_from_slice(&payload_len.to_be_bytes());
        request.extend_from_slice(payload);

        send.write_all(&request)
            .await
            .map_err(|e| RustBoxError::Transport(format!("write failed: {e}")))?;

        send.finish()
            .map_err(|e| RustBoxError::Transport(format!("finish send failed: {e}")))?;

        debug!("Sent command 0x{:02X}, payload {} bytes", cmd, payload.len());

        // Read response: [status: 1B][payload_len: 4B BE][payload]
        let response_data = recv
            .read_to_end(64 * 1024 * 1024) // 64 MB max response
            .await
            .map_err(|e| RustBoxError::Transport(format!("read failed: {e}")))?;

        if response_data.len() < 5 {
            return Err(RustBoxError::Transport(
                "response too short (need at least 5 bytes)".to_string(),
            ));
        }

        let status = response_data[0];
        let resp_payload_len =
            u32::from_be_bytes(response_data[1..5].try_into().map_err(|_| {
                RustBoxError::Transport("invalid response length bytes".to_string())
            })?) as usize;

        if status != STATUS_OK && status != STATUS_CREATED {
            let body = if response_data.len() > 5 {
                String::from_utf8_lossy(&response_data[5..]).to_string()
            } else {
                String::new()
            };
            if status == STATUS_NOT_FOUND {
                return Err(RustBoxError::Transport(format!("not found: {body}")));
            }
            return Err(RustBoxError::Transport(format!("server error 0x{status:02X}: {body}")));
        }

        if response_data.len() < 5 + resp_payload_len {
            return Err(RustBoxError::Transport(format!(
                "response truncated: expected {} bytes, got {}",
                resp_payload_len,
                response_data.len() - 5
            )));
        }

        debug!(
            "Received response: status=0x{:02X}, payload {} bytes",
            status, resp_payload_len
        );

        Ok(response_data[5..5 + resp_payload_len].to_vec())
    }

    /// Set the user ID (parsed from UUID string) for subsequent commands.
    pub fn set_user_id(&mut self, user_id_str: &str) -> Result<(), RustBoxError> {
        let uuid: uuid::Uuid = user_id_str
            .parse()
            .map_err(|e| RustBoxError::Transport(format!("invalid user_id: {e}")))?;
        self.user_id = *uuid.as_bytes();
        Ok(())
    }

    /// Set the user ID from raw UUID bytes.
    #[allow(dead_code)]
    pub fn set_user_id_bytes(&mut self, bytes: &[u8]) -> Result<(), RustBoxError> {
        if bytes.len() < 16 {
            return Err(RustBoxError::Transport("user_id must be at least 16 bytes".into()));
        }
        self.user_id.copy_from_slice(&bytes[..16]);
        Ok(())
    }

    /// Legacy register: sends 32-byte auth_key_hash only.
    #[allow(dead_code)]
    pub async fn register(&self, auth_key_hash: &[u8; 32]) -> Result<String, RustBoxError> {
        let response = self.send_command(CMD_REGISTER, auth_key_hash).await?;
        String::from_utf8(response)
            .map_err(|e| RustBoxError::Transport(format!("invalid user_id response: {e}")))
    }

    /// Register with username (new format).
    /// Payload: [username_len: 2B BE][username][salt: 32B][auth_key_hash: 32B]
    pub async fn register_with_username(
        &self,
        username: &str,
        salt_hex: Option<&str>,
        auth_key_hash: &[u8; 32],
    ) -> Result<String, RustBoxError> {
        let username_bytes = username.as_bytes();
        let username_len = (username_bytes.len() as u16).to_be_bytes();

        let salt_bytes = if let Some(hex_str) = salt_hex {
            hex::decode(hex_str)
                .map_err(|e| RustBoxError::Transport(format!("invalid salt hex: {e}")))?
        } else {
            vec![0u8; 32]
        };

        let mut payload = Vec::with_capacity(2 + username_bytes.len() + 32 + 32);
        payload.extend_from_slice(&username_len);
        payload.extend_from_slice(username_bytes);
        payload.extend_from_slice(&salt_bytes);
        payload.extend_from_slice(auth_key_hash);

        let response = self.send_command(CMD_REGISTER, &payload).await?;
        String::from_utf8(response)
            .map_err(|e| RustBoxError::Transport(format!("invalid user_id response: {e}")))
    }

    /// Fetch salt for a username from server. Returns None if user not found.
    pub async fn get_salt(&self, username: &str) -> Result<Option<Vec<u8>>, RustBoxError> {
        let username_bytes = username.as_bytes();
        let username_len = (username_bytes.len() as u32).to_be_bytes();

        let mut payload = Vec::with_capacity(4 + username_bytes.len());
        payload.extend_from_slice(&username_len);
        payload.extend_from_slice(username_bytes);

        match self.send_command(CMD_GET_SALT, &payload).await {
            Ok(response) => {
                if response.len() >= 32 {
                    Ok(Some(response[..32].to_vec()))
                } else {
                    Ok(Some(response))
                }
            }
            Err(RustBoxError::Transport(msg)) if msg.contains("not found") => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// List manifests for the current user. Returns JSON string.
    #[allow(dead_code)]
    pub async fn list_manifests(&self) -> Result<String, RustBoxError> {
        let response = self.send_command(CMD_LIST_MANIFESTS, &self.user_id).await?;
        String::from_utf8(response)
            .map_err(|e| RustBoxError::Transport(format!("invalid list_manifests response: {e}")))
    }

    /// Delete a manifest by ID.
    #[allow(dead_code)]
    pub async fn delete_manifest(&self, manifest_id: &str) -> Result<(), RustBoxError> {
        let mut payload = Vec::with_capacity(16 + manifest_id.len());
        payload.extend_from_slice(&self.user_id);
        payload.extend_from_slice(manifest_id.as_bytes());
        self.send_command(CMD_DELETE_MANIFEST, &payload).await?;
        Ok(())
    }

    /// Get database overview for current user. Returns JSON string.
    #[allow(dead_code)]
    pub async fn get_db_overview(&self) -> Result<String, RustBoxError> {
        let response = self.send_command(CMD_DB_OVERVIEW, &self.user_id).await?;
        String::from_utf8(response)
            .map_err(|e| RustBoxError::Transport(format!("invalid db_overview response: {e}")))
    }
}

#[async_trait(?Send)]
impl Transport for QuicTransport {
    async fn upload_chunk(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError> {
        // Payload: [user_id: 16B][hash: 32B][chunk_data]
        let mut payload = Vec::with_capacity(16 + 32 + data.len());
        payload.extend_from_slice(&self.user_id);
        payload.extend_from_slice(hash);
        payload.extend_from_slice(data);

        match self.send_command(CMD_UPLOAD_CHUNK, &payload).await {
            Ok(_) => Ok(()),
            Err(RustBoxError::Transport(msg)) if msg.contains("already exists") => {
                debug!("Chunk already exists on server, skipping: {}", hex::encode(hash));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn download_chunk(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError> {
        // Payload: [hash: 32B]
        self.send_command(CMD_DOWNLOAD_CHUNK, hash).await
    }

    async fn upload_manifest(&self, data: &[u8]) -> Result<String, RustBoxError> {
        // Payload: [user_id: 16B][manifest_data]
        let mut payload = Vec::with_capacity(16 + data.len());
        payload.extend_from_slice(&self.user_id);
        payload.extend_from_slice(data);
        // Response: manifest_id as UTF-8 string
        let response = self.send_command(CMD_UPLOAD_MANIFEST, &payload).await?;
        String::from_utf8(response)
            .map_err(|e| RustBoxError::Transport(format!("invalid manifest_id response: {e}")))
    }

    async fn download_manifest(&self, id: &str) -> Result<Vec<u8>, RustBoxError> {
        // Payload: [manifest_id as UTF-8]
        self.send_command(CMD_DOWNLOAD_MANIFEST, id.as_bytes())
            .await
    }

    async fn get_merkle_root(&self) -> Result<[u8; 32], RustBoxError> {
        // Payload: [user_id: 16B]
        let response = self.send_command(CMD_GET_ROOT, &self.user_id).await?;
        if response.len() < 8 {
            return Err(RustBoxError::Transport(format!(
                "expected at least 8 bytes for get_root response, got {} bytes",
                response.len()
            )));
        }
        // Response: [version: 8B BE][merkle_root: 32B] or just [version: 8B BE] if no root
        if response.len() == 8 {
            // No merkle root yet, return zeros
            return Ok([0u8; 32]);
        }
        if response.len() < 40 {
            return Err(RustBoxError::Transport(format!(
                "expected 40 bytes (version + root), got {}",
                response.len()
            )));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&response[8..40]);
        Ok(root)
    }

    async fn get_merkle_diff(
        &self,
        local_root: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, RustBoxError> {
        // Payload: [user_id: 16B][local_root_len: 4B BE][local_root: 32B][num_known: 4B BE]
        let mut payload = Vec::with_capacity(16 + 4 + 32 + 4);
        payload.extend_from_slice(&self.user_id);
        payload.extend_from_slice(&32u32.to_be_bytes());
        payload.extend_from_slice(local_root);
        payload.extend_from_slice(&0u32.to_be_bytes()); // num_known = 0

        let response = self.send_command(CMD_GET_DIFF, &payload).await?;

        // Response: [num_missing: 4B BE][hash1: 32B][hash2: 32B]...
        if response.len() < 4 {
            return Err(RustBoxError::Transport("diff response too short".into()));
        }
        let num_missing = u32::from_be_bytes(
            response[..4].try_into().map_err(|_| RustBoxError::Transport("invalid num_missing".into()))?
        ) as usize;

        let hash_data = &response[4..];
        if hash_data.len() != num_missing * 32 {
            return Err(RustBoxError::Transport(format!(
                "expected {} hash bytes, got {}",
                num_missing * 32,
                hash_data.len()
            )));
        }

        let hashes: Vec<[u8; 32]> = hash_data
            .chunks_exact(32)
            .map(|chunk| {
                let mut h = [0u8; 32];
                h.copy_from_slice(chunk);
                h
            })
            .collect();

        Ok(hashes)
    }
}

/// A rustls certificate verifier that accepts any server certificate.
/// Used for development with self-signed certificates.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
