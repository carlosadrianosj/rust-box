use std::sync::Arc;

use quinn::Connection;
use sha2::{Sha256, Digest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::db::{blobs, manifests};
use crate::error::{Result, ServerError};
use crate::state::AppState;

/// Binary protocol command bytes.
const CMD_UPLOAD_CHUNK: u8 = 0x01;
const CMD_DOWNLOAD_CHUNK: u8 = 0x02;
const CMD_UPLOAD_MANIFEST: u8 = 0x03;
const CMD_DOWNLOAD_MANIFEST: u8 = 0x04;
const CMD_GET_ROOT: u8 = 0x05;
const CMD_GET_DIFF: u8 = 0x06;
const CMD_REGISTER: u8 = 0x10;
const CMD_GET_SALT: u8 = 0x11;
const CMD_LIST_MANIFESTS: u8 = 0x12;
const CMD_DELETE_MANIFEST: u8 = 0x13;
const CMD_DB_OVERVIEW: u8 = 0x14;

/// Response status bytes.
const STATUS_OK: u8 = 0x00;
const STATUS_CREATED: u8 = 0x01;
const STATUS_NOT_FOUND: u8 = 0x02;
const STATUS_CONFLICT: u8 = 0x03;
const STATUS_BAD_REQUEST: u8 = 0x04;
const STATUS_ERROR: u8 = 0xFF;

/// Hardcoded POC1 test user ID.
const POC1_TEST_USER_ID: &str = "00000000-0000-0000-0000-000000000001";

/// Handle a single QUIC connection. Processes streams until the connection closes.
pub async fn handle_connection(state: Arc<AppState>, connection: Connection) -> Result<()> {
    loop {
        let stream = connection.accept_bi().await;
        match stream {
            Ok((send, recv)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(state, send, recv).await {
                        tracing::error!(error = %e, "stream handler error");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                tracing::info!("QUIC connection closed by peer");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(error = %e, "error accepting bi-directional stream");
                return Err(ServerError::Internal(format!("stream accept error: {e}")));
            }
        }
    }
}

/// Handle a single bi-directional QUIC stream.
///
/// Protocol: [cmd: 1B][payload_len: 4B BE][payload]
/// Response: [status: 1B][response_len: 4B BE][response]
async fn handle_stream(
    state: Arc<AppState>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    // Read the command byte.
    let cmd = recv.read_u8().await
        .map_err(|e| ServerError::Internal(format!("read cmd failed: {e}")))?;

    // Read the payload length (4 bytes, big-endian).
    let payload_len = recv.read_u32().await
        .map_err(|e| ServerError::Internal(format!("read payload_len failed: {e}")))?;

    // Read the payload.
    let mut payload = vec![0u8; payload_len as usize];
    recv.read_exact(&mut payload).await
        .map_err(|e| ServerError::Internal(format!("read payload failed: {e}")))?;

    let cmd_name = match cmd {
        CMD_UPLOAD_CHUNK => "UPLOAD_CHUNK",
        CMD_DOWNLOAD_CHUNK => "DOWNLOAD_CHUNK",
        CMD_UPLOAD_MANIFEST => "UPLOAD_MANIFEST",
        CMD_DOWNLOAD_MANIFEST => "DOWNLOAD_MANIFEST",
        CMD_GET_ROOT => "GET_ROOT",
        CMD_GET_DIFF => "GET_DIFF",
        CMD_REGISTER => "REGISTER",
        CMD_GET_SALT => "GET_SALT",
        CMD_LIST_MANIFESTS => "LIST_MANIFESTS",
        CMD_DELETE_MANIFEST => "DELETE_MANIFEST",
        CMD_DB_OVERVIEW => "DB_OVERVIEW",
        _ => "UNKNOWN",
    };
    tracing::info!(cmd = cmd_name, payload_len = payload_len, "QUIC command");

    // Dispatch based on command.
    let (status, response_data) = match cmd {
        CMD_UPLOAD_CHUNK => handle_upload_chunk(&state, &payload).await,
        CMD_DOWNLOAD_CHUNK => handle_download_chunk(&state, &payload).await,
        CMD_UPLOAD_MANIFEST => handle_upload_manifest(&state, &payload).await,
        CMD_DOWNLOAD_MANIFEST => handle_download_manifest(&state, &payload).await,
        CMD_GET_ROOT => handle_get_root(&state, &payload).await,
        CMD_GET_DIFF => handle_get_diff(&state, &payload).await,
        CMD_REGISTER => handle_register(&state, &payload).await,
        CMD_GET_SALT => handle_get_salt(&state, &payload).await,
        CMD_LIST_MANIFESTS => handle_list_manifests(&state, &payload).await,
        CMD_DELETE_MANIFEST => handle_delete_manifest(&state, &payload).await,
        CMD_DB_OVERVIEW => handle_db_overview(&state, &payload).await,
        _ => (STATUS_BAD_REQUEST, format!("unknown command: 0x{:02x}", cmd).into_bytes()),
    };

    // Write response: [status: 1B][response_len: 4B BE][response]
    send.write_u8(status).await
        .map_err(|e| ServerError::Internal(format!("write status failed: {e}")))?;
    send.write_u32(response_data.len() as u32).await
        .map_err(|e| ServerError::Internal(format!("write response_len failed: {e}")))?;
    send.write_all(&response_data).await
        .map_err(|e| ServerError::Internal(format!("write response failed: {e}")))?;
    send.finish()
        .map_err(|e| ServerError::Internal(format!("finish stream failed: {e}")))?;

    Ok(())
}

/// Upload chunk via QUIC.
/// Payload format: [user_id: 16B][hash: 32B][chunk_data: remaining]
/// Falls back to POC1 test user if user_id is all zeros.
async fn handle_upload_chunk(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    if payload.len() < 49 {
        return (STATUS_BAD_REQUEST, b"payload too short for upload_chunk".to_vec());
    }

    let user_id = uuid::Uuid::from_bytes(
        payload[..16].try_into().expect("checked length")
    );
    let user_id = if user_id.is_nil() {
        POC1_TEST_USER_ID.parse::<uuid::Uuid>().unwrap()
    } else {
        user_id
    };

    let expected_hash = &payload[16..48];
    let chunk_data = &payload[48..];

    // Verify hash.
    let actual_hash = Sha256::digest(chunk_data);
    if actual_hash.as_slice() != expected_hash {
        return (STATUS_BAD_REQUEST, b"hash mismatch".to_vec());
    }

    match blobs::blob_exists(&state.pool, expected_hash).await {
        Ok(true) => return (STATUS_CONFLICT, b"chunk already exists".to_vec()),
        Ok(false) => {}
        Err(e) => return (STATUS_ERROR, format!("db error: {e}").into_bytes()),
    }

    match blobs::insert_blob(&state.pool, expected_hash, chunk_data, user_id).await {
        Ok(()) => {
            tracing::info!(hash = %hex::encode(expected_hash), "chunk uploaded via QUIC");
            (STATUS_CREATED, b"ok".to_vec())
        }
        Err(e) => (STATUS_ERROR, format!("insert error: {e}").into_bytes()),
    }
}

/// Download chunk via QUIC.
/// Payload format: [hash: 32B]
async fn handle_download_chunk(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    if payload.len() != 32 {
        return (STATUS_BAD_REQUEST, b"hash must be 32 bytes".to_vec());
    }

    match blobs::get_blob(&state.pool, payload).await {
        Ok(Some(data)) => {
            tracing::debug!(hash = %hex::encode(payload), size = data.len(), "chunk downloaded via QUIC");
            (STATUS_OK, data)
        }
        Ok(None) => (STATUS_NOT_FOUND, b"chunk not found".to_vec()),
        Err(e) => (STATUS_ERROR, format!("db error: {e}").into_bytes()),
    }
}

/// Upload manifest via QUIC.
/// Payload format: [user_id: 16B][manifest_data: remaining]
async fn handle_upload_manifest(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    if payload.len() < 17 {
        return (STATUS_BAD_REQUEST, b"payload too short for upload_manifest".to_vec());
    }

    let user_id = uuid::Uuid::from_bytes(
        payload[..16].try_into().expect("checked length")
    );
    let user_id = if user_id.is_nil() {
        POC1_TEST_USER_ID.parse::<uuid::Uuid>().unwrap()
    } else {
        user_id
    };

    let manifest_data = &payload[16..];
    let merkle_root = Sha256::digest(manifest_data).to_vec();

    match manifests::insert_manifest(&state.pool, user_id, manifest_data, &merkle_root).await {
        Ok(id) => {
            tracing::info!(manifest_id = %id, "manifest uploaded via QUIC");
            // Return the UUID as UTF-8 string.
            (STATUS_CREATED, id.to_string().into_bytes())
        }
        Err(e) => (STATUS_ERROR, format!("insert error: {e}").into_bytes()),
    }
}

/// Download manifest via QUIC.
/// Payload format: [uuid: UTF-8 string (36B)]
async fn handle_download_manifest(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    let id_str = match std::str::from_utf8(payload) {
        Ok(s) => s.trim(),
        Err(_) => return (STATUS_BAD_REQUEST, b"invalid UTF-8 in manifest id".to_vec()),
    };

    let id: uuid::Uuid = match id_str.parse() {
        Ok(id) => id,
        Err(e) => return (STATUS_BAD_REQUEST, format!("invalid UUID: {e}").into_bytes()),
    };

    match manifests::get_manifest(&state.pool, id).await {
        Ok(Some(data)) => {
            tracing::debug!(manifest_id = %id, size = data.len(), "manifest downloaded via QUIC");
            (STATUS_OK, data)
        }
        Ok(None) => (STATUS_NOT_FOUND, b"manifest not found".to_vec()),
        Err(e) => (STATUS_ERROR, format!("db error: {e}").into_bytes()),
    }
}

/// Get merkle root via QUIC.
/// Payload format: [user_id: 16B (UUID)]
async fn handle_get_root(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    if payload.len() != 16 {
        return (STATUS_BAD_REQUEST, b"user_id must be 16 bytes (UUID)".to_vec());
    }

    let user_id = uuid::Uuid::from_bytes(
        payload.try_into().expect("already checked length is 16")
    );

    match manifests::get_merkle_root(&state.pool, user_id).await {
        Ok(Some((root, version))) => {
            // Response: [version: 8B BE][merkle_root: 32B]
            let mut response = Vec::with_capacity(40);
            response.extend_from_slice(&version.to_be_bytes());
            response.extend_from_slice(&root);
            (STATUS_OK, response)
        }
        Ok(None) => {
            // No manifest yet: version=0, empty root.
            let response = 0i64.to_be_bytes().to_vec();
            (STATUS_OK, response)
        }
        Err(e) => (STATUS_ERROR, format!("db error: {e}").into_bytes()),
    }
}

/// Get diff via QUIC.
/// Payload format: [user_id: 16B][local_root_len: 4B BE][local_root][num_known: 4B BE][known_hash_1: 32B][known_hash_2: 32B]...
async fn handle_get_diff(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    if payload.len() < 20 {
        return (STATUS_BAD_REQUEST, b"payload too short for get_diff".to_vec());
    }

    let user_id = uuid::Uuid::from_bytes(
        payload[..16].try_into().expect("checked length")
    );

    let local_root_len = u32::from_be_bytes(
        payload[16..20].try_into().expect("checked length")
    ) as usize;

    if payload.len() < 20 + local_root_len + 4 {
        return (STATUS_BAD_REQUEST, b"payload too short for local_root + num_known".to_vec());
    }

    let _local_root = &payload[20..20 + local_root_len];
    let offset = 20 + local_root_len;

    let num_known = u32::from_be_bytes(
        payload[offset..offset + 4].try_into().expect("checked length")
    ) as usize;

    let hashes_offset = offset + 4;
    if payload.len() < hashes_offset + num_known * 32 {
        return (STATUS_BAD_REQUEST, b"payload too short for known hashes".to_vec());
    }

    let mut known_set = std::collections::HashSet::new();
    for i in 0..num_known {
        let start = hashes_offset + i * 32;
        let hash = &payload[start..start + 32];
        known_set.insert(hash.to_vec());
    }

    // Get all server hashes for this user.
    let server_hashes = match blobs::list_blob_hashes(&state.pool, user_id).await {
        Ok(h) => h,
        Err(e) => return (STATUS_ERROR, format!("db error: {e}").into_bytes()),
    };

    // Filter to those the client doesn't know about.
    let missing: Vec<&Vec<u8>> = server_hashes
        .iter()
        .filter(|h| !known_set.contains(h.as_slice()))
        .collect();

    // Response: [num_missing: 4B BE][hash1: 32B][hash2: 32B]...
    let mut response = Vec::with_capacity(4 + missing.len() * 32);
    response.extend_from_slice(&(missing.len() as u32).to_be_bytes());
    for hash in &missing {
        response.extend_from_slice(hash);
    }

    (STATUS_OK, response)
}

/// Register/auth via QUIC.
///
/// New format: [username_len: 2B BE][username][salt: 32B][auth_key_hash: 32B]
/// Legacy format: [auth_key_hash: 32B] (exactly 32 bytes)
///
/// Response: user_id string (UUID)
async fn handle_register(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    // Legacy format: exactly 32 bytes = auth_key_hash only.
    if payload.len() == 32 {
        return handle_register_legacy(state, payload).await;
    }

    // New format: [username_len: 2B BE][username][salt: 32B][auth_key_hash: 32B]
    if payload.len() < 2 {
        return (STATUS_BAD_REQUEST, b"payload too short for register".to_vec());
    }

    let username_len = u16::from_be_bytes(
        payload[..2].try_into().expect("checked length")
    ) as usize;

    let expected_len = 2 + username_len + 32 + 32;
    if payload.len() < expected_len {
        return (STATUS_BAD_REQUEST, format!(
            "payload too short: need {} bytes, got {}", expected_len, payload.len()
        ).into_bytes());
    }

    let username = match std::str::from_utf8(&payload[2..2 + username_len]) {
        Ok(s) => s.to_string(),
        Err(_) => return (STATUS_BAD_REQUEST, b"invalid UTF-8 in username".to_vec()),
    };

    let salt = &payload[2 + username_len..2 + username_len + 32];
    let auth_key_hash = &payload[2 + username_len + 32..2 + username_len + 64];

    // Check if user with this username already exists.
    match crate::db::users::get_user_by_username(&state.pool, &username).await {
        Ok(Some((existing_id, existing_key))) => {
            // Verify auth_key_hash matches.
            if existing_key == auth_key_hash {
                tracing::info!(user_id = %existing_id, username = %username, "existing user logged in via QUIC");
                return (STATUS_OK, existing_id.to_string().into_bytes());
            } else {
                return (STATUS_BAD_REQUEST, b"username exists but auth_key_hash mismatch".to_vec());
            }
        }
        Ok(None) => {}
        Err(e) => return (STATUS_ERROR, format!("db lookup error: {e}").into_bytes()),
    }

    // Create new user with username.
    match crate::db::users::create_user_with_username(
        &state.pool, &username, salt, auth_key_hash, auth_key_hash,
    ).await {
        Ok(user_id) => {
            tracing::info!(user_id = %user_id, username = %username, "new user registered via QUIC");
            (STATUS_CREATED, user_id.to_string().into_bytes())
        }
        Err(e) => (STATUS_ERROR, format!("create user error: {e}").into_bytes()),
    }
}

/// Legacy register handler (no username).
async fn handle_register_legacy(state: &AppState, auth_key_hash: &[u8]) -> (u8, Vec<u8>) {
    match crate::db::users::get_user_by_public_key(&state.pool, auth_key_hash).await {
        Ok(Some(existing_id)) => {
            tracing::info!(user_id = %existing_id, "existing user logged in via QUIC (legacy)");
            return (STATUS_OK, existing_id.to_string().into_bytes());
        }
        Ok(None) => {}
        Err(e) => {
            return (STATUS_ERROR, format!("db lookup error: {e}").into_bytes());
        }
    }

    match crate::db::users::create_user(&state.pool, auth_key_hash, auth_key_hash).await {
        Ok(user_id) => {
            tracing::info!(user_id = %user_id, "new user registered via QUIC (legacy)");
            (STATUS_CREATED, user_id.to_string().into_bytes())
        }
        Err(e) => (STATUS_ERROR, format!("create user error: {e}").into_bytes()),
    }
}

/// Get salt for a username via QUIC.
/// Payload format: [username_len: 4B BE][username]
/// Response: [salt: 32B] or STATUS_NOT_FOUND
async fn handle_get_salt(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    if payload.len() < 4 {
        return (STATUS_BAD_REQUEST, b"payload too short for get_salt".to_vec());
    }

    let username_len = u32::from_be_bytes(
        payload[..4].try_into().expect("checked length")
    ) as usize;

    if payload.len() < 4 + username_len {
        return (STATUS_BAD_REQUEST, b"payload truncated".to_vec());
    }

    let username = match std::str::from_utf8(&payload[4..4 + username_len]) {
        Ok(s) => s,
        Err(_) => return (STATUS_BAD_REQUEST, b"invalid UTF-8 in username".to_vec()),
    };

    match crate::db::users::get_salt_by_username(&state.pool, username).await {
        Ok(Some(salt)) => {
            tracing::debug!(username = %username, "salt returned via QUIC");
            (STATUS_OK, salt)
        }
        Ok(None) => (STATUS_NOT_FOUND, b"username not found".to_vec()),
        Err(e) => (STATUS_ERROR, format!("db error: {e}").into_bytes()),
    }
}

/// List manifests for a user via QUIC.
/// Payload format: [user_id: 16B]
/// Response: JSON array of manifest summaries
async fn handle_list_manifests(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    if payload.len() != 16 {
        return (STATUS_BAD_REQUEST, b"user_id must be 16 bytes".to_vec());
    }

    let user_id = uuid::Uuid::from_bytes(
        payload.try_into().expect("checked length")
    );

    match manifests::list_manifests_for_user(&state.pool, user_id).await {
        Ok(list) => {
            tracing::info!(user_id = %user_id, count = list.len(), "LIST_MANIFESTS result");
            match serde_json::to_vec(&list) {
                Ok(json) => (STATUS_OK, json),
                Err(e) => (STATUS_ERROR, format!("json serialization error: {e}").into_bytes()),
            }
        }
        Err(e) => (STATUS_ERROR, format!("db error: {e}").into_bytes()),
    }
}

/// Delete a manifest via QUIC.
/// Payload format: [user_id: 16B][manifest_id: 36B UTF-8 UUID]
/// Response: "ok" or error
async fn handle_delete_manifest(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    if payload.len() < 52 {
        return (STATUS_BAD_REQUEST, b"payload too short for delete_manifest".to_vec());
    }

    let user_id = uuid::Uuid::from_bytes(
        payload[..16].try_into().expect("checked length")
    );

    let manifest_id_str = match std::str::from_utf8(&payload[16..]) {
        Ok(s) => s.trim(),
        Err(_) => return (STATUS_BAD_REQUEST, b"invalid UTF-8 in manifest id".to_vec()),
    };

    let manifest_id: uuid::Uuid = match manifest_id_str.parse() {
        Ok(id) => id,
        Err(e) => return (STATUS_BAD_REQUEST, format!("invalid UUID: {e}").into_bytes()),
    };

    match manifests::delete_manifest(&state.pool, manifest_id, user_id).await {
        Ok(()) => {
            tracing::info!(manifest_id = %manifest_id, "manifest deleted via QUIC");
            (STATUS_OK, b"ok".to_vec())
        }
        Err(e) => (STATUS_ERROR, format!("delete error: {e}").into_bytes()),
    }
}

/// Database overview via QUIC.
/// Payload format: [user_id: 16B]
/// Response: JSON overview object
async fn handle_db_overview(state: &AppState, payload: &[u8]) -> (u8, Vec<u8>) {
    if payload.len() != 16 {
        return (STATUS_BAD_REQUEST, b"user_id must be 16 bytes".to_vec());
    }

    let user_id = uuid::Uuid::from_bytes(
        payload.try_into().expect("checked length")
    );

    let manifest_list = match manifests::list_manifests_for_user(&state.pool, user_id).await {
        Ok(list) => list,
        Err(e) => return (STATUS_ERROR, format!("db error: {e}").into_bytes()),
    };

    let blob_summaries = match blobs::list_blob_summaries(&state.pool, user_id).await {
        Ok(s) => s,
        Err(e) => return (STATUS_ERROR, format!("db error: {e}").into_bytes()),
    };

    let total_blob_bytes: i64 = blob_summaries.iter().map(|(_, size)| *size as i64).sum();

    let overview = serde_json::json!({
        "manifests": manifest_list,
        "blobs": blob_summaries.iter().map(|(hash_hex, size)| {
            serde_json::json!({ "hash_hex": hash_hex, "size": size })
        }).collect::<Vec<_>>(),
        "total_manifests": manifest_list.len(),
        "total_blobs": blob_summaries.len(),
        "total_blob_bytes": total_blob_bytes,
    });

    match serde_json::to_vec(&overview) {
        Ok(json) => (STATUS_OK, json),
        Err(e) => (STATUS_ERROR, format!("json serialization error: {e}").into_bytes()),
    }
}
