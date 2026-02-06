use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use sha2::{Sha256, Digest};

use crate::db::blobs;
use crate::error::ServerError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ChunkUserQuery {
    pub user_id: Option<String>,
}

/// PUT /api/chunks/{hash}?user_id={uuid}
///
/// Upload an encrypted chunk. The hash in the URL is the hex-encoded SHA-256
/// of the chunk body. The server verifies that SHA-256(body) == hash before storing.
///
/// Returns 201 Created on success, 409 Conflict if the blob already exists,
/// or 400 Bad Request if the hash does not match.
pub async fn upload_chunk(
    State(state): State<Arc<AppState>>,
    Path(hash_hex): Path<String>,
    Query(params): Query<ChunkUserQuery>,
    body: Bytes,
) -> Result<impl IntoResponse, ServerError> {
    // Decode the expected hash from the URL.
    let expected_hash = hex::decode(&hash_hex)
        .map_err(|e| ServerError::BadRequest(format!("invalid hex hash: {e}")))?;

    if expected_hash.len() != 32 {
        return Err(ServerError::BadRequest(
            "hash must be 32 bytes (SHA-256)".to_string(),
        ));
    }

    // Compute the actual hash of the uploaded body.
    let actual_hash = Sha256::digest(&body);
    if actual_hash.as_slice() != expected_hash.as_slice() {
        return Err(ServerError::BadRequest(format!(
            "hash mismatch: expected {}, got {}",
            hash_hex,
            hex::encode(actual_hash)
        )));
    }

    let user_id_str = params.user_id.ok_or_else(|| {
        ServerError::BadRequest("user_id query parameter is required".to_string())
    })?;
    let user_id: uuid::Uuid = user_id_str
        .parse()
        .map_err(|e| ServerError::BadRequest(format!("invalid user_id: {e}")))?;

    // Check if blob already exists to return 409 instead of DB error.
    if blobs::blob_exists(&state.pool, &expected_hash).await? {
        return Err(ServerError::Conflict(format!(
            "chunk {} already exists",
            hash_hex
        )));
    }

    blobs::insert_blob(&state.pool, &expected_hash, &body, user_id).await?;

    tracing::info!(
        hash = %hash_hex,
        size = body.len(),
        "chunk uploaded"
    );

    Ok(StatusCode::CREATED)
}

/// GET /api/chunks/{hash}
///
/// Download an encrypted chunk by its hex-encoded SHA-256 hash.
/// Returns 200 with the raw bytes or 404 if the chunk does not exist.
pub async fn download_chunk(
    State(state): State<Arc<AppState>>,
    Path(hash_hex): Path<String>,
) -> Result<impl IntoResponse, ServerError> {
    let hash = hex::decode(&hash_hex)
        .map_err(|e| ServerError::BadRequest(format!("invalid hex hash: {e}")))?;

    let data = blobs::get_blob(&state.pool, &hash).await?;

    match data {
        Some(bytes) => {
            tracing::debug!(hash = %hash_hex, size = bytes.len(), "chunk downloaded");
            Ok((StatusCode::OK, bytes))
        }
        None => Err(ServerError::NotFound(format!("chunk {} not found", hash_hex))),
    }
}
