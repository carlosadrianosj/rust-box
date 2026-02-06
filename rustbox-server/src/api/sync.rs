use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::{blobs, manifests};
use crate::error::ServerError;
use crate::state::AppState;

/// Query parameters for GET /api/sync/root.
#[derive(Debug, Deserialize)]
pub struct RootQuery {
    pub user_id: String,
}

/// Request body for POST /api/sync/diff.
#[derive(Debug, Deserialize)]
pub struct DiffRequest {
    pub user_id: String,
    pub local_root: String,
    /// Hex-encoded hashes of chunks the client already has.
    #[serde(default)]
    pub known_hashes: Vec<String>,
}

/// Response body for POST /api/sync/diff.
#[derive(Debug, Serialize)]
pub struct DiffResponse {
    /// Hex-encoded hashes of chunks on the server that the client does not have.
    pub missing_hashes: Vec<String>,
    /// Whether the roots match (no sync needed).
    pub in_sync: bool,
}

/// GET /api/sync/root?user_id=X
///
/// Returns the latest merkle root and version for the given user.
pub async fn get_root(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RootQuery>,
) -> Result<impl IntoResponse, ServerError> {
    let user_id: uuid::Uuid = params.user_id.parse()
        .map_err(|e| ServerError::BadRequest(format!("invalid user_id: {e}")))?;

    let result = manifests::get_merkle_root(&state.pool, user_id).await?;

    match result {
        Some((root, version)) => {
            Ok((
                StatusCode::OK,
                Json(json!({
                    "merkle_root": hex::encode(&root),
                    "version": version,
                })),
            ))
        }
        None => {
            Ok((
                StatusCode::OK,
                Json(json!({
                    "merkle_root": serde_json::Value::Null,
                    "version": 0,
                })),
            ))
        }
    }
}

/// POST /api/sync/diff
///
/// Accepts the client's local merkle root and list of known chunk hashes.
/// Returns the list of chunk hashes on the server that the client is missing.
pub async fn get_diff(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DiffRequest>,
) -> Result<impl IntoResponse, ServerError> {
    let user_id: uuid::Uuid = req.user_id.parse()
        .map_err(|e| ServerError::BadRequest(format!("invalid user_id: {e}")))?;

    // Get the server's latest merkle root.
    let server_root = manifests::get_merkle_root(&state.pool, user_id).await?;

    let in_sync = match &server_root {
        Some((root, _version)) => hex::encode(root) == req.local_root,
        None => req.local_root.is_empty(),
    };

    if in_sync {
        return Ok((
            StatusCode::OK,
            Json(DiffResponse {
                missing_hashes: vec![],
                in_sync: true,
            }),
        ));
    }

    // Get all blob hashes on the server for this user.
    let server_hashes = blobs::list_blob_hashes(&state.pool, user_id).await?;

    // Build a set of known client hashes for fast lookup.
    let known_set: std::collections::HashSet<String> = req.known_hashes.into_iter().collect();

    // Find hashes on the server that the client doesn't have.
    let missing: Vec<String> = server_hashes
        .iter()
        .map(|h| hex::encode(h))
        .filter(|hex_hash| !known_set.contains(hex_hash))
        .collect();

    Ok((
        StatusCode::OK,
        Json(DiffResponse {
            missing_hashes: missing,
            in_sync: false,
        }),
    ))
}
