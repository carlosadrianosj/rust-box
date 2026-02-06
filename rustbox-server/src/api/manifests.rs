use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sha2::{Sha256, Digest};
use serde::Deserialize;
use serde_json::json;

use crate::db::manifests as db;
use crate::error::ServerError;
use crate::state::AppState;

/// POST /api/manifests?user_id={uuid}
///
/// Upload an encrypted manifest. The body is raw bytes (the encrypted manifest).
/// The server computes SHA-256 of the body as a merkle_root placeholder,
/// stores the manifest, and returns the generated UUID as JSON: {"id": "<uuid>"}.
pub async fn upload_manifest(
    State(state): State<Arc<AppState>>,
    Query(params): Query<UserIdQuery>,
    body: Bytes,
) -> Result<impl IntoResponse, ServerError> {
    if body.is_empty() {
        return Err(ServerError::BadRequest("manifest body cannot be empty".to_string()));
    }

    let user_id: uuid::Uuid = params.user_id
        .parse()
        .map_err(|e| ServerError::BadRequest(format!("invalid user_id: {e}")))?;

    // Use SHA-256 of the manifest body as the merkle_root placeholder.
    let merkle_root = Sha256::digest(&body).to_vec();

    let id = db::insert_manifest(&state.pool, user_id, &body, &merkle_root).await?;

    tracing::info!(manifest_id = %id, size = body.len(), "manifest uploaded");

    Ok((StatusCode::CREATED, axum::Json(json!({ "id": id.to_string() }))))
}

/// GET /api/manifests/{id}
///
/// Download an encrypted manifest by its UUID.
/// Returns 200 with the raw bytes or 404 if not found.
pub async fn download_manifest(
    State(state): State<Arc<AppState>>,
    Path(id_str): Path<String>,
) -> Result<impl IntoResponse, ServerError> {
    let id: uuid::Uuid = id_str
        .parse()
        .map_err(|e| ServerError::BadRequest(format!("invalid UUID: {e}")))?;

    let data = db::get_manifest(&state.pool, id).await?;

    match data {
        Some(bytes) => {
            tracing::debug!(manifest_id = %id, size = bytes.len(), "manifest downloaded");
            Ok((StatusCode::OK, bytes))
        }
        None => Err(ServerError::NotFound(format!("manifest {} not found", id))),
    }
}

#[derive(Deserialize)]
pub struct UserIdQuery {
    pub user_id: String,
}

/// GET /api/manifests/list?user_id={uuid}
///
/// List all manifests for a user (metadata only, no data).
pub async fn list_manifests(
    State(state): State<Arc<AppState>>,
    Query(params): Query<UserIdQuery>,
) -> Result<impl IntoResponse, ServerError> {
    let user_id: uuid::Uuid = params.user_id
        .parse()
        .map_err(|e| ServerError::BadRequest(format!("invalid user_id: {e}")))?;

    let manifests = db::list_manifests_for_user(&state.pool, user_id).await?;

    tracing::debug!(user_id = %user_id, count = manifests.len(), "manifests listed");

    Ok(axum::Json(json!({ "manifests": manifests })))
}

/// DELETE /api/manifests/{id}?user_id={uuid}
///
/// Delete a manifest (only if owned by user).
pub async fn delete_manifest(
    State(state): State<Arc<AppState>>,
    Path(id_str): Path<String>,
    Query(params): Query<UserIdQuery>,
) -> Result<impl IntoResponse, ServerError> {
    let manifest_id: uuid::Uuid = id_str
        .parse()
        .map_err(|e| ServerError::BadRequest(format!("invalid manifest UUID: {e}")))?;
    let user_id: uuid::Uuid = params.user_id
        .parse()
        .map_err(|e| ServerError::BadRequest(format!("invalid user_id: {e}")))?;

    db::delete_manifest(&state.pool, manifest_id, user_id).await?;

    tracing::info!(manifest_id = %manifest_id, user_id = %user_id, "manifest deleted");

    Ok((StatusCode::OK, axum::Json(json!({ "deleted": true }))))
}
