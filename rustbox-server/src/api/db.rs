use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use crate::db::{manifests, blobs};
use crate::error::ServerError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct UserIdQuery {
    pub user_id: String,
}

/// GET /api/db/overview?user_id={uuid}
///
/// Returns database overview: manifests, blobs, totals.
pub async fn get_overview(
    State(state): State<Arc<AppState>>,
    Query(params): Query<UserIdQuery>,
) -> Result<impl IntoResponse, ServerError> {
    let user_id: uuid::Uuid = params.user_id
        .parse()
        .map_err(|e| ServerError::BadRequest(format!("invalid user_id: {e}")))?;

    let manifest_list = manifests::list_manifests_for_user(&state.pool, user_id).await?;

    let blob_summaries = blobs::list_blob_summaries(&state.pool, user_id).await?;

    let total_blob_bytes: i64 = blob_summaries.iter().map(|(_, size)| *size as i64).sum();

    let overview = json!({
        "manifests": manifest_list,
        "blobs": blob_summaries.iter().map(|(hash_hex, size)| {
            json!({ "hash_hex": hash_hex, "size": size })
        }).collect::<Vec<serde_json::Value>>(),
        "total_manifests": manifest_list.len(),
        "total_blobs": blob_summaries.len(),
        "total_blob_bytes": total_blob_bytes,
    });

    Ok(axum::Json(overview))
}
