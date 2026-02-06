use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::db::users;
use crate::error::ServerError;
use crate::state::AppState;

/// Registration request body.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Hex-encoded auth_key_hash (32 bytes SHA-256).
    pub auth_key_hash: String,
    /// Optional username for cross-client identity.
    pub username: Option<String>,
    /// Optional hex-encoded salt (32 bytes) — sent only on first registration.
    pub salt_hex: Option<String>,
}

/// Query parameters for the salt endpoint.
#[derive(Debug, Deserialize)]
pub struct SaltQuery {
    pub username: String,
}

/// GET /api/auth/salt?username=X
///
/// Returns the stored salt for a username, or 404 if not found.
pub async fn get_salt(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SaltQuery>,
) -> Result<impl IntoResponse, ServerError> {
    let salt = users::get_salt_by_username(&state.pool, &params.username).await?;

    match salt {
        Some(salt_bytes) => {
            tracing::debug!(username = %params.username, "salt returned for user");
            Ok((
                StatusCode::OK,
                Json(json!({
                    "salt_hex": hex::encode(&salt_bytes),
                })),
            ))
        }
        None => Err(ServerError::NotFound(format!(
            "no salt found for username '{}'",
            params.username
        ))),
    }
}

/// POST /api/auth/register
///
/// Accepts a hex-encoded auth_key_hash (32 bytes), optional username and salt.
/// Creates a user record, and returns the user UUID.
/// Same protocol as QUIC register (CMD 0x10).
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ServerError> {
    let key_bytes = hex::decode(&req.auth_key_hash)
        .map_err(|e| ServerError::BadRequest(format!("invalid hex auth_key_hash: {e}")))?;

    if key_bytes.len() != 32 {
        return Err(ServerError::BadRequest(
            "auth_key_hash must be 32 bytes".to_string(),
        ));
    }

    // If username is provided, use the username-based flow.
    if let Some(ref username) = req.username {
        // Check if user with this username already exists.
        if let Some((existing_id, existing_key)) =
            users::get_user_by_username(&state.pool, username).await?
        {
            // Verify auth_key_hash matches.
            if existing_key == key_bytes {
                tracing::info!(user_id = %existing_id, username = %username, "existing user logged in via HTTP");
                return Ok((
                    StatusCode::OK,
                    Json(json!({
                        "user_id": existing_id.to_string(),
                        "existing": true,
                    })),
                ));
            } else {
                return Err(ServerError::BadRequest(
                    "username exists but auth_key_hash does not match".to_string(),
                ));
            }
        }

        // New user — salt must be provided.
        let salt_bytes = if let Some(ref salt_hex) = req.salt_hex {
            hex::decode(salt_hex)
                .map_err(|e| ServerError::BadRequest(format!("invalid hex salt: {e}")))?
        } else {
            return Err(ServerError::BadRequest(
                "salt_hex is required for first registration with username".to_string(),
            ));
        };

        let user_id = users::create_user_with_username(
            &state.pool,
            username,
            &salt_bytes,
            &key_bytes,
            &key_bytes,
        )
        .await?;

        tracing::info!(user_id = %user_id, username = %username, "new user registered via HTTP");

        return Ok((
            StatusCode::CREATED,
            Json(json!({
                "user_id": user_id.to_string(),
                "existing": false,
            })),
        ));
    }

    // Legacy flow: no username, just auth_key_hash.
    if let Some(existing_id) = users::get_user_by_public_key(&state.pool, &key_bytes).await? {
        return Ok((
            StatusCode::OK,
            Json(json!({
                "user_id": existing_id.to_string(),
                "existing": true,
            })),
        ));
    }

    // Use auth_key_hash as both public_key and auth_token (same as QUIC handler).
    let user_id = users::create_user(&state.pool, &key_bytes, &key_bytes).await?;

    tracing::info!(user_id = %user_id, "new user registered via HTTP (legacy)");

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "user_id": user_id.to_string(),
            "existing": false,
        })),
    ))
}
