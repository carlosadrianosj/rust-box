use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{Result, ServerError};

/// Create a new user with a public key and auth token.
/// Returns the generated user UUID.
pub async fn create_user(pool: &PgPool, public_key: &[u8], auth_token: &[u8]) -> Result<Uuid> {
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO users (public_key, auth_token) VALUES ($1, $2) RETURNING id"
    )
    .bind(public_key)
    .bind(auth_token)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") || msg.contains("unique") {
            ServerError::Conflict(format!("user with this public key already exists"))
        } else {
            ServerError::Database(format!("create_user failed: {e}"))
        }
    })?;

    Ok(row.0)
}

/// Create a new user with username, salt, public key, and auth token.
/// Returns the generated user UUID.
pub async fn create_user_with_username(
    pool: &PgPool,
    username: &str,
    salt: &[u8],
    public_key: &[u8],
    auth_token: &[u8],
) -> Result<Uuid> {
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO users (username, salt, public_key, auth_token) VALUES ($1, $2, $3, $4) RETURNING id"
    )
    .bind(username)
    .bind(salt)
    .bind(public_key)
    .bind(auth_token)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") || msg.contains("unique") {
            ServerError::Conflict(format!("user '{}' already exists", username))
        } else {
            ServerError::Database(format!("create_user_with_username failed: {e}"))
        }
    })?;

    Ok(row.0)
}

/// Look up a user ID by their public key.
pub async fn get_user_by_public_key(pool: &PgPool, public_key: &[u8]) -> Result<Option<Uuid>> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE public_key = $1"
    )
    .bind(public_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| ServerError::Database(format!("get_user_by_public_key failed: {e}")))?;

    Ok(row.map(|(id,)| id))
}

/// Get a user by their UUID.
#[allow(dead_code)]
pub async fn get_user_by_id(pool: &PgPool, user_id: Uuid) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT public_key, auth_token FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ServerError::Database(format!("get_user_by_id failed: {e}")))?;

    Ok(row)
}

/// Get the salt for a user by their username.
/// Returns None if the username is not found.
pub async fn get_salt_by_username(pool: &PgPool, username: &str) -> Result<Option<Vec<u8>>> {
    let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
        "SELECT salt FROM users WHERE username = $1"
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|e| ServerError::Database(format!("get_salt_by_username failed: {e}")))?;

    Ok(row.and_then(|(salt,)| salt))
}

/// Get user ID and public_key by username.
/// Returns None if the username is not found.
pub async fn get_user_by_username(pool: &PgPool, username: &str) -> Result<Option<(Uuid, Vec<u8>)>> {
    let row: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, public_key FROM users WHERE username = $1"
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|e| ServerError::Database(format!("get_user_by_username failed: {e}")))?;

    Ok(row)
}
