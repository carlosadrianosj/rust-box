use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{Result, ServerError};

/// Insert a new blob (encrypted chunk) into the database.
///
/// Returns an error if a blob with the same hash already exists.
pub async fn insert_blob(pool: &PgPool, hash: &[u8], data: &[u8], user_id: Uuid) -> Result<()> {
    let size = data.len() as i32;

    let result = sqlx::query(
        "INSERT INTO blobs (hash, data, size, user_id) VALUES ($1, $2, $3, $4) ON CONFLICT (hash) DO NOTHING"
    )
    .bind(hash)
    .bind(data)
    .bind(size)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| ServerError::Database(format!("insert_blob failed: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(ServerError::Conflict(format!(
            "blob with hash {} already exists",
            hex::encode(hash)
        )));
    }

    Ok(())
}

/// Get a blob's data by its hash.
pub async fn get_blob(pool: &PgPool, hash: &[u8]) -> Result<Option<Vec<u8>>> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT data FROM blobs WHERE hash = $1"
    )
    .bind(hash)
    .fetch_optional(pool)
    .await
    .map_err(|e| ServerError::Database(format!("get_blob failed: {e}")))?;

    Ok(row.map(|(data,)| data))
}

/// Check if a blob exists by its hash.
pub async fn blob_exists(pool: &PgPool, hash: &[u8]) -> Result<bool> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = $1)"
    )
    .bind(hash)
    .fetch_optional(pool)
    .await
    .map_err(|e| ServerError::Database(format!("blob_exists failed: {e}")))?;

    Ok(row.map(|(exists,)| exists).unwrap_or(false))
}

/// List blob summaries (hash_hex, size) for a given user — no data.
pub async fn list_blob_summaries(pool: &PgPool, user_id: Uuid) -> Result<Vec<(String, i32)>> {
    let rows: Vec<(Vec<u8>, i32)> = sqlx::query_as(
        "SELECT hash, size FROM blobs WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ServerError::Database(format!("list_blob_summaries failed: {e}")))?;

    Ok(rows.into_iter().map(|(h, s)| (hex::encode(&h), s)).collect())
}

/// List all blob hashes for a given user.
pub async fn list_blob_hashes(pool: &PgPool, user_id: Uuid) -> Result<Vec<Vec<u8>>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT hash FROM blobs WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ServerError::Database(format!("list_blob_hashes failed: {e}")))?;

    Ok(rows.into_iter().map(|(h,)| h).collect())
}
