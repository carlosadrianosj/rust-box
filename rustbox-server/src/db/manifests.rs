use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{Result, ServerError};

/// Insert a new manifest and return the generated UUID.
pub async fn insert_manifest(
    pool: &PgPool,
    user_id: Uuid,
    data: &[u8],
    merkle_root: &[u8],
) -> Result<Uuid> {
    // Compute next version for this user.
    let next_version: i64 = {
        let row: Option<(Option<i64>,)> = sqlx::query_as(
            "SELECT MAX(version) FROM manifests WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ServerError::Database(format!("version query failed: {e}")))?;

        row.and_then(|(v,)| v).unwrap_or(0) + 1
    };

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO manifests (user_id, data, merkle_root, version) VALUES ($1, $2, $3, $4) RETURNING id"
    )
    .bind(user_id)
    .bind(data)
    .bind(merkle_root)
    .bind(next_version)
    .fetch_one(pool)
    .await
    .map_err(|e| ServerError::Database(format!("insert_manifest failed: {e}")))?;

    Ok(row.0)
}

/// Get manifest data by ID.
pub async fn get_manifest(pool: &PgPool, id: Uuid) -> Result<Option<Vec<u8>>> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT data FROM manifests WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ServerError::Database(format!("get_manifest failed: {e}")))?;

    Ok(row.map(|(data,)| data))
}

/// Get the latest manifest for a user (data and version).
#[allow(dead_code)]
pub async fn get_latest_manifest(pool: &PgPool, user_id: Uuid) -> Result<Option<(Vec<u8>, i64)>> {
    let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT data, version FROM manifests WHERE user_id = $1 ORDER BY version DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ServerError::Database(format!("get_latest_manifest failed: {e}")))?;

    Ok(row)
}

/// List all manifests for a user (summary only — no data blob).
pub async fn list_manifests_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<serde_json::Value>> {
    let rows: Vec<(Uuid, i32, Vec<u8>, i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, octet_length(data) as data_size, merkle_root, version, created_at \
         FROM manifests WHERE user_id = $1 ORDER BY version ASC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ServerError::Database(format!("list_manifests_for_user failed: {e}")))?;

    let list: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, data_size, merkle_root, version, created_at)| {
            serde_json::json!({
                "id": id.to_string(),
                "data_size": data_size,
                "merkle_root_hex": hex::encode(&merkle_root),
                "version": version,
                "created_at": created_at.to_rfc3339(),
            })
        })
        .collect();

    Ok(list)
}

/// Delete a manifest by ID, but only if it belongs to the given user.
pub async fn delete_manifest(pool: &PgPool, manifest_id: Uuid, user_id: Uuid) -> Result<()> {
    let result = sqlx::query(
        "DELETE FROM manifests WHERE id = $1 AND user_id = $2"
    )
    .bind(manifest_id)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| ServerError::Database(format!("delete_manifest failed: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(ServerError::NotFound(format!(
            "manifest {} not found or not owned by user", manifest_id
        )));
    }

    Ok(())
}

/// Get the merkle root and version for the latest manifest of a user.
pub async fn get_merkle_root(pool: &PgPool, user_id: Uuid) -> Result<Option<(Vec<u8>, i64)>> {
    let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT merkle_root, version FROM manifests WHERE user_id = $1 ORDER BY version DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ServerError::Database(format!("get_merkle_root failed: {e}")))?;

    Ok(row)
}
