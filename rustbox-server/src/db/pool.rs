use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::error::{Result, ServerError};

/// Create a PostgreSQL connection pool with sensible defaults.
///
/// - max_connections: 10
/// - connect_timeout: 5 seconds
pub async fn create_pool(url: &str) -> Result<PgPool> {
    let pool: PgPool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .map_err(|e| ServerError::Database(format!("failed to connect to database: {e}")))?;

    tracing::info!("database connection pool created");
    Ok(pool)
}

/// Run the initial schema migration (idempotent, uses IF NOT EXISTS).
///
/// Each statement must be executed separately because PostgreSQL's prepared
/// statements do not support multiple commands.
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            public_key BYTEA UNIQUE NOT NULL,
            auth_token BYTEA NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .map_err(|e| ServerError::Database(format!("migration (users) failed: {e}")))?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS blobs (
            hash BYTEA PRIMARY KEY,
            data BYTEA NOT NULL,
            size INT NOT NULL,
            user_id UUID REFERENCES users(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .map_err(|e| ServerError::Database(format!("migration (blobs) failed: {e}")))?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS manifests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id),
            data BYTEA NOT NULL,
            merkle_root BYTEA,
            version BIGINT NOT NULL DEFAULT 1,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .map_err(|e| ServerError::Database(format!("migration (manifests) failed: {e}")))?;

    tracing::info!("database migrations applied");
    Ok(())
}
