use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use rusqlite::Connection;
use tokio::sync::Mutex;
use tracing::debug;

use rustbox_core::error::RustBoxError;
use rustbox_core::traits::storage::PersistentStorage;

/// Persistent key-value metadata storage backed by SQLite.
///
/// Uses a single `metadata(key TEXT PRIMARY KEY, value BLOB)` table.
/// Synchronous rusqlite calls are wrapped in `tokio::task::spawn_blocking`.
pub struct SqliteMeta {
    conn: Arc<Mutex<Connection>>,
    #[allow(dead_code)]
    db_path: PathBuf,
}

impl SqliteMeta {
    /// Open (or create) the SQLite database at the given path.
    pub fn open(db_path: &Path) -> Result<Self, RustBoxError> {
        let conn = Connection::open(db_path)
            .map_err(|e| RustBoxError::Storage(format!("open SQLite DB failed: {e}")))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )",
            [],
        )
        .map_err(|e| RustBoxError::Storage(format!("create metadata table failed: {e}")))?;

        // Enable WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| RustBoxError::Storage(format!("set WAL mode failed: {e}")))?;

        debug!("Opened SQLite metadata DB at {}", db_path.display());

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: db_path.to_path_buf(),
        })
    }
}

#[async_trait(?Send)]
impl PersistentStorage for SqliteMeta {
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), RustBoxError> {
        let conn = self.conn.clone();
        let key = key.to_string();
        let value = value.to_vec();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, value],
            )
            .map_err(|e| RustBoxError::Storage(format!("sqlite set failed: {e}")))?;

            debug!("Set key '{}' ({} bytes)", key, value.len());
            Ok(())
        })
        .await
        .map_err(|e| RustBoxError::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, RustBoxError> {
        let conn = self.conn.clone();
        let key = key.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare("SELECT value FROM metadata WHERE key = ?1")
                .map_err(|e| RustBoxError::Storage(format!("sqlite prepare failed: {e}")))?;

            let result: Result<Vec<u8>, _> =
                stmt.query_row(rusqlite::params![key], |row| row.get(0));

            match result {
                Ok(value) => {
                    debug!("Got key '{}' ({} bytes)", key, value.len());
                    Ok(Some(value))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    debug!("Key '{}' not found", key);
                    Ok(None)
                }
                Err(e) => Err(RustBoxError::Storage(format!("sqlite get failed: {e}"))),
            }
        })
        .await
        .map_err(|e| RustBoxError::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn delete(&self, key: &str) -> Result<(), RustBoxError> {
        let conn = self.conn.clone();
        let key = key.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "DELETE FROM metadata WHERE key = ?1",
                rusqlite::params![key],
            )
            .map_err(|e| RustBoxError::Storage(format!("sqlite delete failed: {e}")))?;

            debug!("Deleted key '{}'", key);
            Ok(())
        })
        .await
        .map_err(|e| RustBoxError::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, RustBoxError> {
        let conn = self.conn.clone();
        let prefix = prefix.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let pattern = format!("{prefix}%");
            let mut stmt = conn
                .prepare("SELECT key FROM metadata WHERE key LIKE ?1 ORDER BY key")
                .map_err(|e| RustBoxError::Storage(format!("sqlite prepare failed: {e}")))?;

            let keys: Vec<String> = stmt
                .query_map(rusqlite::params![pattern], |row| row.get(0))
                .map_err(|e| RustBoxError::Storage(format!("sqlite query failed: {e}")))?
                .collect::<Result<Vec<String>, _>>()
                .map_err(|e| RustBoxError::Storage(format!("sqlite collect failed: {e}")))?;

            debug!("Listed {} keys with prefix '{}'", keys.len(), prefix);
            Ok(keys)
        })
        .await
        .map_err(|e| RustBoxError::Storage(format!("spawn_blocking failed: {e}")))?
    }
}
