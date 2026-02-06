use std::path::Path;

use tracing::info;

use rustbox_core::merkle::tree::MerkleTree;
use rustbox_core::traits::storage::{ContentAddressableStorage, PersistentStorage};

use crate::storage::{LocalFs, SqliteMeta};

/// Show the current status of the RustBox vault.
///
/// Displays tracked files, local Merkle root, sync state, and blob count.
pub async fn run_status() -> Result<(), Box<dyn std::error::Error>> {
    let rustbox_dir = Path::new(".rustbox");

    if !rustbox_dir.exists() {
        return Err("No RustBox vault found. Run `rustbox init` first.".into());
    }

    println!("RustBox Vault Status");
    println!("====================");

    // Show username
    let username_path = rustbox_dir.join("username");
    if username_path.exists() {
        let username = tokio::fs::read_to_string(&username_path).await.unwrap_or_default();
        println!("  User: {username}");
    }

    // Count local blobs.
    let blobs_dir = rustbox_dir.join("blobs");
    let local_store = LocalFs::new(&blobs_dir);
    let local_hashes = local_store.list_hashes().await?;

    let local_tree = MerkleTree::from_leaves(&local_hashes);
    let local_root = local_tree.root();

    println!();
    println!("Local storage:");
    println!("  Blobs:       {}", local_hashes.len());
    println!("  Merkle root: {}", hex::encode(&local_root[..16]));

    // Read metadata DB.
    let db_path = rustbox_dir.join("meta.db");
    if db_path.exists() {
        let meta_db = SqliteMeta::open(&db_path)?;

        // Show stored server address
        if let Some(server_bytes) = meta_db.get("server").await? {
            let server = String::from_utf8_lossy(&server_bytes);
            println!("  Server: {server}");
        }

        // Show user_id
        if let Some(uid_bytes) = meta_db.get("user_id").await? {
            let user_id = String::from_utf8_lossy(&uid_bytes);
            println!("  User ID: {user_id}");
        }

        // List tracked files.
        let manifest_keys = meta_db.list_keys("manifest:").await?;

        println!();
        if manifest_keys.is_empty() {
            println!("Tracked files: (none)");
        } else {
            println!("Tracked files:");
            for key in &manifest_keys {
                let file_id = key
                    .strip_prefix("manifest:")
                    .unwrap_or(key);

                let manifest_id = meta_db
                    .get(key)
                    .await?
                    .map(|v| String::from_utf8_lossy(&v).to_string())
                    .unwrap_or_else(|| "(unknown)".to_string());

                let file_hash = meta_db
                    .get(&format!("file_hash:{file_id}"))
                    .await?
                    .map(|v| hex::encode(&v[..8.min(v.len())]))
                    .unwrap_or_else(|| "(unknown)".to_string());

                println!("  - {file_id}");
                println!("    manifest: {manifest_id}");
                println!("    hash:     {file_hash}...");
            }
        }

        // Sync state.
        println!();
        let last_root = meta_db.get("sync:last_root").await?;
        let last_time = meta_db.get("sync:last_time").await?;

        match (last_root, last_time) {
            (Some(root), Some(time_bytes)) => {
                let root_hex = hex::encode(&root[..16.min(root.len())]);
                let timestamp = if time_bytes.len() == 8 {
                    let secs = u64::from_be_bytes(
                        time_bytes.try_into().unwrap_or([0u8; 8]),
                    );
                    format_timestamp(secs)
                } else {
                    "(invalid)".to_string()
                };

                println!("Last sync:");
                println!("  Root:    {root_hex}...");
                println!("  Time:    {timestamp}");

                // Check if local root matches last synced root.
                let in_sync = root.len() == 32 && {
                    let mut r = [0u8; 32];
                    r.copy_from_slice(&root);
                    r == local_root
                };

                if in_sync {
                    println!("  Status:  IN SYNC");
                } else {
                    println!("  Status:  OUT OF SYNC (local changes pending)");
                }
            }
            _ => {
                println!("Last sync: never");
            }
        }
    } else {
        println!();
        println!("Metadata DB: not found");
    }

    info!("Status displayed");
    Ok(())
}

/// Format a Unix timestamp into a human-readable date string.
fn format_timestamp(secs: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let time = UNIX_EPOCH + Duration::from_secs(secs);
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            // Simple formatting without chrono dependency.
            let total_secs = d.as_secs();
            let days = total_secs / 86400;
            let remaining = total_secs % 86400;
            let hours = remaining / 3600;
            let minutes = (remaining % 3600) / 60;
            let seconds = remaining % 60;

            // Approximate date from epoch days (not accounting for leap years precisely).
            let mut year = 1970u64;
            let mut remaining_days = days;
            loop {
                let days_in_year = if is_leap_year(year) { 366 } else { 365 };
                if remaining_days < days_in_year {
                    break;
                }
                remaining_days -= days_in_year;
                year += 1;
            }

            let months = [31, if is_leap_year(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let mut month = 1u64;
            for &m_days in &months {
                if remaining_days < m_days {
                    break;
                }
                remaining_days -= m_days;
                month += 1;
            }
            let day = remaining_days + 1;

            format!(
                "{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02} UTC"
            )
        }
        Err(_) => format!("epoch + {secs}s"),
    }
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
