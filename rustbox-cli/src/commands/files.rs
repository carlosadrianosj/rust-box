use std::path::Path;

use tracing::info;

use rustbox_core::constants::XCHACHA20_NONCE_LEN;
use rustbox_core::crypto::chacha20::xchacha20_decrypt;
use rustbox_core::crypto::key_hierarchy::derive_manifest_key;
use rustbox_core::manifest::file_manifest::FileManifest;
use rustbox_core::manifest::serialization::deserialize;
use rustbox_core::traits::storage::PersistentStorage;
use rustbox_core::traits::transport::Transport;

use crate::commands::init::unlock_vault;
use crate::storage::SqliteMeta;
use crate::transport::QuicTransport;

/// List all files on the RustBox server for the current user.
///
/// Connects to the server, fetches the manifest list, downloads and decrypts
/// each manifest client-side to extract filename, size, and chunk count.
pub async fn run_files(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let password = std::env::var("RUSTBOX_PASSWORD")
        .unwrap_or_else(|_| rpassword::prompt_password("Enter vault password: ").expect("failed to read password"));
    let master_key = unlock_vault(&password).await?;

    let meta_db = SqliteMeta::open(Path::new(".rustbox/meta.db"))?;
    let user_id_bytes = meta_db.get("user_id").await?
        .ok_or("not logged in: run `rustbox-cli login` first")?;
    let user_id_str = String::from_utf8(user_id_bytes)
        .map_err(|e| format!("invalid user_id in metadata: {e}"))?;

    info!("Connecting to server {server}...");
    let mut transport = QuicTransport::connect(server).await?;
    transport.set_user_id(&user_id_str)?;
    info!("Using user_id: {user_id_str}");

    let list_json = transport.list_manifests().await?;
    let server_data: serde_json::Value = serde_json::from_str(&list_json)?;

    // Server may return either {"manifests": [...]} or a bare array [...]
    let manifests = if let Some(arr) = server_data.get("manifests").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = server_data.as_array() {
        arr.clone()
    } else {
        Vec::new()
    };

    info!("Found {} file(s) on server", manifests.len());

    if manifests.is_empty() {
        println!("No files on server.");
        return Ok(());
    }

    println!("Server files for user {user_id_str}:");
    println!("{:<40} {:>12} {:>8}  {}", "FILENAME", "SIZE", "CHUNKS", "MANIFEST_ID");
    println!("{}", "-".repeat(90));

    for summary in &manifests {
        let manifest_id = summary.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let data_size = summary.get("data_size").and_then(|v| v.as_i64()).unwrap_or(0);

        match try_decrypt_manifest(&transport, manifest_id, &master_key).await {
            Ok((filename, size, chunks)) => {
                println!(
                    "{:<40} {:>12} {:>8}  {}",
                    truncate_str(&filename, 40),
                    format_size(size),
                    chunks,
                    manifest_id,
                );
            }
            Err(e) => {
                info!("Failed to decrypt manifest {manifest_id}: {e}");
                println!(
                    "{:<40} {:>12} {:>8}  {}",
                    format!("(encrypted_{})...", &manifest_id[..8.min(manifest_id.len())]),
                    format_size(data_size as u64),
                    "?",
                    manifest_id,
                );
            }
        }
    }

    println!();
    println!("Total: {} file(s)", manifests.len());

    Ok(())
}

async fn try_decrypt_manifest(
    transport: &QuicTransport,
    manifest_id: &str,
    master_key: &[u8; 32],
) -> Result<(String, u64, usize), Box<dyn std::error::Error>> {
    let payload = transport.download_manifest(manifest_id).await?;

    if payload.len() < XCHACHA20_NONCE_LEN + 4 {
        return Err("payload too short".into());
    }

    let nonce: [u8; XCHACHA20_NONCE_LEN] = payload[..XCHACHA20_NONCE_LEN]
        .try_into()
        .map_err(|_| "invalid nonce")?;

    let fid_len_bytes = &payload[XCHACHA20_NONCE_LEN..XCHACHA20_NONCE_LEN + 4];
    let fid_len = u32::from_be_bytes([
        fid_len_bytes[0], fid_len_bytes[1],
        fid_len_bytes[2], fid_len_bytes[3],
    ]) as usize;

    let fid_start = XCHACHA20_NONCE_LEN + 4;
    let fid_end = fid_start + fid_len;

    if fid_len == 0 || fid_len >= 1024 || payload.len() < fid_end {
        return Err("invalid envelope".into());
    }

    let file_id = String::from_utf8(payload[fid_start..fid_end].to_vec())?;
    let ciphertext = &payload[fid_end..];

    let manifest_key = derive_manifest_key(master_key, &file_id)?;
    let manifest_bytes = xchacha20_decrypt(&manifest_key, &nonce, ciphertext, &[])
        .map_err(|_| "decryption failed")?;

    let manifest: FileManifest = deserialize(&manifest_bytes)?;

    Ok((manifest.filename, manifest.original_size, manifest.chunks.len()))
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}
