use std::path::Path;

use indicatif::{ProgressBar, ProgressStyle};
use tracing::info;

use rustbox_core::traits::storage::{ContentAddressableStorage, PersistentStorage};
use rustbox_core::traits::transport::Transport;
use rustbox_core::merkle::tree::MerkleTree;
use rustbox_core::sync::engine::compute_sync_plan;

use crate::commands::init::unlock_vault;
use crate::storage::{LocalFs, SqliteMeta};
use crate::transport::QuicTransport;

/// Synchronize local blobs with the RustBox server.
///
/// Compares local and remote Merkle roots, computes a diff, and uploads
/// or downloads chunks as needed.
pub async fn run_sync(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let password = std::env::var("RUSTBOX_PASSWORD")
        .unwrap_or_else(|_| rpassword::prompt_password("Enter vault password: ").expect("failed to read password"));
    let _master_key = unlock_vault(&password).await?;

    let blobs_dir = Path::new(".rustbox/blobs");
    let local_store = LocalFs::new(blobs_dir);
    let meta_db = SqliteMeta::open(&Path::new(".rustbox/meta.db"))?;

    // Get local chunk hashes.
    let local_hashes = local_store.list_hashes().await?;
    let local_tree = MerkleTree::from_leaves(&local_hashes);
    let local_root = local_tree.root();

    info!(
        "Local state: {} blobs, merkle root: {}",
        local_hashes.len(),
        hex::encode(&local_root[..8])
    );

    // Load user_id from metadata (set during login).
    let user_id_bytes = meta_db.get("user_id").await?
        .ok_or("not logged in: run `rustbox-cli login` first")?;
    let user_id_str = String::from_utf8(user_id_bytes)
        .map_err(|e| format!("invalid user_id in metadata: {e}"))?;

    // Connect to server.
    info!("Connecting to server {server}...");
    let mut transport = QuicTransport::connect(server).await?;
    transport.set_user_id(&user_id_str)?;
    info!("Using user_id: {user_id_str}");

    // Get server Merkle root.
    let server_root = transport.get_merkle_root().await?;

    info!(
        "Server merkle root: {}",
        hex::encode(&server_root[..8])
    );

    if local_root == server_root {
        println!("Already in sync. Nothing to do.");
        return Ok(());
    }

    // Get diff from server (hashes server has that we do not).
    let server_diff_hashes = transport.get_merkle_diff(&local_root).await?;

    // Compute sync plan.
    let plan = compute_sync_plan(&local_hashes, &server_diff_hashes);

    info!(
        "Sync plan: {} to upload, {} to download",
        plan.to_upload.len(),
        plan.to_download.len()
    );

    // Upload missing chunks to server.
    if !plan.to_upload.is_empty() {
        println!(
            "Uploading {} chunks to server...",
            plan.to_upload.len()
        );

        let pb = ProgressBar::new(plan.to_upload.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} Uploading [{bar:40.cyan/blue}] {pos}/{len}")
                .map_err(|e| format!("progress bar template error: {e}"))?
                .progress_chars("#>-"),
        );

        for hash in &plan.to_upload {
            let data = local_store.get(hash).await?;
            transport.upload_chunk(hash, &data).await?;
            pb.inc(1);
        }

        pb.finish_with_message("Upload complete");
    }

    // Download missing chunks from server.
    if !plan.to_download.is_empty() {
        println!(
            "Downloading {} chunks from server...",
            plan.to_download.len()
        );

        let pb = ProgressBar::new(plan.to_download.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} Downloading [{bar:40.cyan/blue}] {pos}/{len}")
                .map_err(|e| format!("progress bar template error: {e}"))?
                .progress_chars("#>-"),
        );

        for hash in &plan.to_download {
            let data = transport.download_chunk(hash).await?;
            local_store.store(hash, &data).await?;
            pb.inc(1);
        }

        pb.finish_with_message("Download complete");
    }

    // Update sync state in metadata.
    let new_local_hashes = local_store.list_hashes().await?;
    let new_tree = MerkleTree::from_leaves(&new_local_hashes);
    let new_root = new_tree.root();

    meta_db
        .set("sync:last_root", &new_root)
        .await?;

    let now = rustbox_core::traits::clock::Clock::now_secs(&crate::platform::NativeClock::new())?;
    meta_db
        .set("sync:last_time", &now.to_be_bytes())
        .await?;

    info!("Sync complete!");
    println!();
    println!("Sync complete:");
    println!("  Uploaded:   {} chunks", plan.to_upload.len());
    println!("  Downloaded: {} chunks", plan.to_download.len());
    println!("  New root:   {}", hex::encode(&new_root[..16]));

    Ok(())
}
