use std::path::Path;

use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Sha256, Digest};
use tracing::info;

use rustbox_core::chunking::pipeline::encrypt_chunk;
use rustbox_core::chunking::splitter::split_into_chunks;
use rustbox_core::constants::XCHACHA20_NONCE_LEN;
use rustbox_core::crypto::chacha20::xchacha20_encrypt;
use rustbox_core::crypto::key_hierarchy::{derive_file_enc_key, derive_manifest_key};
use rustbox_core::manifest::file_manifest::{ChunkEntry, FileManifest};
use rustbox_core::manifest::serialization::serialize;
use rustbox_core::merkle::tree::MerkleTree;
use rustbox_core::traits::random::SecureRandom;
use rustbox_core::traits::storage::ContentAddressableStorage;
use rustbox_core::traits::transport::Transport;

use crate::commands::init::unlock_vault;
use crate::platform::{NativeClock, NativeRandom};
use crate::storage::LocalFs;
use crate::transport::QuicTransport;

/// Upload a file to the RustBox server.
///
/// Reads the file, splits it into chunks, encrypts each chunk, stores them
/// locally, builds a Merkle tree and file manifest, encrypts the manifest,
/// and uploads everything to the server.
pub async fn run_upload(file_path: &str, server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(format!("file not found: {file_path}").into());
    }

    let password = std::env::var("RUSTBOX_PASSWORD")
        .unwrap_or_else(|_| rpassword::prompt_password("Enter vault password: ").expect("failed to read password"));
    let master_key = unlock_vault(&password).await?;

    info!("Reading file: {file_path}");
    let file_data = tokio::fs::read(path)
        .await
        .map_err(|e| format!("failed to read file: {e}"))?;

    let file_size = file_data.len() as u64;
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Use filename as file_id for POC1.
    let file_id = &filename;

    // Compute original file hash.
    let file_hash: [u8; 32] = Sha256::digest(&file_data).into();

    info!(
        "File: {} ({} bytes, hash: {})",
        filename,
        file_size,
        hex::encode(&file_hash[..8])
    );

    // Split into chunks.
    let raw_chunks = split_into_chunks(&file_data);
    info!("Split into {} chunks", raw_chunks.len());

    // Derive file encryption key.
    let file_enc_key = derive_file_enc_key(&master_key, file_id)?;

    let rng = NativeRandom::new();
    let clock = NativeClock::new();

    // Set up local blob storage.
    let blobs_dir = Path::new(".rustbox/blobs");
    let local_store = LocalFs::new(blobs_dir);

    // Load user_id from metadata (set during login).
    let meta_db_for_user = crate::storage::SqliteMeta::open(&Path::new(".rustbox/meta.db"))?;
    use rustbox_core::traits::storage::PersistentStorage;
    let user_id_bytes = meta_db_for_user
        .get("user_id")
        .await?
        .ok_or("Not logged in. Run `rustbox login --server HOST:PORT` first.")?;

    // Connect to server.
    info!("Connecting to server {server}...");
    let mut transport = QuicTransport::connect(server).await?;

    // Parse user_id UUID from stored string bytes and set on transport.
    let user_id_str = String::from_utf8(user_id_bytes)
        .map_err(|e| format!("invalid stored user_id: {e}"))?;
    transport.set_user_id(&user_id_str)?;
    info!("Using user_id: {user_id_str}");

    // Progress bar.
    let pb = ProgressBar::new(raw_chunks.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} chunks ({eta})")
            .map_err(|e| format!("progress bar template error: {e}"))?
            .progress_chars("#>-"),
    );

    // Encrypt and upload each chunk.
    let mut chunk_entries = Vec::with_capacity(raw_chunks.len());
    let mut chunk_hashes = Vec::with_capacity(raw_chunks.len());

    for raw_chunk in &raw_chunks {
        let encrypted = encrypt_chunk(&file_enc_key, raw_chunk.index, &raw_chunk.data, &rng)?;

        info!(
            "Uploading chunk {}/{} (SHA256: {})",
            raw_chunk.index + 1,
            raw_chunks.len(),
            hex::encode(&encrypted.hash[..8])
        );

        // Store locally.
        local_store
            .store(&encrypted.hash, &encrypted.encrypted_data)
            .await?;

        // Upload to server.
        transport
            .upload_chunk(&encrypted.hash, &encrypted.encrypted_data)
            .await?;

        // Build chunk entry for manifest.
        chunk_entries.push(ChunkEntry {
            index: encrypted.index,
            hash: encrypted.hash,
            nonce: encrypted.nonce,
            encrypted_size: encrypted.encrypted_data.len() as u32,
            plaintext_size: raw_chunk.data.len() as u32,
        });

        chunk_hashes.push(encrypted.hash);
        pb.inc(1);
    }

    pb.finish_with_message("All chunks uploaded");

    // Build Merkle tree.
    let merkle_tree = MerkleTree::from_leaves(&chunk_hashes);
    info!(
        "Merkle root: {}",
        hex::encode(&merkle_tree.root()[..8])
    );

    // Create file manifest.
    let now_secs = rustbox_core::traits::clock::Clock::now_secs(&clock)?;
    let mut manifest = FileManifest::new(file_id.to_string(), filename.clone(), file_size);
    manifest.created_at = now_secs;
    manifest.modified_at = now_secs;
    manifest.file_hash = file_hash;
    manifest.mime_type = guess_mime_type(&filename);
    for entry in chunk_entries {
        manifest.add_chunk(entry);
    }

    // Serialize manifest.
    let manifest_bytes = serialize(&manifest)?;

    // Encrypt manifest with manifest key.
    let manifest_key = derive_manifest_key(&master_key, file_id)?;
    let mut manifest_nonce = [0u8; XCHACHA20_NONCE_LEN];
    rng.fill_bytes(&mut manifest_nonce)?;

    let encrypted_manifest =
        xchacha20_encrypt(&manifest_key, &manifest_nonce, &manifest_bytes, b"")?;

    // Build envelope: [nonce (24B) | file_id_len (4B BE) | file_id (UTF-8) | ciphertext]
    let file_id_bytes = file_id.as_bytes();
    let file_id_len = (file_id_bytes.len() as u32).to_be_bytes();
    let mut manifest_payload = Vec::with_capacity(
        XCHACHA20_NONCE_LEN + 4 + file_id_bytes.len() + encrypted_manifest.len(),
    );
    manifest_payload.extend_from_slice(&manifest_nonce);
    manifest_payload.extend_from_slice(&file_id_len);
    manifest_payload.extend_from_slice(file_id_bytes);
    manifest_payload.extend_from_slice(&encrypted_manifest);

    // Upload manifest.
    info!("Uploading manifest ({} bytes)...", manifest_payload.len());
    let manifest_id = transport.upload_manifest(&manifest_payload).await?;

    // Save manifest_id to local metadata.
    let meta_db = crate::storage::SqliteMeta::open(&Path::new(".rustbox/meta.db"))?;
    meta_db
        .set(
            &format!("manifest:{file_id}"),
            manifest_id.as_bytes(),
        )
        .await?;
    meta_db
        .set(
            &format!("merkle_root:{file_id}"),
            &merkle_tree.root(),
        )
        .await?;
    meta_db
        .set(
            &format!("file_hash:{file_id}"),
            &file_hash,
        )
        .await?;

    info!("Upload complete!");
    println!();
    println!("Upload complete:");
    println!("  File:        {filename}");
    println!("  Size:        {file_size} bytes");
    println!("  Chunks:      {}", raw_chunks.len());
    println!("  Merkle root: {}", hex::encode(&merkle_tree.root()[..16]));
    println!("  Manifest ID: {manifest_id}");

    Ok(())
}

fn guess_mime_type(filename: &str) -> Option<String> {
    let ext = filename.rsplit('.').next()?.to_lowercase();
    let mime = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "mov" => "video/quicktime",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "text/javascript",
        "json" => "application/json",
        "xml" => "text/xml",
        "csv" => "text/csv",
        "md" => "text/markdown",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => return None,
    };
    Some(mime.to_string())
}
