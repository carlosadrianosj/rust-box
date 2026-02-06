use std::path::Path;

use indicatif::{ProgressBar, ProgressStyle};
use tracing::info;

use rustbox_core::chunking::assembler::{DecryptedChunk, reassemble_chunks};
use rustbox_core::chunking::pipeline::decrypt_chunk;
use rustbox_core::constants::XCHACHA20_NONCE_LEN;
use rustbox_core::crypto::chacha20::xchacha20_decrypt;
use rustbox_core::crypto::key_hierarchy::{derive_file_enc_key, derive_manifest_key};
use rustbox_core::manifest::file_manifest::FileManifest;
use rustbox_core::manifest::serialization::deserialize;
use rustbox_core::traits::transport::Transport;

use crate::commands::init::unlock_vault;
use crate::transport::QuicTransport;

/// Download a file from the RustBox server by manifest ID.
///
/// Downloads the encrypted manifest, decrypts it, downloads each chunk,
/// decrypts the chunks, reassembles them, and writes the output file.
pub async fn run_download(
    manifest_id: &str,
    output: &str,
    server: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let password = std::env::var("RUSTBOX_PASSWORD")
        .unwrap_or_else(|_| rpassword::prompt_password("Enter vault password: ").expect("failed to read password"));
    let master_key = unlock_vault(&password).await?;

    // Load user_id from metadata (set during login).
    let meta_db = crate::storage::SqliteMeta::open(std::path::Path::new(".rustbox/meta.db"))?;
    let user_id_bytes = {
        use rustbox_core::traits::storage::PersistentStorage;
        meta_db.get("user_id").await?
            .ok_or("not logged in: run `rustbox-cli login` first")?
    };
    let user_id_str = String::from_utf8(user_id_bytes)
        .map_err(|e| format!("invalid user_id in metadata: {e}"))?;

    info!("Connecting to server {server}...");
    let mut transport = QuicTransport::connect(server).await?;
    transport.set_user_id(&user_id_str)?;
    info!("Using user_id: {user_id_str}");

    // Download encrypted manifest.
    info!("Downloading manifest {manifest_id}...");
    let manifest_payload = transport.download_manifest(manifest_id).await?;

    if manifest_payload.len() < XCHACHA20_NONCE_LEN + 4 {
        return Err("manifest payload too short".into());
    }

    // Parse envelope: [nonce (24B) | file_id_len (4B BE) | file_id (UTF-8) | ciphertext]
    let nonce: [u8; XCHACHA20_NONCE_LEN] = manifest_payload[..XCHACHA20_NONCE_LEN]
        .try_into()
        .map_err(|_| "invalid manifest nonce")?;

    let file_id_len_bytes = &manifest_payload[XCHACHA20_NONCE_LEN..XCHACHA20_NONCE_LEN + 4];
    let file_id_len = u32::from_be_bytes([
        file_id_len_bytes[0], file_id_len_bytes[1],
        file_id_len_bytes[2], file_id_len_bytes[3],
    ]) as usize;

    let file_id_start = XCHACHA20_NONCE_LEN + 4;
    let file_id_end = file_id_start + file_id_len;

    let (file_id, encrypted_manifest): (String, &[u8]) =
        if file_id_len > 0 && file_id_len < 1024 && manifest_payload.len() >= file_id_end {
            // New envelope format with embedded file_id
            let fid = String::from_utf8(manifest_payload[file_id_start..file_id_end].to_vec())
                .map_err(|e| format!("invalid file_id UTF-8: {e}"))?;
            let ciphertext = &manifest_payload[file_id_end..];
            (fid, ciphertext)
        } else {
            // Legacy fallback: [nonce | ciphertext], look up file_id from local metadata
            let fid = find_file_id_for_manifest(manifest_id).await
                .unwrap_or_else(|| {
                    info!("Using manifest_id as file_id fallback");
                    manifest_id.to_string()
                });
            let ciphertext = &manifest_payload[XCHACHA20_NONCE_LEN..];
            (fid, ciphertext)
        };

    // Derive manifest key and decrypt.
    let manifest_key = derive_manifest_key(&master_key, &file_id)?;
    let manifest_bytes = xchacha20_decrypt(&manifest_key, &nonce, encrypted_manifest, b"")
        .map_err(|_| "failed to decrypt manifest (wrong password or file_id?)")?;

    let manifest: FileManifest = deserialize(&manifest_bytes)?;

    info!(
        "Manifest: file={}, {} chunks, {} bytes original",
        manifest.filename,
        manifest.chunks.len(),
        manifest.original_size,
    );

    // Derive file encryption key.
    let file_enc_key = derive_file_enc_key(&master_key, &file_id)?;

    // Progress bar.
    let pb = ProgressBar::new(manifest.chunks.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} chunks ({eta})")
            .map_err(|e| format!("progress bar template error: {e}"))?
            .progress_chars("#>-"),
    );

    // Download and decrypt each chunk.
    let mut decrypted_chunks = Vec::with_capacity(manifest.chunks.len());

    for entry in &manifest.chunks {
        // Download encrypted chunk.
        let encrypted_data = transport.download_chunk(&entry.hash).await?;

        // Decrypt chunk.
        let plaintext = decrypt_chunk(
            &file_enc_key,
            entry.index,
            &encrypted_data,
            &entry.nonce,
        )?;

        decrypted_chunks.push(DecryptedChunk {
            index: entry.index,
            data: plaintext,
        });

        pb.inc(1);
    }

    pb.finish_with_message("All chunks downloaded");

    // Reassemble.
    let file_data = reassemble_chunks(&decrypted_chunks);

    // Verify file hash.
    use sha2::{Sha256, Digest};
    let computed_hash: [u8; 32] = Sha256::digest(&file_data).into();
    if computed_hash != manifest.file_hash {
        return Err(format!(
            "file hash mismatch: expected {}, got {}",
            hex::encode(&manifest.file_hash[..8]),
            hex::encode(&computed_hash[..8]),
        )
        .into());
    }

    info!("File hash verified");

    // Write output file.
    let output_path = Path::new(output);
    tokio::fs::write(output_path, &file_data)
        .await
        .map_err(|e| format!("failed to write output file: {e}"))?;

    info!("Download complete!");
    println!();
    println!("Download complete:");
    println!("  File:     {}", manifest.filename);
    println!("  Size:     {} bytes", file_data.len());
    println!("  Chunks:   {}", manifest.chunks.len());
    println!("  Output:   {output}");
    println!("  Hash OK:  {}", hex::encode(&computed_hash[..16]));

    Ok(())
}

/// Try to find the file_id associated with a manifest_id in local metadata.
async fn find_file_id_for_manifest(manifest_id: &str) -> Option<String> {
    let meta_db = crate::storage::SqliteMeta::open(Path::new(".rustbox/meta.db")).ok()?;

    use rustbox_core::traits::storage::PersistentStorage;
    let keys = meta_db.list_keys("manifest:").await.ok()?;

    for key in keys {
        if let Some(value) = meta_db.get(&key).await.ok()? {
            let stored_id = String::from_utf8(value).ok()?;
            if stored_id == manifest_id {
                // Key is "manifest:{file_id}" -- extract file_id.
                return key.strip_prefix("manifest:").map(|s| s.to_string());
            }
        }
    }

    None
}
