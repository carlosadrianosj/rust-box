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

/// Delete a file from the RustBox server by manifest ID.
pub async fn run_delete(
    manifest_id: &str,
    server: &str,
    skip_confirm: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let password = std::env::var("RUSTBOX_PASSWORD")
        .unwrap_or_else(|_| rpassword::prompt_password("Enter vault password: ").expect("failed to read password"));
    let master_key = unlock_vault(&password).await?;

    let meta_db = SqliteMeta::open(Path::new(".rustbox/meta.db"))?;
    let user_id_bytes = meta_db.get("user_id").await?
        .ok_or("not logged in: run `rustbox login` first")?;
    let user_id_str = String::from_utf8(user_id_bytes)
        .map_err(|e| format!("invalid user_id in metadata: {e}"))?;

    info!("Connecting to server {server}...");
    let mut transport = QuicTransport::connect(server).await?;
    transport.set_user_id(&user_id_str)?;

    // Download and decrypt manifest to show the filename before confirming
    let filename = match try_get_filename(&transport, manifest_id, &master_key).await {
        Ok(name) => name,
        Err(e) => {
            info!("Could not decrypt manifest to get filename: {e}");
            format!("(unknown — manifest {manifest_id})")
        }
    };

    if !skip_confirm {
        eprint!("Delete \"{}\"? [y/N] ", filename);
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    transport.delete_manifest(manifest_id).await?;
    println!("Deleted: {} (manifest {})", filename, manifest_id);

    Ok(())
}

async fn try_get_filename(
    transport: &QuicTransport,
    manifest_id: &str,
    master_key: &[u8; 32],
) -> Result<String, Box<dyn std::error::Error>> {
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
    Ok(manifest.filename)
}
