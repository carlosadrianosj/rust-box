pub mod platform;
pub mod transport;
pub mod storage;
pub mod worker;

use wasm_bindgen::prelude::*;
use sha2::{Sha256, Digest};

use rustbox_core::chunking::assembler::{DecryptedChunk, reassemble_chunks};
use rustbox_core::chunking::pipeline::{encrypt_chunk, decrypt_chunk, EncryptedChunk};
use rustbox_core::chunking::splitter::split_into_chunks;
use rustbox_core::constants::{PBKDF2_SALT_LEN, VAULT_VERIFY_CONSTANT, XCHACHA20_NONCE_LEN};
use rustbox_core::crypto::chacha20::{xchacha20_encrypt, xchacha20_decrypt};
use rustbox_core::crypto::key_hierarchy::{derive_auth_key, derive_file_enc_key, derive_manifest_key};
use rustbox_core::crypto::pbkdf2::derive_master_key_default;
use rustbox_core::manifest::file_manifest::{ChunkEntry, FileManifest};
use rustbox_core::manifest::serialization;
use rustbox_core::merkle::tree::MerkleTree;
use rustbox_core::traits::clock::Clock;
use rustbox_core::traits::random::SecureRandom;
use rustbox_core::traits::storage::PersistentStorage;
use rustbox_core::traits::transport::Transport;

use crate::platform::{WasmClock, WasmRandom};
use crate::storage::IndexedDbStorage;
use crate::transport::FetchTransport;

// Re-export worker functions at crate root for wasm_bindgen
pub use crate::worker::crypto_worker::{encrypt_chunk_worker, decrypt_chunk_worker};

// -- Storage keys for vault metadata --
const KEY_VAULT_SALT: &str = "vault:salt";
const KEY_VAULT_VERIFY: &str = "vault:verify_blob";
const KEY_VAULT_VERIFY_NONCE: &str = "vault:verify_nonce";
const KEY_MASTER_KEY: &str = "vault:master_key";
const KEY_USER_ID: &str = "vault:user_id";
const KEY_USERNAME: &str = "vault:username";

/// Log a message to the browser console.
fn console_log(msg: &str) {
    web_sys::console::log_1(&JsValue::from_str(msg));
}

/// Create a FetchTransport with user_id set from IndexedDB (if available).
async fn make_transport(server_url: &str) -> FetchTransport {
    let mut transport = FetchTransport::new(server_url);
    // Try to load user_id from IndexedDB
    if let Ok(db) = crate::storage::IndexedDbStorage::open().await {
        if let Ok(Some(uid_bytes)) = db.get(KEY_USER_ID).await {
            if let Ok(uid) = String::from_utf8(uid_bytes) {
                transport.set_user_id(&uid);
            }
        }
    }
    transport
}

/// Helper: guess MIME type from filename extension.
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
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "csv" => "text/csv",
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

/// Helper: generate a unique file ID from filename and current timestamp.
fn generate_file_id(filename: &str, clock: &WasmClock) -> String {
    let ts = clock.now_millis().unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(filename.as_bytes());
    hasher.update(ts.to_be_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..16]) // 16 bytes = 32 hex chars, enough for a unique ID
}

// =============================================================================
// Public wasm_bindgen API
// =============================================================================

/// Return the RustBox WASM library version.
#[wasm_bindgen]
pub fn rustbox_version() -> String {
    "0.1.0".to_string()
}

/// Initialize the vault with a username and master password.
///
/// The salt parameter is optional — if provided (from server), it's used directly.
/// Otherwise, a new random salt is generated (for first-time registration).
///
/// 1. Uses provided salt or generates a random 32-byte salt
/// 2. Derives master key via PBKDF2-HMAC-SHA256 (100,000 iterations)
/// 3. Encrypts VAULT_VERIFY_CONSTANT with the master key
/// 4. Stores salt, username, and verification blob in IndexedDB
/// 5. Caches the master key in IndexedDB for the session
///
/// Returns a JSON object: { "status": "ok", "new_salt": bool }
#[wasm_bindgen]
pub async fn init_vault(username: &str, password: &str, salt_hex: &str) -> Result<JsValue, JsValue> {
    console_log(&format!("rustbox: initializing vault for '{}'...", username));

    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let rng = WasmRandom::new();

    // Check if vault already exists with matching username -- if so, try to unlock
    let existing_salt = db
        .get(KEY_VAULT_SALT)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let existing_username = db
        .get(KEY_USERNAME)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    if let Some(salt_bytes) = existing_salt {
        // Check if username matches
        let stored_username = existing_username
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();

        if stored_username == username {
            console_log("rustbox: vault exists for this user, unlocking...");
            return unlock_existing_vault(&db, password, &salt_bytes).await;
        }

        // Different user — wipe local vault and recreate
        console_log("rustbox: different user detected, resetting local vault...");
        db.delete(KEY_VAULT_SALT).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        db.delete(KEY_VAULT_VERIFY).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        db.delete(KEY_VAULT_VERIFY_NONCE).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        db.delete(KEY_MASTER_KEY).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        db.delete(KEY_USER_ID).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        db.delete(KEY_USERNAME).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    }

    // Determine salt: use server-provided salt or generate new
    let (salt, new_salt) = if !salt_hex.is_empty() {
        let s = hex::decode(salt_hex)
            .map_err(|e| JsValue::from_str(&format!("invalid salt_hex: {e}")))?;
        (s, false)
    } else {
        let mut s = vec![0u8; PBKDF2_SALT_LEN];
        rng.fill_bytes(&mut s)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        (s, true)
    };

    // Derive master key
    let master_key = derive_master_key_default(password.as_bytes(), &salt)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Encrypt verification constant
    let mut verify_nonce = [0u8; XCHACHA20_NONCE_LEN];
    rng.fill_bytes(&mut verify_nonce)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let verify_blob = xchacha20_encrypt(&master_key, &verify_nonce, VAULT_VERIFY_CONSTANT, &[])
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Store everything in IndexedDB
    db.set(KEY_VAULT_SALT, &salt)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    db.set(KEY_VAULT_VERIFY, &verify_blob)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    db.set(KEY_VAULT_VERIFY_NONCE, &verify_nonce)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Store username
    db.set(KEY_USERNAME, username.as_bytes())
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Cache master key for session
    db.set(KEY_MASTER_KEY, &master_key)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    console_log("rustbox: vault initialized successfully");

    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &JsValue::from_str("status"), &JsValue::from_str("ok"))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(&result, &JsValue::from_str("new_salt"), &JsValue::from(new_salt))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(&result, &JsValue::from_str("salt_hex"), &JsValue::from_str(&hex::encode(&salt)))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(result.into())
}

/// Internal: unlock an existing vault by verifying the password.
async fn unlock_existing_vault(
    db: &IndexedDbStorage,
    password: &str,
    salt: &[u8],
) -> Result<JsValue, JsValue> {
    let master_key = derive_master_key_default(password.as_bytes(), salt)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Load and decrypt verification blob
    let verify_blob = db
        .get(KEY_VAULT_VERIFY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault verify blob missing"))?;

    let verify_nonce_bytes = db
        .get(KEY_VAULT_VERIFY_NONCE)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault verify nonce missing"))?;

    if verify_nonce_bytes.len() != XCHACHA20_NONCE_LEN {
        return Err(JsValue::from_str("invalid verify nonce length"));
    }
    let mut verify_nonce = [0u8; XCHACHA20_NONCE_LEN];
    verify_nonce.copy_from_slice(&verify_nonce_bytes);

    let decrypted = xchacha20_decrypt(&master_key, &verify_nonce, &verify_blob, &[])
        .map_err(|_| JsValue::from_str("wrong password: decryption failed"))?;

    if decrypted != VAULT_VERIFY_CONSTANT {
        return Err(JsValue::from_str("wrong password: verification mismatch"));
    }

    // Cache master key for session
    db.set(KEY_MASTER_KEY, &master_key)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    console_log("rustbox: vault unlocked successfully");

    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &JsValue::from_str("status"), &JsValue::from_str("ok"))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(result.into())
}

/// Upload a file to the RustBox server with zero-knowledge encryption.
///
/// Pipeline:
/// 1. Split data into fixed-size chunks (1 MB each)
/// 2. Derive file_enc_key from master key + file_id
/// 3. Encrypt each chunk with XChaCha20-Poly1305 (unique per-chunk key + random nonce)
/// 4. Build Merkle tree over encrypted chunk hashes
/// 5. Create FileManifest with all chunk metadata
/// 6. Encrypt and serialize the manifest
/// 7. Upload chunks and manifest to server via Fetch API
/// 8. Return the manifest ID
///
/// Returns JSON: { "manifest_id": "...", "file_id": "...", "chunks": N }
#[wasm_bindgen]
pub async fn upload_file(
    data: &[u8],
    filename: &str,
    server_url: &str,
) -> Result<JsValue, JsValue> {
    console_log(&format!(
        "rustbox: uploading '{}' ({} bytes)...",
        filename,
        data.len()
    ));

    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Retrieve cached master key
    let master_key_bytes = db
        .get(KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault not initialized: call init_vault first"))?;

    if master_key_bytes.len() != 32 {
        return Err(JsValue::from_str("invalid master key length"));
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_bytes);

    let rng = WasmRandom::new();
    let clock = WasmClock::new();

    // Generate file ID
    let file_id = generate_file_id(filename, &clock);
    console_log(&format!("rustbox: file_id = {}", file_id));

    // Derive file encryption key
    let file_enc_key = derive_file_enc_key(&master_key, &file_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Compute original file hash
    let file_hash: [u8; 32] = Sha256::digest(data).into();

    // Split into chunks
    let raw_chunks = split_into_chunks(data);
    let chunk_count = raw_chunks.len();
    console_log(&format!("rustbox: split into {} chunks", chunk_count));

    // Encrypt each chunk
    let mut encrypted_chunks: Vec<EncryptedChunk> = Vec::with_capacity(chunk_count);
    for raw_chunk in &raw_chunks {
        let enc = encrypt_chunk(&file_enc_key, raw_chunk.index, &raw_chunk.data, &rng)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        encrypted_chunks.push(enc);
    }

    // Build Merkle tree from chunk hashes
    let chunk_hashes: Vec<[u8; 32]> = encrypted_chunks.iter().map(|c| c.hash).collect();
    let merkle_tree = MerkleTree::from_leaves(&chunk_hashes);
    console_log(&format!(
        "rustbox: merkle root = {}",
        hex::encode(merkle_tree.root())
    ));

    // Build FileManifest
    let now = clock.now_secs().unwrap_or(0);
    let mut manifest = FileManifest::new(file_id.clone(), filename.to_string(), data.len() as u64);
    manifest.created_at = now;
    manifest.modified_at = now;
    manifest.file_hash = file_hash;
    manifest.mime_type = guess_mime_type(filename);

    for (raw_chunk, enc_chunk) in raw_chunks.iter().zip(encrypted_chunks.iter()) {
        manifest.add_chunk(ChunkEntry {
            index: enc_chunk.index,
            hash: enc_chunk.hash,
            nonce: enc_chunk.nonce,
            encrypted_size: enc_chunk.encrypted_data.len() as u32,
            plaintext_size: raw_chunk.data.len() as u32,
        });
    }

    // Serialize and encrypt the manifest
    let manifest_bytes = serialization::serialize(&manifest)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let manifest_key = derive_manifest_key(&master_key, &file_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut manifest_nonce = [0u8; XCHACHA20_NONCE_LEN];
    rng.fill_bytes(&mut manifest_nonce)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let encrypted_manifest =
        xchacha20_encrypt(&manifest_key, &manifest_nonce, &manifest_bytes, &[])
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Build the upload payload: nonce (24 bytes) + file_id_len (4 bytes) + file_id + ciphertext
    let file_id_bytes = file_id.as_bytes();
    let file_id_len = (file_id_bytes.len() as u32).to_be_bytes();
    let mut manifest_payload = Vec::with_capacity(
        XCHACHA20_NONCE_LEN + 4 + file_id_bytes.len() + encrypted_manifest.len(),
    );
    manifest_payload.extend_from_slice(&manifest_nonce);
    manifest_payload.extend_from_slice(&file_id_len);
    manifest_payload.extend_from_slice(file_id_bytes);
    manifest_payload.extend_from_slice(&encrypted_manifest);

    // Upload to server
    let transport = make_transport(server_url).await;

    // Upload all encrypted chunks
    for enc_chunk in &encrypted_chunks {
        transport
            .upload_chunk(&enc_chunk.hash, &enc_chunk.encrypted_data)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    }
    console_log(&format!("rustbox: uploaded {} chunks", chunk_count));

    // Upload the encrypted manifest
    let manifest_id = transport
        .upload_manifest(&manifest_payload)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    console_log(&format!("rustbox: manifest_id = {}", manifest_id));

    // Store richer manifest metadata locally for sync tracking and list_files
    let meta_key = format!("manifest:{}", manifest_id);
    let meta_value = serde_json::json!({
        "manifest_id": manifest_id,
        "file_id": file_id,
        "filename": filename,
        "size": data.len(),
        "chunks": chunk_count,
        "merkle_root": hex::encode(merkle_tree.root()),
        "uploaded_at": now,
        "created_at": now,
    });
    let meta_bytes = serde_json::to_vec(&meta_value)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    db.set(&meta_key, &meta_bytes)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Build response
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("manifest_id"),
        &JsValue::from_str(&manifest_id),
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("file_id"),
        &JsValue::from_str(&file_id),
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("chunks"),
        &JsValue::from(chunk_count as u32),
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    console_log("rustbox: upload complete");
    Ok(result.into())
}

/// Download and decrypt a file from the RustBox server.
///
/// Pipeline:
/// 1. Download encrypted manifest by ID
/// 2. Parse envelope: nonce + file_id_len + file_id + ciphertext
/// 3. Derive manifest key from master key + file_id, decrypt manifest
/// 4. Derive file encryption key from master key + file_id
/// 5. Download each encrypted chunk by hash
/// 6. Decrypt each chunk with its per-chunk key + stored nonce
/// 7. Reassemble original file from decrypted chunks
///
/// Returns a JS object: { bytes: Uint8Array, filename: String, mime_type: String|null }
#[wasm_bindgen]
pub async fn download_file(manifest_id: &str, server_url: &str) -> Result<JsValue, JsValue> {
    console_log(&format!(
        "rustbox: downloading manifest '{}'...",
        manifest_id
    ));

    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Retrieve cached master key
    let master_key_bytes = db
        .get(KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault not initialized: call init_vault first"))?;

    if master_key_bytes.len() != 32 {
        return Err(JsValue::from_str("invalid master key length"));
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_bytes);

    let transport = make_transport(server_url).await;

    // Download the encrypted manifest
    let manifest_payload = transport
        .download_manifest(manifest_id)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Parse the manifest envelope
    if manifest_payload.len() < XCHACHA20_NONCE_LEN + 4 {
        return Err(JsValue::from_str("manifest payload too short"));
    }

    let mut manifest_nonce = [0u8; XCHACHA20_NONCE_LEN];
    manifest_nonce.copy_from_slice(&manifest_payload[..XCHACHA20_NONCE_LEN]);

    let file_id_len_bytes = &manifest_payload[XCHACHA20_NONCE_LEN..XCHACHA20_NONCE_LEN + 4];
    let file_id_len = u32::from_be_bytes([
        file_id_len_bytes[0],
        file_id_len_bytes[1],
        file_id_len_bytes[2],
        file_id_len_bytes[3],
    ]) as usize;

    let file_id_start = XCHACHA20_NONCE_LEN + 4;
    let file_id_end = file_id_start + file_id_len;

    if manifest_payload.len() < file_id_end {
        return Err(JsValue::from_str("manifest payload truncated at file_id"));
    }

    let file_id = String::from_utf8(manifest_payload[file_id_start..file_id_end].to_vec())
        .map_err(|e| JsValue::from_str(&format!("invalid file_id UTF-8: {}", e)))?;

    let encrypted_manifest = &manifest_payload[file_id_end..];

    console_log(&format!("rustbox: file_id = {}", file_id));

    // Derive manifest key and decrypt
    let manifest_key = derive_manifest_key(&master_key, &file_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let manifest_bytes =
        xchacha20_decrypt(&manifest_key, &manifest_nonce, encrypted_manifest, &[])
            .map_err(|e| JsValue::from_str(&format!("manifest decryption failed: {}", e)))?;

    let manifest: FileManifest = serialization::deserialize(&manifest_bytes)
        .map_err(|e| JsValue::from_str(&format!("manifest deserialization failed: {}", e)))?;

    console_log(&format!(
        "rustbox: manifest decoded: '{}', {} chunks, {} bytes original",
        manifest.filename,
        manifest.chunks.len(),
        manifest.original_size,
    ));

    // Derive file encryption key
    let file_enc_key = derive_file_enc_key(&master_key, &file_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Download and decrypt each chunk
    let mut decrypted_chunks: Vec<DecryptedChunk> = Vec::with_capacity(manifest.chunks.len());

    for chunk_entry in &manifest.chunks {
        console_log(&format!(
            "rustbox: downloading chunk {} ({} bytes)...",
            chunk_entry.index, chunk_entry.encrypted_size
        ));

        let encrypted_data = transport
            .download_chunk(&chunk_entry.hash)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Verify hash
        let actual_hash: [u8; 32] = Sha256::digest(&encrypted_data).into();
        if actual_hash != chunk_entry.hash {
            return Err(JsValue::from_str(&format!(
                "chunk {} hash mismatch: expected {}, got {}",
                chunk_entry.index,
                hex::encode(chunk_entry.hash),
                hex::encode(actual_hash)
            )));
        }

        let plaintext = decrypt_chunk(
            &file_enc_key,
            chunk_entry.index,
            &encrypted_data,
            &chunk_entry.nonce,
        )
        .map_err(|e| {
            JsValue::from_str(&format!(
                "chunk {} decryption failed: {}",
                chunk_entry.index, e
            ))
        })?;

        decrypted_chunks.push(DecryptedChunk {
            index: chunk_entry.index,
            data: plaintext,
        });
    }

    // Reassemble
    let reassembled = reassemble_chunks(&decrypted_chunks);

    // Verify file hash
    let actual_file_hash: [u8; 32] = Sha256::digest(&reassembled).into();
    if actual_file_hash != manifest.file_hash {
        return Err(JsValue::from_str(&format!(
            "file hash mismatch: expected {}, got {}",
            hex::encode(manifest.file_hash),
            hex::encode(actual_file_hash)
        )));
    }

    console_log(&format!(
        "rustbox: download complete, {} bytes",
        reassembled.len()
    ));

    // Build JS result object: { bytes: Uint8Array, filename: String, mime_type: String|null }
    let result = js_sys::Object::new();
    let uint8arr = js_sys::Uint8Array::from(reassembled.as_slice());
    js_sys::Reflect::set(&result, &JsValue::from_str("bytes"), &uint8arr)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(&result, &JsValue::from_str("filename"), &JsValue::from_str(&manifest.filename))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    if let Some(ref mime) = manifest.mime_type {
        js_sys::Reflect::set(&result, &JsValue::from_str("mime_type"), &JsValue::from_str(mime))
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    } else {
        js_sys::Reflect::set(&result, &JsValue::from_str("mime_type"), &JsValue::NULL)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    }

    Ok(result.into())
}

/// Sync files with the server using manifest-based diff.
///
/// 1. Fetch manifest list from server for the current user
/// 2. Compare with local manifest:* keys in IndexedDB
/// 3. For each missing manifest: download, decrypt, store metadata + download missing chunks
///
/// Returns JSON: { "status": "synced" | "updated", "downloaded": N, "uploaded": N }
#[wasm_bindgen]
pub async fn sync_files(server_url: &str) -> Result<JsValue, JsValue> {
    console_log("rustbox: starting manifest-based sync...");

    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Get master key
    let master_key_bytes = PersistentStorage::get(&db, KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault not initialized: call init_vault first"))?;

    if master_key_bytes.len() != 32 {
        return Err(JsValue::from_str("invalid master key length"));
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_bytes);

    // Get user_id
    let user_id_bytes = PersistentStorage::get(&db, KEY_USER_ID)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("not logged in"))?;
    let user_id = String::from_utf8(user_id_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid user_id: {e}")))?;

    let transport = make_transport(server_url).await;

    // 1. Fetch manifest list from server
    let list_json = transport
        .list_manifests(&user_id)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let server_data: serde_json::Value = serde_json::from_str(&list_json)
        .map_err(|e| JsValue::from_str(&format!("JSON parse failed: {e}")))?;

    let server_manifests = server_data
        .get("manifests")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    console_log(&format!(
        "rustbox: server has {} manifests for user {}",
        server_manifests.len(),
        user_id
    ));

    // 2. Get local manifest keys
    let local_keys = db
        .list_keys("manifest:")
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let local_manifest_ids: std::collections::HashSet<String> = local_keys
        .iter()
        .filter_map(|k| k.strip_prefix("manifest:").map(|s| s.to_string()))
        .collect();

    console_log(&format!(
        "rustbox: {} manifests stored locally",
        local_manifest_ids.len()
    ));

    // 3. Download missing manifests + their chunks
    use rustbox_core::traits::storage::ContentAddressableStorage;
    let mut downloaded = 0u32;

    for manifest_summary in &server_manifests {
        let manifest_id = match manifest_summary.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => continue,
        };

        // Skip if already stored locally
        if local_manifest_ids.contains(manifest_id) {
            continue;
        }

        console_log(&format!("rustbox: syncing manifest {}...", manifest_id));

        // Download and decrypt the manifest
        let payload = transport
            .download_manifest(manifest_id)
            .await
            .map_err(|e| JsValue::from_str(&format!("download manifest {}: {}", manifest_id, e)))?;

        if payload.len() < XCHACHA20_NONCE_LEN + 4 {
            console_log(&format!("rustbox: manifest {} payload too short, skipping", manifest_id));
            continue;
        }

        let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
        nonce.copy_from_slice(&payload[..XCHACHA20_NONCE_LEN]);

        let fid_len = u32::from_be_bytes([
            payload[XCHACHA20_NONCE_LEN],
            payload[XCHACHA20_NONCE_LEN + 1],
            payload[XCHACHA20_NONCE_LEN + 2],
            payload[XCHACHA20_NONCE_LEN + 3],
        ]) as usize;

        let fid_start = XCHACHA20_NONCE_LEN + 4;
        let fid_end = fid_start + fid_len;

        if fid_len == 0 || fid_len >= 1024 || payload.len() < fid_end {
            console_log(&format!("rustbox: manifest {} invalid envelope, skipping", manifest_id));
            continue;
        }

        let file_id = match String::from_utf8(payload[fid_start..fid_end].to_vec()) {
            Ok(s) => s,
            Err(_) => {
                console_log(&format!("rustbox: manifest {} invalid file_id, skipping", manifest_id));
                continue;
            }
        };
        let ciphertext = &payload[fid_end..];

        let manifest_key = derive_manifest_key(&master_key, &file_id)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let manifest_bytes = match xchacha20_decrypt(&manifest_key, &nonce, ciphertext, &[]) {
            Ok(b) => b,
            Err(e) => {
                console_log(&format!("rustbox: manifest {} decrypt failed: {}, skipping", manifest_id, e));
                continue;
            }
        };

        let manifest: FileManifest = match serialization::deserialize(&manifest_bytes) {
            Ok(m) => m,
            Err(e) => {
                console_log(&format!("rustbox: manifest {} deserialize failed: {}, skipping", manifest_id, e));
                continue;
            }
        };

        console_log(&format!(
            "rustbox: manifest {} -> '{}', {} chunks, {} bytes",
            manifest_id, manifest.filename, manifest.chunks.len(), manifest.original_size
        ));

        // Download missing chunks for this manifest
        for chunk_entry in &manifest.chunks {
            // Skip chunks we already have
            if db.exists(&chunk_entry.hash).await.unwrap_or(false) {
                continue;
            }

            let chunk_data = transport
                .download_chunk(&chunk_entry.hash)
                .await
                .map_err(|e| JsValue::from_str(&format!(
                    "download chunk {}: {}",
                    hex::encode(chunk_entry.hash), e
                )))?;

            // Verify hash
            let actual_hash: [u8; 32] = Sha256::digest(&chunk_data).into();
            if actual_hash != chunk_entry.hash {
                return Err(JsValue::from_str(&format!(
                    "chunk hash mismatch: expected {}, got {}",
                    hex::encode(chunk_entry.hash),
                    hex::encode(actual_hash)
                )));
            }

            db.store(&chunk_entry.hash, &chunk_data)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }

        // Store manifest metadata in IndexedDB (same format as upload_file and list_server_manifests)
        let created_at = manifest_summary
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let meta = serde_json::json!({
            "manifest_id": manifest_id,
            "filename": manifest.filename,
            "size": manifest.original_size,
            "chunks": manifest.chunks.len(),
            "created_at": created_at,
            "file_id": file_id,
        });

        let meta_key = format!("manifest:{}", manifest_id);
        if let Ok(meta_bytes) = serde_json::to_vec(&meta) {
            db.set(&meta_key, &meta_bytes)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }

        downloaded += 1;
    }

    let status = if downloaded > 0 { "updated" } else { "synced" };
    console_log(&format!(
        "rustbox: sync complete — {} manifests downloaded",
        downloaded
    ));

    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"status".into(), &JsValue::from_str(status))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(&result, &"downloaded".into(), &JsValue::from(downloaded))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(&result, &"uploaded".into(), &JsValue::from(0u32))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(result.into())
}

/// Get the current status of the RustBox client.
///
/// Returns JSON:
/// {
///   "version": "0.1.0",
///   "vault_initialized": bool,
///   "vault_unlocked": bool,
///   "stored_manifests": number,
///   "stored_blobs": number
/// }
#[wasm_bindgen]
pub async fn get_status() -> Result<JsValue, JsValue> {
    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let vault_initialized = PersistentStorage::get(&db, KEY_VAULT_SALT)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .is_some();

    let vault_unlocked = PersistentStorage::get(&db, KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .is_some();

    let manifest_keys = db
        .list_keys("manifest:")
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    use rustbox_core::traits::storage::ContentAddressableStorage;
    let blob_hashes = db
        .list_hashes()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = js_sys::Object::new();

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("version"),
        &JsValue::from_str("0.1.0"),
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("vault_initialized"),
        &JsValue::from(vault_initialized),
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("vault_unlocked"),
        &JsValue::from(vault_unlocked),
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("stored_manifests"),
        &JsValue::from(manifest_keys.len() as u32),
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("stored_blobs"),
        &JsValue::from(blob_hashes.len() as u32),
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(result.into())
}

// =============================================================================
// V2 New Exports
// =============================================================================

/// List all files stored in the vault.
///
/// Reads all `manifest:*` keys from IndexedDB and returns a JSON array of
/// file entries with: manifest_id, filename, size, chunks, uploaded_at, merkle_root
#[wasm_bindgen]
pub async fn list_files() -> Result<JsValue, JsValue> {
    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let manifest_keys = db
        .list_keys("manifest:")
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = js_sys::Array::new();

    for key in &manifest_keys {
        if let Some(value_bytes) = PersistentStorage::get(&db, key)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?
        {
            // Try to parse as JSON metadata
            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&value_bytes) {
                let entry = js_sys::Object::new();

                // Extract manifest_id from key or metadata
                let manifest_id = meta.get("manifest_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| key.strip_prefix("manifest:").unwrap_or(key));

                js_sys::Reflect::set(&entry, &"manifest_id".into(), &JsValue::from_str(manifest_id))
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

                if let Some(filename) = meta.get("filename").and_then(|v| v.as_str()) {
                    js_sys::Reflect::set(&entry, &"filename".into(), &JsValue::from_str(filename))
                        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                }

                if let Some(size) = meta.get("size").and_then(|v| v.as_u64()) {
                    js_sys::Reflect::set(&entry, &"size".into(), &JsValue::from(size as f64))
                        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                }

                if let Some(chunks) = meta.get("chunks").and_then(|v| v.as_u64()) {
                    js_sys::Reflect::set(&entry, &"chunks".into(), &JsValue::from(chunks as u32))
                        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                }

                if let Some(uploaded_at) = meta.get("uploaded_at").and_then(|v| v.as_u64())
                    .or_else(|| meta.get("created_at").and_then(|v| v.as_u64()))
                {
                    js_sys::Reflect::set(&entry, &"uploaded_at".into(), &JsValue::from(uploaded_at as f64))
                        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                }

                if let Some(merkle_root) = meta.get("merkle_root").and_then(|v| v.as_str()) {
                    js_sys::Reflect::set(&entry, &"merkle_root".into(), &JsValue::from_str(merkle_root))
                        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                }

                if let Some(file_id) = meta.get("file_id").and_then(|v| v.as_str()) {
                    js_sys::Reflect::set(&entry, &"file_id".into(), &JsValue::from_str(file_id))
                        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                }

                result.push(&entry);
            }
        }
    }

    Ok(result.into())
}

/// Login (register) with a RustBox server.
///
/// 1. Fetch salt from server for this username (GET /api/auth/salt?username=X)
/// 2. Init/unlock vault with username + password + salt
/// 3. Derive auth_key from master_key, hash it with SHA-256
/// 4. POST auth_key_hash to server via /api/auth/register (with username + salt if new)
/// 5. Store user_id in IndexedDB
///
/// Returns JSON: { "user_id": "...", "status": "ok" }
#[wasm_bindgen]
pub async fn login(username: &str, password: &str, server_url: &str) -> Result<JsValue, JsValue> {
    console_log(&format!("rustbox: logging in as '{}'...", username));

    let base_url = server_url.trim_end_matches('/');

    // Step 1: Fetch salt from server
    console_log("rustbox: fetching salt from server...");
    let salt_url = format!("{}/api/auth/salt?username={}", base_url, username);

    let salt_opts = web_sys::RequestInit::new();
    salt_opts.set_method("GET");
    salt_opts.set_mode(web_sys::RequestMode::Cors);

    let salt_request = web_sys::Request::new_with_str_and_init(&salt_url, &salt_opts)
        .map_err(|e| JsValue::from_str(&format!("salt request failed: {:?}", e)))?;

    let window = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window object"))?;

    let salt_resp_value = wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&salt_request))
        .await
        .map_err(|e| JsValue::from_str(&format!("salt fetch failed: {:?}", e)))?;

    let salt_resp: web_sys::Response = salt_resp_value
        .dyn_into()
        .map_err(|_| JsValue::from_str("salt response is not a Response"))?;

    let server_salt_hex = if salt_resp.status() == 200 {
        // Salt found on server — existing user
        let json_promise = salt_resp.json()
            .map_err(|e| JsValue::from_str(&format!("salt json() failed: {:?}", e)))?;
        let json_val = wasm_bindgen_futures::JsFuture::from(json_promise)
            .await
            .map_err(|e| JsValue::from_str(&format!("salt json read failed: {:?}", e)))?;
        let hex = js_sys::Reflect::get(&json_val, &JsValue::from_str("salt_hex"))
            .map_err(|e| JsValue::from_str(&format!("missing salt_hex: {:?}", e)))?
            .as_string()
            .ok_or_else(|| JsValue::from_str("salt_hex is not a string"))?;
        console_log("rustbox: got salt from server (existing user)");
        hex
    } else {
        // 404 — new user, will generate salt in init_vault
        console_log("rustbox: no salt on server (new user)");
        String::new()
    };

    // Step 2: Init/unlock vault with username + password + salt
    let vault_result = init_vault(username, password, &server_salt_hex).await?;

    // If user is new on server (salt was 404), we need to send the salt in register.
    // The salt may come from init_vault (new_salt=true) or from existing local vault.
    let salt_hex_for_register = if server_salt_hex.is_empty() {
        // New user on server — get salt from vault_result or from IndexedDB
        let from_result = js_sys::Reflect::get(&vault_result, &JsValue::from_str("salt_hex"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();

        if !from_result.is_empty() {
            from_result
        } else {
            // Vault was unlocked (not created) — read salt from IndexedDB
            let db_tmp = IndexedDbStorage::open()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let salt_bytes = db_tmp
                .get(KEY_VAULT_SALT)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?
                .ok_or_else(|| JsValue::from_str("no salt in vault after unlock"))?;
            hex::encode(&salt_bytes)
        }
    } else {
        String::new() // Server already has salt, no need to send
    };

    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Retrieve cached master key
    let master_key_bytes = db
        .get(KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault not initialized after init_vault"))?;

    if master_key_bytes.len() != 32 {
        return Err(JsValue::from_str("invalid master key length"));
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_bytes);

    // Derive auth key from master key
    let auth_key = derive_auth_key(&master_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Hash the auth key
    let auth_key_hash: [u8; 32] = Sha256::digest(&auth_key).into();

    console_log("rustbox: registering with server...");

    // Step 3: POST to /api/auth/register with username
    let url = format!("{}/api/auth/register", base_url);
    let auth_key_hex = hex::encode(&auth_key_hash);

    let json_body = if !salt_hex_for_register.is_empty() {
        format!(
            r#"{{"auth_key_hash":"{}","username":"{}","salt_hex":"{}"}}"#,
            auth_key_hex, username, salt_hex_for_register
        )
    } else {
        format!(
            r#"{{"auth_key_hash":"{}","username":"{}"}}"#,
            auth_key_hex, username
        )
    };

    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(web_sys::RequestMode::Cors);
    opts.set_body(&JsValue::from_str(&json_body));

    let request = web_sys::Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| JsValue::from_str(&format!("request creation failed: {:?}", e)))?;

    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| JsValue::from_str(&format!("set header failed: {:?}", e)))?;

    let resp_value = wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| JsValue::from_str(&format!("fetch failed: {:?}", e)))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| JsValue::from_str("response is not a Response"))?;

    let status = resp.status();
    if status < 200 || status > 201 {
        let text_promise = resp.text()
            .map_err(|e| JsValue::from_str(&format!("text() failed: {:?}", e)))?;
        let text_val = wasm_bindgen_futures::JsFuture::from(text_promise)
            .await
            .map_err(|e| JsValue::from_str(&format!("reading error text failed: {:?}", e)))?;
        let error_text = text_val.as_string().unwrap_or_else(|| "unknown error".to_string());
        return Err(JsValue::from_str(&format!("login failed ({}): {}", status, error_text)));
    }

    // Parse response JSON: { "user_id": "..." }
    let json_promise = resp.json()
        .map_err(|e| JsValue::from_str(&format!("json() failed: {:?}", e)))?;
    let json_val = wasm_bindgen_futures::JsFuture::from(json_promise)
        .await
        .map_err(|e| JsValue::from_str(&format!("reading json failed: {:?}", e)))?;

    let user_id = js_sys::Reflect::get(&json_val, &JsValue::from_str("user_id"))
        .map_err(|e| JsValue::from_str(&format!("missing user_id: {:?}", e)))?
        .as_string()
        .ok_or_else(|| JsValue::from_str("user_id is not a string"))?;

    console_log(&format!("rustbox: logged in as {}", user_id));

    // Store user_id in IndexedDB
    db.set(KEY_USER_ID, user_id.as_bytes())
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"user_id".into(), &JsValue::from_str(&user_id))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(&result, &"status".into(), &JsValue::from_str("ok"))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(result.into())
}

/// Upload a file with progress callback.
///
/// The `on_progress` function is called with (step: String, current: u32, total: u32)
/// at each stage of the upload pipeline.
#[wasm_bindgen]
pub async fn upload_file_with_progress(
    data: &[u8],
    filename: &str,
    server_url: &str,
    on_progress: &js_sys::Function,
) -> Result<JsValue, JsValue> {
    console_log(&format!(
        "rustbox: uploading '{}' ({} bytes) with progress...",
        filename,
        data.len()
    ));

    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let master_key_bytes = db
        .get(KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault not initialized: call init_vault first"))?;

    if master_key_bytes.len() != 32 {
        return Err(JsValue::from_str("invalid master key length"));
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_bytes);

    let rng = WasmRandom::new();
    let clock = WasmClock::new();
    let file_id = generate_file_id(filename, &clock);

    // Progress: encrypting
    let _ = on_progress.call3(
        &JsValue::NULL,
        &JsValue::from_str("encrypting"),
        &JsValue::from(0u32),
        &JsValue::from(1u32),
    );

    let file_enc_key = derive_file_enc_key(&master_key, &file_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let file_hash: [u8; 32] = Sha256::digest(data).into();
    let raw_chunks = split_into_chunks(data);
    let chunk_count = raw_chunks.len() as u32;

    // Progress: splitting
    let _ = on_progress.call3(
        &JsValue::NULL,
        &JsValue::from_str("splitting"),
        &JsValue::from(0u32),
        &JsValue::from(chunk_count),
    );

    let mut encrypted_chunks: Vec<EncryptedChunk> = Vec::with_capacity(raw_chunks.len());
    for raw_chunk in &raw_chunks {
        let enc = encrypt_chunk(&file_enc_key, raw_chunk.index, &raw_chunk.data, &rng)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        encrypted_chunks.push(enc);
    }

    let chunk_hashes: Vec<[u8; 32]> = encrypted_chunks.iter().map(|c| c.hash).collect();
    let merkle_tree = MerkleTree::from_leaves(&chunk_hashes);

    let now = clock.now_secs().unwrap_or(0);
    let mut manifest = FileManifest::new(file_id.clone(), filename.to_string(), data.len() as u64);
    manifest.created_at = now;
    manifest.modified_at = now;
    manifest.file_hash = file_hash;
    manifest.mime_type = guess_mime_type(filename);

    for (raw_chunk, enc_chunk) in raw_chunks.iter().zip(encrypted_chunks.iter()) {
        manifest.add_chunk(ChunkEntry {
            index: enc_chunk.index,
            hash: enc_chunk.hash,
            nonce: enc_chunk.nonce,
            encrypted_size: enc_chunk.encrypted_data.len() as u32,
            plaintext_size: raw_chunk.data.len() as u32,
        });
    }

    let transport = make_transport(server_url).await;

    // Upload chunks with progress
    for (i, enc_chunk) in encrypted_chunks.iter().enumerate() {
        let _ = on_progress.call3(
            &JsValue::NULL,
            &JsValue::from_str("uploading"),
            &JsValue::from((i + 1) as u32),
            &JsValue::from(chunk_count),
        );

        transport
            .upload_chunk(&enc_chunk.hash, &enc_chunk.encrypted_data)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    }

    // Progress: uploading manifest
    let _ = on_progress.call3(
        &JsValue::NULL,
        &JsValue::from_str("manifest"),
        &JsValue::from(chunk_count),
        &JsValue::from(chunk_count),
    );

    // Serialize and encrypt manifest
    let manifest_bytes = serialization::serialize(&manifest)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let manifest_key = derive_manifest_key(&master_key, &file_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut manifest_nonce = [0u8; XCHACHA20_NONCE_LEN];
    rng.fill_bytes(&mut manifest_nonce)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let encrypted_manifest =
        xchacha20_encrypt(&manifest_key, &manifest_nonce, &manifest_bytes, &[])
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let file_id_bytes = file_id.as_bytes();
    let file_id_len = (file_id_bytes.len() as u32).to_be_bytes();
    let mut manifest_payload = Vec::with_capacity(
        XCHACHA20_NONCE_LEN + 4 + file_id_bytes.len() + encrypted_manifest.len(),
    );
    manifest_payload.extend_from_slice(&manifest_nonce);
    manifest_payload.extend_from_slice(&file_id_len);
    manifest_payload.extend_from_slice(file_id_bytes);
    manifest_payload.extend_from_slice(&encrypted_manifest);

    let manifest_id = transport
        .upload_manifest(&manifest_payload)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Store richer metadata
    let meta_key = format!("manifest:{}", manifest_id);
    let meta_value = serde_json::json!({
        "manifest_id": manifest_id,
        "file_id": file_id,
        "filename": filename,
        "size": data.len(),
        "chunks": raw_chunks.len(),
        "merkle_root": hex::encode(merkle_tree.root()),
        "uploaded_at": now,
        "created_at": now,
    });
    let meta_bytes = serde_json::to_vec(&meta_value)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    db.set(&meta_key, &meta_bytes)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Progress: complete
    let _ = on_progress.call3(
        &JsValue::NULL,
        &JsValue::from_str("complete"),
        &JsValue::from(chunk_count),
        &JsValue::from(chunk_count),
    );

    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"manifest_id".into(), &JsValue::from_str(&manifest_id))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(&result, &"file_id".into(), &JsValue::from_str(&file_id))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(&result, &"chunks".into(), &JsValue::from(chunk_count))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(result.into())
}

/// Download and decrypt a file with progress callback.
///
/// The `on_progress` function is called with (step: String, current: u32, total: u32)
/// at each stage.
#[wasm_bindgen]
pub async fn download_file_with_progress(
    manifest_id: &str,
    server_url: &str,
    on_progress: &js_sys::Function,
) -> Result<JsValue, JsValue> {
    console_log(&format!("rustbox: downloading '{}' with progress...", manifest_id));

    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let master_key_bytes = db
        .get(KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault not initialized"))?;

    if master_key_bytes.len() != 32 {
        return Err(JsValue::from_str("invalid master key length"));
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_bytes);

    let transport = make_transport(server_url).await;

    // Progress: downloading manifest
    let _ = on_progress.call3(
        &JsValue::NULL,
        &JsValue::from_str("manifest"),
        &JsValue::from(0u32),
        &JsValue::from(1u32),
    );

    let manifest_payload = transport
        .download_manifest(manifest_id)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    if manifest_payload.len() < XCHACHA20_NONCE_LEN + 4 {
        return Err(JsValue::from_str("manifest payload too short"));
    }

    let mut manifest_nonce = [0u8; XCHACHA20_NONCE_LEN];
    manifest_nonce.copy_from_slice(&manifest_payload[..XCHACHA20_NONCE_LEN]);

    let file_id_len_bytes = &manifest_payload[XCHACHA20_NONCE_LEN..XCHACHA20_NONCE_LEN + 4];
    let file_id_len = u32::from_be_bytes([
        file_id_len_bytes[0], file_id_len_bytes[1],
        file_id_len_bytes[2], file_id_len_bytes[3],
    ]) as usize;

    let file_id_start = XCHACHA20_NONCE_LEN + 4;
    let file_id_end = file_id_start + file_id_len;

    if manifest_payload.len() < file_id_end {
        return Err(JsValue::from_str("manifest payload truncated at file_id"));
    }

    let file_id = String::from_utf8(manifest_payload[file_id_start..file_id_end].to_vec())
        .map_err(|e| JsValue::from_str(&format!("invalid file_id UTF-8: {}", e)))?;

    let encrypted_manifest = &manifest_payload[file_id_end..];

    let manifest_key = derive_manifest_key(&master_key, &file_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let manifest_bytes =
        xchacha20_decrypt(&manifest_key, &manifest_nonce, encrypted_manifest, &[])
            .map_err(|e| JsValue::from_str(&format!("manifest decryption failed: {}", e)))?;

    let manifest: FileManifest = serialization::deserialize(&manifest_bytes)
        .map_err(|e| JsValue::from_str(&format!("manifest deserialization failed: {}", e)))?;

    let file_enc_key = derive_file_enc_key(&master_key, &file_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let total_chunks = manifest.chunks.len() as u32;
    let mut decrypted_chunks: Vec<DecryptedChunk> = Vec::with_capacity(manifest.chunks.len());

    for chunk_entry in &manifest.chunks {
        let _ = on_progress.call3(
            &JsValue::NULL,
            &JsValue::from_str("downloading"),
            &JsValue::from(chunk_entry.index as u32 + 1),
            &JsValue::from(total_chunks),
        );

        let encrypted_data = transport
            .download_chunk(&chunk_entry.hash)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let actual_hash: [u8; 32] = Sha256::digest(&encrypted_data).into();
        if actual_hash != chunk_entry.hash {
            return Err(JsValue::from_str(&format!(
                "chunk {} hash mismatch", chunk_entry.index
            )));
        }

        let plaintext = decrypt_chunk(
            &file_enc_key,
            chunk_entry.index,
            &encrypted_data,
            &chunk_entry.nonce,
        )
        .map_err(|e| JsValue::from_str(&format!("chunk {} decryption failed: {}", chunk_entry.index, e)))?;

        decrypted_chunks.push(DecryptedChunk {
            index: chunk_entry.index,
            data: plaintext,
        });
    }

    let reassembled = reassemble_chunks(&decrypted_chunks);

    let actual_file_hash: [u8; 32] = Sha256::digest(&reassembled).into();
    if actual_file_hash != manifest.file_hash {
        return Err(JsValue::from_str(&format!(
            "file hash mismatch: expected {}, got {}",
            hex::encode(manifest.file_hash),
            hex::encode(actual_file_hash)
        )));
    }

    // Progress: complete
    let _ = on_progress.call3(
        &JsValue::NULL,
        &JsValue::from_str("complete"),
        &JsValue::from(total_chunks),
        &JsValue::from(total_chunks),
    );

    // Build JS result object: { bytes: Uint8Array, filename: String, mime_type: String|null }
    let result = js_sys::Object::new();
    let uint8arr = js_sys::Uint8Array::from(reassembled.as_slice());
    js_sys::Reflect::set(&result, &JsValue::from_str("bytes"), &uint8arr)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    js_sys::Reflect::set(&result, &JsValue::from_str("filename"), &JsValue::from_str(&manifest.filename))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    if let Some(ref mime) = manifest.mime_type {
        js_sys::Reflect::set(&result, &JsValue::from_str("mime_type"), &JsValue::from_str(mime))
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    } else {
        js_sys::Reflect::set(&result, &JsValue::from_str("mime_type"), &JsValue::NULL)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    }

    Ok(result.into())
}

/// Lock the vault by clearing the cached master key from IndexedDB.
#[wasm_bindgen]
pub async fn lock_vault() -> Result<JsValue, JsValue> {
    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    PersistentStorage::delete(&db, KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    PersistentStorage::delete(&db, KEY_USER_ID)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Note: we keep KEY_VAULT_SALT, KEY_USERNAME, KEY_VAULT_VERIFY, KEY_VAULT_VERIFY_NONCE
    // so the vault can be re-unlocked without re-fetching salt from server.

    console_log("rustbox: vault locked");

    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"status".into(), &JsValue::from_str("locked"))
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(result.into())
}

/// List manifests from the server for the current user.
///
/// For each manifest: downloads it, decrypts client-side, extracts filename/size/chunks.
/// Returns a JS array of enriched manifest objects.
#[wasm_bindgen]
pub async fn list_server_manifests(server_url: &str) -> Result<JsValue, JsValue> {
    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let master_key_bytes = db
        .get(KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault not initialized"))?;

    if master_key_bytes.len() != 32 {
        return Err(JsValue::from_str("invalid master key length"));
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_bytes);

    let user_id_bytes = db
        .get(KEY_USER_ID)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("not logged in"))?;
    let user_id = String::from_utf8(user_id_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid user_id: {e}")))?;

    let transport = make_transport(server_url).await;

    // Fetch manifest list from server
    let list_json = transport
        .list_manifests(&user_id)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let server_data: serde_json::Value = serde_json::from_str(&list_json)
        .map_err(|e| JsValue::from_str(&format!("JSON parse failed: {e}")))?;

    let manifests = server_data
        .get("manifests")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let result_array = js_sys::Array::new();

    for manifest_summary in &manifests {
        let manifest_id = manifest_summary
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let data_size = manifest_summary
            .get("data_size")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let created_at = manifest_summary
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Try to download and decrypt the manifest to get filename/size/chunks
        // NOTE: Build JS objects manually (not serde_wasm_bindgen) to ensure plain
        // Objects, not Maps.  Property access (obj.manifest_id) only works on Objects.
        let entry = js_sys::Object::new();

        js_sys::Reflect::set(&entry, &"manifest_id".into(), &JsValue::from_str(manifest_id))
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        js_sys::Reflect::set(&entry, &"created_at".into(), &JsValue::from_str(created_at))
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        js_sys::Reflect::set(&entry, &"data_size".into(), &JsValue::from(data_size as f64))
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        match try_decrypt_manifest(&transport, manifest_id, &master_key).await {
            Ok(info) => {
                js_sys::Reflect::set(&entry, &"filename".into(), &JsValue::from_str(&info.0))
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                js_sys::Reflect::set(&entry, &"size".into(), &JsValue::from(info.1 as f64))
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                js_sys::Reflect::set(&entry, &"chunk_count".into(), &JsValue::from(info.2 as u32))
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
            }
            Err(_) => {
                let fallback_name = format!("encrypted_{}", &manifest_id[..8.min(manifest_id.len())]);
                js_sys::Reflect::set(&entry, &"filename".into(), &JsValue::from_str(&fallback_name))
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                js_sys::Reflect::set(&entry, &"size".into(), &JsValue::from(data_size as f64))
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                js_sys::Reflect::set(&entry, &"chunk_count".into(), &JsValue::from(0u32))
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
            }
        }

        // Also store metadata in IndexedDB so list_files() stays consistent
        let meta_key = format!("manifest:{}", manifest_id);
        if PersistentStorage::get(&db, &meta_key).await.ok().flatten().is_none() {
            let filename_val = js_sys::Reflect::get(&entry, &"filename".into())
                .ok().and_then(|v| v.as_string()).unwrap_or_default();
            let size_val = js_sys::Reflect::get(&entry, &"size".into())
                .ok().and_then(|v| v.as_f64()).unwrap_or(0.0) as u64;
            let chunks_val = js_sys::Reflect::get(&entry, &"chunk_count".into())
                .ok().and_then(|v| v.as_f64()).unwrap_or(0.0) as u64;
            let meta = serde_json::json!({
                "manifest_id": manifest_id,
                "filename": filename_val,
                "size": size_val,
                "chunks": chunks_val,
                "created_at": created_at,
            });
            if let Ok(meta_bytes) = serde_json::to_vec(&meta) {
                let _ = db.set(&meta_key, &meta_bytes).await;
            }
        }

        result_array.push(&entry);
    }

    Ok(result_array.into())
}

/// Helper: try to download and decrypt a manifest, returning (filename, original_size, chunk_count).
async fn try_decrypt_manifest(
    transport: &FetchTransport,
    manifest_id: &str,
    master_key: &[u8; 32],
) -> Result<(String, u64, usize), String> {
    let payload = transport
        .download_manifest(manifest_id)
        .await
        .map_err(|e| e.to_string())?;

    if payload.len() < XCHACHA20_NONCE_LEN + 4 {
        return Err("payload too short".to_string());
    }

    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    nonce.copy_from_slice(&payload[..XCHACHA20_NONCE_LEN]);

    let fid_len_bytes = &payload[XCHACHA20_NONCE_LEN..XCHACHA20_NONCE_LEN + 4];
    let fid_len = u32::from_be_bytes([
        fid_len_bytes[0], fid_len_bytes[1],
        fid_len_bytes[2], fid_len_bytes[3],
    ]) as usize;

    let fid_start = XCHACHA20_NONCE_LEN + 4;
    let fid_end = fid_start + fid_len;

    if fid_len == 0 || fid_len >= 1024 || payload.len() < fid_end {
        return Err("invalid envelope".to_string());
    }

    let file_id = String::from_utf8(payload[fid_start..fid_end].to_vec())
        .map_err(|e| e.to_string())?;
    let ciphertext = &payload[fid_end..];

    let manifest_key = derive_manifest_key(master_key, &file_id)
        .map_err(|e| e.to_string())?;
    let manifest_bytes = xchacha20_decrypt(&manifest_key, &nonce, ciphertext, &[])
        .map_err(|e| e.to_string())?;

    let manifest: FileManifest = serialization::deserialize(&manifest_bytes)
        .map_err(|e| e.to_string())?;

    Ok((manifest.filename, manifest.original_size, manifest.chunks.len()))
}

/// Delete a file from the server by manifest ID.
#[wasm_bindgen]
pub async fn delete_file(manifest_id: &str, server_url: &str) -> Result<JsValue, JsValue> {
    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let user_id_bytes = db
        .get(KEY_USER_ID)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("not logged in"))?;
    let user_id = String::from_utf8(user_id_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid user_id: {e}")))?;

    let transport = make_transport(server_url).await;

    transport
        .delete_manifest(manifest_id, &user_id)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Remove local metadata for this manifest
    let meta_key = format!("manifest:{}", manifest_id);
    let _ = PersistentStorage::delete(&db, &meta_key).await;

    console_log(&format!("rustbox: deleted manifest {}", manifest_id));

    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"deleted".into(), &JsValue::TRUE)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(result.into())
}

/// Get database overview from the server.
///
/// Returns server-side storage info: manifests, blobs, totals.
/// Each manifest is enriched with decrypted filename/size where possible.
#[wasm_bindgen]
pub async fn get_db_overview(server_url: &str) -> Result<JsValue, JsValue> {
    let db = IndexedDbStorage::open()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let master_key_bytes = db
        .get(KEY_MASTER_KEY)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("vault not initialized"))?;

    if master_key_bytes.len() != 32 {
        return Err(JsValue::from_str("invalid master key length"));
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_bytes);

    let user_id_bytes = db
        .get(KEY_USER_ID)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("not logged in"))?;
    let user_id = String::from_utf8(user_id_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid user_id: {e}")))?;

    let transport = make_transport(server_url).await;

    let overview_json = transport
        .get_db_overview(&user_id)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut overview: serde_json::Value = serde_json::from_str(&overview_json)
        .map_err(|e| JsValue::from_str(&format!("JSON parse failed: {e}")))?;

    // Enrich manifest entries with decrypted filenames
    if let Some(manifests) = overview.get_mut("manifests").and_then(|v| v.as_array_mut()) {
        for manifest_entry in manifests.iter_mut() {
            let manifest_id = manifest_entry
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if let Ok((filename, size, chunks)) =
                try_decrypt_manifest(&transport, &manifest_id, &master_key).await
            {
                manifest_entry.as_object_mut().map(|m| {
                    m.insert("filename".to_string(), serde_json::json!(filename));
                    m.insert("original_size".to_string(), serde_json::json!(size));
                    m.insert("chunk_count".to_string(), serde_json::json!(chunks));
                });
            }
        }
    }

    // Use json_compatible() to produce plain JS Objects (not Maps)
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    use serde::Serialize;
    overview.serialize(&serializer)
        .map_err(|e| JsValue::from_str(&format!("serialize error: {e}")))
}
