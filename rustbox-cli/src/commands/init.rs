use std::path::Path;

use sha2::{Sha256, Digest};
use tracing::info;

use rustbox_core::constants::{VAULT_VERIFY_CONSTANT, XCHACHA20_NONCE_LEN, PBKDF2_SALT_LEN};
use rustbox_core::crypto::chacha20::xchacha20_encrypt;
use rustbox_core::crypto::pbkdf2::derive_master_key_default;
use rustbox_core::traits::random::SecureRandom;

use crate::platform::NativeRandom;
use crate::storage::SqliteMeta;

/// Initialize a new RustBox vault in the current directory.
///
/// Creates the `.rustbox/` directory structure, derives a master key from the
/// user's password (optionally using a server-provided salt), and saves the
/// encrypted verification token.
///
/// If `salt_hex` is provided (from server), it is used. Otherwise, a new
/// random salt is generated.
pub async fn run_init(salt_hex: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let rustbox_dir = Path::new(".rustbox");

    if rustbox_dir.exists() {
        return Err("RustBox vault already initialized (.rustbox/ exists)".into());
    }

    // Get username from env or prompt.
    let username = if let Ok(u) = std::env::var("RUSTBOX_USERNAME") {
        u
    } else {
        print!("Enter username: ");
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut u = String::new();
        std::io::stdin().read_line(&mut u)?;
        let u = u.trim().to_string();
        if u.is_empty() {
            return Err("Username cannot be empty".into());
        }
        u
    };

    // Get password from env (for testing/CI) or prompt interactively.
    let password = if let Ok(p) = std::env::var("RUSTBOX_PASSWORD") {
        p
    } else {
        let p = rpassword::prompt_password("Enter vault password: ")?;
        if p.is_empty() {
            return Err("Password cannot be empty".into());
        }
        let confirm = rpassword::prompt_password("Confirm vault password: ")?;
        if p != confirm {
            return Err("Passwords do not match".into());
        }
        p
    };

    info!("Initializing RustBox vault for '{}'...", username);

    let rng = NativeRandom::new();

    // Determine salt: use server-provided or generate new.
    let (salt, new_salt) = if let Some(hex_str) = salt_hex {
        let s = hex::decode(hex_str)?;
        (s, false)
    } else {
        let mut s = [0u8; PBKDF2_SALT_LEN];
        rng.fill_bytes(&mut s)?;
        (s.to_vec(), true)
    };

    // Derive master key via PBKDF2.
    info!("Deriving master key (this may take a moment)...");
    let master_key = derive_master_key_default(password.as_bytes(), &salt)?;

    // Create directory structure.
    tokio::fs::create_dir_all(rustbox_dir.join("blobs"))
        .await
        .map_err(|e| format!("failed to create .rustbox/blobs: {e}"))?;

    // Save salt to .rustbox/salt.
    tokio::fs::write(rustbox_dir.join("salt"), &salt)
        .await
        .map_err(|e| format!("failed to write salt: {e}"))?;

    // Save username.
    tokio::fs::write(rustbox_dir.join("username"), username.as_bytes())
        .await
        .map_err(|e| format!("failed to write username: {e}"))?;

    // Encrypt the verification constant with master_key and save to .rustbox/verify.
    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    rng.fill_bytes(&mut nonce)?;

    let ciphertext = xchacha20_encrypt(&master_key, &nonce, VAULT_VERIFY_CONSTANT, b"")?;

    let mut verify_data = Vec::with_capacity(XCHACHA20_NONCE_LEN + ciphertext.len());
    verify_data.extend_from_slice(&nonce);
    verify_data.extend_from_slice(&ciphertext);

    tokio::fs::write(rustbox_dir.join("verify"), &verify_data)
        .await
        .map_err(|e| format!("failed to write verify token: {e}"))?;

    // Create SQLite metadata DB.
    let db_path = rustbox_dir.join("meta.db");
    let _meta = SqliteMeta::open(&db_path)?;

    let key_fingerprint: [u8; 32] = Sha256::digest(&master_key).into();
    info!(
        "Vault initialized successfully. Key fingerprint: {}",
        hex::encode(&key_fingerprint[..8])
    );

    println!("RustBox vault initialized at .rustbox/");
    println!("Username: {username}");
    println!("Key fingerprint: {}", hex::encode(&key_fingerprint[..8]));
    if new_salt {
        println!("Salt (hex): {}", hex::encode(&salt));
    }
    println!("Remember your password -- there is no recovery mechanism.");

    Ok(())
}

/// Derive the master key from password and the saved salt, then verify
/// against the stored verification token.
///
/// Returns the verified master key on success.
pub async fn unlock_vault(password: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let rustbox_dir = Path::new(".rustbox");

    if !rustbox_dir.exists() {
        return Err("No RustBox vault found. Run `rustbox init` first.".into());
    }

    // Read salt.
    let salt = tokio::fs::read(rustbox_dir.join("salt"))
        .await
        .map_err(|e| format!("failed to read salt: {e}"))?;

    // Derive master key.
    let master_key = derive_master_key_default(password.as_bytes(), &salt)?;

    // Read and verify the verification token.
    let verify_data = tokio::fs::read(rustbox_dir.join("verify"))
        .await
        .map_err(|e| format!("failed to read verify token: {e}"))?;

    if verify_data.len() < XCHACHA20_NONCE_LEN + 1 {
        return Err("corrupt verify token".into());
    }

    let nonce: [u8; XCHACHA20_NONCE_LEN] = verify_data[..XCHACHA20_NONCE_LEN]
        .try_into()
        .map_err(|_| "invalid nonce in verify token")?;
    let ciphertext = &verify_data[XCHACHA20_NONCE_LEN..];

    let plaintext = rustbox_core::crypto::chacha20::xchacha20_decrypt(
        &master_key,
        &nonce,
        ciphertext,
        b"",
    )
    .map_err(|_| "incorrect password (verification failed)")?;

    if plaintext != VAULT_VERIFY_CONSTANT {
        return Err("incorrect password (verification constant mismatch)".into());
    }

    Ok(master_key)
}
