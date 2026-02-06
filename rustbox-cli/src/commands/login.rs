use std::path::Path;

use sha2::{Sha256, Digest};
use tracing::info;

use rustbox_core::constants::PBKDF2_SALT_LEN;
use rustbox_core::crypto::key_hierarchy::derive_auth_key;
use rustbox_core::traits::random::SecureRandom;

use crate::commands::init::unlock_vault;
use crate::platform::NativeRandom;
use crate::transport::QuicTransport;

/// Login (register) with a RustBox server.
///
/// 1. Reads username from .rustbox/username or RUSTBOX_USERNAME env
/// 2. Connects to server via QUIC
/// 3. Fetches salt for username (CMD_GET_SALT)
/// 4. If no salt: generates new salt, creates/updates local vault, registers as new user
/// 5. If salt found: uses server salt, unlocks vault, registers as existing user
/// 6. Saves user_id to local metadata
pub async fn run_login(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let rustbox_dir = Path::new(".rustbox");

    // Get username
    let username = if let Ok(u) = std::env::var("RUSTBOX_USERNAME") {
        u
    } else {
        let username_path = rustbox_dir.join("username");
        if username_path.exists() {
            tokio::fs::read_to_string(&username_path).await?
        } else {
            print!("Enter username: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut u = String::new();
            std::io::stdin().read_line(&mut u)?;
            u.trim().to_string()
        }
    };

    if username.is_empty() {
        return Err("Username cannot be empty".into());
    }

    // Get password
    let password = std::env::var("RUSTBOX_PASSWORD")
        .unwrap_or_else(|_| rpassword::prompt_password("Enter vault password: ").expect("failed to read password"));

    info!("Connecting to server {server}...");

    let transport = QuicTransport::connect(server).await?;

    // Fetch salt from server
    info!("Fetching salt for '{}' from server...", username);
    let server_salt = match transport.get_salt(&username).await {
        Ok(Some(salt_bytes)) => {
            info!("Got salt from server (existing user)");
            Some(salt_bytes)
        }
        Ok(None) => {
            info!("No salt on server (new user)");
            None
        }
        Err(e) => {
            info!("Salt fetch failed (treating as new user): {e}");
            None
        }
    };

    // Determine salt and derive master key
    let (salt, new_salt) = if let Some(ref s) = server_salt {
        (s.clone(), false)
    } else if rustbox_dir.exists() && rustbox_dir.join("salt").exists() {
        // Use existing local salt
        let s = tokio::fs::read(rustbox_dir.join("salt")).await?;
        (s, true) // Treat as new since server doesn't have it
    } else {
        // Generate new salt
        let rng = NativeRandom::new();
        let mut s = [0u8; PBKDF2_SALT_LEN];
        rng.fill_bytes(&mut s)?;
        (s.to_vec(), true)
    };

    // If vault exists, try to unlock with the salt
    let master_key = if rustbox_dir.exists() && rustbox_dir.join("salt").exists() {
        // Check if local salt matches
        let local_salt = tokio::fs::read(rustbox_dir.join("salt")).await?;
        if local_salt == salt {
            unlock_vault(&password).await?
        } else {
            // Salt mismatch — need to recreate vault with server salt
            info!("Salt mismatch, recreating vault with server salt...");
            tokio::fs::remove_dir_all(rustbox_dir).await?;
            crate::commands::init::run_init(Some(&hex::encode(&salt))).await?;
            unlock_vault(&password).await?
        }
    } else {
        // No vault yet — create one
        crate::commands::init::run_init(Some(&hex::encode(&salt))).await?;
        unlock_vault(&password).await?
    };

    // Save username if not already saved
    let username_path = rustbox_dir.join("username");
    if !username_path.exists() || tokio::fs::read_to_string(&username_path).await.unwrap_or_default() != username {
        tokio::fs::write(&username_path, username.as_bytes()).await?;
    }

    info!("Master key verified, deriving auth key...");

    let auth_key = derive_auth_key(&master_key)?;
    let auth_key_hash: [u8; 32] = Sha256::digest(&auth_key).into();

    info!("Registering with server as '{}'...", username);

    let salt_hex = if new_salt { Some(hex::encode(&salt)) } else { None };
    let user_id = transport
        .register_with_username(&username, salt_hex.as_deref(), &auth_key_hash)
        .await?;

    info!("Login successful. user_id={user_id}");

    // Save user_id and server address to local metadata.
    let meta_db = crate::storage::SqliteMeta::open(&Path::new(".rustbox/meta.db"))?;
    use rustbox_core::traits::storage::PersistentStorage;
    meta_db.set("user_id", user_id.as_bytes()).await?;
    meta_db.set("server", server.as_bytes()).await?;

    println!("Logged in successfully as '{username}'.");
    println!("User ID: {user_id}");
    println!("Server:  {server} (stored for future commands)");

    Ok(())
}
