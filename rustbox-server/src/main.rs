mod config;
mod error;
mod state;
mod certs;
mod db;
mod api;
mod quic;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;

use p256::ecdsa::SigningKey;
use p256::EncodedPoint;
use tracing_subscriber::EnvFilter;

use config::Config;
use session::store::SessionStore;
use state::AppState;

#[tokio::main]
async fn main() {
    // Install the ring crypto provider for rustls before any TLS operations.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring crypto provider");

    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("rustbox_server=info,tower_http=info")),
        )
        .init();

    tracing::info!("RustBox Server starting...");

    // Load .env file if present (non-fatal if missing).
    if let Err(e) = dotenvy::dotenv() {
        tracing::debug!("no .env file loaded: {e}");
    }

    // Load configuration.
    let config = Config::from_env();
    tracing::info!(
        https_port = config.https_port,
        quic_port = config.quic_port,
        "configuration loaded"
    );

    // Create database connection pool.
    let pool = match db::pool::create_pool(&config.database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(error = %e, "failed to create database pool");
            std::process::exit(1);
        }
    };

    // Run migrations.
    if let Err(e) = db::pool::run_migrations(&pool).await {
        tracing::error!(error = %e, "failed to run database migrations");
        std::process::exit(1);
    }

    // Generate server ECDH key pair using rustbox-core.
    let (ecdh_private, ecdh_public) = generate_ecdh_keypair();
    tracing::info!(
        ecdh_pub_len = ecdh_public.len(),
        "server ECDH key pair generated"
    );

    // Generate server ECDSA key pair.
    let (ecdsa_private, ecdsa_public) = generate_ecdsa_keypair();
    tracing::info!(
        ecdsa_pub_len = ecdsa_public.len(),
        "server ECDSA key pair generated"
    );

    // Build shared application state.
    let state = Arc::new(AppState {
        pool,
        server_ecdh_private: ecdh_private,
        server_ecdh_public: ecdh_public,
        server_ecdsa_private: ecdsa_private,
        server_ecdsa_public: ecdsa_public,
        sessions: SessionStore::new(),
    });

    // Build the Axum router.
    let router = api::build_router(state.clone());

    // Spawn the Axum HTTPS listener.
    let https_port = config.https_port;
    let axum_handle = tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], https_port));
        tracing::info!(%addr, "Axum HTTP listener starting");

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "failed to bind HTTP listener");
                return;
            }
        };

        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!(error = %e, "Axum server error");
        }
    });

    // Spawn the Quinn QUIC listener.
    let quic_port = config.quic_port;
    let quic_state = state.clone();
    let quic_handle = tokio::spawn(async move {
        if let Err(e) = quic::listener::start_quic_listener(quic_state, quic_port).await {
            tracing::error!(error = %e, "QUIC listener error");
        }
    });

    tracing::info!(
        https_port = config.https_port,
        quic_port = config.quic_port,
        "RustBox Server running"
    );

    // Run both listeners concurrently. If either exits, the server shuts down.
    tokio::select! {
        _ = axum_handle => {
            tracing::warn!("Axum listener exited");
        }
        _ = quic_handle => {
            tracing::warn!("QUIC listener exited");
        }
    }
}

/// Generate an ECDH P-256 key pair using getrandom.
fn generate_ecdh_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut key_bytes = [0u8; 32];
    getrandom::getrandom(&mut key_bytes).expect("failed to generate random bytes for ECDH key");

    let secret = p256::SecretKey::from_bytes((&key_bytes).into())
        .expect("failed to create P-256 secret key");
    let public = secret.public_key();
    let encoded = p256::EncodedPoint::from(public);

    (secret.to_bytes().to_vec(), encoded.as_bytes().to_vec())
}

/// Generate an ECDSA P-256 key pair using getrandom.
fn generate_ecdsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut key_bytes = [0u8; 32];
    getrandom::getrandom(&mut key_bytes).expect("failed to generate random bytes for ECDSA key");

    let signing_key = SigningKey::from_bytes((&key_bytes).into())
        .expect("failed to create P-256 signing key");
    let verifying_key = signing_key.verifying_key();
    let encoded = EncodedPoint::from(verifying_key);

    (signing_key.to_bytes().to_vec(), encoded.as_bytes().to_vec())
}

