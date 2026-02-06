use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use rustls::ServerConfig as RustlsServerConfig;

use crate::certs::generate_self_signed_cert;
use crate::error::{Result, ServerError};
use crate::state::AppState;

/// Start the Quinn QUIC listener on the given port.
///
/// Accepts incoming connections and spawns a handler task for each one.
pub async fn start_quic_listener(state: Arc<AppState>, port: u16) -> Result<()> {
    let (certs, key) = generate_self_signed_cert();

    let mut rustls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::Crypto(format!("TLS config error: {e}")))?;

    // Enable ALPN for QUIC.
    rustls_config.alpn_protocols = vec![b"rustbox-quic".to_vec()];

    let quinn_config = QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| ServerError::Crypto(format!("QUIC crypto config error: {e}")))?,
    ));

    let addr: SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .map_err(|e| ServerError::Internal(format!("invalid address: {e}")))?;

    let endpoint = Endpoint::server(quinn_config, addr)
        .map_err(|e| ServerError::Internal(format!("QUIC endpoint bind error: {e}")))?;

    tracing::info!(%addr, "QUIC listener started");

    // Accept loop.
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            // Accept the incoming connection attempt, then await the handshake.
            let connecting = match incoming.accept() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to accept incoming QUIC connection");
                    return;
                }
            };

            match connecting.await {
                Ok(connection) => {
                    let remote = connection.remote_address();
                    tracing::info!(%remote, "QUIC connection established");

                    if let Err(e) = super::handler::handle_connection(state, connection).await {
                        tracing::error!(%remote, error = %e, "connection handler error");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "QUIC handshake failed");
                }
            }
        });
    }

    Ok(())
}
