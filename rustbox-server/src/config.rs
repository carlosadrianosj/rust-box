use std::env;

/// Server configuration loaded from environment variables.
pub struct Config {
    /// PostgreSQL connection URL.
    pub database_url: String,
    /// Port for the Axum HTTPS listener.
    pub https_port: u16,
    /// Port for the Quinn QUIC listener.
    pub quic_port: u16,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// - `DATABASE_URL` (required): PostgreSQL connection string.
    /// - `HTTPS_PORT` (optional, default 8443): Port for HTTPS API.
    /// - `QUIC_PORT` (optional, default 4433): Port for QUIC transport.
    pub fn from_env() -> Self {
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://rustbox:rustbox@localhost:5432/rustbox".to_string());

        let https_port = env::var("HTTPS_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(8443);

        let quic_port = env::var("QUIC_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(4433);

        Self {
            database_url,
            https_port,
            quic_port,
        }
    }
}
