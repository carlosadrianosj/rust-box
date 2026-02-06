mod commands;
mod platform;
mod storage;
mod transport;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rustbox", about = "Zero-knowledge encrypted file sync")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new RustBox vault in the current directory
    Init,

    /// Login (register) with a RustBox server (auto-creates vault if needed)
    Login {
        /// Server address (host:port)
        #[arg(long)]
        server: String,
    },

    /// Upload a file to the RustBox server
    Upload {
        /// Path to the file to upload
        file: String,

        /// Server address (host:port). If omitted, uses address stored from last login.
        #[arg(long)]
        server: Option<String>,
    },

    /// Download a file from the RustBox server by manifest ID
    Download {
        /// Manifest ID returned by upload
        manifest_id: String,

        /// Output file path
        output: String,

        /// Server address (host:port). If omitted, uses address stored from last login.
        #[arg(long)]
        server: Option<String>,
    },

    /// Synchronize local blobs with the RustBox server
    Sync {
        /// Server address (host:port). If omitted, uses address stored from last login.
        #[arg(long)]
        server: Option<String>,
    },

    /// Show the current status of the RustBox vault
    Status,

    /// List all files on the server (cross-client view)
    Files {
        /// Server address (host:port). If omitted, uses address stored from last login.
        #[arg(long)]
        server: Option<String>,
    },

    /// Delete a file from the RustBox server by manifest ID
    Delete {
        /// Manifest ID to delete (from `rustbox files`)
        manifest_id: String,

        /// Server address (host:port). If omitted, uses address stored from last login.
        #[arg(long)]
        server: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() {
    // Initialize tracing (controlled by RUST_LOG env var).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init => commands::init::run_init(None).await,
        Commands::Login { server } => commands::login::run_login(&server).await,
        Commands::Upload { file, server } => {
            let server = match resolve_server(server.as_deref()) {
                Ok(s) => s,
                Err(e) => { eprintln!("Error: {e}"); std::process::exit(1); }
            };
            commands::upload::run_upload(&file, &server).await
        }
        Commands::Download {
            manifest_id,
            output,
            server,
        } => {
            let server = match resolve_server(server.as_deref()) {
                Ok(s) => s,
                Err(e) => { eprintln!("Error: {e}"); std::process::exit(1); }
            };
            commands::download::run_download(&manifest_id, &output, &server).await
        }
        Commands::Sync { server } => {
            let server = match resolve_server(server.as_deref()) {
                Ok(s) => s,
                Err(e) => { eprintln!("Error: {e}"); std::process::exit(1); }
            };
            commands::sync::run_sync(&server).await
        }
        Commands::Status => commands::status::run_status().await,
        Commands::Files { server } => {
            let server = match resolve_server(server.as_deref()) {
                Ok(s) => s,
                Err(e) => { eprintln!("Error: {e}"); std::process::exit(1); }
            };
            commands::files::run_files(&server).await
        }
        Commands::Delete { manifest_id, server, yes } => {
            let server = match resolve_server(server.as_deref()) {
                Ok(s) => s,
                Err(e) => { eprintln!("Error: {e}"); std::process::exit(1); }
            };
            commands::delete::run_delete(&manifest_id, &server, yes).await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

/// Resolve server address: use provided value, or fall back to stored value from last login.
fn resolve_server(provided: Option<&str>) -> Result<String, String> {
    if let Some(s) = provided {
        return Ok(s.to_string());
    }

    // Try reading from .rustbox/meta.db
    let meta_path = std::path::Path::new(".rustbox/meta.db");
    if !meta_path.exists() {
        return Err(
            "No --server provided and no stored server found. Run `rustbox login --server HOST:PORT` first.".to_string()
        );
    }

    // Use a blocking read since we're not inside an async context yet
    let conn = rusqlite::Connection::open(meta_path)
        .map_err(|e| format!("Failed to open meta.db: {e}"))?;

    let result: Result<Vec<u8>, _> = conn.query_row(
        "SELECT value FROM metadata WHERE key = 'server'",
        [],
        |row| row.get(0),
    );

    match result {
        Ok(bytes) => {
            let server = String::from_utf8(bytes)
                .map_err(|e| format!("Invalid stored server address: {e}"))?;
            Ok(server)
        }
        Err(_) => Err(
            "No --server provided and no stored server found. Run `rustbox login --server HOST:PORT` first.".to_string()
        ),
    }
}
