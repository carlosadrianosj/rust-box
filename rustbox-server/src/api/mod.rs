pub mod chunks;
pub mod manifests;
pub mod sync;
pub mod auth;
pub mod db;

use std::sync::Arc;

use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the Axum router with all API routes, CORS, and tracing middleware.
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let chunk_routes = Router::new()
        .route(
            "/:hash",
            axum::routing::put(chunks::upload_chunk).get(chunks::download_chunk),
        );

    let manifest_routes = Router::new()
        .route("/", axum::routing::post(manifests::upload_manifest))
        .route("/list", axum::routing::get(manifests::list_manifests))
        .route(
            "/:id",
            axum::routing::get(manifests::download_manifest)
                .delete(manifests::delete_manifest),
        );

    let sync_routes = Router::new()
        .route("/root", axum::routing::get(sync::get_root))
        .route("/diff", axum::routing::post(sync::get_diff));

    let auth_routes = Router::new()
        .route("/register", axum::routing::post(auth::register))
        .route("/salt", axum::routing::get(auth::get_salt));

    let db_routes = Router::new()
        .route("/overview", axum::routing::get(db::get_overview));

    Router::new()
        .nest("/api/chunks", chunk_routes)
        .nest("/api/manifests", manifest_routes)
        .nest("/api/sync", sync_routes)
        .nest("/api/auth", auth_routes)
        .nest("/api/db", db_routes)
        .route("/health", axum::routing::get(health_check))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Simple health check endpoint.
async fn health_check() -> &'static str {
    "ok"
}
