//! HTTP API (axum) routes and DTOs exported to TypeScript.
//!
//! The same router serves the desktop app (bound to `127.0.0.1:<random port>`) and the
//! containerized dev mode. Every route except `GET /api/v1/health` requires
//! `Authorization: Bearer <token>`. Errors are `application/problem+json` (RFC 9457).

mod auth;
pub mod contract;
mod dto;
mod error;

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::routing::get;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub use dto::HealthResponse;
pub use error::ApiError;

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

/// Runtime configuration of the API server. `Debug` never prints the token.
#[derive(Clone)]
pub struct ApiConfig {
    /// Bearer token required on every authenticated route. Must be long and random.
    pub token: String,
    /// Application data directory (catalog, sessions).
    pub data_dir: PathBuf,
    /// Roots that the folder browser may list (dev web mode only).
    pub captures_roots: Vec<PathBuf>,
    /// Refuse every mutating route (preview and screenshot sessions).
    pub read_only: bool,
    /// Extra origins allowed by CORS (the desktop webview origin). Same-origin needs none.
    pub cors_origins: Vec<HeaderValue>,
}

impl std::fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConfig")
            .field("token", &"<redacted>")
            .field("data_dir", &self.data_dir)
            .field("captures_roots", &self.captures_roots)
            .field("read_only", &self.read_only)
            .field("cors_origins", &self.cors_origins)
            .finish()
    }
}

/// Shared state handed to handlers.
#[derive(Debug)]
pub(crate) struct AppState {
    pub(crate) config: ApiConfig,
}

/// Builds the full router: `/api/v1/*` routes, authentication, CORS and problem+json fallback.
pub fn router(config: ApiConfig) -> Router {
    let cors = cors_layer(&config.cors_origins);
    let state = Arc::new(AppState { config });

    let protected = Router::new()
        // Registration point: one `.merge(<module>::routes())` line per feature, sorted.
        .route("/server-info", get(dto::server_info))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_bearer,
        ));

    let api = Router::new()
        .route("/health", get(dto::health))
        .merge(protected)
        .method_not_allowed_fallback(error::method_not_allowed)
        .fallback(error::not_found);

    Router::new()
        .nest("/api/v1", api)
        .fallback(error::not_found)
        .layer(cors)
        .with_state(state)
}

fn cors_layer(origins: &[HeaderValue]) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins.iter().cloned()))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("last-event-id"),
        ])
}

/// Serves the API on an already-bound listener until `shutdown` resolves.
///
/// Binding is left to the caller so the desktop app can bind `127.0.0.1:0` and read the port.
pub async fn serve(
    listener: TcpListener,
    config: ApiConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = router(config);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests;
