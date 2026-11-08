//! HTTP API (axum) routes and DTOs exported to TypeScript.
//!
//! The same router serves the desktop app (bound to `127.0.0.1:<random port>`) and the
//! containerized dev mode. Every route except `GET /api/v1/health` requires
//! `Authorization: Bearer <token>`. Errors are `application/problem+json` (RFC 9457).
//! Mutating routes are additionally refused in read-only mode and for cross-site requests
//! (`guard`). The sessions and import routes follow the frozen [`contract`].

mod auth;
pub mod contract;
mod convert;
mod dto;
mod error;
mod extract;
mod fs;
mod guard;
mod imports;
mod sessions;

use std::future::{Future, IntoFuture};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::routing::get;
use netsift_engine::IngestOptions;
use netsift_store::Catalog;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub use dto::HealthResponse;
pub use error::ApiError;

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

/// After the shutdown signal, open connections (SSE streams included) get this long to close
/// before the server stops anyway.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// After the server stops, running imports (cancelled) get this long to write their last rows
/// and mark their session `incomplete`. Past it, the session stays `importing` and is recovered
/// as `incomplete` by `netsift_engine::recover_interrupted` at the next start.
pub const IMPORT_GRACE: Duration = Duration::from_secs(10);

/// Runtime configuration of the API server. `Debug` never prints the token.
#[derive(Clone)]
pub struct ApiConfig {
    /// Bearer token required on every authenticated route. Must be long and random.
    pub token: String,
    /// Application data directory (catalog, sessions).
    pub data_dir: PathBuf,
    /// Roots that the folder browser may list (dev web mode only). Scan and import are limited
    /// to them unless `allow_any_path` is set.
    pub captures_roots: Vec<PathBuf>,
    /// Refuse every mutating route (preview and screenshot sessions).
    pub read_only: bool,
    /// Extra origins allowed by CORS (the desktop webview origin). Same-origin needs none.
    pub cors_origins: Vec<HeaderValue>,
    /// Accept any absolute path for scan and import (desktop: the path comes from the native
    /// folder dialog). False in dev web mode: only paths inside `captures_roots`.
    pub allow_any_path: bool,
    /// Imports allowed to run at the same time (at least 1; [`DEFAULT_MAX_IMPORTS`]). Beyond,
    /// `POST /sessions/import` answers 409 `urn:netsift:problem:too-many-imports`.
    pub max_imports: usize,
}

/// Default of [`ApiConfig::max_imports`]: each import already uses every core.
pub const DEFAULT_MAX_IMPORTS: usize = 2;

impl std::fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConfig")
            .field("token", &"<redacted>")
            .field("data_dir", &self.data_dir)
            .field("captures_roots", &self.captures_roots)
            .field("read_only", &self.read_only)
            .field("cors_origins", &self.cors_origins)
            .field("allow_any_path", &self.allow_any_path)
            .field("max_imports", &self.max_imports)
            .finish()
    }
}

/// Shared state handed to handlers.
pub(crate) struct AppState {
    pub(crate) config: ApiConfig,
    /// `captures_roots`, canonicalized (roots that do not exist are dropped).
    pub(crate) roots: Vec<PathBuf>,
    /// Catalog of the request handlers, opened on first use. Imports open their own.
    catalog: Mutex<Option<Catalog>>,
    pub(crate) imports: imports::Registry,
    /// Options of every import (name, selection and recursion are set per request).
    pub(crate) ingest_template: IngestOptions,
    shutdown: watch::Sender<bool>,
}

impl AppState {
    fn new(config: ApiConfig, ingest_template: IngestOptions) -> Self {
        let roots = fs::canonical_roots(&config.captures_roots);
        Self {
            config,
            roots,
            catalog: Mutex::new(None),
            imports: imports::Registry::new(),
            ingest_template,
            shutdown: watch::Sender::new(false),
        }
    }

    /// Runs `f` with the shared catalog (blocking: call it from [`blocking`]).
    pub(crate) fn with_catalog<R>(
        &self,
        f: impl FnOnce(&Catalog) -> Result<R, ApiError>,
    ) -> Result<R, ApiError> {
        let mut guard = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.is_none() {
            let catalog = Catalog::open(&self.config.data_dir).map_err(|e| {
                tracing::error!("cannot open the catalog: {e}");
                ApiError::Internal
            })?;
            *guard = Some(catalog);
        }
        match guard.as_ref() {
            Some(catalog) => f(catalog),
            None => Err(ApiError::Internal),
        }
    }

    pub(crate) fn is_shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }

    /// Resolves once the server starts shutting down.
    pub(crate) fn shutdown_signal(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut rx = self.shutdown.subscribe();
        async move {
            // An error means the state is gone: shutting down as well.
            let _ = rx.wait_for(|down| *down).await;
        }
    }

    /// Ends the SSE streams and cancels the running imports.
    pub(crate) fn begin_shutdown(&self) {
        self.shutdown.send_replace(true);
        self.imports.cancel_all();
    }

    /// Waits (at most `limit`) for every import thread to end. True if they all ended.
    pub(crate) async fn wait_imports(&self, limit: Duration) -> bool {
        tokio::time::timeout(limit, self.imports.wait_idle())
            .await
            .is_ok()
    }
}

/// Runs blocking work (SQLite, file system) on the blocking thread pool.
pub(crate) async fn blocking<R: Send + 'static>(
    state: &Arc<AppState>,
    f: impl FnOnce(&AppState) -> Result<R, ApiError> + Send + 'static,
) -> Result<R, ApiError> {
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || f(&state))
        .await
        .map_err(|_| ApiError::Internal)?
}

/// Import options used by the server: progress at most 4 times per second.
fn default_ingest_options() -> IngestOptions {
    IngestOptions {
        progress_interval: imports::PROGRESS_INTERVAL,
        ..IngestOptions::default()
    }
}

/// Builds the full router: `/api/v1/*` routes, authentication, CORS and problem+json fallback.
pub fn router(config: ApiConfig) -> Router {
    build(config, default_ingest_options()).0
}

pub(crate) fn build(config: ApiConfig, ingest: IngestOptions) -> (Router, Arc<AppState>) {
    let cors = cors_layer(&config.cors_origins);
    let state = Arc::new(AppState::new(config, ingest));

    let protected = Router::new()
        // Registration point: one `.merge(<module>::routes())` line per feature, sorted.
        .merge(fs::routes())
        .merge(imports::routes())
        .merge(sessions::routes())
        .route("/server-info", get(dto::server_info))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            guard::mutations,
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_bearer,
        ));

    let api = Router::new()
        .route("/health", get(dto::health))
        .merge(protected)
        .method_not_allowed_fallback(error::method_not_allowed)
        .fallback(error::not_found);

    let app = Router::new()
        .nest("/api/v1", api)
        .fallback(error::not_found)
        .layer(cors)
        .with_state(Arc::clone(&state));
    (app, state)
}

fn cors_layer(origins: &[HeaderValue]) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins.iter().cloned()))
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("last-event-id"),
        ])
}

/// Serves the API on an already-bound listener until `shutdown` resolves.
///
/// Binding is left to the caller so the desktop app can bind `127.0.0.1:0` and read the port.
/// Shutdown is bounded: SSE streams end at once, open connections get [`SHUTDOWN_GRACE`],
/// then running imports are cancelled and get [`IMPORT_GRACE`] to mark their session
/// `incomplete`.
pub async fn serve(
    listener: TcpListener,
    config: ApiConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    serve_with(listener, build(config, default_ingest_options()), shutdown).await
}

pub(crate) async fn serve_with(
    listener: TcpListener,
    (app, state): (Router, Arc<AppState>),
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let on_signal = Arc::clone(&state);
    let signal = async move {
        shutdown.await;
        tracing::info!("shutting down: closing streams and cancelling imports");
        on_signal.begin_shutdown();
    };
    let shutting_down = state.shutdown_signal();
    let forced = async move {
        shutting_down.await;
        tokio::time::sleep(SHUTDOWN_GRACE).await;
    };
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(signal)
        .into_future();
    tokio::select! {
        result = server => result?,
        () = forced => tracing::warn!("connections still open after the grace period; closing them"),
    }
    // Idempotent; also covers a server that stopped on an I/O error.
    state.begin_shutdown();
    if !state.wait_imports(IMPORT_GRACE).await {
        tracing::warn!(
            "an import did not stop in time; it will be marked incomplete at next start"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
