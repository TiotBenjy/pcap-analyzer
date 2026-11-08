//! HTTP API (axum) routes and DTOs exported to TypeScript.
//!
//! The same router serves the desktop app (bound to `127.0.0.1:<random port>`) and the
//! containerized dev mode. Every route except `GET /api/v1/health` requires
//! `Authorization: Bearer <token>`. Errors are `application/problem+json` (RFC 9457).
//! Mutating routes are additionally refused in read-only mode and for cross-site requests
//! (`guard`). The sessions and import routes follow the frozen [`contract`].

mod auth;
mod connections;
pub mod contract;
mod convert;
mod dns;
mod dto;
mod endpoint;
mod error;
mod extract;
mod fs;
mod geoip;
mod guard;
mod http;
mod imports;
mod objects;
mod overview;
mod ports;
mod servers;
mod sessions;
mod smb;
mod tls;

use std::future::{Future, IntoFuture};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::routing::get;
use netsift_engine::IngestOptions;
use netsift_store::{Catalog, StoreError};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub use dto::{GeoipInfo, GeoipSource, GeoipStatus, HealthResponse};
pub use error::ApiError;
/// Location of the country database: the desktop app resolves it, the server reports it.
pub use netsift_geo::{DB_FILE_NAME as GEOIP_FILE_NAME, default_path as default_geoip_path};

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
    /// Fallback country database, never written: read when the user copy
    /// `<data_dir>/geoip/dbip-country-lite.mmdb` is missing or unusable (desktop: the copy shipped
    /// in the bundle). The user copy is always read first; it is the file written by the updates
    /// of Settings (`POST /geoip/download`, `POST /geoip/import`) and by `./x.sh geoip` in dev.
    pub geoip_fallback_path: Option<PathBuf>,
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
            .field("geoip_fallback_path", &self.geoip_fallback_path)
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
    /// Country database of the imports (hot-swapped by the updates).
    pub(crate) geoip: geoip::Geoip,
    shutdown: watch::Sender<bool>,
}

impl AppState {
    fn new(config: ApiConfig, mut ingest_template: IngestOptions) -> Self {
        let roots = fs::canonical_roots(&config.captures_roots);
        let user_geoip = netsift_geo::default_path(&config.data_dir);
        // Imports get the database loaded by `geoip` (`AnalyzerConfig::geo`); the engine reads
        // this path only when none is usable.
        ingest_template.geoip_path = Some(user_geoip.clone());
        if !config.read_only {
            let removed = netsift_geo::remove_orphan_temp_files(&user_geoip);
            if removed > 0 {
                tracing::info!(removed, "interrupted GeoIP update files removed");
            }
        }
        let geoip = geoip::Geoip::new(user_geoip, config.geoip_fallback_path.clone());
        Self {
            config,
            roots,
            catalog: Mutex::new(None),
            imports: imports::Registry::new(),
            ingest_template,
            geoip,
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
        .merge(connections::routes())
        .merge(dns::routes())
        .merge(fs::routes())
        .merge(geoip::routes())
        .merge(http::routes())
        .merge(imports::routes())
        .merge(objects::routes())
        .merge(overview::routes())
        .merge(ports::routes())
        .merge(servers::routes())
        .merge(sessions::routes())
        .merge(smb::routes())
        .merge(tls::routes())
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

/// A server ready to run. Use it instead of [`serve`] when the embedding application needs a
/// [`ServerMonitor`] (the desktop app asks for confirmation before closing during an import).
pub struct Server {
    app: Router,
    state: Arc<AppState>,
}

impl Server {
    pub fn new(config: ApiConfig) -> Self {
        let (app, state) = build(config, default_ingest_options());
        Self { app, state }
    }

    /// Read-only view of the server state, usable from any thread.
    pub fn monitor(&self) -> ServerMonitor {
        ServerMonitor(Arc::downgrade(&self.state))
    }

    /// Same as [`serve`].
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        serve_with(listener, (self.app, self.state), shutdown).await
    }
}

/// Read-only view of a [`Server`], valid while the server exists.
#[derive(Clone)]
pub struct ServerMonitor(Weak<AppState>);

impl ServerMonitor {
    /// Number of imports running now (0 once the server is gone).
    pub fn running_imports(&self) -> usize {
        self.0
            .upgrade()
            .map_or(0, |state| state.imports.running_count())
    }
}

/// Error of [`recover_interrupted`].
#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    #[error("cannot open the catalog in {path}: {source}")]
    Catalog { path: PathBuf, source: StoreError },
    #[error("cannot recover the interrupted imports: {0}")]
    Engine(#[from] netsift_engine::EngineError),
}

/// Marks the sessions left `importing` by a previous run (crash, kill, import that did not stop
/// within [`IMPORT_GRACE`]) as `incomplete`, and returns their ids. Call it once at startup,
/// before serving, and not in read-only mode.
pub fn recover_interrupted(data_dir: &Path) -> Result<Vec<String>, RecoverError> {
    let catalog = Catalog::open(data_dir).map_err(|source| RecoverError::Catalog {
        path: data_dir.to_owned(),
        source,
    })?;
    Ok(netsift_engine::recover_interrupted(&catalog)?
        .into_iter()
        .map(|id| id.to_string())
        .collect())
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
    Server::new(config).serve(listener, shutdown).await
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
#[cfg(test)]
mod upgrade_tests;
