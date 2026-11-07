//! Response types shared with the UI (exported to `ui/src/api/types/` by ts-rs) and the
//! handlers that produce them.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use ts_rs::TS;

use crate::AppState;

/// `GET /api/v1/health` (unauthenticated): liveness probe used by scripts and the UI.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct HealthResponse {
    /// Always `"ok"` when the server answers.
    pub status: String,
    /// Backend version (`CARGO_PKG_VERSION`).
    pub version: String,
}

pub(crate) async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}

/// `GET /api/v1/server-info` (authenticated): server mode, used by the UI to adapt itself.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct ServerInfo {
    pub version: String,
    /// True when mutating routes are disabled (preview, screenshots).
    pub read_only: bool,
    /// True when the web folder browser is available (dev mode with mounted capture roots).
    pub can_browse: bool,
}

pub(crate) async fn server_info(State(state): State<Arc<AppState>>) -> Json<ServerInfo> {
    Json(ServerInfo {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        read_only: state.config.read_only,
        can_browse: !state.config.captures_roots.is_empty(),
    })
}
