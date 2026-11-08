//! Response types shared with the UI (exported to `ui/src/api/types/` by ts-rs) and the
//! handlers that produce them.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use ts_rs::TS;

use crate::{ApiError, AppState, blocking};

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
    /// Country database used by the next imports (shown in Settings > About).
    pub geoip: GeoipInfo,
}

/// State of the country database file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum GeoipStatus {
    /// Readable: the next imports resolve the countries of public addresses.
    Available,
    /// No database file: countries stay unknown.
    Missing,
    /// A file exists but cannot be used (corrupt, too large): countries stay unknown.
    Invalid,
}

/// Country database (DB-IP IP-to-Country Lite) seen by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct GeoipInfo {
    pub status: GeoipStatus,
    /// Build time of the database (microseconds since the Unix epoch), when available.
    pub built_at_us: Option<i64>,
}

impl GeoipInfo {
    pub(crate) fn missing() -> Self {
        Self {
            status: GeoipStatus::Missing,
            built_at_us: None,
        }
    }
}

pub(crate) async fn server_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ServerInfo>, ApiError> {
    let geoip = blocking(&state, |s| Ok(s.geoip.info())).await?;
    Ok(Json(ServerInfo {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        read_only: state.config.read_only,
        can_browse: !state.config.captures_roots.is_empty(),
        geoip,
    }))
}
