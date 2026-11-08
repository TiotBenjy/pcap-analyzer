//! Path policy (allowed roots) and the dev web mode folder browser (`GET /fs/browse`).
//!
//! Every path received from the client is absolute, free of `..` components, and
//! canonicalized (symbolic links resolved) before being compared with the canonical roots, so
//! that neither `..` nor a link pointing outside a root can escape it.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use crate::contract::{BrowseResponse, FsEntry};
use crate::extract::ApiQuery;
use crate::{ApiError, AppState, blocking};

/// Most entries returned by one listing (folders first, then files, by name).
pub(crate) const MAX_BROWSE_ENTRIES: usize = 5_000;
/// Most directory entries examined by one listing.
const MAX_EXAMINED: usize = 50_000;
/// Longest accepted path, in bytes.
const MAX_PATH_LEN: usize = 4_096;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/fs/browse", get(browse))
}

/// Canonical form of the configured roots; missing roots are dropped (with a warning).
pub(crate) fn canonical_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for root in roots {
        match std::fs::canonicalize(root) {
            Ok(c) if c.is_dir() => {
                if !out.contains(&c) {
                    out.push(c);
                }
            }
            _ => tracing::warn!(root = %root.display(), "captures root ignored: not a folder"),
        }
    }
    out
}

fn within(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|r| path.starts_with(r))
}

/// Syntactic checks, then canonicalization (a missing path is a 404).
fn canonical_input(raw: &str) -> Result<PathBuf, ApiError> {
    if raw.is_empty() || raw.len() > MAX_PATH_LEN || raw.contains('\0') {
        return Err(ApiError::BadRequest("invalid path".to_owned()));
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(ApiError::BadRequest("the path must be absolute".to_owned()));
    }
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(ApiError::BadRequest(
            "the path must not contain '..'".to_owned(),
        ));
    }
    std::fs::canonicalize(path).map_err(|_| ApiError::NotFound)
}

/// Input of scan and import: inside an allowed root, or anywhere in desktop mode.
pub(crate) fn resolve_input(state: &AppState, raw: &str) -> Result<PathBuf, ApiError> {
    let path = canonical_input(raw)?;
    if state.config.allow_any_path || within(&path, &state.roots) {
        Ok(path)
    } else {
        Err(ApiError::Forbidden("path outside the allowed roots"))
    }
}

#[derive(Debug, Deserialize)]
struct BrowseQuery {
    path: Option<String>,
}

async fn browse(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<BrowseQuery>,
) -> Result<Json<BrowseResponse>, ApiError> {
    blocking(&state, move |s| list_dir(&s.roots, query.path.as_deref()))
        .await
        .map(Json)
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Lists a folder inside the roots (`None`: the first root). The browser is always limited to
/// the roots, even when imports accept any path.
pub(crate) fn list_dir(roots: &[PathBuf], raw: Option<&str>) -> Result<BrowseResponse, ApiError> {
    let Some(first) = roots.first() else {
        return Err(ApiError::NotFound);
    };
    let dir = match raw {
        None | Some("") => first.clone(),
        Some(raw) => {
            let dir = canonical_input(raw)?;
            if !within(&dir, roots) {
                return Err(ApiError::Forbidden("path outside the allowed roots"));
            }
            dir
        }
    };
    if !dir.is_dir() {
        return Err(ApiError::BadRequest("not a folder".to_owned()));
    }
    let listing = std::fs::read_dir(&dir)
        .map_err(|_| ApiError::BadRequest("the folder cannot be listed".to_owned()))?;
    let mut entries = Vec::new();
    for item in listing.take(MAX_EXAMINED).flatten() {
        // Names that are not UTF-8 could not be sent back as a path: skipped, like hidden files.
        let Ok(name) = item.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let Ok(kind) = item.file_type() else {
            continue;
        };
        let entry = if kind.is_dir() {
            Some((true, 0))
        } else if kind.is_file() {
            item.metadata().ok().map(|m| (false, m.len()))
        } else if kind.is_symlink() {
            // Followed only when the target stays inside a root.
            std::fs::canonicalize(item.path())
                .ok()
                .filter(|target| within(target, roots))
                .and_then(|target| std::fs::metadata(target).ok())
                .and_then(|m| {
                    if m.is_dir() {
                        Some((true, 0))
                    } else if m.is_file() {
                        Some((false, m.len()))
                    } else {
                        None
                    }
                })
        } else {
            // FIFOs, sockets, devices: never listed (opening them could block).
            None
        };
        if let Some((is_dir, size)) = entry {
            entries.push(FsEntry { name, is_dir, size });
        }
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    entries.truncate(MAX_BROWSE_ENTRIES);
    let parent = if roots.contains(&dir) {
        None
    } else {
        dir.parent().filter(|p| within(p, roots)).map(text)
    };
    Ok(BrowseResponse {
        path: text(&dir),
        parent,
        roots: roots.iter().map(|r| text(r)).collect(),
        entries,
    })
}
