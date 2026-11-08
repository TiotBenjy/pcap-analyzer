//! Guard of the mutating routes: read-only mode and cross-site request refusal.
//!
//! In dev web mode the Vite proxy adds the bearer token to every `/api` request, so the token
//! alone does not stop a foreign page from sending a request through the proxy. Browsers tag
//! every request with `Origin` (on non-GET requests) and `Sec-Fetch-Site`, which pages cannot
//! forge. A mutating request is accepted when:
//! 1. its `Origin` is one of the allowed CORS origins (desktop webview), or
//! 2. the browser says `Sec-Fetch-Site: same-origin` (or `none`: user-initiated), or
//! 3. it has no `Sec-Fetch-Site` and either no `Origin` (non-browser client) or an `Origin`
//!    equal to the `Host` it was sent to.
//!
//! Anything else (`Sec-Fetch-Site: cross-site` / `same-site`, foreign `Origin`) is refused.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::{ApiError, AppState};

pub(crate) async fn mutations(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if !is_safe(req.method()) {
        if state.config.read_only {
            return Err(ApiError::ReadOnly);
        }
        if !request_allowed(req.headers(), &state.config.cors_origins) {
            return Err(ApiError::Forbidden("cross-site request refused"));
        }
    }
    Ok(next.run(req).await)
}

fn is_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

pub(crate) fn request_allowed(headers: &HeaderMap, allowed: &[HeaderValue]) -> bool {
    let origin = headers.get(header::ORIGIN);
    if origin.is_some_and(|o| allowed.contains(o)) {
        return true;
    }
    if let Some(site) = headers.get("sec-fetch-site") {
        let site = site.to_str().unwrap_or_default();
        return site.eq_ignore_ascii_case("same-origin") || site.eq_ignore_ascii_case("none");
    }
    match origin {
        None => true,
        Some(origin) => origin_matches_host(origin, headers.get(header::HOST)),
    }
}

fn origin_matches_host(origin: &HeaderValue, host: Option<&HeaderValue>) -> bool {
    let (Ok(origin), Some(Ok(host))) = (origin.to_str(), host.map(HeaderValue::to_str)) else {
        return false;
    };
    let authority = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"));
    authority.is_some_and(|a| !host.is_empty() && a.eq_ignore_ascii_case(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(*k, HeaderValue::from_static(v));
        }
        map
    }

    #[test]
    fn cross_site_rules() {
        let allowed = [HeaderValue::from_static("tauri://localhost")];
        let ok = |h: &[(&'static str, &'static str)]| request_allowed(&headers(h), &allowed);
        // Non-browser client (curl, tests).
        assert!(ok(&[]));
        // Desktop webview: cross-site for the browser, but an allowed origin.
        assert!(ok(&[
            ("origin", "tauri://localhost"),
            ("sec-fetch-site", "cross-site")
        ]));
        // Dev web mode through the Vite proxy (Host rewritten, Origin kept).
        assert!(ok(&[
            ("origin", "http://localhost:5173"),
            ("host", "127.0.0.1:7878"),
            ("sec-fetch-site", "same-origin")
        ]));
        assert!(ok(&[
            ("origin", "http://127.0.0.1:7878"),
            ("host", "127.0.0.1:7878")
        ]));
        assert!(!ok(&[
            ("origin", "http://evil.example"),
            ("sec-fetch-site", "cross-site")
        ]));
        assert!(!ok(&[("sec-fetch-site", "cross-site")]));
        assert!(!ok(&[
            ("origin", "http://localhost:3000"),
            ("sec-fetch-site", "same-site")
        ]));
        assert!(!ok(&[
            ("origin", "http://evil.example"),
            ("host", "127.0.0.1:7878")
        ]));
        assert!(!ok(&[("origin", "null"), ("host", "127.0.0.1:7878")]));
    }
}
