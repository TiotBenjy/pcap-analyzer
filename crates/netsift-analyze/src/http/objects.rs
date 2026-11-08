//! Which message bodies become objects (task P3.6, ADR-016).
//!
//! Only what the Pictures view shows reaches the disk: **response** bodies whose content is an
//! image according to its magic number ([`IMAGE_TYPES`], sniffed by
//! [`super::inspect::sniff_mime`]). The declared `Content-Type` plays no part: a PNG served as
//! `application/octet-stream` is kept, an HTML page labelled `image/png` is not. Request bodies
//! (forms, uploads, which may hold passwords), pages, scripts and every other type stay in
//! memory only. See [`HttpConfig::store_bodies`] for the size bounds and the session budget.

use super::inspect::{MessageView, Role};
use super::types::HttpConfig;

/// Media types (as sniffed) stored as objects: what the Pictures view shows. SVG is stored for
/// download only: it is never rasterized nor rendered.
pub const IMAGE_TYPES: &[&str] = &[
    "image/bmp",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/svg+xml",
    "image/webp",
    "image/x-icon",
];

/// True when the body of `view`, sniffed as `mime_magic`, is to be stored as an object.
pub fn selected(view: &MessageView<'_>, mime_magic: Option<&str>, config: &HttpConfig) -> bool {
    let size = view.body.len() as u64;
    config.store_bodies
        && view.role == Role::Response
        // The whole decoded body, not a prefix (incomplete, truncated, bomb, budget exceeded).
        && view.body_complete
        // A partial response (range request) holds a piece of the object, never all of it.
        && view.status != Some(206)
        && mime_magic.is_some_and(|m| IMAGE_TYPES.contains(&m))
        && size >= config.object_min_bytes
        && size <= config.object_max_bytes
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use netsift_flow::{Endpoint, FlowId, FlowKey};

    use super::*;
    use crate::http::BodyState;

    fn key() -> FlowKey {
        let ep = |last, port| Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
            port,
        };
        FlowKey {
            proto: 6,
            client: ep(1, 40_000),
            server: ep(2, 80),
        }
    }

    fn view<'a>(key: &'a FlowKey, role: Role, status: Option<u16>, body: &'a [u8]) -> MessageView<'a> {
        MessageView {
            flow: FlowId(1),
            key,
            role,
            ts_ns: 0,
            frame: 0,
            method: None,
            target: None,
            status,
            headers: &[],
            state: BodyState::Complete,
            body,
            body_complete: true,
        }
    }

    #[test]
    fn only_complete_image_responses_within_bounds() {
        let key = key();
        let config = HttpConfig::default();
        let png = [0u8; 100];
        let ok = view(&key, Role::Response, Some(200), &png);
        assert!(selected(&ok, Some("image/png"), &config));
        assert!(selected(&ok, Some("image/svg+xml"), &config));
        assert!(selected(&ok, Some("image/x-icon"), &config));
        // Not an image by content (whatever the declared type), or not shown by the view.
        for other in [None, Some("text/html"), Some("application/pdf"), Some("image/tiff")] {
            assert!(!selected(&ok, other, &config), "{other:?}");
        }
        // Requests (forms, uploads) never.
        let req = view(&key, Role::Request, None, &png);
        assert!(!selected(&req, Some("image/png"), &config));
        // Partial content, incomplete body.
        assert!(!selected(&view(&key, Role::Response, Some(206), &png), Some("image/png"), &config));
        let cut = MessageView {
            body_complete: false,
            ..ok
        };
        assert!(!selected(&cut, Some("image/png"), &config));
        // Size bounds.
        let tiny = [0u8; 8];
        assert!(!selected(&view(&key, Role::Response, Some(200), &tiny), Some("image/gif"), &config));
        let bounded = HttpConfig {
            object_max_bytes: 99,
            ..HttpConfig::default()
        };
        assert!(!selected(&ok, Some("image/png"), &bounded));
        // Switched off.
        let off = HttpConfig {
            store_bodies: false,
            ..HttpConfig::default()
        };
        assert!(!selected(&ok, Some("image/png"), &off));
    }
}
