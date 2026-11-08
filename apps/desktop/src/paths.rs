//! Data directory, GeoIP database and API configuration of the desktop app. Pure functions of
//! their inputs, tested without a window.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use netsift_api::ApiConfig;
use tauri::http::HeaderValue;

/// Name of the data directory under the local data directory. The opener scope of
/// `capabilities/default.json` (`$LOCALDATA/NetSift/exports`) depends on it.
pub const DATA_DIR_NAME: &str = "NetSift";
/// Folder of the exported files (Save PCAP, CSV), the only one the UI may open.
pub const EXPORTS_DIR_NAME: &str = "exports";
/// Folder of the GeoIP database inside the bundle resources (`bundle.resources`).
pub const GEOIP_RESOURCE_DIR: &str = "geoip";

/// Origins of the bundled UI: `tauri://localhost` (Linux, macOS), `http://tauri.localhost` (Windows).
pub const WEBVIEW_ORIGINS: [&str; 2] = ["tauri://localhost", "http://tauri.localhost"];

/// `<local data dir>/NetSift` (`~/.local/share/NetSift`, `%LOCALAPPDATA%\NetSift`).
/// Local, not roaming: sessions can weigh gigabytes and must not sync with a Windows profile.
pub fn data_dir(local_data_dir: Option<PathBuf>) -> Result<PathBuf> {
    let base = local_data_dir.context("no local data folder is defined for this user")?;
    Ok(base.join(DATA_DIR_NAME))
}

/// Creates the data directory and its exports folder (first start), with an error that names
/// the folder.
pub fn ensure_data_dir(dir: &Path) -> Result<()> {
    let exports = dir.join(EXPORTS_DIR_NAME);
    std::fs::create_dir_all(&exports)
        .with_context(|| format!("cannot create the data folder {}", exports.display()))?;
    Ok(())
}

/// Country database for the imports: a copy in the data directory first (lets the user update
/// it without reinstalling), else the one shipped in the bundle. `None` when neither exists:
/// the API then reports it missing and countries stay unknown.
pub fn resolve_geoip(data_dir: &Path, resource_dir: Option<&Path>) -> Option<PathBuf> {
    let user = netsift_api::default_geoip_path(data_dir);
    if user.is_file() {
        return Some(user);
    }
    let bundled = resource_dir?
        .join(GEOIP_RESOURCE_DIR)
        .join(netsift_api::GEOIP_FILE_NAME);
    bundled.is_file().then_some(bundled)
}

/// Imports allowed at the same time: each import already uses every core and up to its memory
/// bound, so small machines run one at a time.
pub fn max_imports(cores: usize) -> usize {
    if cores <= 4 {
        1
    } else {
        netsift_api::DEFAULT_MAX_IMPORTS
    }
}

/// API configuration of the desktop app: paths come from native dialogs (any absolute path is
/// accepted), CORS admits only the webview origins, no folder browser.
pub fn api_config(
    token: String,
    data_dir: PathBuf,
    geoip_path: Option<PathBuf>,
    cores: usize,
) -> ApiConfig {
    ApiConfig {
        token,
        data_dir,
        captures_roots: Vec::new(),
        read_only: false,
        cors_origins: WEBVIEW_ORIGINS
            .iter()
            .map(|o| HeaderValue::from_static(o))
            .collect(),
        allow_any_path: true,
        max_imports: max_imports(cores),
        geoip_path,
    }
}

/// 256-bit random token, hex encoded.
pub fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("no OS randomness: {e}"))?;
    Ok(bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_long_random_and_hex() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn webview_origins_are_valid_header_values() {
        for o in WEBVIEW_ORIGINS {
            assert!(HeaderValue::from_str(o).is_ok());
        }
    }

    #[test]
    fn data_dir_is_netsift_under_the_local_data_dir() {
        let dir = data_dir(Some(PathBuf::from("/home/u/.local/share"))).unwrap();
        assert_eq!(dir, PathBuf::from("/home/u/.local/share/NetSift"));
        let err = data_dir(None).unwrap_err();
        assert!(err.to_string().contains("no local data folder"), "{err}");
    }

    #[test]
    fn ensure_data_dir_creates_the_exports_folder_or_names_the_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("share").join(DATA_DIR_NAME);
        ensure_data_dir(&dir).unwrap();
        assert!(dir.join(EXPORTS_DIR_NAME).is_dir());
        // Idempotent.
        ensure_data_dir(&dir).unwrap();

        // A file in the way: the error names the folder that could not be created.
        let blocked = tmp.path().join("blocked");
        std::fs::write(&blocked, b"x").unwrap();
        let err = ensure_data_dir(&blocked.join(DATA_DIR_NAME)).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("cannot create the data folder"),
            "{message}"
        );
        assert!(message.contains("blocked"), "{message}");
    }

    #[test]
    fn geoip_prefers_the_data_dir_copy_then_the_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let resources = tmp.path().join("resources");
        assert_eq!(resolve_geoip(&data, Some(&resources)), None);
        assert_eq!(resolve_geoip(&data, None), None);

        let bundled = resources
            .join(GEOIP_RESOURCE_DIR)
            .join(netsift_api::GEOIP_FILE_NAME);
        std::fs::create_dir_all(bundled.parent().unwrap()).unwrap();
        std::fs::write(&bundled, b"mmdb").unwrap();
        assert_eq!(resolve_geoip(&data, Some(&resources)), Some(bundled));
        assert_eq!(resolve_geoip(&data, None), None);

        let user = netsift_api::default_geoip_path(&data);
        std::fs::create_dir_all(user.parent().unwrap()).unwrap();
        std::fs::write(&user, b"mmdb").unwrap();
        assert_eq!(resolve_geoip(&data, Some(&resources)), Some(user.clone()));
        assert_eq!(resolve_geoip(&data, None), Some(user));
    }

    #[test]
    fn geoip_ignores_a_directory_named_like_the_database() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(netsift_api::default_geoip_path(tmp.path())).unwrap();
        assert_eq!(resolve_geoip(tmp.path(), None), None);
    }

    #[test]
    fn desktop_api_config() {
        let config = api_config(
            "t".repeat(64),
            PathBuf::from("/d"),
            Some(PathBuf::from("/r/geoip/x.mmdb")),
            8,
        );
        assert!(config.allow_any_path);
        assert!(!config.read_only);
        assert_eq!(config.captures_roots, Vec::<PathBuf>::new());
        assert_eq!(config.max_imports, netsift_api::DEFAULT_MAX_IMPORTS);
        assert_eq!(config.geoip_path, Some(PathBuf::from("/r/geoip/x.mmdb")));
        assert_eq!(config.data_dir, PathBuf::from("/d"));
        let origins: Vec<_> = config
            .cors_origins
            .iter()
            .map(|o| o.to_str().unwrap())
            .collect();
        assert_eq!(origins, WEBVIEW_ORIGINS);
        // The token never shows up in logs.
        assert!(!format!("{config:?}").contains(&"t".repeat(64)));

        assert_eq!(
            api_config(String::new(), PathBuf::new(), None, 4).max_imports,
            1
        );
        assert_eq!(max_imports(1), 1);
        assert_eq!(max_imports(0), 1);
        assert_eq!(max_imports(16), netsift_api::DEFAULT_MAX_IMPORTS);
    }

    #[test]
    fn opener_scope_is_the_exports_folder_only() {
        let caps: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let perms = caps["permissions"].as_array().unwrap();
        let opener: Vec<_> = perms
            .iter()
            .filter(|p| p.to_string().contains("opener:"))
            .collect();
        assert_eq!(opener.len(), 1, "{opener:?}");
        assert_eq!(opener[0]["identifier"], "opener:allow-open-path");
        let expected = format!("$LOCALDATA/{DATA_DIR_NAME}/{EXPORTS_DIR_NAME}");
        let paths: Vec<_> = opener[0]["allow"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, [expected.clone(), format!("{expected}/**")]);
        // No blanket permission set.
        assert!(!perms.iter().any(|p| p == "core:default"));
    }
}
