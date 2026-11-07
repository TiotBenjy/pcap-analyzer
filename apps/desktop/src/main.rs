//! NetSift desktop application.
//!
//! Starts the HTTP API on `127.0.0.1:<random port>` with a random bearer token, then opens the
//! window on the bundled UI. The UI obtains URL and token through the `get_api_endpoint`
//! command (ADR-001). No other window, no outbound network access.

// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use netsift_api::ApiConfig;
use serde::Serialize;
use tauri::http::HeaderValue;
use tauri::{Manager, RunEvent};
use tokio::sync::oneshot;

/// Origins of the bundled UI: `tauri://localhost` (Linux, macOS), `http://tauri.localhost` (Windows).
const WEBVIEW_ORIGINS: [&str; 2] = ["tauri://localhost", "http://tauri.localhost"];

/// Endpoint handed to the UI. Serialized field names match `ui/src/api/client.ts`.
#[derive(Debug, Clone, Serialize)]
struct ApiEndpoint {
    base_url: String,
    token: String,
}

struct ApiHandle {
    endpoint: ApiEndpoint,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri injects State by value
fn get_api_endpoint(handle: tauri::State<'_, ApiHandle>) -> ApiEndpoint {
    handle.endpoint.clone()
}

/// 256-bit random token, hex encoded.
fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("no OS randomness: {e}"))?;
    Ok(bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    }))
}

/// `<local data dir>/NetSift` (`~/.local/share/NetSift`, `%LOCALAPPDATA%\NetSift`).
/// Local, not roaming: sessions can weigh gigabytes and must not sync with a Windows profile.
fn data_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir().context("no local data directory on this system")?;
    Ok(base.join("NetSift"))
}

fn start_api() -> Result<ApiHandle> {
    let data_dir = data_dir()?;
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("cannot create {}", data_dir.display()))?;

    // Bind synchronously during `setup`: the window already exists, but IPC is served by the main
    // thread, so `get_api_endpoint` cannot be answered before the endpoint is managed.
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("cannot bind loopback")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let token = random_token()?;

    let config = ApiConfig {
        token: token.clone(),
        data_dir,
        captures_roots: Vec::new(),
        read_only: false,
        cors_origins: WEBVIEW_ORIGINS
            .iter()
            .map(|o| HeaderValue::from_static(o))
            .collect(),
    };
    let (tx, rx) = oneshot::channel::<()>();
    tauri::async_runtime::spawn(async move {
        let listener = match tokio::net::TcpListener::from_std(listener) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "cannot adopt API listener");
                return;
            }
        };
        let shutdown = async {
            let _ = rx.await;
        };
        if let Err(e) = netsift_api::serve(listener, config, shutdown).await {
            tracing::error!(error = %e, "API server stopped with an error");
        }
    });
    tracing::info!(%addr, "embedded API listening");

    Ok(ApiHandle {
        endpoint: ApiEndpoint {
            base_url: format!("http://{addr}/api/v1"),
            token,
        },
        shutdown: Mutex::new(Some(tx)),
    })
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .init();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let handle = start_api()?;
            app.manage(handle);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_api_endpoint])
        .build(tauri::generate_context!())
        .context("cannot build the Tauri application")?;

    app.run(|app, event| {
        if let RunEvent::Exit = event
            && let Some(handle) = app.try_state::<ApiHandle>()
            && let Ok(mut guard) = handle.shutdown.lock()
            && let Some(tx) = guard.take()
        {
            let _ = tx.send(());
        }
    });
    Ok(())
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
}
