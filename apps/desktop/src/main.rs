//! NetSift desktop application.
//!
//! In `setup`: create the data directory, recover the imports interrupted by a previous run,
//! start the HTTP API on `127.0.0.1:<random port>` with a random bearer token, then create the
//! window on the bundled UI (`create: false` in `tauri.conf.json`). The UI obtains URL and token
//! through the `get_api_endpoint` command (ADR-001). A startup failure is shown in a native
//! dialog (release builds have no console on Windows). Quitting during an import (window close,
//! or Cmd+Q on macOS) asks for confirmation; at exit the API stops within
//! [`embedded::STOP_LIMIT`]. A second launch brings the running window to the front and exits
//! before its own `setup`, so it never recovers the imports of the first. No other window, no
//! outbound network access.

// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod embedded;
mod lifecycle;
mod paths;

use anyhow::{Context, Result};
use tauri::{App, AppHandle, ExitRequestApi, Manager, RunEvent, WebviewWindow, WindowEvent};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use crate::embedded::{ApiEndpoint, EmbeddedApi, STOP_LIMIT};
use crate::lifecycle::{CloseDecision, CloseGate, Foreground, Language, LanguageCell, texts};

/// Label of the only window (`app.windows[0]` of `tauri.conf.json`).
const MAIN_WINDOW: &str = "main";

/// State managed by Tauri once the API runs.
struct Desktop {
    api: EmbeddedApi,
    close: CloseGate,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri injects State by value
fn get_api_endpoint(desktop: tauri::State<'_, Desktop>) -> ApiEndpoint {
    desktop.api.endpoint().clone()
}

/// The UI reports its language so the native dialogs match it. Unknown codes are ignored.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn set_ui_language(lang: String, language: tauri::State<'_, LanguageCell>) {
    if let Some(lang) = Language::parse(&lang) {
        language.set(lang);
    }
}

fn start(app: &App) -> Result<()> {
    let data_dir = paths::data_dir(dirs::data_local_dir())?;
    paths::ensure_data_dir(&data_dir)?;
    for id in netsift_api::recover_interrupted(&data_dir)? {
        tracing::warn!(session = %id, "interrupted import marked incomplete");
    }
    let resource_dir = app.path().resource_dir().ok();
    let geoip = paths::resolve_geoip(&data_dir, resource_dir.as_deref());
    if let Some(path) = &geoip {
        tracing::info!(path = %path.display(), "GeoIP database");
    } else {
        tracing::warn!("no GeoIP database: countries will be unknown");
    }
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let config = paths::api_config(paths::random_token()?, data_dir, geoip, cores);
    let api = EmbeddedApi::start(config, |task| {
        tauri::async_runtime::spawn(task);
    })?;
    // Managed before the window exists: its first `get_api_endpoint` call always succeeds.
    app.manage(Desktop {
        api,
        close: CloseGate::default(),
    });

    let window = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN_WINDOW)
        .context("no main window in the configuration")?
        .clone();
    tauri::WebviewWindowBuilder::from_config(app.handle(), &window)?
        .build()
        .context("cannot open the main window")?;
    Ok(())
}

/// Native error dialog, then exit (code 1) once dismissed.
fn show_startup_error(app: &AppHandle, error: &anyhow::Error) {
    let lang = app.state::<LanguageCell>().get();
    let exit = app.clone();
    app.dialog()
        .message(lifecycle::startup_message(lang, error))
        .title(texts(lang).startup_title)
        .kind(MessageDialogKind::Error)
        .buttons(MessageDialogButtons::Ok)
        .show(move |_| exit.exit(1));
}

fn on_close_requested(window: &tauri::Window, api: &tauri::CloseRequestApi) {
    let Some(desktop) = window.try_state::<Desktop>() else {
        return;
    };
    match desktop.close.request(desktop.api.running_imports()) {
        CloseDecision::Close => {}
        CloseDecision::Wait => api.prevent_close(),
        CloseDecision::Ask => {
            api.prevent_close();
            ask_quit(window.app_handle());
        }
    }
}

/// Cmd+Q on macOS (and `exit` calls) reach here without a window close event. Exit requests
/// without a window (the window already closed, or a startup failure) are not held.
fn on_exit_requested(app: &AppHandle, api: &ExitRequestApi) {
    let Some(desktop) = app.try_state::<Desktop>() else {
        return;
    };
    if app.get_webview_window(MAIN_WINDOW).is_none() {
        return;
    }
    match desktop.close.request(desktop.api.running_imports()) {
        CloseDecision::Close => {}
        CloseDecision::Wait => api.prevent_exit(),
        CloseDecision::Ask => {
            api.prevent_exit();
            ask_quit(app);
        }
    }
}

/// Confirmation dialog shared by both quit paths. "Quit" exits the application: the resulting
/// exit request passes the confirmed [`CloseGate`].
fn ask_quit(app: &AppHandle) {
    let Some(window) = app.get_webview_window(MAIN_WINDOW) else {
        app.state::<Desktop>().close.answer(false);
        return;
    };
    let t = texts(app.state::<LanguageCell>().get());
    let handle = app.clone();
    app.dialog()
        .message(t.close_body)
        .title(t.close_title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            t.close_quit.to_owned(),
            t.close_keep.to_owned(),
        ))
        .parent(&window)
        .show(move |quit| {
            handle.state::<Desktop>().close.answer(quit);
            if quit {
                handle.exit(0);
            }
        });
}

/// [`lifecycle::bring_to_front`] on the Tauri window.
struct MainWindow(WebviewWindow);

impl Foreground for MainWindow {
    type Error = tauri::Error;
    fn unminimize(&self) -> tauri::Result<()> {
        self.0.unminimize()
    }
    fn show(&self) -> tauri::Result<()> {
        self.0.show()
    }
    fn set_focus(&self) -> tauri::Result<()> {
        self.0.set_focus()
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .init();

    let app = tauri::Builder::default()
        // First plugin: a second launch signals the running instance, then exits during
        // `build`, before `setup` (no `recover_interrupted` on the imports of the first).
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                lifecycle::bring_to_front(&MainWindow(window));
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(LanguageCell::new(Language::from_env()))
        .setup(|app| {
            if let Err(e) = start(app) {
                tracing::error!("cannot start: {e:#}");
                show_startup_error(app.handle(), &e);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                on_close_requested(window, api);
            }
        })
        .invoke_handler(tauri::generate_handler![get_api_endpoint, set_ui_language])
        .build(tauri::generate_context!())
        .context("cannot build the Tauri application")?;

    app.run(|app, event| match event {
        RunEvent::ExitRequested { api, .. } => on_exit_requested(app, &api),
        RunEvent::Exit => {
            if let Some(desktop) = app.try_state::<Desktop>() {
                // Cancels the imports and waits for their writer, within a bound.
                if desktop.api.stop(STOP_LIMIT) {
                    tracing::info!("API stopped");
                } else {
                    tracing::warn!(
                        "API still busy at exit; interrupted imports are recovered at next start"
                    );
                }
            }
        }
        _ => {}
    });
    Ok(())
}
