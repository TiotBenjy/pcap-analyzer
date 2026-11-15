//! Online checks run once when the server starts (ADR-025): each feature allowed to reach the
//! network registers one [`StartupCheck`] in [`STARTUP_CHECKS`], gated by its setting
//! ([`OnlineSettings`], off by default).
//!
//! - Settings are those read from `<data_dir>/settings.json` when the server was built: a
//!   setting enabled later takes effect at the next start (or by an explicit user action of the
//!   feature).
//! - Nothing runs on a read-only server (previews, screenshots).
//! - Checks run in the background, concurrently, and stop when the server shuts down. They must
//!   fail silently: log at `debug` or `info`, keep their result in their own state, never show
//!   an error to the user.
//! - Requests go through [`crate::outbound`], with the feature's own allow list.
//! - State: each feature keeps its own (last result, source of its tests...) in
//!   `AppState::online`, an [`OnlineStates`] holding one value per type: the feature defines a
//!   `Default` type in its module and reads it with `state.online.get::<MyState>()`, without
//!   touching `AppState`.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use futures_util::future::BoxFuture;
use tokio::task::JoinHandle;

use crate::AppState;
use crate::settings::OnlineSettings;

/// One check run at startup when its setting is on.
pub(crate) struct StartupCheck {
    /// Name in the logs.
    pub(crate) id: &'static str,
    /// Setting that enables the check.
    pub(crate) enabled: fn(&OnlineSettings) -> bool,
    /// The check itself.
    pub(crate) run: fn(Arc<AppState>) -> BoxFuture<'static, ()>,
}

/// States of the online features, one slot per state type (`TypeId`), created on first use
/// with `Default`. Shared by the startup checks and the routes of the feature.
#[derive(Default)]
pub(crate) struct OnlineStates {
    slots: Mutex<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
}

impl OnlineStates {
    /// The state of type `T`, created with `T::default()` on first use. Always the same value
    /// for a given type: wrap mutable parts in a `Mutex` or atomics.
    pub(crate) fn get<T: Any + Default + Send + Sync>(&self) -> Arc<T> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = slots
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Arc::new(T::default()));
        if let Ok(state) = Arc::clone(slot).downcast::<T>() {
            return state;
        }
        // Unreachable (the key is the type), but never panic: start again from the default.
        let state = Arc::new(T::default());
        *slot = Arc::clone(&state) as Arc<dyn Any + Send + Sync>;
        state
    }
}

/// Registration point: one line per feature, sorted by id.
#[rustfmt::skip]
pub(crate) const STARTUP_CHECKS: &[StartupCheck] = &[
    StartupCheck { id: "geoip", enabled: |o| o.geoip_check, run: crate::geoip::freshness::run },
];

/// Starts the enabled checks of [`STARTUP_CHECKS`] (call once, inside the server runtime).
pub(crate) fn spawn_startup_checks(state: &Arc<AppState>) -> Vec<JoinHandle<()>> {
    spawn_checks(state, STARTUP_CHECKS)
}

fn spawn_checks(state: &Arc<AppState>, checks: &[StartupCheck]) -> Vec<JoinHandle<()>> {
    if state.config.read_only {
        return Vec::new();
    }
    let online = state.settings.get().online;
    checks
        .iter()
        .filter(|check| (check.enabled)(&online))
        .map(|check| {
            let id = check.id;
            tracing::debug!(id, "startup check started");
            let run = (check.run)(Arc::clone(state));
            let shutdown = state.shutdown_signal();
            tokio::spawn(async move {
                tokio::select! {
                    () = run => tracing::debug!(id, "startup check ended"),
                    () = shutdown => tracing::debug!(id, "startup check stopped by the shutdown"),
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::http::HeaderValue;
    use netsift_engine::IngestOptions;

    use super::*;
    use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

    static GEOIP_RUNS: AtomicUsize = AtomicUsize::new(0);
    static UPDATE_RUNS: AtomicUsize = AtomicUsize::new(0);

    const CHECKS: &[StartupCheck] = &[
        StartupCheck {
            id: "geoip",
            enabled: |o| o.geoip_check,
            run: |_| {
                Box::pin(async {
                    GEOIP_RUNS.fetch_add(1, Ordering::SeqCst);
                })
            },
        },
        StartupCheck {
            id: "update",
            enabled: |o| o.update_check,
            run: |_| {
                Box::pin(async {
                    UPDATE_RUNS.fetch_add(1, Ordering::SeqCst);
                })
            },
        },
    ];

    /// Never ends unless stopped.
    const STUCK: &[StartupCheck] = &[StartupCheck {
        id: "stuck",
        enabled: |_| true,
        run: |_| Box::pin(std::future::pending()),
    }];

    fn state(dir: &std::path::Path, read_only: bool, settings: &str) -> Arc<AppState> {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(crate::settings::FILE_NAME), settings).unwrap();
        let config = ApiConfig {
            token: "t".to_owned(),
            data_dir: dir.to_owned(),
            captures_roots: Vec::new(),
            read_only,
            cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_fallback_path: None,
        };
        build(config, IngestOptions::default()).1
    }

    async fn join(handles: Vec<JoinHandle<()>>) -> usize {
        let n = handles.len();
        for h in handles {
            h.await.unwrap();
        }
        n
    }

    #[test]
    fn each_feature_gets_its_own_state() {
        #[derive(Default)]
        struct Geoip(AtomicUsize);
        #[derive(Default)]
        struct Update(Mutex<Option<String>>);

        let states = OnlineStates::default();
        states.get::<Geoip>().0.fetch_add(2, Ordering::SeqCst);
        *states.get::<Update>().0.lock().unwrap() = Some("0.2.0".to_owned());
        assert_eq!(states.get::<Geoip>().0.load(Ordering::SeqCst), 2);
        assert_eq!(
            states.get::<Update>().0.lock().unwrap().as_deref(),
            Some("0.2.0")
        );
        assert!(Arc::ptr_eq(&states.get::<Geoip>(), &states.get::<Geoip>()));
    }

    #[test]
    fn production_registry_is_sorted_by_id() {
        let ids: Vec<_> = STARTUP_CHECKS.iter().map(|c| c.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted);
    }

    // One test: the counters are shared statics.
    #[tokio::test]
    async fn only_enabled_checks_run_and_never_on_a_read_only_server() {
        let tmp = tempfile::TempDir::new().unwrap();

        // Defaults (empty file): nothing.
        let s = state(&tmp.path().join("a"), false, "{}");
        assert_eq!(join(spawn_checks(&s, CHECKS)).await, 0);

        let s = state(
            &tmp.path().join("b"),
            false,
            r#"{"online":{"update_check":true}}"#,
        );
        assert_eq!(join(spawn_checks(&s, CHECKS)).await, 1);
        assert_eq!(GEOIP_RUNS.load(Ordering::SeqCst), 0);
        assert_eq!(UPDATE_RUNS.load(Ordering::SeqCst), 1);

        let both = r#"{"online":{"geoip_check":true,"update_check":true}}"#;
        let s = state(&tmp.path().join("c"), false, both);
        assert_eq!(join(spawn_checks(&s, CHECKS)).await, 2);
        assert_eq!(GEOIP_RUNS.load(Ordering::SeqCst), 1);
        assert_eq!(UPDATE_RUNS.load(Ordering::SeqCst), 2);

        let s = state(&tmp.path().join("d"), true, both);
        assert_eq!(join(spawn_checks(&s, CHECKS)).await, 0);
        assert_eq!(UPDATE_RUNS.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn checks_stop_at_shutdown() {
        let tmp = tempfile::TempDir::new().unwrap();
        let s = state(tmp.path(), false, "{}");
        // The state of the server holds the slots of the features.
        s.online.get::<AtomicUsize>().fetch_add(1, Ordering::SeqCst);
        assert_eq!(s.online.get::<AtomicUsize>().load(Ordering::SeqCst), 1);
        let handles = spawn_checks(&s, STUCK);
        assert_eq!(handles.len(), 1);
        s.begin_shutdown();
        tokio::time::timeout(Duration::from_secs(5), join(handles))
            .await
            .unwrap();
    }
}
