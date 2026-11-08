//! The embedded API server: start on `127.0.0.1:<random port>`, bounded stop.
//!
//! Independent of Tauri (the caller supplies the task spawner), so the start and stop sequence
//! is tested on a plain tokio runtime.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use netsift_api::{ApiConfig, Server, ServerMonitor};
use serde::Serialize;
use tokio::sync::oneshot;

/// Longest wait for the API at exit: open connections ([`netsift_api::SHUTDOWN_GRACE`]), then
/// the cancelled imports flushing their writer ([`netsift_api::IMPORT_GRACE`]), plus a margin.
/// Past it the process exits anyway; an import still running is recovered as `incomplete` at
/// the next start.
pub const STOP_LIMIT: Duration = Duration::from_secs(
    netsift_api::SHUTDOWN_GRACE.as_secs() + netsift_api::IMPORT_GRACE.as_secs() + 2,
);

/// Endpoint handed to the UI. Serialized field names match `ui/src/api/client.ts`.
#[derive(Debug, Clone, Serialize)]
pub struct ApiEndpoint {
    pub base_url: String,
    pub token: String,
}

/// A boxed server task, handed to the spawner.
pub type ServerTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Shutdown signal and completion notice of a running task.
struct Stopper {
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    /// Disconnected when the task ends (its sender is dropped).
    done: Mutex<mpsc::Receiver<()>>,
}

impl Stopper {
    /// Signals the task, then waits at most `limit` for it to end. True if it ended (or had
    /// already ended). Blocking: call it outside the async runtime. Idempotent.
    fn stop(&self, limit: Duration) -> bool {
        if let Some(tx) = self
            .shutdown
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = tx.send(());
        }
        let done = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        !matches!(done.recv_timeout(limit), Err(RecvTimeoutError::Timeout))
    }
}

pub struct EmbeddedApi {
    endpoint: ApiEndpoint,
    monitor: ServerMonitor,
    stopper: Stopper,
}

impl EmbeddedApi {
    /// Binds the loopback listener synchronously (the port is known before the window opens)
    /// and hands the server task to `spawn` (a tokio runtime).
    pub fn start(config: ApiConfig, spawn: impl FnOnce(ServerTask)) -> Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .context("cannot open a local port for the API")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let token = config.token.clone();
        let server = Server::new(config);
        let monitor = server.monitor();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        spawn(Box::pin(async move {
            // Dropped when the task ends, whatever the outcome: `stop` returns at once.
            let _done = done_tx;
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "cannot adopt the API listener");
                    return;
                }
            };
            let shutdown = async {
                let _ = shutdown_rx.await;
            };
            if let Err(e) = server.serve(listener, shutdown).await {
                tracing::error!(error = %e, "API server stopped with an error");
            }
        }));
        tracing::info!(%addr, "embedded API listening");
        Ok(Self {
            endpoint: ApiEndpoint {
                base_url: format!("http://{addr}/api/v1"),
                token,
            },
            monitor,
            stopper: Stopper {
                shutdown: Mutex::new(Some(shutdown_tx)),
                done: Mutex::new(done_rx),
            },
        })
    }

    pub fn endpoint(&self) -> &ApiEndpoint {
        &self.endpoint
    }

    pub fn running_imports(&self) -> usize {
        self.monitor.running_imports()
    }

    /// Stops the server (imports cancelled, sessions marked `incomplete`) and waits at most
    /// `limit`. True if the server ended in time.
    pub fn stop(&self, limit: Duration) -> bool {
        self.stopper.stop(limit)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::time::Instant;

    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    fn config(dir: &std::path::Path) -> ApiConfig {
        crate::paths::api_config("x".repeat(64), dir.to_owned(), None, 8)
    }

    fn get(base_url: &str, path: &str) -> std::io::Result<String> {
        let addr = base_url
            .trim_start_matches("http://")
            .trim_end_matches("/api/v1");
        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        write!(
            stream,
            "GET /api/v1{path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        )?;
        let mut out = String::new();
        stream.read_to_string(&mut out)?;
        Ok(out)
    }

    #[test]
    fn serves_on_loopback_then_stops_within_the_limit() {
        let rt = runtime();
        let tmp = tempfile::tempdir().unwrap();
        let api = EmbeddedApi::start(config(tmp.path()), |task| {
            rt.spawn(task);
        })
        .unwrap();
        let ep = api.endpoint().clone();
        assert!(
            ep.base_url.starts_with("http://127.0.0.1:"),
            "{}",
            ep.base_url
        );
        assert!(ep.base_url.ends_with("/api/v1"));
        assert_eq!(ep.token.len(), 64);
        let health = get(&ep.base_url, "/health").unwrap();
        assert!(health.starts_with("HTTP/1.1 200"), "{health}");
        // Authenticated routes refuse requests without the token.
        let info = get(&ep.base_url, "/server-info").unwrap();
        assert!(info.starts_with("HTTP/1.1 401"), "{info}");
        assert_eq!(api.running_imports(), 0);

        let started = Instant::now();
        assert!(api.stop(STOP_LIMIT));
        assert!(started.elapsed() < STOP_LIMIT);
        assert!(get(&ep.base_url, "/health").is_err());
        // Idempotent.
        assert!(api.stop(Duration::from_millis(10)));
    }

    #[test]
    fn stop_gives_up_after_the_limit() {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        // A task that receives the signal but never ends.
        let stuck = std::thread::spawn(move || {
            let _ = shutdown_rx.blocking_recv();
            std::thread::sleep(Duration::from_secs(2));
            drop(done_tx);
        });
        let stopper = Stopper {
            shutdown: Mutex::new(Some(shutdown_tx)),
            done: Mutex::new(done_rx),
        };
        let started = Instant::now();
        assert!(!stopper.stop(Duration::from_millis(100)));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(100));
        assert!(waited < Duration::from_secs(1), "{waited:?}");
        stuck.join().unwrap();
        assert!(stopper.stop(Duration::from_millis(10)));
    }

    #[test]
    fn stop_returns_at_once_when_the_task_already_ended() {
        let (shutdown_tx, _) = oneshot::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        drop(done_tx);
        let stopper = Stopper {
            shutdown: Mutex::new(Some(shutdown_tx)),
            done: Mutex::new(done_rx),
        };
        let started = Instant::now();
        assert!(stopper.stop(Duration::from_secs(10)));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn stop_limit_covers_both_grace_periods() {
        assert!(STOP_LIMIT > netsift_api::SHUTDOWN_GRACE + netsift_api::IMPORT_GRACE);
    }
}
