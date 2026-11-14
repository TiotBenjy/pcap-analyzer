//! No secret reaches the logs: an import of every credential emitter runs with a `tracing`
//! subscriber capturing every level of every target, and the captured output is scanned for each
//! secret and hashcat line stored in the session.
//!
//! Alone in its test binary: it installs the global subscriber (the import runs on several
//! threads).

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::credentials::credentials_showcase;
use netsift_fixtures::{Encoding, Scenario, write_file};
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;
use tracing::Level;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn no_secret_in_the_logs_after_an_import() {
    let captured = Captured::default();
    let writer = captured.clone();
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();
    tracing::info!("log capture probe");

    let mut sc = Scenario::new();
    credentials_showcase(&mut sc);
    // A truncated copy of the showcase too: half-parsed exchanges must not log either.
    let mut packets = sc.packets().to_vec();
    packets.truncate(packets.len() / 2 + 7);
    let mut again = Scenario::starting_at(sc.now() + 1_000_000_000).with_seed(3);
    credentials_showcase(&mut again);
    packets.extend(again.into_packets());

    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let file = tmp.path().join("creds.pcapng");
    write_file(&file, &packets, &Encoding::pcapng()).unwrap();
    let options = IngestOptions {
        shards: Some(3),
        ..IngestOptions::default()
    };
    let report = ingest(&catalog, &file, &options, &CancelToken::new(), &mut |_| {}).unwrap();
    assert_eq!(report.state, SessionState::Ready);
    tracing::debug!(?report, "import finished");

    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut stmt = session
        .conn()
        .prepare(
            "SELECT secret FROM credentials WHERE secret IS NOT NULL AND secret <> '' \
                  UNION SELECT hashcat_line FROM credentials WHERE hashcat_line IS NOT NULL",
        )
        .unwrap();
    let secrets: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(secrets.len() >= 12, "{} secrets stored", secrets.len());

    let logs = String::from_utf8_lossy(&captured.0.lock().unwrap_or_else(PoisonError::into_inner))
        .into_owned();
    assert!(logs.contains("log capture probe"), "the capture works");
    for secret in &secrets {
        assert!(
            !logs.contains(secret.as_str()),
            "a secret of {} characters leaked into the logs",
            secret.len()
        );
    }
    // The base64 forms seen on the wire must not leak either.
    for wire in [
        "YWRtaW46YmFzaWMtZml4dHVyZQ==",
        "AGFsaWNlQGV4YW1wbGUudGVzdABzbXRwLWZpeHR1cmU=",
    ] {
        assert!(
            !logs.contains(wire),
            "an encoded secret leaked into the logs"
        );
    }
}
