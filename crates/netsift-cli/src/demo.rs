//! `netsift demo-session` (feature `demo`): synthetic demo data for screenshots and previews.
//!
//! Writes, under `<data-dir>/demo-captures/`:
//! - `chunked/`: about 50 dumpcap chunks (`demo_NNNNN_<time>.pcapng`) of the fixtures demo
//!   scenario, with one file missing (sequence hole) and a ten-minute pause (time gap);
//! - `single/demo-single.pcap`: one capture file;
//!
//! then imports each one as a `ready` session of the data directory.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::writer::{Encoding, encode};
use netsift_fixtures::{Naming, SplitBy, SplitOptions, split_to_dir};
use netsift_store::Catalog;

/// Folder of the generated captures, inside the data directory.
pub const SOURCES_DIR: &str = "demo-captures";
/// Rounds of the demo scenario (about 1.3 s each) of the chunked capture.
const ROUNDS: usize = 150;
/// Chunk rotation: 51 files of four seconds, before one is removed.
const CHUNK_SECONDS: i64 = 4;
/// Index of the removed chunk file.
const MISSING_CHUNK: usize = 20;
/// The capture pauses after this many seconds, for `PAUSE_SECONDS`.
const PAUSE_AFTER_SECONDS: i64 = 121;
const PAUSE_SECONDS: i64 = 600;

#[derive(Debug, Args)]
pub struct DemoArgs {
    /// Data directory (catalog and sessions); created if needed.
    #[arg(long)]
    pub data_dir: PathBuf,
    /// Replace the sessions and demo captures already present.
    #[arg(long)]
    pub force: bool,
}

fn write_chunked(dir: &Path) -> Result<usize> {
    let mut packets = generate(Kind::Demo, ROUNDS, 7);
    let start = packets.first().map_or(0, |p| p.ts_ns);
    let pause_at = start + PAUSE_AFTER_SECONDS * NS_PER_SEC;
    for p in &mut packets {
        if p.ts_ns >= pause_at {
            p.ts_ns += PAUSE_SECONDS * NS_PER_SEC;
        }
    }
    let opts = SplitOptions::new(
        SplitBy::Duration(CHUNK_SECONDS * NS_PER_SEC),
        Naming::Dumpcap,
    )
    .with_prefix("demo")
    .with_encoding(Encoding::pcapng());
    let (_, paths) = split_to_dir(dir, &packets, &opts)
        .with_context(|| format!("cannot write the demo chunks to {}", dir.display()))?;
    let missing = paths
        .get(MISSING_CHUNK)
        .context("not enough demo chunks generated")?;
    std::fs::remove_file(missing)
        .with_context(|| format!("cannot remove {}", missing.display()))?;
    Ok(paths.len() - 1)
}

fn write_single(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let bytes = encode(&generate(Kind::Demo, 30, 11), &Encoding::pcap())?;
    let path = dir.join("demo-single.pcap");
    std::fs::write(&path, bytes).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(path)
}

pub fn run(args: &DemoArgs, out: &mut dyn Write) -> Result<()> {
    let data_dir = &args.data_dir;
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("cannot create data directory {}", data_dir.display()))?;
    let catalog = Catalog::open(data_dir)
        .with_context(|| format!("cannot open the catalog in {}", data_dir.display()))?;
    let existing = catalog.list()?;
    let sources = data_dir.join(SOURCES_DIR);
    if (!existing.is_empty() || sources.exists()) && !args.force {
        bail!(
            "{} already holds {} session(s) or demo captures; use --force to replace them",
            data_dir.display(),
            existing.len()
        );
    }
    for session in existing {
        catalog.delete(&session.id)?;
    }
    if sources.exists() {
        std::fs::remove_dir_all(&sources)
            .with_context(|| format!("cannot remove {}", sources.display()))?;
    }

    let chunked = sources.join("chunked");
    let files = write_chunked(&chunked)?;
    let single = write_single(&sources.join("single"))?;
    writeln!(out, "wrote {files} chunks to {}", chunked.display())?;

    for (input, name) in [
        (chunked, "Demo chunked capture"),
        (single, "Demo single file"),
    ] {
        let options = IngestOptions {
            name: Some(name.to_owned()),
            ..IngestOptions::default()
        };
        let report = ingest(&catalog, &input, &options, &CancelToken::new(), &mut |_| {})?;
        writeln!(
            out,
            "session {} ({}): {}, {} packets, {} chunks, {} anomalies",
            report.session,
            report.name,
            report.state,
            report.packets,
            report.chunks,
            report.anomalies
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsift_store::query::get_meta;
    use netsift_store::{OpenMode, SessionState};

    #[test]
    fn creates_two_ready_sessions_with_continuity_anomalies() {
        let tmp = tempfile::TempDir::new().unwrap();
        let args = DemoArgs {
            data_dir: tmp.path().join("data"),
            force: false,
        };
        let mut out = Vec::new();
        run(&args, &mut out).unwrap();

        let chunked = args.data_dir.join(SOURCES_DIR).join("chunked");
        assert_eq!(std::fs::read_dir(&chunked).unwrap().count(), 50);

        let catalog = Catalog::open(&args.data_dir).unwrap();
        let sessions = catalog.list().unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().all(|s| s.state == SessionState::Ready));
        let demo = sessions
            .iter()
            .find(|s| s.name == "Demo chunked capture")
            .unwrap();
        let session = catalog.open_session(&demo.id, OpenMode::ReadOnly).unwrap();
        let kinds: Vec<String> = session
            .conn()
            .prepare("SELECT kind FROM anomalies")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(kinds.iter().any(|k| k == "missing_sequence"), "{kinds:?}");
        assert!(kinds.iter().any(|k| k == "time_gap"), "{kinds:?}");
        let packets: u64 = get_meta(session.conn(), "stats.packets")
            .unwrap()
            .unwrap()
            .parse()
            .unwrap();
        assert!(packets > 1000);

        // Populated: refused without --force, replaced with it.
        assert!(run(&args, &mut Vec::new()).is_err());
        let forced = DemoArgs {
            force: true,
            ..args
        };
        run(&forced, &mut Vec::new()).unwrap();
        assert_eq!(
            Catalog::open(&forced.data_dir)
                .unwrap()
                .list()
                .unwrap()
                .len(),
            2
        );
    }
}
