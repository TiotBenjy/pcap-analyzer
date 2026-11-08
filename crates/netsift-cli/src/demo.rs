//! `netsift demo-session` (feature `demo`): synthetic demo data for screenshots and previews.
//!
//! Writes, under `<data-dir>/demo-captures/`:
//! - `chunked/`: about 50 dumpcap chunks (`demo_NNNNN_<time>.pcapng`) of the fixtures demo
//!   scenario plus varied TLS sessions, with one file missing (sequence hole) and a ten-minute
//!   pause (time gap);
//! - `single/demo-single.pcap`: one capture file;
//!
//! then imports each one as a `ready` session of the data directory.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::scenario::{Scenario, SmbNtlm};
use netsift_fixtures::scenarios::{Kind, generate, hosts, tls_showcase_from_port};
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::writer::{Encoding, encode};
use netsift_fixtures::{Naming, Packet, SplitBy, SplitOptions, http_mix, split_to_dir};
use netsift_store::Catalog;

/// Demo rounds plus one `NTLMv2` authentication over SMB, so the SMB view shows an announced-OS
/// donut, host announcements and an authentication (added here, like HTTP/TLS, not in `Kind`).
fn demo_packets(rounds: usize, seed: u64) -> Vec<Packet> {
    let mut packets = generate(Kind::Demo, rounds, seed);
    let start = packets.last().map_or(0, |p| p.ts_ns) + NS_PER_SEC;
    let mut sc = Scenario::starting_at(start).with_seed(seed ^ 0x5342);
    sc.smb_ntlm(
        hosts::workstation(),
        hosts::file_server(),
        &SmbNtlm::v2("jdoe", "CONTOSO"),
    );
    // Servers view: DHCP lease, NTP, DNS SRV of a domain controller, LDAP and Kerberos.
    netsift_fixtures::servers::servers_showcase(&mut sc);
    packets.extend(sc.into_packets());
    packets
}

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
/// Gap between two rounds of varied HTTP traffic.
const HTTP_MIX_EVERY_SECONDS: i64 = 6;

#[derive(Debug, Args)]
pub struct DemoArgs {
    /// Data directory (catalog and sessions); created if needed.
    #[arg(long)]
    pub data_dir: PathBuf,
    /// Replace the sessions and demo captures already present.
    #[arg(long)]
    pub force: bool,
}

/// Rounds of the TLS showcase (versions, weak suites, certificates) merged into the chunked
/// capture, one every `TLS_SHOWCASE_EVERY_SECONDS` from the fifth second.
const TLS_SHOWCASE_ROUNDS: u16 = 8;
const TLS_SHOWCASE_EVERY_SECONDS: i64 = 20;

fn add_tls_showcase(packets: &mut Vec<netsift_fixtures::Packet>, start: i64) {
    for round in 0..TLS_SHOWCASE_ROUNDS {
        let at = start + (5 + i64::from(round) * TLS_SHOWCASE_EVERY_SECONDS) * NS_PER_SEC;
        let mut sc = Scenario::starting_at(at).with_seed(u64::from(round) + 100);
        tls_showcase_from_port(&mut sc, 40_000 + round * 10);
        packets.extend(sc.into_packets());
    }
    packets.sort_by_key(|p| p.ts_ns);
}

/// Varied HTTP traffic (`netsift_fixtures::http_mix`), one round every few seconds over the
/// `seconds` following `start`, merged into `packets` (sorted by time).
fn add_http_mix(packets: &mut Vec<Packet>, start: i64, seconds: i64) {
    let mut sc = Scenario::starting_at(start + NS_PER_SEC).with_seed(0x4854_5450);
    while sc.now() < start + seconds * NS_PER_SEC {
        http_mix::round(&mut sc);
        sc.advance(HTTP_MIX_EVERY_SECONDS * NS_PER_SEC);
    }
    packets.extend(sc.into_packets());
    packets.sort_by_key(|p| p.ts_ns);
}

fn write_chunked(dir: &Path) -> Result<usize> {
    let mut packets = demo_packets(ROUNDS, 7);
    let start = packets.first().map_or(0, |p| p.ts_ns);
    let end = packets.last().map_or(0, |p| p.ts_ns);
    // Stops a few seconds before the end: the chunk count stays the same.
    add_http_mix(&mut packets, start, (end - start) / NS_PER_SEC - 5);
    add_tls_showcase(&mut packets, start);
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
    let mut packets = demo_packets(30, 11);
    let start = packets.first().map_or(0, |p| p.ts_ns);
    add_http_mix(&mut packets, start, 20);
    let bytes = encode(&packets, &Encoding::pcap())?;
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
        // Varied TLS sessions for the TLS view: TLS 1.0 to 1.3, weak suites, certificates.
        let (versions, weak, certs): (i64, i64, i64) = session
            .conn()
            .query_row(
                "SELECT count(DISTINCT version), sum(cipher_weak IS NOT NULL), \
                 (SELECT count(*) FROM tls_certificates) FROM tls_sessions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(versions, 3);
        assert!(weak >= 24, "{weak}");
        assert!(certs >= 5, "{certs}");
        // Infrastructure roles for the Servers view: DNS, DHCP, LDAP, NTP, Kerberos, SMB.
        let roles: Vec<String> = session
            .conn()
            .prepare("SELECT DISTINCT role FROM server_roles ORDER BY role")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for role in ["dhcp", "dns", "kerberos", "ldap", "ntp", "smb"] {
            assert!(roles.iter().any(|r| r == role), "{role} missing: {roles:?}");
        }

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
