//! Tests of the `ftp` analyzer on the synthetic sessions of `netsift_fixtures::ftp`.

use std::fmt::Write as _;

use netsift_dissect::{Decoded, decode};
use netsift_fixtures::ftp::{self, FtpShowcase, ftp_hosts};
use netsift_fixtures::scenario::TcpOptions;
use netsift_fixtures::{Packet, Scenario};
use netsift_flow::{
    Direction, FlowConfig, FlowCtx, FlowSink, FlowTable, PacketCtx, StreamCtx, shard_hash,
};
use sha2::{Digest as _, Sha256};

use super::analyzer::{MAX_LINES, MAX_TRANSFERS};
use super::{FtpAnalyzer, FtpConfig, FtpRecord, FtpSession, FtpTransfer, LineKind};
use crate::analyzer::{Analyzer, BlobRef, RecordSink};
use crate::record::Record;
use crate::registry::AnalyzerConfig;

/// Records and the blobs stored through `put_object`.
#[derive(Default)]
struct Out {
    records: Vec<Record>,
    blobs: Vec<(BlobRef, Vec<u8>)>,
}

impl RecordSink for Out {
    fn emit(&mut self, record: Record) {
        self.records.push(record);
    }

    fn put_blob(&mut self, data: &[u8]) -> Option<BlobRef> {
        let blob = BlobRef {
            sha256: Sha256::digest(data).into(),
            size: data.len() as u64,
        };
        self.blobs.push((blob, data.to_vec()));
        Some(blob)
    }
}

struct Sink<'a> {
    analyzer: &'a mut dyn Analyzer,
    out: Out,
}

impl FlowSink for Sink<'_> {
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>) {
        self.analyzer.on_packet(ctx, pkt, &mut self.out);
    }
    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        self.analyzer.on_stream(ctx, dir, data, &mut self.out);
    }
    fn on_flow_end(&mut self, ctx: &FlowCtx) {
        self.analyzer.on_flow_end(ctx, &mut self.out);
    }
}

fn run_with(config: &AnalyzerConfig, packets: &[Packet]) -> Out {
    let mut analyzer = FtpAnalyzer::new(config);
    let mut table = FlowTable::new(FlowConfig::default());
    let mut sink = Sink {
        analyzer: &mut analyzer,
        out: Out::default(),
    };
    for (frame, p) in packets.iter().enumerate() {
        let wire_len = u32::try_from(p.data.len()).unwrap();
        table.process(
            p.ts_ns,
            0,
            frame as u64,
            p.linktype,
            wire_len,
            &p.data,
            &mut sink,
        );
    }
    table.finish(&mut sink);
    sink.analyzer.finish(&mut sink.out);
    sink.out
}

fn run(packets: &[Packet]) -> Out {
    run_with(&AnalyzerConfig::default(), packets)
}

fn showcase() -> (Vec<Packet>, FtpShowcase) {
    let mut sc = Scenario::new();
    let expected = ftp::ftp_showcase(&mut sc);
    (sc.into_packets(), expected)
}

fn sessions(out: &Out) -> Vec<&FtpSession> {
    let mut v: Vec<&FtpSession> = out
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Ftp(FtpRecord::Session(s)) => Some(&**s),
            _ => None,
        })
        .collect();
    v.sort_by_key(|s| s.flow_id);
    v
}

fn transfers(out: &Out) -> Vec<&FtpTransfer> {
    let mut v: Vec<&FtpTransfer> = out
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Ftp(FtpRecord::Transfer(t)) => Some(&**t),
            _ => None,
        })
        .collect();
    v.sort_by_key(|t| (t.flow_id, t.seq));
    v
}

/// Compact rendering of every record, the secret masked.
fn render(out: &Out) -> String {
    let mut lines: Vec<_> = out
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Ftp(FtpRecord::Line(l)) => Some(l),
            _ => None,
        })
        .collect();
    lines.sort_by_key(|l| (l.flow_id, l.seq));
    let mut s = String::new();
    for l in lines {
        let text = if l.secret {
            "<secret>"
        } else {
            l.text.as_str()
        };
        let text = if text.is_empty() {
            String::new()
        } else {
            format!(" {text}")
        };
        writeln!(
            s,
            "line {} #{} {} {}{text}{}",
            l.flow_id.0,
            l.seq,
            l.kind.as_str(),
            l.head.as_deref().unwrap_or("-"),
            if l.truncated { " [truncated]" } else { "" }
        )
        .unwrap();
    }
    for t in transfers(out) {
        writeln!(
            s,
            "transfer {} #{} {} {:?} {} {:?} {:?} data={:?} status={:?} {:?} bytes={} rest={:?} \
             truncated={} object={:?} mime={:?} listing={:?}",
            t.flow_id.0,
            t.seq,
            t.command,
            t.path,
            t.direction.as_str(),
            t.mode.map(super::DataMode::as_str),
            t.mode_command,
            t.data_flow.map(|f| f.0),
            t.status,
            t.status_text,
            t.bytes,
            t.restart_offset,
            t.truncated,
            t.object.map(|b| b.to_hex()),
            t.mime,
            t.listing,
        )
        .unwrap();
    }
    for x in sessions(out) {
        writeln!(s, "session {x:?}").unwrap();
    }
    s
}

#[test]
fn showcase_records_snapshot() {
    let (packets, expected) = showcase();
    let out = run(&packets);
    assert_eq!(sessions(&out).len(), expected.sessions);
    assert_eq!(transfers(&out).len(), expected.transfers);
    assert_eq!(out.blobs.len(), expected.stored);
    insta::assert_snapshot!(render(&out));
}

#[test]
fn transfers_carry_their_data_and_files_are_stored() {
    let (packets, expected) = showcase();
    let out = run(&packets);
    let t = transfers(&out);
    let image = t
        .iter()
        .find(|t| t.command == "RETR" && t.path.as_deref() == Some("photos/harbour.png"))
        .unwrap();
    assert_eq!(image.status, Some(226));
    assert_eq!(image.bytes, expected.image.len() as u64);
    assert_eq!(image.mime.as_deref(), Some("image/png"));
    let blob = out
        .blobs
        .iter()
        .find(|(b, _)| Some(*b) == image.object)
        .unwrap();
    assert_eq!(blob.1, expected.image);
    // Data connection opened before STOR.
    let report = t.iter().find(|t| t.command == "STOR").unwrap();
    assert_eq!(report.bytes, ftp::REPORT.len() as u64);
    assert_eq!(report.mode, Some(super::DataMode::Passive));
    assert_eq!(report.mime.as_deref(), Some("application/octet-stream"));
    assert!(report.data_flow.is_some());
    // Active listing from port 20: text, no object.
    let list = t.iter().find(|t| t.command == "LIST").unwrap();
    assert_eq!(list.mode, Some(super::DataMode::Active));
    assert_eq!(
        list.listing.as_deref(),
        Some(ftp::LISTING.replace('\r', "").as_str())
    );
    assert!(list.object.is_none());
    // EPSV over IPv6.
    let readme = t
        .iter()
        .find(|t| t.path.as_deref() == Some("pub/README"))
        .unwrap();
    assert_eq!(readme.bytes, ftp::README.len() as u64);
    assert!(readme.object.is_some());
    // Interrupted: counted, not stored.
    let iso = t
        .iter()
        .find(|t| t.path.as_deref() == Some("iso/image.bin"))
        .unwrap();
    assert_eq!(iso.status, Some(426));
    assert_eq!(iso.bytes, 6000);
    assert!(iso.object.is_none());
}

#[test]
fn sessions_carry_login_and_tls() {
    let (packets, _) = showcase();
    let out = run(&packets);
    let s = sessions(&out);
    let by_user = |u: &str| s.iter().find(|x| x.username.as_deref() == Some(u)).unwrap();
    assert_eq!(by_user("alice").login, Some(true));
    assert_eq!(by_user("alice").files, 2);
    assert_eq!(by_user("bob").listings, 1);
    assert_eq!(by_user("admin").login, Some(false));
    let tls = s.iter().find(|x| x.tls).unwrap();
    assert_eq!(tls.username, None);
    // Nothing after AUTH TLS is transcribed: the last line is the note.
    let notes: Vec<_> = out
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Ftp(FtpRecord::Line(l)) if l.flow_id == tls.flow_id => Some(l),
            _ => None,
        })
        .collect();
    assert_eq!(notes.last().unwrap().kind, LineKind::Note);
    assert_eq!(notes.last().unwrap().text, super::NOTE_TLS);
}

#[test]
fn the_password_never_reaches_debug() {
    let (packets, _) = showcase();
    let out = run(&packets);
    let debug = format!("{:?}", out.records);
    assert!(!debug.contains(ftp::SECRET), "secret in Debug output");
    assert!(debug.contains("<redacted>"));
    // The transcript keeps it, flagged.
    assert!(out.records.iter().any(|r| matches!(
        r,
        Record::Ftp(FtpRecord::Line(l)) if l.secret && l.text == ftp::SECRET
    )));
}

#[test]
fn memory_budget_is_given_back() {
    let config = AnalyzerConfig::default();
    let before = config.ftp.budget.remaining();
    let (packets, _) = showcase();
    let _ = run_with(&config, &packets);
    assert_eq!(config.ftp.budget.remaining(), before);
}

#[test]
fn files_beyond_the_budget_are_counted_without_content() {
    let config = AnalyzerConfig {
        ftp: FtpConfig {
            max_retained_bytes: 1000,
            ..FtpConfig::default()
        }
        .with_fresh_budget(),
        ..AnalyzerConfig::default()
    };
    let (packets, expected) = showcase();
    let out = run_with(&config, &packets);
    let image = transfers(&out)
        .into_iter()
        .find(|t| t.path.as_deref() == Some("photos/harbour.png"))
        .unwrap();
    assert_eq!(image.bytes, expected.image.len() as u64);
    assert!(image.truncated);
    assert!(image.object.is_none());
    assert_eq!(config.ftp.budget.remaining(), 1000);
}

#[test]
fn transcript_and_transfers_are_bounded() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        ftp_hosts::client(),
        ftp_hosts::server(),
        &TcpOptions::new(21),
    );
    s.server_send(b"220 ready\r\n");
    let mut cmds = Vec::new();
    for _ in 0..(MAX_LINES as usize + 10) {
        cmds.extend_from_slice(b"NOOP\r\n");
    }
    for i in 0..(MAX_TRANSFERS + 5) {
        cmds.extend_from_slice(format!("LIST d{i}\r\n").as_bytes());
    }
    s.client_send(&cmds);
    s.close();
    let out = run(&sc.into_packets());
    let session = sessions(&out)[0].clone();
    assert!(session.transcript_truncated);
    assert_eq!(session.lines, MAX_LINES);
    assert_eq!(session.listings, u64::from(MAX_TRANSFERS) + 5);
    assert!(transfers(&out).len() <= MAX_TRANSFERS as usize);
    let stored = out
        .records
        .iter()
        .filter(|r| matches!(r, Record::Ftp(FtpRecord::Line(_))))
        .count();
    assert_eq!(stored, MAX_LINES as usize);
}

#[test]
fn a_flow_older_than_the_announcement_is_not_paired() {
    let mut sc = Scenario::new();
    let (client, server) = (ftp_hosts::client(), ftp_hosts::server());
    // An unrelated connection to the future data port, opened before PASV.
    let mut early = sc.tcp_open(client, server, &TcpOptions::new(50_100)).park();
    let mut ctl = sc.tcp_open(client, server, &TcpOptions::new(21));
    ctl.server_send(b"220 ready\r\n");
    ctl.client_send(b"PASV\r\n");
    ctl.server_send(b"227 Entering Passive Mode (192,168,1,33,195,116)\r\n");
    ctl.client_send(b"RETR a.txt\r\n");
    let ctl = ctl.park();
    {
        let mut e = sc.resume(&early);
        e.server_send(b"not ftp data");
        early = e.park();
    }
    sc.resume(&early).close();
    let mut ctl = sc.resume(&ctl);
    ctl.server_send(b"425 Can't open data connection.\r\n");
    ctl.close();
    let out = run(&sc.into_packets());
    let t = transfers(&out);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].data_flow, None);
    assert_eq!(t[0].status, Some(425));
}

#[test]
fn the_shard_route_ignores_ports() {
    // ADR-032 relies on it: a control connection and its data connection between the same two
    // addresses always reach the same shard.
    let mut sc = Scenario::new();
    let (client, server) = (ftp_hosts::client(), ftp_hosts::server());
    sc.tcp_open(client, server, &TcpOptions::new(21)).close();
    sc.tcp_open(client, server, &TcpOptions::new(50_000))
        .close();
    let opts = TcpOptions {
        client_port: Some(20),
        ..TcpOptions::new(41_000)
    };
    sc.tcp_open(server, client, &opts).close();
    let hashes: Vec<u64> = sc
        .packets()
        .iter()
        .map(|p| shard_hash(&decode(p.linktype, &p.data)))
        .collect();
    assert!(hashes.windows(2).all(|w| w[0] == w[1]), "{hashes:?}");
}

#[test]
fn only_the_address_pair_of_the_control_is_paired() {
    // ADR-032: a third host on the announced port, and an FXP transfer, link another pair than
    // the control. They are never paired, whatever shard they reach.
    let mut sc = Scenario::new();
    ftp::ftp_cross_pair(&mut sc);
    let out = run(&sc.into_packets());
    let t = transfers(&out);
    let genuine = t
        .iter()
        .find(|t| t.path.as_deref() == Some("genuine.txt"))
        .unwrap();
    assert_eq!(genuine.bytes, ftp::CROSS_FILE.len() as u64);
    assert_eq!(genuine.mode_command, Some("PASV"));
    let (_, content) = out
        .blobs
        .iter()
        .find(|(b, _)| Some(*b) == genuine.object)
        .unwrap();
    assert_eq!(content, ftp::CROSS_FILE);
    assert!(out.blobs.iter().all(|(_, c)| c != ftp::STOLEN));
    let fxp = t
        .iter()
        .find(|t| t.path.as_deref() == Some("mirror.iso"))
        .unwrap();
    assert_eq!(fxp.data_flow, None);
    assert_eq!((fxp.bytes, fxp.status), (0, Some(226)));
}

#[test]
fn an_unclaimed_early_connection_or_announcement_never_reaches_a_later_transfer() {
    let mut sc = Scenario::new();
    let (client, server) = (ftp_hosts::client(), ftp_hosts::server());
    let ctl = sc.tcp_open(client, server, &TcpOptions::new(21));
    let mut ctl = ctl.park();
    {
        let mut s = sc.resume(&ctl);
        s.server_send(b"220 ready\r\n");
        s.client_send(b"PASV\r\n");
        s.server_send(b"227 Entering Passive Mode (192,168,1,33,195,100)\r\n");
        ctl = s.park();
    }
    // Opened early for the first PASV, then abandoned: a second PASV comes first.
    let mut early = sc.tcp_open(client, server, &TcpOptions::new(50_020)).park();
    {
        let mut e = sc.resume(&early);
        e.server_send(b"stale");
        early = e.park();
    }
    sc.resume(&early).close();
    {
        let mut s = sc.resume(&ctl);
        s.client_send(b"PASV\r\n");
        s.server_send(b"227 Entering Passive Mode (192,168,1,33,195,101)\r\n");
        s.client_send(b"RETR a.txt\r\n");
        s.server_send(b"425 Can't open data connection.\r\n");
        // The announcement of the failed transfer is gone: a late connection to its port is not
        // given to the next transfer.
        s.client_send(b"RETR b.txt\r\n");
        ctl = s.park();
    }
    let mut late = sc.tcp_open(client, server, &TcpOptions::new(50_021)).park();
    {
        let mut e = sc.resume(&late);
        e.server_send(b"late");
        late = e.park();
    }
    sc.resume(&late).close();
    {
        let mut s = sc.resume(&ctl);
        s.server_send(b"425 Can't open data connection.\r\n");
        s.close();
    }
    let out = run(&sc.into_packets());
    let t = transfers(&out);
    assert_eq!(t.len(), 2);
    assert!(t.iter().all(|t| t.data_flow.is_none()), "{t:?}");
}

#[test]
fn a_password_without_its_verb_stays_secret() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        ftp_hosts::client(),
        ftp_hosts::server(),
        &TcpOptions::new(21),
    );
    s.server_send(b"220 ready\r\n");
    s.client_send(b"USER bob\r\n");
    s.server_send(b"331 Password required\r\n");
    // A client that sends the password alone, then a mangled PASS.
    s.client_send(b"hunter2\r\n");
    s.server_send(b"530 Login incorrect\r\n");
    s.client_send(b"pass\x01letmein\r\n");
    s.server_send(b"500 Unknown command\r\n");
    s.client_send(b"NOOP\r\n");
    s.server_send(b"200 OK\r\n");
    s.close();
    let out = run(&sc.into_packets());
    let lines: Vec<&super::FtpLine> = out
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Ftp(FtpRecord::Line(l)) if l.kind == LineKind::Command => Some(l),
            _ => None,
        })
        .collect();
    let secret: Vec<bool> = lines.iter().map(|l| l.secret).collect();
    assert_eq!(secret, vec![false, true, true, false]);
    let debug = format!("{:?}", out.records);
    assert!(!debug.contains("hunter2") && !debug.contains("letmein"));
}
