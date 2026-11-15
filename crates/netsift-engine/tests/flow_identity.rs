//! Flow identity end to end (ADR-022): two connections on the same 5-tuple with the same first
//! timestamp are two flows, with exact counters and all their HTTP, TLS and SMB rows, whatever
//! the number of shards and whether the capture is one file or overlapping chunks.

use std::fmt::Write as _;
use std::ops::Range;
use std::path::Path;

use netsift_analyze::dissect::decode;
use netsift_analyze::flow::FlowConfig;
use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::scenario::{HttpGet, Scenario, SmbNtlm, TcpOptions, TlsHandshake};
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{Encoding, Naming, Packet, SplitBy, SplitOptions, split_to_dir, write_file};
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;

const T: i64 = 1_700_000_000_000_000_000;
const MS: i64 = 1_000_000;
const CLIENT_PORT: u16 = 50_000;

/// Packets of one part of the capture, and the packet range and client port of each
/// connection, in packet order.
struct Part {
    packets: Vec<Packet>,
    conns: Vec<(Range<usize>, u16)>,
}

impl Part {
    fn append(&mut self, other: Part) {
        let base = self.packets.len();
        self.packets.extend(other.packets);
        self.conns.extend(
            other
                .conns
                .into_iter()
                .map(|(r, port)| (r.start + base..r.end + base, port)),
        );
    }
}

fn fixed_port(server_port: u16) -> TcpOptions {
    TcpOptions {
        client_port: Some(CLIENT_PORT),
        ..TcpOptions::new(server_port)
    }
}

/// Two HTTP connections, same 5-tuple, all packets stamped `ts`.
fn http_pair(ts: i64) -> Part {
    let mut sc = Scenario::starting_at(ts).with_gap(0);
    let mut conns = Vec::new();
    for (path, body) in [("/first", &b"one"[..]), ("/second", &b"second body"[..])] {
        let get = HttpGet {
            path: path.to_owned(),
            content_type: "text/plain".to_owned(),
            body: body.to_vec(),
            tcp: fixed_port(80),
            ..HttpGet::default()
        };
        let ex = sc.http_get(hosts::workstation(), hosts::web_server(), &get);
        conns.push((ex.packets, ex.client_port));
    }
    Part {
        packets: sc.into_packets(),
        conns,
    }
}

/// Two TLS handshakes, same 5-tuple, all packets stamped `ts`.
fn tls_pair(ts: i64) -> Part {
    let mut sc = Scenario::starting_at(ts).with_gap(0);
    let mut conns = Vec::new();
    for sni in ["one.example.test", "two.example.test"] {
        let hs = TlsHandshake {
            tcp: fixed_port(443),
            ..TlsHandshake::new(sni)
        };
        let ex = sc.tls_handshake(hosts::workstation(), hosts::web_server(), &hs);
        conns.push((ex.packets, ex.client_port));
    }
    Part {
        packets: sc.into_packets(),
        conns,
    }
}

/// Two SMB2 NTLM sessions, same 5-tuple (same seed, hence same ephemeral port), all packets
/// stamped `ts`.
fn smb_pair(ts: i64) -> Part {
    let mut part = Part {
        packets: Vec::new(),
        conns: Vec::new(),
    };
    for user in ["alice", "bob"] {
        let mut sc = Scenario::starting_at(ts).with_gap(0).with_seed(5);
        let ex = sc.smb_ntlm(
            hosts::workstation(),
            hosts::file_server(),
            &SmbNtlm::v2(user, "CORP"),
        );
        part.append(Part {
            packets: sc.into_packets(),
            conns: vec![(ex.packets, ex.client_port)],
        });
    }
    let ports: Vec<u16> = part.conns.iter().map(|c| c.1).collect();
    assert_eq!(ports[0], ports[1], "same 5-tuple");
    part
}

/// Expected `flows` lines (`id fwd=packets/bytes rev=packets/bytes`): the id of a connection
/// is the global index of its first frame.
fn expected_flows(part: &Part) -> Vec<String> {
    let mut lines: Vec<String> = part
        .conns
        .iter()
        .map(|(range, client_port)| {
            let (mut fwd, mut rev) = ((0u64, 0u64), (0u64, 0u64));
            for p in &part.packets[range.clone()] {
                let (sport, _) = decode(p.linktype, &p.data).ports().unwrap();
                let side = if sport == *client_port {
                    &mut fwd
                } else {
                    &mut rev
                };
                side.0 += 1;
                side.1 += p.data.len() as u64;
            }
            format!(
                "{} fwd={}/{} rev={}/{}",
                range.start, fwd.0, fwd.1, rev.0, rev.1
            )
        })
        .collect();
    lines.sort_by_key(|l| l.split(' ').next().unwrap().parse::<u64>().unwrap());
    lines
}

fn import(catalog: &Catalog, input: &Path, shards: usize, flow: FlowConfig) -> IngestReport {
    let options = IngestOptions {
        shards: Some(shards),
        flow,
        ..IngestOptions::default()
    };
    let report = ingest(catalog, input, &options, &CancelToken::new(), &mut |_| {}).unwrap();
    assert_eq!(report.state, SessionState::Ready);
    report
}

fn rows(catalog: &Catalog, report: &IngestReport, sql: &str) -> Vec<String> {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut stmt = session.conn().prepare(sql).unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Flow counters only, in the format of [`expected_flows`].
fn flow_counters(catalog: &Catalog, report: &IngestReport) -> Vec<String> {
    rows(
        catalog,
        report,
        "SELECT id || ' fwd=' || packets_fwd || '/' || bytes_fwd || ' rev=' || packets_rev || \
         '/' || bytes_rev FROM flows ORDER BY id",
    )
}

/// Every table touched by the scenarios, ids included.
fn dump(catalog: &Catalog, report: &IngestReport) -> String {
    let mut s = String::new();
    for (name, sql) in [
        (
            "flows",
            "SELECT id || ' ' || src_ip || ':' || src_port || ' -> ' || dst_ip || ':' || \
             dst_port || ' ' || first_ts || '..' || last_ts || ' fwd=' || packets_fwd || '/' || \
             bytes_fwd || ' rev=' || packets_rev || '/' || bytes_rev || ' app=' || \
             coalesce(app_proto, '-') || ' tcp=' || coalesce(tcp_state, '-') \
             FROM flows ORDER BY id",
        ),
        (
            "http_transactions",
            "SELECT flow_id || '/' || seq || ' ' || coalesce(method, '-') || ' ' || \
             coalesce(path, '-') || ' ' || coalesce(status, '-') || ' resp=' || resp_body_len \
             FROM http_transactions ORDER BY flow_id, seq",
        ),
        (
            "tls_sessions",
            "SELECT id || ' ' || client_port || ' ' || coalesce(sni, '-') || ' ' || outcome \
             FROM tls_sessions ORDER BY id",
        ),
        (
            "smb_sessions",
            "SELECT flow_id || ' ' || client_port || ' ' || coalesce(account, '-') || ' ' || \
             coalesce(domain, '-') || ' ' || coalesce(ntlm_phase, '-') \
             FROM smb_sessions ORDER BY flow_id",
        ),
    ] {
        let lines = rows(catalog, report, sql);
        writeln!(s, "# {name} ({} rows)", lines.len()).unwrap();
        for l in lines {
            writeln!(s, "{l}").unwrap();
        }
    }
    s
}

/// A dumpcap chunk name with sequence number `seq`.
fn chunk_name(seq: u32) -> String {
    format!("cap_{seq:05}_20231114221320.pcapng")
}

#[test]
fn same_tuple_and_time_connections_stay_separate_on_any_shards_and_chunking() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    // HTTP at T, SMB at T + 1 ms, TLS at T + 2 ms: one file in time order...
    let (http, smb, tls) = (http_pair(T), smb_pair(T + MS), tls_pair(T + 2 * MS));
    let (http_packets, smb_packets, tls_packets) = (
        http.packets.clone(),
        smb.packets.clone(),
        tls.packets.clone(),
    );
    let mut all = http;
    all.append(smb);
    all.append(tls);
    let expected = expected_flows(&all);
    assert_eq!(expected.len(), 6);

    let single = tmp.path().join("single.pcapng");
    write_file(&single, &all.packets, &Encoding::pcapng()).unwrap();
    let reference = import(&catalog, &single, 1, FlowConfig::default());
    assert_eq!(flow_counters(&catalog, &reference), expected);
    let tables = dump(&catalog, &reference);
    insta::assert_snapshot!("same_tuple_and_time", tables);
    // Every HTTP transaction, TLS session and SMB session of both connections is there.
    for (sql, n) in [
        (
            "SELECT count(DISTINCT flow_id) || '/' || count(*) FROM http_transactions",
            "2/2",
        ),
        (
            "SELECT count(DISTINCT sni) || '/' || count(*) FROM tls_sessions",
            "2/2",
        ),
        (
            "SELECT count(DISTINCT account) || '/' || count(*) FROM smb_sessions",
            "2/2",
        ),
    ] {
        assert_eq!(rows(&catalog, &reference, sql), vec![n.to_owned()], "{sql}");
    }

    for shards in [2, 4, 7] {
        let again = import(&catalog, &single, shards, FlowConfig::default());
        assert_eq!(
            dump(&catalog, &again),
            tables,
            "single file, {shards} shards"
        );
    }

    // ... and overlapping chunks: HTTP + TLS in the first one, SMB in the second (which
    // starts before the first ends), plus a duplicate of the second, skipped by the reader.
    let dir = tmp.path().join("chunks");
    std::fs::create_dir(&dir).unwrap();
    let first: Vec<Packet> = http_packets.into_iter().chain(tls_packets).collect();
    write_file(&dir.join(chunk_name(1)), &first, &Encoding::pcapng()).unwrap();
    write_file(&dir.join(chunk_name(2)), &smb_packets, &Encoding::pcapng()).unwrap();
    std::fs::copy(dir.join(chunk_name(2)), dir.join(chunk_name(3))).unwrap();
    for shards in [1, 3] {
        let report = import(&catalog, &dir, shards, FlowConfig::default());
        assert_eq!((report.chunks, report.chunks_read), (3, 2));
        assert!(report.anomaly_kinds.contains_key("overlap"), "{report:?}");
        assert!(report.anomaly_kinds.contains_key("duplicate"), "{report:?}");
        assert_eq!(report.packets, all.packets.len() as u64);
        assert_eq!(dump(&catalog, &report), tables, "chunks, {shards} shards");
    }
}

/// Connection X, then connection Y between the same hosts, which evicts X (one flow per
/// table), then X resumes from its client: X before and after the eviction share the 5-tuple
/// and the first timestamp.
fn eviction() -> Part {
    let mut sc = Scenario::starting_at(T).with_gap(0);
    let mut x = sc.tcp_open(hosts::workstation(), hosts::web_server(), &fixed_port(80));
    x.client_send(b"GET /before HTTP/1.1\r\nHost: x.test\r\n\r\n");
    x.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nbefore");
    let y_start = x.scenario().len();
    let mut y = x
        .scenario()
        .tcp_open(hosts::workstation(), hosts::web_server(), &fixed_port(8080));
    y.client_send(b"GET /other HTTP/1.1\r\nHost: y.test\r\n\r\n");
    y.server_send(b"HTTP/1.1 204 No Content\r\n\r\n");
    let y_range = y.close();
    let x_resume = x.scenario().len();
    x.client_send(b"GET /after HTTP/1.1\r\nHost: x.test\r\n\r\n");
    x.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nafter");
    let x_range = x.close();
    let end = x_range.end;
    Part {
        packets: sc.into_packets(),
        conns: vec![
            (0..y_start, CLIENT_PORT),
            (y_range, CLIENT_PORT),
            (x_resume..end, CLIENT_PORT),
        ],
    }
}

#[test]
fn an_evicted_flow_resumed_at_the_same_time_is_a_new_flow() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let part = eviction();
    let expected = expected_flows(&part);
    let flow = FlowConfig {
        max_flows: 1,
        ..FlowConfig::default()
    };

    let single = tmp.path().join("single.pcap");
    write_file(&single, &part.packets, &Encoding::pcap()).unwrap();
    let reference = import(&catalog, &single, 1, flow);
    assert_eq!(flow_counters(&catalog, &reference), expected);
    let tables = dump(&catalog, &reference);
    insta::assert_snapshot!("eviction", tables);
    assert_eq!(
        rows(
            &catalog,
            &reference,
            "SELECT count(DISTINCT src_port || dst_port || first_ts) || '/' || count(*) \
             FROM flows"
        ),
        vec!["2/3".to_owned()],
        "x before and after the eviction share the tuple and the first timestamp"
    );
    // Both requests of X are kept, each on its own flow.
    assert_eq!(
        rows(
            &catalog,
            &reference,
            "SELECT group_concat(path, ' ') FROM (SELECT path FROM http_transactions \
             ORDER BY flow_id, seq)"
        ),
        vec!["/before /other /after".to_owned()]
    );

    // X and Y share their host pair, hence their shard: the eviction is the same everywhere.
    for shards in [2, 4] {
        let again = import(&catalog, &single, shards, flow);
        assert_eq!(dump(&catalog, &again), tables, "{shards} shards");
    }
    let dir = tmp.path().join("chunks");
    let opts =
        SplitOptions::new(SplitBy::Packets(5), Naming::Dumpcap).with_encoding(Encoding::pcapng());
    let files = split_to_dir(&dir, &part.packets, &opts).unwrap().1;
    assert!(files.len() > 3);
    for shards in [1, 3] {
        let report = import(&catalog, &dir, shards, flow);
        assert_eq!(report.chunks_read, files.len());
        assert_eq!(dump(&catalog, &report), tables, "chunks, {shards} shards");
    }
}
