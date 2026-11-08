//! Acceptance test of the DNS view (`docs/specs/dns.md`): 10 A queries, 1 NXDOMAIN, 1 query
//! without response, 2 NBNS queries (one for WPAD), one response in the next chunk. Counters
//! and pairing must be exact whatever the number of shards and the chunking, also for group
//! queries answered by other hosts: mDNS "QU" query, NBNS registration refused by a unicast
//! conflict response, several LLMNR and NBNS responders.

use std::path::Path;

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use std::net::Ipv4Addr;

use netsift_fixtures::proto::dns::{DnsAnswer, DnsData, DnsType, encode_query, encode_response};
use netsift_fixtures::proto::netbios::{
    NetbiosName, SUFFIX_SERVER, SUFFIX_WORKSTATION, nbns_name_query, nbns_name_query_response,
    nbns_name_registration,
};
use netsift_fixtures::scenario::DnsExchange;
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{
    Encoding, Host, Naming, Packet, Scenario, SplitBy, SplitOptions, split_to_dir, write_file,
};
use netsift_store::dns::{DnsFilter, messages_page, stats};
use netsift_store::{Catalog, OpenMode, PageRequest, Session};
use tempfile::TempDir;

const MS: i64 = 1_000_000;

/// The packets, and the index of the response that must start the second chunk.
fn traffic() -> (Vec<Packet>, usize) {
    let ws = hosts::workstation();
    let resolver = hosts::router();
    let mut sc = Scenario::new().with_seed(5);
    let mut boundary = 0;
    for i in 0..10u8 {
        let idx = sc.dns(
            ws,
            resolver,
            &DnsExchange::a(format!("host{i}.example.test"), [203, 0, 113, 10 + i]),
        );
        if i == 5 {
            boundary = idx.response.unwrap();
        }
        sc.advance(20 * MS);
    }
    sc.dns(
        ws,
        resolver,
        &DnsExchange::nxdomain("missing.example.test", DnsType::A),
    );
    sc.dns(
        ws,
        resolver,
        &DnsExchange::new("lost.example.test", DnsType::Aaaa).unanswered(),
    );
    // NBNS: a broadcast query answered by the file server, and an unanswered WPAD query.
    let server = NetbiosName::new("FILESRV01", SUFFIX_SERVER);
    sc.nbns_query(ws, hosts::broadcast(), 0x7102, &server);
    sc.nbns_query_response(hosts::file_server(), ws, 0x7102, &server);
    sc.nbns_query(
        ws,
        hosts::broadcast(),
        0x7103,
        &NetbiosName::new("WPAD", 0x00),
    );
    group_queries(&mut sc);
    // Later traffic, so that the window of the last queries ends in packet time.
    sc.advance(10_000 * MS);
    sc.dns(
        ws,
        resolver,
        &DnsExchange::a("late.example.test", [203, 0, 113, 99]),
    );
    (sc.into_packets(), boundary)
}

fn lan(last: u8) -> Host {
    Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, last], [192, 168, 1, last])
}

/// Group queries answered by other hosts (whose packets may reach other shards).
fn group_queries(sc: &mut Scenario) {
    let ws = hosts::workstation();
    let a = |name: &str, ip: [u8; 4]| DnsAnswer::new(name, 30, DnsData::A(Ipv4Addr::from(ip)));
    // mDNS one-shot query with the "unicast response" bit, answered in unicast.
    let mdns = Host::v4([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb], [224, 0, 0, 251]);
    let mut qu = encode_query(0, "printer.local", DnsType::A);
    let len = qu.len();
    qu[len - 2] |= 0x80;
    sc.udp(ws, mdns, 5353, 5353, &qu);
    sc.advance(MS);
    let answer = encode_response(
        0,
        "printer.local",
        DnsType::A,
        0,
        &[a("printer.local", [192, 168, 1, 30])],
    );
    sc.udp(lan(30), ws, 5353, 5353, &answer);
    sc.advance(20 * MS);

    // NBNS broadcast registration refused by the owner of the name (ACT_ERR).
    let taken = NetbiosName::new("WS01", SUFFIX_WORKSTATION);
    let addr = Ipv4Addr::new(192, 168, 1, 10);
    sc.udp(
        ws,
        hosts::broadcast(),
        137,
        137,
        &nbns_name_registration(0x7201, &taken, 300, addr, false),
    );
    sc.advance(MS);
    let mut refusal = nbns_name_query_response(0x7201, &taken, 0, addr);
    // R, opcode REGISTRATION, AA, RD, RA, rcode ACT_ERR.
    refusal[2..4].copy_from_slice(&0xad86_u16.to_be_bytes());
    sc.udp(hosts::file_server(), ws, 137, 137, &refusal);
    sc.advance(20 * MS);

    // LLMNR answered by three hosts: the earliest response wins.
    let llmnr = Host::v4([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc], [224, 0, 0, 252]);
    sc.udp(
        ws,
        llmnr,
        50_010,
        5355,
        &encode_query(0x55, "dupname", DnsType::A),
    );
    for last in [30, 40, 50] {
        sc.advance(MS);
        let response = encode_response(
            0x55,
            "dupname",
            DnsType::A,
            0,
            &[a("dupname", [192, 168, 1, last])],
        );
        sc.udp(lan(last), ws, 5355, 50_010, &response);
    }
    sc.advance(20 * MS);

    // NBNS broadcast query answered by two hosts.
    let dup = NetbiosName::new("DUPNB", SUFFIX_SERVER);
    sc.udp(
        ws,
        hosts::broadcast(),
        137,
        137,
        &nbns_name_query(0x7301, &dup),
    );
    for last in [40, 30] {
        sc.advance(MS);
        let response =
            nbns_name_query_response(0x7301, &dup, 300, Ipv4Addr::new(192, 168, 1, last));
        sc.udp(lan(last), ws, 137, 137, &response);
    }
}

/// DNS tables and host names, without the arrival-order row ids.
fn dump(session: &Session) -> Vec<String> {
    let conn = session.conn();
    let mut out = Vec::new();
    for sql in [
        "SELECT ts || ' ' || proto || ' ' || client_ip || ':' || client_port || ' ' || server_ip \
         || ' ' || coalesce(responder_ip, '-') || ' ' || qname || ' ' || coalesce(rcode, '-') \
         || ' ' || coalesce(latency_ns, '-') || ' ' || answers || ' ' || has_query \
         || has_response || pending || ' ' || pair_id || ' ' || coalesce(flow_id, '-') \
         FROM dns_messages ORDER BY 1",
        "SELECT id || ' ' || proto || ' ' || client_ip || ' ' || server_ip || ' ' || messages \
         || ' ' || errors || ' ' || top_names FROM dns_pairs ORDER BY id",
        "SELECT ip || ' ' || names FROM hosts ORDER BY ip",
    ] {
        let mut stmt = conn.prepare(sql).unwrap();
        out.extend(
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap),
        );
    }
    out
}

/// Group queries are paired with their earliest response, whatever the shard of each packet.
fn check_group_queries(session: &Session) {
    let conn = session.conn();
    let answered_by = |name: &str| -> Vec<(Option<String>, String, bool)> {
        let filter = DnsFilter {
            search: Some(name.to_owned()),
            ..DnsFilter::default()
        };
        let (page, _) = messages_page(conn, None, &filter, &PageRequest::first(10)).unwrap();
        page.items
            .into_iter()
            .map(|m| {
                (
                    m.responder_ip.or(Some(m.server_ip)),
                    m.rcode.unwrap_or_default(),
                    m.has_query,
                )
            })
            .collect()
    };
    assert_eq!(
        answered_by("printer.local"),
        [(Some("192.168.1.30".to_owned()), "NOERROR".to_owned(), true)]
    );
    assert_eq!(
        answered_by("WS01"),
        [(Some("192.168.1.20".to_owned()), "ACT_ERR".to_owned(), true)]
    );
    let mut dup = answered_by("dupname");
    dup.sort();
    assert_eq!(
        dup,
        [
            (Some("192.168.1.30".to_owned()), "NOERROR".to_owned(), true),
            (Some("192.168.1.40".to_owned()), "NOERROR".to_owned(), false),
            (Some("192.168.1.50".to_owned()), "NOERROR".to_owned(), false),
        ]
    );
    let mut nb = answered_by("DUPNB");
    nb.sort();
    assert_eq!(
        nb,
        [
            (Some("192.168.1.30".to_owned()), "NOERROR".to_owned(), false),
            (Some("192.168.1.40".to_owned()), "NOERROR".to_owned(), true),
        ]
    );
}

fn import(dir: &Path, shards: usize) -> (TempDir, Catalog, IngestReport) {
    let data = TempDir::new().unwrap();
    let catalog = Catalog::open(data.path()).unwrap();
    let options = IngestOptions {
        shards: Some(shards),
        ..IngestOptions::default()
    };
    let report = ingest(&catalog, dir, &options, &CancelToken::new(), &mut |_| {}).unwrap();
    (data, catalog, report)
}

#[test]
fn counters_and_pairing_across_chunks() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("chunks");
    let (packets, boundary) = traffic();
    let opts = SplitOptions::new(SplitBy::At(vec![boundary]), Naming::Dumpcap)
        .with_encoding(Encoding::pcapng());
    let (_, paths) = split_to_dir(&dir, &packets, &opts).unwrap();
    assert_eq!(paths.len(), 2);

    let mut reference = None;
    for shards in [1, 3, 7] {
        let (_data, catalog, report) = import(&dir, shards);
        let session = catalog
            .open_session(&report.session, OpenMode::ReadOnly)
            .unwrap();
        let conn = session.conn();
        let s = stats(conn).unwrap();
        let count = |v: &[netsift_store::dns::Bucket], k: &str| {
            v.iter()
                .find(|b| b.key.as_deref() == Some(k))
                .map_or(0, |b| b.count)
        };
        // 10 A + late A + NXDOMAIN + unanswered + 2 NBNS, then the group queries: mDNS QU,
        // refused registration, LLMNR (+ 2 extra responses), NBNS (+ 1 extra response).
        assert_eq!(s.total, 22, "{shards} shards");
        assert_eq!(count(&s.protocols, "dns"), 13);
        assert_eq!(count(&s.protocols, "nbns"), 5);
        assert_eq!(count(&s.protocols, "mdns"), 1);
        assert_eq!(count(&s.protocols, "llmnr"), 3);
        assert_eq!(count(&s.rcodes, "NOERROR"), 18);
        assert_eq!(count(&s.rcodes, "NXDOMAIN"), 1);
        assert_eq!(count(&s.rcodes, "timeout"), 2);
        assert_eq!(count(&s.rcodes, "ACT_ERR"), 1);
        assert_eq!(s.errors, 4);
        assert_eq!(count(&s.qtypes, "A"), 14);
        assert_eq!(count(&s.qtypes, "AAAA"), 1);
        assert_eq!(count(&s.qtypes, "NB"), 4);

        check_group_queries(&session);

        // The query of the chunk boundary is paired with its response from the next chunk.
        let host5 = DnsFilter {
            search: Some("host5.example".to_owned()),
            ..DnsFilter::default()
        };
        let (page, n) = messages_page(conn, None, &host5, &PageRequest::first(10)).unwrap();
        assert_eq!(n, 1);
        let m = &page.items[0];
        assert!(m.has_query && m.has_response);
        assert_eq!(m.rcode.as_deref(), Some("NOERROR"));
        assert_eq!(m.answers[0].value, "203.0.113.15");
        assert!(m.latency_ns.is_some());

        // The NBNS broadcast query is answered by the file server (another shard, maybe).
        let filesrv = DnsFilter {
            search: Some("filesrv".to_owned()),
            ..DnsFilter::default()
        };
        let (page, _) = messages_page(conn, None, &filesrv, &PageRequest::first(10)).unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].responder_ip.as_deref(), Some("192.168.1.20"));
        assert_eq!(page.items[0].server_ip, "192.168.1.255");

        // Search "wpad" finds the NBNS query.
        let wpad = DnsFilter {
            search: Some("wpad".to_owned()),
            ..DnsFilter::default()
        };
        let (page, _) = messages_page(conn, None, &wpad, &PageRequest::first(10)).unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].proto, "nbns");
        assert_eq!(page.items[0].qname, "WPAD");
        assert_eq!(page.items[0].rcode.as_deref(), Some("timeout"));

        let names: String = conn
            .query_row(
                "SELECT names FROM hosts WHERE ip = '192.168.1.20'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(names, r#"["FILESRV01"]"#);

        let summary = (s, names, dump(&session));
        match &reference {
            None => reference = Some(summary),
            Some(r) => assert_eq!(&summary, r, "{shards} shards"),
        }
    }

    // The same traffic as one file gives the same tables.
    let file = tmp.path().join("single.pcap");
    write_file(&file, &packets, &Encoding::pcap()).unwrap();
    let reference = reference.unwrap();
    for shards in [1, 3, 7] {
        let (_data, catalog, report) = import(&file, shards);
        let session = catalog
            .open_session(&report.session, OpenMode::ReadOnly)
            .unwrap();
        assert_eq!(dump(&session), reference.2, "single file, {shards} shards");
    }
}
