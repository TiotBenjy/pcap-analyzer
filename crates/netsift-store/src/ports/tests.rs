use super::*;
use crate::connections::tests::{db, host};
use crate::records::{FlowRow, StoreRecord};

fn port(ip: &str, transport: u8, port: u16, evidence: &str) -> OpenPortRow {
    OpenPortRow {
        ip: ip.parse().unwrap(),
        transport,
        port,
        evidence: evidence.to_owned(),
        service: None,
        detected: None,
        banner: None,
        first_ts: 100,
        last_ts: 200,
    }
}

fn flow(id: u64, src: &str, dst: &str, transport: u8, dst_port: u16) -> FlowRow {
    FlowRow {
        id,
        transport,
        src_ip: src.parse().unwrap(),
        src_port: 50_000,
        dst_ip: dst.parse().unwrap(),
        dst_port,
        first_ts: 0,
        last_ts: 1,
        bytes_fwd: 1,
        bytes_rev: 1,
        packets_fwd: 1,
        packets_rev: 1,
        app_proto: None,
        tcp_state: None,
    }
}

#[allow(clippy::needless_pass_by_value)] // Called with record literals.
fn insert(conn: &Connection, r: StoreRecord) {
    r.insert(conn).unwrap();
}

fn fixture(conn: &Connection) {
    let mut web = port("192.168.1.50", 6, 80, "syn_ack");
    web.service = Some("http".into());
    let mut web_late = port("192.168.1.50", 6, 80, "server_data");
    web_late.detected = Some("http".into());
    web_late.first_ts = 50;
    web_late.last_ts = 900;
    let mut ssh = port("192.168.1.50", 6, 22, "syn_ack");
    ssh.service = Some("ssh".into());
    ssh.detected = Some("ssh".into());
    ssh.banner = Some("SSH-2.0-b".into());
    let mut ssh_other = ssh.clone();
    ssh_other.banner = Some("SSH-2.0-a".into());
    let mut dns = port("192.168.1.1", 17, 53, "udp_reply");
    dns.service = Some("domain".into());
    let mut https = port("81.2.3.4", 6, 443, "syn_ack");
    https.service = Some("https".into());
    https.detected = Some("tls".into());
    let mut web2 = port("81.2.3.4", 6, 80, "syn_ack");
    web2.service = Some("http".into());
    for r in [web, web_late, ssh, ssh_other, dns, https, web2] {
        insert(conn, StoreRecord::OpenPort(r));
    }
    for r in [
        host("192.168.1.50", "private", None, &["files.lan"]),
        host("192.168.1.1", "private", None, &["router.lan"]),
        host("81.2.3.4", "public", Some("FR"), &[]),
    ] {
        insert(conn, StoreRecord::Host(r));
    }
    // Clients: two distinct clients of :80 (one twice), one of :22, none of :443.
    for r in [
        flow(1, "192.168.1.10", "192.168.1.50", 6, 80),
        flow(2, "192.168.1.10", "192.168.1.50", 6, 80),
        flow(3, "192.168.1.11", "192.168.1.50", 6, 80),
        flow(4, "192.168.1.10", "192.168.1.50", 6, 22),
        flow(5, "192.168.1.10", "192.168.1.50", 17, 80),
    ] {
        insert(conn, StoreRecord::Flow(r));
    }
}

fn all(conn: &Connection, filter: &PortFilter, limit: u32) -> Vec<HostPorts> {
    let mut out = Vec::new();
    let mut request = PageRequest::first(limit);
    loop {
        let page = hosts_page(conn, filter, &request).unwrap();
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => request.cursor = Some(c),
            None => return out,
        }
    }
}

#[test]
fn merges_are_commutative_and_keep_the_strongest_evidence() {
    let conn = db();
    fixture(&conn);
    let hosts = all(&conn, &PortFilter::default(), 100);
    let lan = hosts
        .iter()
        .find(|h| h.ip.to_string() == "192.168.1.50")
        .unwrap();
    let web = &lan.ports.iter().find(|p| p.row.port == 80).unwrap().row;
    // syn_ack then server_data: the SYN-ACK is the stronger evidence.
    assert_eq!(web.evidence, "syn_ack");
    assert_eq!(web.service.as_deref(), Some("http"));
    assert_eq!(web.detected.as_deref(), Some("http"));
    assert_eq!((web.first_ts, web.last_ts), (50, 900));
    let ssh = &lan.ports.iter().find(|p| p.row.port == 22).unwrap().row;
    assert_eq!(ssh.banner.as_deref(), Some("SSH-2.0-a"));
}

#[test]
fn hosts_are_grouped_with_their_ports_and_clients() {
    let conn = db();
    fixture(&conn);
    for limit in [1, 2, 100] {
        let hosts = all(&conn, &PortFilter::default(), limit);
        let summary: Vec<_> = hosts
            .iter()
            .map(|h| {
                (
                    h.ip.to_string(),
                    h.ports
                        .iter()
                        .map(|p| (p.row.transport, p.row.port, p.clients))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                ("81.2.3.4".to_owned(), vec![(6, 80, 0), (6, 443, 0)]),
                ("192.168.1.50".to_owned(), vec![(6, 22, 1), (6, 80, 2)]),
                ("192.168.1.1".to_owned(), vec![(17, 53, 0)]),
            ],
            "page size {limit}"
        );
    }
    let hosts = all(&conn, &PortFilter::default(), 100);
    assert_eq!(hosts[0].host.country.as_deref(), Some("FR"));
    assert_eq!(hosts[1].host.names, ["files.lan"]);
    // Distinct clients over every open port (the UDP flow to :80 is not to an open port).
    assert_eq!(hosts[1].clients, 2);
    assert_eq!(hosts[0].clients, 0);
    assert_eq!(count_hosts(&conn, &PortFilter::default()).unwrap(), 3);
}

#[test]
fn filters_apply_to_ports_and_hosts() {
    let conn = db();
    fixture(&conn);
    let view = |f: PortFilter| -> Vec<(String, Vec<u16>)> {
        all(&conn, &f, 100)
            .into_iter()
            .map(|h| {
                (
                    h.ip.to_string(),
                    h.ports.iter().map(|p| p.row.port).collect(),
                )
            })
            .collect()
    };
    assert_eq!(
        view(PortFilter {
            categories: Some(vec!["public".into()]),
            ..PortFilter::default()
        }),
        [("81.2.3.4".to_owned(), vec![80, 443])]
    );
    assert_eq!(
        view(PortFilter {
            port: Some(80),
            ..PortFilter::default()
        }),
        [
            ("81.2.3.4".to_owned(), vec![80]),
            ("192.168.1.50".to_owned(), vec![80])
        ]
    );
    // Service: IANA or detected name.
    assert_eq!(
        view(PortFilter {
            service: Some("TLS".into()),
            ..PortFilter::default()
        }),
        [("81.2.3.4".to_owned(), vec![443])]
    );
    // Text: host name (every port), port number, or IP substring.
    assert_eq!(
        view(PortFilter {
            text: Some("router".into()),
            ..PortFilter::default()
        }),
        [("192.168.1.1".to_owned(), vec![53])]
    );
    assert_eq!(
        view(PortFilter {
            text: Some("22".into()),
            ..PortFilter::default()
        }),
        [("192.168.1.50".to_owned(), vec![22])]
    );
    assert_eq!(
        count_hosts(
            &conn,
            &PortFilter {
                text: Some("nothing".into()),
                ..PortFilter::default()
            }
        )
        .unwrap(),
        0
    );
}

#[test]
fn stats_rank_ports_by_hosts() {
    let conn = db();
    fixture(&conn);
    let (top, distinct, total) = port_stats(&conn, &PortFilter::default(), 15).unwrap();
    let summary: Vec<_> = top
        .iter()
        .map(|s| (s.transport, s.port, s.service.as_deref(), s.hosts))
        .collect();
    assert_eq!(
        summary,
        vec![
            (6, 80, Some("http"), 2),
            (6, 22, Some("ssh"), 1),
            (17, 53, Some("domain"), 1),
            (6, 443, Some("https"), 1),
        ]
    );
    assert_eq!((distinct, total), (4, 5));
    let (top, distinct, _) = port_stats(&conn, &PortFilter::default(), 1).unwrap();
    assert_eq!((top.len(), distinct), (1, 4));
}

#[test]
fn evidence_ranking_does_not_depend_on_arrival_order() {
    let labels = ["server_data", "udp_reply", "syn_ack"];
    for a in labels {
        for b in labels {
            let conn = db();
            insert(&conn, StoreRecord::OpenPort(port("10.0.0.1", 6, 80, a)));
            insert(&conn, StoreRecord::OpenPort(port("10.0.0.1", 6, 80, b)));
            let rank = |l: &str| labels.iter().position(|x| *x == l).unwrap();
            let expected = if rank(a) >= rank(b) { a } else { b };
            let hosts = all(&conn, &PortFilter::default(), 10);
            assert_eq!(hosts[0].ports[0].row.evidence, expected, "{a} + {b}");
        }
    }
}

#[test]
fn long_banners_are_cut_on_a_character_boundary() {
    let conn = db();
    let mut p = port("10.0.0.1", 6, 21, "syn_ack");
    p.banner = Some(format!("{}{}", "a".repeat(255), "é"));
    insert(&conn, StoreRecord::OpenPort(p));
    let hosts = all(&conn, &PortFilter::default(), 10);
    assert_eq!(
        hosts[0].ports[0].row.banner.as_deref().map(str::len),
        Some(255)
    );
}

/// The condition before P4.2 (`?n IS NULL OR`, joined `hosts h`): the reference of
/// [`active_filters_match_the_former_condition`].
const FORMER_CONDITION: &str = "(?1 IS NULL OR h.category IN (SELECT value FROM json_each(?1))) \
     AND (?2 IS NULL OR o.port = ?2) \
     AND (?3 IS NULL OR o.service = ?3 OR o.detected = ?3) \
     AND (?4 IS NULL OR instr(o.ip, ?4) > 0 OR instr(lower(coalesce(h.names, '')), ?4) > 0 \
          OR instr(coalesce(o.service, ''), ?4) > 0 OR instr(coalesce(o.detected, ''), ?4) > 0 \
          OR CAST(o.port AS TEXT) = ?4)";

/// 30 hosts (a third unknown to `hosts`), up to 6 ports each, services on some.
fn thirty_hosts(conn: &Connection) {
    let services = [None, Some("http"), Some("ssh"), Some("domain")];
    for i in 0..30_u16 {
        let ip = format!("10.0.{}.{}", i % 4, i + 1);
        if i % 3 != 2 {
            let names = if i % 2 == 0 {
                vec![format!("Box{i}.lan")]
            } else {
                Vec::new()
            };
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let category = if i % 5 == 0 { "public" } else { "private" };
            insert(conn, StoreRecord::Host(host(&ip, category, None, &names)));
        }
        for k in 0..(i % 6) {
            let number = [22, 53, 80, 443, 8080, 3389][usize::from(k)];
            let mut p = port(&ip, if number == 53 { 17 } else { 6 }, number, "syn_ack");
            p.service = services[usize::from((i + k) % 4)].map(str::to_owned);
            p.detected = services[usize::from((i * k) % 4)].map(str::to_owned);
            insert(conn, StoreRecord::OpenPort(p));
        }
    }
}

#[test]
fn active_filters_match_the_former_condition() {
    let conn = db();
    thirty_hosts(&conn);
    let categories = [
        None,
        Some(vec!["public".to_owned()]),
        Some(vec!["private".to_owned(), "public".to_owned()]),
        Some(Vec::new()),
    ];
    let ports = [None, Some(80_u16), Some(53)];
    let services_q = [None, Some("ssh"), Some(" HTTP ")];
    let texts = [None, Some("box1"), Some("10.0.2"), Some("443"), Some("dom")];
    let mut checked = 0;
    // At read time, then from `open_port_hosts` once the step `ports` ran (P4.8).
    for step in [false, true] {
        if step {
            finalize(&conn).unwrap();
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('finalizers', 'ports:1')",
                [],
            )
            .unwrap();
            let hosts: i64 = conn
                .query_row("SELECT count(*) FROM open_port_hosts", [], |r| r.get(0))
                .unwrap();
            assert_eq!(hosts, 25);
        }
        for cats in &categories {
            for port_q in ports {
                for service in services_q {
                    for text in texts {
                        let filter = PortFilter {
                            categories: cats.clone(),
                            port: port_q,
                            service: service.map(str::to_owned),
                            text: text.map(str::to_owned),
                        };
                        let norm = |v: Option<&str>| {
                            v.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty())
                        };
                        let p = (
                            cats.as_ref().map(|c| serde_json::to_string(c).unwrap()),
                            port_q,
                            norm(service),
                            norm(text),
                        );
                        let former = |sql: &str| -> Vec<(String, i64)> {
                            conn.prepare(sql)
                                .unwrap()
                                .query_map(params![p.0, p.1, p.2, p.3], |r| {
                                    Ok((r.get(0)?, r.get(1)?))
                                })
                                .unwrap()
                                .map(Result::unwrap)
                                .collect()
                        };
                        // Hosts and their number of matching ports.
                        let want = former(&format!(
                            "SELECT o.ip, count(*) FROM open_ports o LEFT JOIN hosts h ON h.ip = o.ip \
                         WHERE {FORMER_CONDITION} GROUP BY o.ip ORDER BY count(*) DESC, o.ip DESC"
                        ));
                        let got: Vec<(String, i64)> = all(&conn, &filter, 4)
                            .iter()
                            .map(|h| (h.ip.to_string(), i64::try_from(h.ports.len()).unwrap()))
                            .collect();
                        assert_eq!(got, want, "{filter:?}");
                        assert_eq!(
                            count_hosts(&conn, &filter).unwrap(),
                            u64::try_from(want.len()).unwrap()
                        );
                        // Port ranking.
                        let want_stats = former(&format!(
                            "SELECT CAST(o.transport * 65536 + o.port AS TEXT), count(*) AS hosts \
                         FROM open_ports o \
                         LEFT JOIN hosts h ON h.ip = o.ip WHERE {FORMER_CONDITION} \
                         GROUP BY o.transport, o.port ORDER BY hosts DESC, o.port, o.transport"
                        ));
                        let (top, distinct, total) = port_stats(&conn, &filter, 100).unwrap();
                        let got_stats: Vec<(String, i64)> = top
                            .iter()
                            .map(|s| {
                                (
                                    (i64::from(s.transport) * 65_536 + i64::from(s.port))
                                        .to_string(),
                                    i64::try_from(s.hosts).unwrap(),
                                )
                            })
                            .collect();
                        assert_eq!(got_stats, want_stats, "{filter:?}");
                        assert_eq!(distinct, u64::try_from(want_stats.len()).unwrap());
                        let ports_total: i64 = want_stats.iter().map(|(_, n)| n).sum();
                        assert_eq!(total, u64::try_from(ports_total).unwrap());
                        checked += usize::from(!want.is_empty());
                    }
                }
            }
        }
    }
    assert!(checked > 40, "too few non-empty cases: {checked}");
}

#[test]
fn the_per_host_table_is_read_in_key_order() {
    let conn = db();
    let plan = |sql: &str| -> String {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        stmt.query_map(["[\"public\"]"], |r| r.get::<_, String>(3))
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
            .join("\n")
    };
    // Page (first and next): the rank index backwards, category covered, stops at the page size.
    for cursor in ["", " AND (g.ports, g.ip) < (3, '10.0.0.1')"] {
        let p = plan(&format!(
            "SELECT g.ip, g.ports, g.ip FROM open_port_hosts g INDEXED BY open_port_hosts_rank \
             WHERE (g.category IN (SELECT value FROM json_each(?1))){cursor} \
             ORDER BY g.ports DESC, g.ip DESC LIMIT 51"
        ));
        assert!(
            p.contains("USING COVERING INDEX open_port_hosts_rank"),
            "{p}"
        );
        assert!(!p.contains("TEMP B-TREE"), "{p}");
    }
    // Count: the category index.
    let p = plan(
        "SELECT count(*) FROM open_port_hosts g WHERE g.category IN (SELECT value FROM json_each(?1))",
    );
    assert!(
        p.contains("SEARCH g USING COVERING INDEX open_port_hosts_category (category=?)"),
        "{p}"
    );
    assert!(!p.contains("TEMP B-TREE"), "{p}");
}
