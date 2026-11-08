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
fn merges_are_commutative_and_keep_the_smallest_values() {
    let conn = db();
    fixture(&conn);
    let hosts = all(&conn, &PortFilter::default(), 100);
    let lan = hosts
        .iter()
        .find(|h| h.ip.to_string() == "192.168.1.50")
        .unwrap();
    let web = &lan.ports.iter().find(|p| p.row.port == 80).unwrap().row;
    assert_eq!(web.evidence, "server_data");
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
