use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::migrate::migrate;
use crate::schema::SESSION_SCHEMA;

fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

fn dhcp(ts: i64, op: u8, msg_type: &str, src: Ipv4Addr, xid: u32) -> DhcpRow {
    DhcpRow {
        ts,
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(Ipv4Addr::BROADCAST),
        op,
        msg_type: Some(msg_type.to_owned()),
        xid,
        client_mac: Some([2, 0, 0, 0, 0, 0x30]),
        ciaddr: None,
        yiaddr: None,
        siaddr: None,
        giaddr: None,
        server_id: None,
        requested_ip: None,
        subnet_mask: None,
        routers: Vec::new(),
        dns_servers: Vec::new(),
        lease_s: None,
        hostname: None,
    }
}

/// DORA of `laptop-30` with 192.168.1.1, plus an OFFER relayed by 10.9.9.9 for 192.168.1.1.
fn dhcp_rows() -> Vec<ServerRow> {
    let server = v4(192, 168, 1, 1);
    let lease = v4(192, 168, 1, 30);
    let mut discover = dhcp(10, 1, "discover", Ipv4Addr::UNSPECIFIED, 7);
    discover.hostname = Some("laptop-30".to_owned());
    let mut offer = dhcp(20, 2, "offer", server, 7);
    offer.yiaddr = Some(lease);
    offer.server_id = Some(server);
    offer.routers = vec![server];
    let mut request = dhcp(30, 1, "request", Ipv4Addr::UNSPECIFIED, 7);
    request.requested_ip = Some(lease);
    request.hostname = Some("laptop-30".to_owned());
    let mut ack = dhcp(40, 2, "ack", server, 7);
    ack.yiaddr = Some(lease);
    ack.server_id = Some(server);
    ack.lease_s = Some(3600);
    let mut relayed = dhcp(50, 2, "offer", v4(10, 9, 9, 9), 8);
    relayed.yiaddr = Some(v4(192, 168, 1, 31));
    relayed.server_id = Some(server);
    [discover, offer, request, ack, relayed]
        .into_iter()
        .map(|d| ServerRow::Dhcp(Box::new(d)))
        .collect()
}

fn ntp(ts: i64, client: u8, stratum: u8, reference: &str) -> ServerRow {
    ServerRow::Ntp(NtpRow {
        ts,
        server_ip: IpAddr::V4(v4(203, 0, 113, 123)),
        client_ip: IpAddr::V4(v4(192, 168, 1, client)),
        version: 4,
        stratum,
        reference: reference.to_owned(),
    })
}

fn krb(ts: i64, kind: &str, realm: Option<&str>, code: Option<i32>) -> ServerRow {
    ServerRow::Kerberos(KerberosRow {
        ts,
        server_ip: IpAddr::V4(v4(192, 168, 1, 5)),
        client_ip: IpAddr::V4(v4(192, 168, 1, 30)),
        kind: kind.to_owned(),
        realm: realm.map(str::to_owned),
        error_code: code,
    })
}

fn server_rows() -> Vec<ServerRow> {
    let mut rows = dhcp_rows();
    rows.extend([
        ntp(100, 30, 2, "192.0.2.1"),
        ntp(200, 30, 3, "192.0.2.2"),
        ntp(150, 31, 2, "192.0.2.1"),
        krb(300, "error", Some("CORP.EXAMPLE"), Some(25)),
        krb(310, "as_rep", Some("CORP.EXAMPLE"), None),
        krb(320, "tgs_rep", None, None),
        krb(330, "tgs_rep", Some("CORP.EXAMPLE"), None),
    ]);
    rows
}

/// Rows of the other analyzers the roles are derived from (written as their writers would).
const OTHERS: &str = "
    INSERT INTO hosts (ip, names, first_ts, last_ts) VALUES
        ('192.168.1.1', '[\"router.lan\"]', 0, 1000),
        ('192.168.1.5', '[\"dc.corp.example\"]', 0, 1000),
        ('192.168.1.30', '[]', 0, 1000),
        ('203.0.113.123', '[]', 0, 1000);
    INSERT INTO dns_messages (ts, transport, proto, client_ip, client_port, server_ip,
        server_port, responder_ip, txid, opcode, qname, qtype, latency_ns, answers,
        has_query, has_response) VALUES
        (400, 17, 'dns', '192.168.1.30', 5000, '192.168.1.1', 53, NULL, 1, 'QUERY',
         '_ldap._tcp.dc._msdcs.corp.example', 'SRV', 5,
         '[{\"n\":\"_ldap._tcp.dc._msdcs.corp.example\",\"t\":\"SRV\",\"v\":\"0 100 389 DC.corp.example\",\"ttl\":600}]',
         1, 1),
        (410, 17, 'dns', '192.168.1.31', 5001, '192.168.1.1', 53, NULL, 2, 'QUERY',
         '_kerberos._udp.corp.example', 'SRV', 5,
         '[{\"n\":\"_kerberos._udp.corp.example\",\"t\":\"SRV\",\"v\":\"0 100 88 dc.corp.example\",\"ttl\":600}]',
         1, 1),
        (420, 17, 'dns', '192.168.1.30', 5002, '192.168.1.1', 53, NULL, 3, 'QUERY',
         'unanswered.example', 'A', NULL, '[]', 1, 0),
        (430, 17, 'mdns', '192.168.1.30', 5353, '224.0.0.251', 5353, '192.168.1.40', 0,
         'QUERY', 'printer.local', 'A', 9, '[]', 1, 1);
    INSERT INTO open_ports (ip, transport, port, evidence, first_ts, last_ts) VALUES
        ('192.168.1.5', 6, 389, 'syn_ack', 500, 510),
        ('192.168.1.5', 6, 22, 'syn_ack', 500, 510);
    INSERT INTO flows (id, transport, src_ip, src_port, dst_ip, dst_port, first_ts, last_ts)
        VALUES (1, 6, '192.168.1.30', 40000, '192.168.1.5', 389, 500, 510),
               (2, 6, '192.168.1.31', 40001, '192.168.1.5', 389, 505, 515);
    INSERT INTO smb_sessions (flow_id, client_ip, server_ip, first_ts, last_ts, dialect) VALUES
        (3, '192.168.1.30', '192.168.1.20', 600, 650, 'SMB 2.1'),
        (4, '192.168.1.31', '192.168.1.20', 700, 750, 'SMB 3.1.1');
    INSERT INTO smb_announces (src_ip, server_name, dst_name, server_type, announce_count,
        first_ts, last_ts) VALUES
        ('192.168.1.5', 'DC', 'CORP<1B>', 4107, 3, 800, 900),
        ('192.168.1.20', 'FILES', 'CORP<1D>', 3, 2, 800, 900),
        ('192.168.1.40', 'WS', 'CORP<1D>', 1, 2, 800, 900);
    INSERT INTO http_transactions (flow_id, seq, client_ip, client_port, server_ip, server_port,
        ts, end_ts, method_group, status_key, status_class, resp_ts) VALUES
        (5, 0, '192.168.1.30', 40002, '203.0.113.80', 80, 950, 960, 'GET', 200, '2xx', 955),
        (5, 1, '192.168.1.30', 40002, '203.0.113.80', 80, 970, 980, 'GET', -1, 'none', NULL);
";

fn insert(conn: &Connection, rows: &[ServerRow]) {
    for row in rows {
        row.insert(conn).unwrap();
    }
}

/// Every piece of evidence of up to 1000 servers per role.
fn all(conn: &Connection, role: Option<&str>) -> Vec<EvidenceEntry> {
    let q = EvidenceQuery {
        role,
        categories: None,
        limit: 1000,
    };
    evidence(conn, &q).unwrap().entries
}

fn rows(conn: &Connection, sql: &str) -> Vec<String> {
    conn.prepare(sql)
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn render(entries: &[EvidenceEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        writeln!(
            out,
            "{} {} {} count={} clients={:?} {}..{} example={:?} names={:?}",
            e.role,
            e.ip,
            e.kind,
            e.count,
            e.clients,
            e.first_ts,
            e.last_ts,
            e.example,
            e.host.names
        )
        .unwrap();
    }
    out
}

#[test]
fn evidence_of_every_role() {
    let conn = db();
    conn.execute_batch(OTHERS).unwrap();
    insert(&conn, &server_rows());
    let entries = all(&conn, None);
    insta::assert_snapshot!(render(&entries));

    let dhcp = all(&conn, Some("dhcp"));
    assert!(dhcp.iter().all(|e| e.role == "dhcp"));
    // The relayed OFFER is credited to the server it names (option 54), not to the relay.
    assert!(dhcp.iter().all(|e| e.ip == IpAddr::V4(v4(192, 168, 1, 1))));
    let offer = dhcp.iter().find(|e| e.kind == "dhcp_offer").unwrap();
    assert_eq!(
        (offer.count, offer.example.as_deref()),
        (2, Some("192.168.1.31"))
    );

    let roles: i64 = conn
        .query_row("SELECT count(*) FROM server_roles", [], |r| r.get(0))
        .unwrap();
    assert_eq!(roles, 8);
    // The light view of the Overview counter agrees with the evidence view.
    assert_eq!(
        rows(
            &conn,
            "SELECT role || ' ' || ip FROM server_roles ORDER BY 1"
        ),
        rows(
            &conn,
            "SELECT DISTINCT role || ' ' || ip FROM server_evidence ORDER BY 1"
        )
    );
}

#[test]
fn many_servers_of_one_role_never_hide_another_role() {
    let conn = db();
    // An HTTP scan: 21 000 distinct responders (more than any global cut), and one DHCP server.
    conn.execute_batch(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 21000)
         INSERT INTO http_transactions (flow_id, seq, client_ip, client_port, server_ip,
             server_port, ts, end_ts, method_group, status_key, status_class, resp_ts)
         SELECT i, 0, '10.0.0.1', 40000, '172.16.' || (i / 256) || '.' || (i % 256), 80,
                i, i, 'GET', 200, '2xx', i FROM n;",
    )
    .unwrap();
    let mut ack = dhcp(5, 2, "ack", v4(192, 168, 1, 1), 1);
    ack.yiaddr = Some(v4(192, 168, 1, 30));
    ServerRow::Dhcp(Box::new(ack)).insert(&conn).unwrap();
    let q = EvidenceQuery {
        role: None,
        categories: None,
        limit: 50,
    };
    let got = evidence(&conn, &q).unwrap();
    assert_eq!(
        got.totals,
        vec![("dhcp".to_owned(), 1), ("http".to_owned(), 21_000)]
    );
    assert_eq!(got.entries.iter().filter(|e| e.role == "http").count(), 50);
    assert!(got.entries.iter().any(|e| e.role == "dhcp"));
}

#[test]
fn the_category_filter_applies_before_the_limit() {
    let conn = db();
    conn.execute_batch(
        "INSERT INTO hosts (ip, category, first_ts, last_ts) VALUES
             ('198.51.100.1', 'public', 0, 1), ('198.51.100.2', 'public', 0, 1),
             ('192.168.1.80', 'private', 0, 1);
         INSERT INTO http_transactions (flow_id, seq, client_ip, client_port, server_ip,
             server_port, ts, end_ts, method_group, status_key, status_class, resp_ts) VALUES
             (1, 0, '10.0.0.1', 1, '198.51.100.1', 80, 1, 1, 'GET', 200, '2xx', 1),
             (1, 1, '10.0.0.1', 1, '198.51.100.1', 80, 2, 2, 'GET', 200, '2xx', 2),
             (2, 0, '10.0.0.1', 1, '198.51.100.2', 80, 3, 3, 'GET', 200, '2xx', 3),
             (2, 1, '10.0.0.1', 1, '198.51.100.2', 80, 4, 4, 'GET', 200, '2xx', 4),
             (3, 0, '10.0.0.1', 1, '192.168.1.80', 80, 5, 5, 'GET', 200, '2xx', 5),
             (4, 0, '10.0.0.1', 1, '203.0.113.9', 80, 6, 6, 'GET', 200, '2xx', 6);",
    )
    .unwrap();
    let private = ["private".to_owned()];
    let q = EvidenceQuery {
        role: Some("http"),
        categories: Some(&private),
        limit: 1,
    };
    let got = evidence(&conn, &q).unwrap();
    // The weakest server is the only private one; 203.0.113.9 has no host row: kept for the
    // caller, which decides from the address.
    assert_eq!(got.totals, vec![("http".to_owned(), 2)]);
    assert_eq!(got.entries.len(), 1);
    let ips: Vec<String> = all(&conn, Some("http"))
        .iter()
        .map(|e| e.ip.to_string())
        .collect();
    assert_eq!(
        ips,
        [
            "198.51.100.1",
            "198.51.100.2",
            "192.168.1.80",
            "203.0.113.9"
        ]
    );
    assert!(
        ["192.168.1.80", "203.0.113.9"].contains(&got.entries[0].ip.to_string().as_str()),
        "{:?}",
        got.entries
    );
}

#[test]
fn a_relayed_reply_seen_on_both_legs_counts_once() {
    let conn = db();
    let server = v4(10, 0, 0, 1);
    let relay = v4(192, 168, 5, 1);
    // Server -> relay, then relay -> client (sent from giaddr), same transaction.
    let mut to_relay = dhcp(10, 2, "offer", server, 77);
    to_relay.giaddr = Some(relay);
    to_relay.server_id = Some(server);
    let mut to_client = to_relay.clone();
    to_client.ts = 11;
    to_client.src_ip = IpAddr::V4(relay);
    // Only the relay leg of another transaction: still counted.
    let mut alone = to_client.clone();
    alone.xid = 78;
    for d in [to_relay, to_client, alone] {
        ServerRow::Dhcp(Box::new(d)).insert(&conn).unwrap();
    }
    let dhcp = all(&conn, Some("dhcp"));
    assert_eq!(dhcp.len(), 1);
    assert_eq!(
        (dhcp[0].ip.to_string().as_str(), dhcp[0].count),
        ("10.0.0.1", 2)
    );
}

#[test]
fn upserts_do_not_depend_on_arrival_order() {
    let a = db();
    let b = db();
    let rows = server_rows();
    insert(&a, &rows);
    let mut reversed = rows;
    reversed.reverse();
    insert(&b, &reversed);
    let dump = |conn: &Connection| {
        let entries = all(conn, None);
        let ntp: String = conn
            .query_row(
                "SELECT group_concat(server_ip || client_ip || responses || version || stratum \
                 || reference || first_ts || last_ts, ';') FROM ntp_responses",
                [],
                |r| r.get(0),
            )
            .unwrap();
        format!("{}{ntp}", render(&entries))
    };
    assert_eq!(dump(&a), dump(&b));
}

#[test]
fn ties_are_broken_deterministically() {
    for order in [[0, 1], [1, 0]] {
        let conn = db();
        let rows = [ntp(5, 30, 2, "A"), ntp(5, 30, 2, "B")];
        for i in order {
            rows[i].insert(&conn).unwrap();
        }
        let reference: String = conn
            .query_row("SELECT reference FROM ntp_responses", [], |r| r.get(0))
            .unwrap();
        assert_eq!(reference, "B");
    }
}

#[test]
fn finalize_names_leased_hosts_only() {
    let conn = db();
    conn.execute_batch(OTHERS).unwrap();
    insert(&conn, &server_rows());
    // An ACK naming the host itself, for an address never seen in the traffic.
    let mut ghost = dhcp(60, 2, "ack", v4(192, 168, 1, 1), 9);
    ghost.yiaddr = Some(v4(192, 168, 1, 99));
    ghost.hostname = Some("ghost".to_owned());
    ServerRow::Dhcp(Box::new(ghost)).insert(&conn).unwrap();
    finalize(&conn).unwrap();
    finalize(&conn).unwrap();
    let names = |ip: &str| -> String {
        conn.query_row("SELECT names FROM hosts WHERE ip = ?1", [ip], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(names("192.168.1.30"), r#"["laptop-30"]"#);
    assert_eq!(names("192.168.1.1"), r#"["router.lan"]"#);
    let ghost: i64 = conn
        .query_row(
            "SELECT count(*) FROM hosts WHERE ip = '192.168.1.99'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ghost, 0);
}

#[test]
fn an_upgraded_session_is_not_analyzed() {
    let conn = db();
    assert!(analyzed(&conn).unwrap());
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, 'dhcp_messages,server_evidence,server_roles')",
        [crate::session::TABLES_ADDED_AFTER_IMPORT],
    )
    .unwrap();
    assert!(!analyzed(&conn).unwrap());
    assert_eq!(
        crate::traffic::count_rows(&conn, "server_roles").unwrap(),
        None
    );
    conn.execute_batch("DROP VIEW server_roles; DROP VIEW server_evidence")
        .unwrap();
    assert!(!analyzed(&conn).unwrap());
}
