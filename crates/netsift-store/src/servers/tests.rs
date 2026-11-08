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
    let (entries, truncated) = evidence(&conn, None).unwrap();
    assert!(!truncated);
    insta::assert_snapshot!(render(&entries));

    let (dhcp, _) = evidence(&conn, Some("dhcp")).unwrap();
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
        let (entries, _) = evidence(conn, None).unwrap();
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
