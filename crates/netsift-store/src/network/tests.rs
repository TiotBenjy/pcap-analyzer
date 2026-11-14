use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use rusqlite::Connection;
use rusqlite::types::Value;

use super::*;
use crate::connections::tests::{conv, db, host};
use crate::records::StoreRecord;
use crate::{HostTrafficRow, OpenPortRow};

#[allow(clippy::needless_pass_by_value)] // Called with record literals.
fn insert(conn: &Connection, record: StoreRecord) {
    record.insert(conn).unwrap();
}

const COUNTRIES: [&str; 20] = [
    "US", "FR", "DE", "GB", "NL", "JP", "CA", "BR", "IT", "ES", "SE", "PL", "BE", "CH", "AT", "NO",
    "DK", "FI", "IE", "PT",
];

/// Spec fixture: 200 public hosts (20 countries, the last 10 hosts without country) talking to
/// one LAN server over TLS, with distinct volumes; host `i` sends `i * 100` bytes.
fn two_hundred(conn: &Connection) {
    insert(
        conn,
        StoreRecord::Host(host("192.168.1.1", "private", None, &["server.lan"])),
    );
    for i in 1..=200_u32 {
        let ip = format!("{}.{}.{}.1", 20 + i / 250, i / 10, i % 250);
        let country = if i > 190 {
            None
        } else {
            Some(COUNTRIES[(i % 20) as usize])
        };
        insert(conn, StoreRecord::Host(host(&ip, "public", country, &[])));
        insert(
            conn,
            StoreRecord::Conversation(conv(
                "192.168.1.1",
                &ip,
                10,
                u64::from(i) * 100,
                &["tcp", "tls"],
            )),
        );
    }
}

/// Runs the end-of-import step that fills the tables read by the graph.
fn finalized(conn: &Connection) {
    finalize(conn).unwrap();
}

fn hosts_mode(limit: u32) -> GraphMode {
    GraphMode::Hosts {
        limit,
        expand: None,
        include_orphans: false,
    }
}

fn ids(g: &Graph) -> Vec<String> {
    g.nodes.iter().map(|n| n.key.id()).collect()
}

#[test]
fn two_hundred_public_hosts_are_bounded_and_clustered() {
    let conn = db();
    two_hundred(&conn);
    finalized(&conn);
    let g = graph(&conn, &GraphFilter::default(), &hosts_mode(40)).unwrap();
    assert_eq!(g.hosts, 201);
    assert_eq!(g.hosts_shown, 40);
    // 40 hosts, 15 clusters (largest countries), one other node.
    assert!(g.nodes.len() <= 60, "{}", g.nodes.len());
    assert_eq!(g.nodes.len(), 40 + MAX_CLUSTERS + 1);
    let hosts = g
        .nodes
        .iter()
        .filter(|n| matches!(n.key, NodeKey::Host(_)))
        .count();
    assert_eq!(hosts, 40);
    assert_eq!(g.nodes.last().unwrap().key, NodeKey::Other);
    // Every host is in exactly one node.
    assert_eq!(g.nodes.iter().map(|n| n.hosts).sum::<u64>(), 201);
    // The server first (in every conversation), then the biggest public host (clusters may
    // weigh more than single hosts).
    assert_eq!(g.nodes[0].key.id(), "h:192.168.1.1");
    assert_eq!(g.nodes[0].info.as_ref().unwrap().names, ["server.lan"]);
    assert_eq!(g.nodes[0].protocols, ["tcp", "tls"]);
    let second = g
        .nodes
        .iter()
        .skip(1)
        .find(|n| matches!(n.key, NodeKey::Host(_)))
        .unwrap();
    assert_eq!(second.key.id(), "h:20.20.200.1");
    // Sorted by bytes (other last).
    let named = &g.nodes[..g.nodes.len() - 1];
    assert!(named.windows(2).all(|w| w[0].bytes() >= w[1].bytes()));
    // Traffic is preserved: every edge touches the server, nothing is lost by folding.
    let total: u64 = (1..=200_u64).map(|i| i * 100 + 10).sum();
    assert_eq!(g.total_bytes, total);
    assert_eq!(g.edges.iter().map(GraphEdge::bytes).sum::<u64>(), total);
    assert_eq!(g.edges.len(), g.nodes.len() - 1);
    assert_eq!(g.edges_total, g.edges.len() as u64);
    for e in &g.edges {
        assert!(e.source < e.target, "{e:?}");
        assert!(e.source == "h:192.168.1.1" || e.target == "h:192.168.1.1");
    }
    // A cluster edge: bytes oriented from the smaller id.
    let cluster = g
        .edges
        .iter()
        .find(|e| e.source.starts_with("h:192"))
        .unwrap();
    assert!(cluster.bytes_fwd < cluster.bytes_rev, "{cluster:?}");
    // Clusters are countries of public hosts outside the top 40.
    let k: Vec<&NodeKey> = g
        .nodes
        .iter()
        .map(|n| &n.key)
        .filter(|k| matches!(k, NodeKey::Cluster(_)))
        .collect();
    assert_eq!(k.len(), MAX_CLUSTERS);

    // The node limit is clamped.
    let g = graph(&conn, &GraphFilter::default(), &hosts_mode(1)).unwrap();
    assert_eq!(g.hosts_shown, u64::from(MIN_NODES));
    let g = graph(&conn, &GraphFilter::default(), &hosts_mode(10_000)).unwrap();
    assert_eq!(g.hosts_shown, u64::from(MAX_NODES));
    assert!(g.nodes.len() <= MAX_NODES as usize + MAX_CLUSTERS + 1);
}

#[test]
fn expanding_a_cluster_draws_its_hosts() {
    let conn = db();
    two_hundred(&conn);
    let mode = GraphMode::Hosts {
        limit: 10,
        expand: Some("US".to_owned()),
        include_orphans: false,
    };
    finalized(&conn);
    let g = graph(&conn, &GraphFilter::default(), &mode).unwrap();
    // US: hosts 20, 40, ..., 180 (9 of them, 180 and 200 being in the top 10 or without country).
    let us: Vec<&GraphNode> = g
        .nodes
        .iter()
        .filter(|n| n.info.as_ref().and_then(|i| i.country.as_deref()) == Some("US"))
        .collect();
    assert_eq!(us.len(), 9);
    assert!(!ids(&g).contains(&"k:US".to_owned()));
    assert_eq!(g.nodes.iter().map(|n| n.hosts).sum::<u64>(), 201);
}

#[test]
fn protocol_category_and_ipv6_filters() {
    let conn = db();
    for (ip, category) in [
        ("10.0.0.1", "private"),
        ("10.0.0.2", "private"),
        ("10.0.0.3", "private"),
        ("224.0.0.251", "multicast"),
        ("fe80::1", "link_local"),
    ] {
        insert(&conn, StoreRecord::Host(host(ip, category, None, &[])));
    }
    for r in [
        conv("10.0.0.1", "10.0.0.2", 100, 100, &["tcp", "tls"]),
        conv("10.0.0.1", "10.0.0.3", 50, 50, &["http", "tcp"]),
        conv("10.0.0.3", "224.0.0.251", 20, 0, &["udp", "ssdp"]),
        conv("fe80::1", "10.0.0.2", 5, 0, &["icmp"]),
    ] {
        insert(&conn, StoreRecord::Conversation(r));
    }
    finalized(&conn);
    let run = |filter: GraphFilter| graph(&conn, &filter, &hosts_mode(40)).unwrap();
    let https = run(GraphFilter {
        protocols: Some(vec![ProtocolGroup::Https]),
        ..GraphFilter::default()
    });
    assert_eq!(ids(&https), ["h:10.0.0.1", "h:10.0.0.2"]);
    assert_eq!(https.orphans, 3, "the hosts left aside are orphans");
    assert_eq!(https.total_bytes, 200);

    // "Other": labels outside the groups (ssdp, icmp).
    let other = run(GraphFilter {
        protocols: Some(vec![ProtocolGroup::Other]),
        ..GraphFilter::default()
    });
    assert_eq!(other.edges.len(), 2);
    // No protocol selected: empty graph.
    let none = run(GraphFilter {
        protocols: Some(Vec::new()),
        ..GraphFilter::default()
    });
    assert_eq!(none.nodes.len(), 0);
    assert_eq!(none.orphans, 5);

    // Both ends must be in the categories.
    let lan = run(GraphFilter {
        categories: Some(vec!["private".to_owned()]),
        ..GraphFilter::default()
    });
    assert_eq!(lan.hosts, 3);
    assert_eq!(lan.orphans, 0, "orphans are counted within the categories");
    let no_v6 = run(GraphFilter {
        ipv6: false,
        ..GraphFilter::default()
    });
    assert!(!ids(&no_v6).contains(&"h:fe80::1".to_owned()));
    assert_eq!(no_v6.hosts, 4);
    assert_eq!(no_v6.orphans, 0);
}

#[test]
fn orphans_are_counted_and_listed_on_demand() {
    let conn = db();
    two_hundred(&conn);
    for i in 1..=40_u64 {
        let ip = format!("10.9.0.{i}");
        insert(&conn, StoreRecord::Host(host(&ip, "private", None, &[])));
        insert(
            &conn,
            StoreRecord::HostTraffic(HostTrafficRow {
                ip: ip.parse().unwrap(),
                bytes_sent: i,
                bytes_received: 0,
                packets_sent: 1,
                packets_received: 0,
            }),
        );
    }
    finalized(&conn);
    let g = graph(&conn, &GraphFilter::default(), &hosts_mode(40)).unwrap();
    assert_eq!(g.orphans, 40);
    assert_eq!(g.hosts_shown, 40);
    let mode = GraphMode::Hosts {
        limit: 40,
        expand: None,
        include_orphans: true,
    };
    let g = graph(&conn, &GraphFilter::default(), &mode).unwrap();
    assert_eq!(g.hosts_shown, 40 + u64::from(MAX_ORPHANS));
    // Most traffic first, without bytes in the graph.
    let orphan = g
        .nodes
        .iter()
        .find(|n| n.key.id() == "h:10.9.0.40")
        .unwrap();
    assert_eq!(orphan.bytes(), 0);
    assert_eq!(orphan.hosts, 1);
    assert!(!ids(&g).contains(&"h:10.9.0.1".to_owned()));
}

#[test]
fn country_mode_groups_hosts_by_country() {
    let conn = db();
    two_hundred(&conn);
    finalized(&conn);
    let g = graph(
        &conn,
        &GraphFilter::default(),
        &GraphMode::Countries { limit: 40 },
    )
    .unwrap();
    // 20 countries, the LAN server, the 10 hosts without country.
    assert_eq!(g.nodes.len(), 22);
    assert_eq!(g.hosts, 201);
    let local = g.nodes.iter().find(|n| n.key == NodeKey::Local).unwrap();
    assert_eq!(local.hosts, 1);
    let unknown = g.nodes.iter().find(|n| n.key == NodeKey::Unknown).unwrap();
    assert_eq!(unknown.hosts, 10);
    let us = g
        .nodes
        .iter()
        .find(|n| n.key == NodeKey::Country("US".to_owned()))
        .unwrap();
    // 20, 40, ..., 180 (200 has no country).
    assert_eq!(us.hosts, 9);
    assert_eq!(g.nodes[0].key, NodeKey::Local);
    assert_eq!(g.edges.len(), 21);
    assert!(
        g.edges
            .iter()
            .all(|e| e.target == "local" || e.source == "local")
    );

    // Ten countries at most (the limit is clamped to 10): the rest is "other".
    let g = graph(
        &conn,
        &GraphFilter::default(),
        &GraphMode::Countries { limit: 3 },
    )
    .unwrap();
    assert_eq!(g.nodes.len(), 11);
    assert_eq!(g.nodes.last().unwrap().key, NodeKey::Other);
    assert_eq!(g.nodes.iter().map(|n| n.hosts).sum::<u64>(), 201);
    let total: u64 = (1..=200_u64).map(|i| i * 100 + 10).sum();
    assert_eq!(g.edges.iter().map(GraphEdge::bytes).sum::<u64>(), total);
}

#[test]
fn edges_are_capped() {
    let conn = db();
    // 60 hosts, each talking to the 10 next ones: 600 pairs.
    for i in 0..60_u32 {
        for d in 1..=10_u32 {
            let a = format!("10.0.0.{i}");
            let b = format!("10.0.1.{}", (i + d) % 60);
            insert(
                &conn,
                StoreRecord::Conversation(conv(&a, &b, u64::from(i * 10 + d), 0, &["udp"])),
            );
        }
    }
    finalized(&conn);
    let g = graph(&conn, &GraphFilter::default(), &hosts_mode(150)).unwrap();
    assert_eq!(g.edges_total, 600);
    assert_eq!(g.edges.len(), MAX_EDGES);
    assert!(g.edges.windows(2).all(|w| w[0].bytes() >= w[1].bytes()));
}

#[test]
fn protocol_counts_cover_every_group() {
    let conn = db();
    for r in [
        conv("10.0.0.1", "10.0.0.2", 1, 1, &["tcp", "tls"]),
        conv("10.0.0.1", "10.0.0.3", 1, 1, &["smb", "netbios", "tcp"]),
        conv("10.0.0.1", "10.0.0.4", 1, 1, &["icmp"]),
        conv("10.0.0.1", "10.0.0.5", 1, 1, &["ntp", "udp", "ssdp"]),
    ] {
        insert(&conn, StoreRecord::Conversation(r));
    }
    finalized(&conn);
    let counts: HashMap<&str, u64> = protocol_counts(&conn)
        .unwrap()
        .into_iter()
        .map(|(g, n)| (g.as_str(), n))
        .collect();
    assert_eq!(counts["https"], 1);
    assert_eq!(
        counts["smb"], 1,
        "one conversation, two labels of the group"
    );
    assert_eq!(counts["tcp"], 2);
    assert_eq!(counts["udp"], 1);
    assert_eq!(counts["other"], 2);
    assert_eq!(counts["ssh"], 0);
    assert_eq!(counts.len(), ProtocolGroup::ALL.len());
}

#[test]
fn node_detail_gathers_the_host() {
    let conn = db();
    two_hundred(&conn);
    insert(
        &conn,
        StoreRecord::OpenPort(OpenPortRow {
            ip: "192.168.1.1".parse().unwrap(),
            transport: 6,
            port: 443,
            evidence: "syn_ack".to_owned(),
            service: Some("https".to_owned()),
            detected: None,
            banner: None,
            first_ts: 0,
            last_ts: 0,
        }),
    );
    insert(
        &conn,
        StoreRecord::Conversation(conv("20.0.5.1", "192.168.1.1", 7, 7, &["dns", "udp"])),
    );
    let d = node_detail(&conn, "192.168.1.1".parse().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(d.info.names, ["server.lan"]);
    assert_eq!(d.peers, 200, "both directions of a pair are one peer");
    assert_eq!(d.protocols, ["dns", "tcp", "tls", "udp"]);
    assert_eq!(d.open_ports.len(), 1);
    assert_eq!(d.open_ports[0].service.as_deref(), Some("https"));
    assert_eq!(d.neighbors.len(), MAX_NEIGHBORS as usize);
    assert_eq!(d.neighbors[0].ip.to_string(), "20.20.200.1");
    assert_eq!(d.neighbors[0].bytes_received, 20_000);
    assert_eq!(d.neighbors[0].info.category.as_deref(), Some("public"));
    let five = d.neighbors.iter().find(|n| n.ip.to_string() == "20.0.5.1");
    assert!(five.is_none(), "not among the 10 largest");
    assert!(
        node_detail(&conn, "1.2.3.4".parse().unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn read_queries_use_indexes() {
    let conn = db();
    two_hundred(&conn);
    finalized(&conn);
    let plan = |sql: &str, params: &[&dyn ToSql]| -> String {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params.iter()), |r| {
                r.get::<_, String>(3)
            })
            .unwrap();
        rows.map(Result::unwrap).collect::<Vec<_>>().join("\n")
    };
    let no_filter: [&dyn ToSql; 3] = [&ALL_GROUPS, &None::<String>, &true];

    // Graph: ranked hosts, expandable hosts, expansion rows and orphans by index; the folded
    // tables are read whole (a few thousand rows), `conversations` never.
    let p = plan(&top_sql(), &[]);
    assert!(
        p.contains("network_hosts_keyed") && !p.contains("TEMP B-TREE"),
        "{p}"
    );
    let p = plan(&expandable_sql(), &[&"US", &EXPAND_HOSTS]);
    assert!(
        p.contains("SEARCH network_hosts USING INDEX network_hosts_crank"),
        "{p}"
    );
    let p = plan(
        &expand_rows_sql(),
        &[&ALL_GROUPS, &None::<String>, &true, &"US"],
    );
    assert!(p.contains("network_expand_country"), "{p}");
    let p = plan(ORPHANS_SQL, &[&0, &None::<String>, &true, &30]);
    assert!(
        p.contains("network_hosts_orphans") && !p.contains("TEMP B-TREE"),
        "{p}"
    );
    let p = plan(
        &format!(
            "SELECT a FROM network_edges WHERE {}",
            filter_sql("cat_a", "cat_b")
        ),
        &no_filter,
    );
    assert!(!p.contains("conversations"), "{p}");

    // Detail of a host: indexed lookups of its conversations only.
    let p = plan(&neighbors_sql(), &[&"192.168.1.1", &MAX_NEIGHBORS]);
    assert!(!p.contains("SCAN conversations"), "{p}");
    assert!(p.contains("conversations_dst_ip"), "{p}");
    let p = plan(HOST_LABELS, &[&"192.168.1.1"]);
    assert!(!p.contains("SCAN c "), "{p}");
    assert!(!p.ends_with("SCAN c"), "{p}");
    let p = plan(
        "SELECT port FROM open_ports WHERE ip = ?1 ORDER BY port, transport LIMIT 50",
        &[&"192.168.1.1"],
    );
    assert!(!p.contains("SCAN"), "{p}");
}

#[test]
fn conversation_ends_missing_from_hosts_are_still_hosts() {
    let conn = db();
    insert(
        &conn,
        StoreRecord::Host(host("10.0.0.1", "private", None, &[])),
    );
    insert(
        &conn,
        StoreRecord::Conversation(conv("10.0.0.1", "10.0.0.2", 10, 5, &["udp"])),
    );
    finalized(&conn);
    let g = graph(&conn, &GraphFilter::default(), &hosts_mode(40)).unwrap();
    assert_eq!(ids(&g), ["h:10.0.0.1", "h:10.0.0.2"]);
    assert_eq!(g.hosts, 2);
    assert_eq!(g.orphans, 0);
}

#[test]
fn the_step_is_idempotent_and_order_independent() {
    let a = db();
    two_hundred(&a);
    finalized(&a);
    finalized(&a);
    let b = db();
    let mut rows: Vec<StoreRecord> = Vec::new();
    for i in (1..=200_u32).rev() {
        let ip = format!("20.{}.{}.1", i / 10, i % 250);
        let country = if i > 190 {
            None
        } else {
            Some(COUNTRIES[(i % 20) as usize])
        };
        rows.push(StoreRecord::Conversation(conv(
            "192.168.1.1",
            &ip,
            10,
            u64::from(i) * 100,
            &["tcp", "tls"],
        )));
        rows.push(StoreRecord::Host(host(&ip, "public", country, &[])));
    }
    rows.push(StoreRecord::Host(host(
        "192.168.1.1",
        "private",
        None,
        &["server.lan"],
    )));
    for r in rows {
        insert(&b, r);
    }
    finalized(&b);
    let mode = GraphMode::Hosts {
        limit: 40,
        expand: Some("US".to_owned()),
        include_orphans: true,
    };
    let filter = GraphFilter::default();
    assert_eq!(
        dump(&graph(&a, &filter, &mode).unwrap()),
        dump(&graph(&b, &filter, &mode).unwrap())
    );
}

/// Text form of a graph (snapshots, comparisons).
fn dump(g: &Graph) -> String {
    let mut out = format!(
        "hosts={} shown={} edges={}/{} orphans={} bytes={}\n",
        g.hosts,
        g.hosts_shown,
        g.edges.len(),
        g.edges_total,
        g.orphans,
        g.total_bytes
    );
    for n in &g.nodes {
        writeln!(
            out,
            "node {} hosts={} sent={} received={} packets={} {:?}",
            n.key.id(),
            n.hosts,
            n.bytes_sent,
            n.bytes_received,
            n.packets,
            n.protocols
        )
        .unwrap();
    }
    for e in &g.edges {
        writeln!(
            out,
            "edge {} {} fwd={} rev={} conversations={} flows={} {:?}",
            e.source, e.target, e.bytes_fwd, e.bytes_rev, e.conversations, e.flows, e.protocols
        )
        .unwrap();
    }
    out
}

#[test]
fn graph_snapshot() {
    let conn = db();
    for (ip, category, country) in [
        ("192.168.1.10", "private", None),
        ("192.168.1.1", "private", None),
        ("81.0.0.1", "public", Some("FR")),
        ("5.0.0.1", "public", Some("DE")),
        ("224.0.0.251", "multicast", None),
        ("fe80::1", "link_local", None),
    ] {
        insert(&conn, StoreRecord::Host(host(ip, category, country, &[])));
    }
    for r in [
        conv("192.168.1.10", "81.0.0.1", 5_000, 90_000, &["tcp", "tls"]),
        conv("192.168.1.10", "5.0.0.1", 700, 3_000, &["http", "tcp"]),
        conv("192.168.1.10", "192.168.1.1", 300, 600, &["dns", "udp"]),
        conv("192.168.1.1", "224.0.0.251", 120, 0, &["mdns", "udp"]),
        conv("fe80::1", "192.168.1.10", 64, 64, &["icmp"]),
    ] {
        insert(&conn, StoreRecord::Conversation(r));
    }
    finalized(&conn);
    let mut out = String::new();
    for (name, filter, mode) in [
        ("hosts", GraphFilter::default(), hosts_mode(40)),
        (
            "https",
            GraphFilter {
                protocols: Some(vec![ProtocolGroup::Https]),
                ..GraphFilter::default()
            },
            hosts_mode(40),
        ),
        (
            "countries",
            GraphFilter::default(),
            GraphMode::Countries { limit: 40 },
        ),
    ] {
        writeln!(out, "== {name}").unwrap();
        out.push_str(&dump(&graph(&conn, &filter, &mode).unwrap()));
    }
    insta::assert_snapshot!(out);
}

/// Timing of the step and of the read queries on a large synthetic session (ADR-018):
/// `./x.sh cargo test --release -p netsift-store network::tests::timings -- --ignored --nocapture`
/// (`NETSIFT_BENCH_CONVERSATIONS`, default 500 000).
#[test]
#[ignore = "timing run, several seconds"]
#[allow(clippy::too_many_lines)] // Data generation, then one timing per case.
fn timings() {
    use std::time::Instant;
    let n: u64 = std::env::var("NETSIFT_BENCH_CONVERSATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500_000);
    // On disk, with the pragmas of an import (64 MiB page cache, temporary data in memory).
    let dir = tempfile::tempdir().unwrap();
    let mut conn = Connection::open(dir.path().join("session.db")).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "cache_size", -65_536).unwrap();
    conn.pragma_update(None, "temp_store", "MEMORY").unwrap();
    crate::migrate::migrate(&mut conn, &crate::schema::SESSION_SCHEMA).unwrap();
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let tx = conn.transaction().unwrap();
    {
        let mut host = tx
            .prepare("INSERT OR IGNORE INTO hosts (ip, country, category, first_ts, last_ts) VALUES (?1, ?2, ?3, 0, 0)")
            .unwrap();
        let mut conv = tx
            .prepare(
                "INSERT OR IGNORE INTO conversations (src_ip, dst_ip, first_ts, last_ts, bytes_fwd, \
                 bytes_rev, packets_fwd, packets_rev, flows, protocols) \
                 VALUES (?1, ?2, 0, 0, ?3, ?4, 1, 1, 1, ?5)",
            )
            .unwrap();
        let lan: Vec<String> = (0..500)
            .map(|i| format!("10.0.{}.{}", i / 250, i % 250 + 1))
            .collect();
        for ip in &lan {
            host.execute(rusqlite::params![ip, None::<String>, "private"])
                .unwrap();
        }
        let public = (n * 2 / 5).max(1);
        let protos = [
            r#"["dns","udp"]"#,
            r#"["tcp","tls"]"#,
            r#"["http","tcp"]"#,
            r#"["tcp"]"#,
            r#"["udp"]"#,
            r#"["icmp"]"#,
            r#"["ssh","tcp"]"#,
        ];
        for _ in 0..n {
            let p = next() % public;
            let ip = format!(
                "{}.{}.{}.{}",
                1 + p % 223,
                (p >> 8) % 256,
                (p >> 16) % 256,
                1 + (p >> 24) % 254
            );
            let cc = COUNTRIES[usize::try_from(p % 20).unwrap()];
            host.execute(rusqlite::params![ip, cc, "public"]).unwrap();
            let src = &lan[usize::try_from(next() % 500).unwrap()];
            let proto = protos[usize::try_from(next() % 7).unwrap()];
            conv.execute(rusqlite::params![
                src,
                ip,
                i64::try_from(next() % 1_000_000).unwrap(),
                i64::try_from(next() % 1_000_000).unwrap(),
                proto
            ])
            .unwrap();
        }
    }
    tx.commit().unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM conversations", [], |r| r.get(0))
        .unwrap();
    let hosts: i64 = conn
        .query_row("SELECT count(*) FROM hosts", [], |r| r.get(0))
        .unwrap();
    // In a transaction, as `run_finalizers` does.
    let before = peak_rss();
    let t = Instant::now();
    let tx = conn.transaction().unwrap();
    let stats = build::run(&tx).unwrap();
    tx.commit().unwrap();
    println!(
        "conversations={count} hosts={hosts} finalize={:?} peak_rss_mib before={before} after={} \
         {stats:?}",
        t.elapsed(),
        peak_rss()
    );
    // Each part of the step, again, for the profile (rolled back).
    let tx = conn.transaction().unwrap();
    for table in TABLES {
        tx.execute(&format!("DELETE FROM {table}"), []).unwrap();
    }
    let p = Instant::now();
    build::fill_hosts(&tx).unwrap();
    let hosts_time = p.elapsed();
    let p = Instant::now();
    build::rank_hosts(&tx).unwrap();
    let rank_time = p.elapsed();
    let p = Instant::now();
    build::fold(&tx).unwrap();
    let fold_time = p.elapsed();
    let p = Instant::now();
    build::count_hosts(&tx).unwrap();
    println!(
        "hosts={hosts_time:?} ranks={rank_time:?} fold={fold_time:?} counts={:?}",
        p.elapsed()
    );
    tx.rollback().unwrap();
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM network_edges", [], |r| r.get(0))
        .unwrap();
    println!("network_edges rows={rows}");
    let https = GraphFilter {
        protocols: Some(vec![ProtocolGroup::Https]),
        ..GraphFilter::default()
    };
    let lan = GraphFilter {
        categories: Some(vec!["private".to_owned()]),
        ..GraphFilter::default()
    };
    let expand = GraphMode::Hosts {
        limit: 40,
        expand: Some("US".to_owned()),
        include_orphans: true,
    };
    for (name, filter, mode) in [
        ("default", GraphFilter::default(), hosts_mode(40)),
        ("https", https, hosts_mode(40)),
        ("lan", lan, hosts_mode(150)),
        ("expand+orphans", GraphFilter::default(), expand),
        (
            "countries",
            GraphFilter::default(),
            GraphMode::Countries { limit: 40 },
        ),
    ] {
        let t = Instant::now();
        let g = graph(&conn, &filter, &mode).unwrap();
        let counts = protocol_counts(&conn).unwrap();
        println!(
            "{name}: {:?} nodes={} edges={} groups={}",
            t.elapsed(),
            g.nodes.len(),
            g.edges.len(),
            counts.len()
        );
    }
    let t = Instant::now();
    let d = node_detail(&conn, "10.0.0.1".parse().unwrap())
        .unwrap()
        .unwrap();
    println!("detail: {:?} peers={}", t.elapsed(), d.peers);
}

/// Peak resident memory of the process in MiB (Linux), 0 elsewhere.
fn peak_rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map_or(0, |kib| kib / 1024)
}

/// Tables written by the step.
const TABLES: [&str; 7] = [
    "network_hosts",
    "network_edges",
    "network_country_edges",
    "network_expand",
    "network_host_counts",
    "network_protocols",
    "network_ends",
];

/// A scan and a flood with spoofed sources: one scanner probing `n` LAN addresses missing from
/// `hosts`, and `n` spoofed public sources (20 countries; every 7th one IPv6 without country nor
/// `hosts` row) sending to one victim.
fn flood(n: u32) -> build::StepStats {
    let conn = db();
    insert(
        &conn,
        StoreRecord::Host(host("10.0.0.1", "private", None, &[])),
    );
    insert(
        &conn,
        StoreRecord::Host(host("10.0.0.2", "private", None, &[])),
    );
    for i in 0..n {
        let target = format!("10.{}.{}.{}", 1 + i / 62_500, (i / 250) % 250, i % 250 + 1);
        insert(
            &conn,
            StoreRecord::Conversation(conv("10.0.0.1", &target, 60, 0, &["tcp"])),
        );
        let source = if i % 7 == 0 {
            format!("2001:db8::{i:x}")
        } else {
            let ip = format!("100.{}.{}.{}", i / 62_500, (i / 250) % 250, i % 250 + 1);
            let country = COUNTRIES[(i % 20) as usize];
            insert(
                &conn,
                StoreRecord::Host(host(&ip, "public", Some(country), &[])),
            );
            ip
        };
        insert(
            &conn,
            StoreRecord::Conversation(conv(&source, "10.0.0.2", u64::from(i) + 1, 0, &["udp"])),
        );
    }
    let stats = build::run(&conn).unwrap();
    let hosts: u64 = conn
        .query_row("SELECT count(*) FROM network_hosts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(hosts, 2 + 2 * u64::from(n));
    stats
}

#[test]
fn the_step_memory_does_not_depend_on_the_number_of_hosts() {
    let small = flood(1_000);
    let large = flood(10_000);
    // In memory: the keyed hosts (150 overall and 150 per group), 20 countries, the expandable
    // hosts (30 per country), a few categories and label sets, whatever the number of hosts.
    let keyed = MAX_NODES as usize * (ProtocolGroup::ALL.len() + 1);
    let expandable = 20 * EXPAND_HOSTS as usize;
    for s in [small, large] {
        assert_eq!(s.countries, 20, "{s:?}");
        assert!(s.edges <= keyed + 2 * 20 + 10, "{s:?}");
        assert!(s.country_edges <= 25, "{s:?}");
        assert!(s.expand <= expandable, "{s:?}");
        assert!(s.names <= keyed + 2 * 20 + expandable + 10, "{s:?}");
        assert_eq!(s.label_sets, 2, "{s:?}");
        assert!(s.host_counts <= 2 * 20 + 10, "{s:?}");
    }
    // Ten times the hosts: the maps do not grow with them.
    assert_eq!(large.country_edges, small.country_edges);
    assert_eq!(large.host_counts, small.host_counts);
    assert!(large.edges <= small.edges, "{small:?} {large:?}");
    assert!(large.expand <= small.expand, "{small:?} {large:?}");
    assert!(large.names <= small.names, "{small:?} {large:?}");
}

#[test]
fn the_step_reads_by_index_and_never_sorts() {
    let conn = db();
    two_hundred(&conn);
    // With statistics, as after `PRAGMA optimize` (rerun at the opening of a session).
    finalized(&conn);
    conn.execute_batch("ANALYZE").unwrap();
    let plan = |sql: &str| -> String {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(3)).unwrap();
        rows.map(Result::unwrap).collect::<Vec<_>>().join("\n")
    };
    // A sorter or a temporary b-tree over hosts or conversations would hold them in memory.
    let unsorted = |p: &str| !p.contains("ORDER BY") && !p.contains("GROUP BY");
    let p = plan(build::RANK_SQL);
    assert!(
        p.contains("network_hosts_bytes") && !p.contains("TEMP B-TREE"),
        "{p}"
    );
    let p = plan(&build::fold_sql());
    assert!(p.contains("SCAN c"), "{p}");
    assert!(p.contains("SEARCH s USING PRIMARY KEY"), "{p}");
    assert!(p.contains("SEARCH d USING PRIMARY KEY"), "{p}");
    assert!(unsorted(&p), "{p}");
    for sql in build::MERGE_SQL {
        let p = plan(sql);
        assert!(!p.contains("TEMP B-TREE"), "{p}");
    }
}

/// Random session with many ties: 1 200 addresses (3 countries, some without country, IPv6,
/// some missing from `hosts`), 40 hosts without conversation, 3 000 conversations (some with
/// themselves), frequent and rare label sets; then 60 small hosts of a fourth country.
fn random_records() -> Vec<StoreRecord> {
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let pool: Vec<String> = (0..1_240_u32)
        .map(|i| match i % 6 {
            0..=3 => format!("{}.{}.0.9", 1 + i / 250, i % 250),
            4 => format!("10.1.{}.{}", i / 250, i % 250),
            _ => format!("2001:db8::{i:x}"),
        })
        .collect();
    let mut out = Vec::new();
    for (i, ip) in pool.iter().enumerate() {
        if i % 13 == 0 && i < 1_200 {
            continue; // Only seen in conversations.
        }
        let (category, country) = match i % 6 {
            4 => ("private", None),
            _ if i % 11 == 0 => ("public", None),
            _ => ("public", Some(["US", "FR", "DE"][i % 3])),
        };
        out.push(StoreRecord::Host(host(ip, category, country, &[])));
        if i % 5 == 0 {
            out.push(StoreRecord::HostTraffic(HostTrafficRow {
                ip: ip.parse().unwrap(),
                bytes_sent: next() % 50,
                bytes_received: 0,
                packets_sent: 1,
                packets_received: 0,
            }));
        }
    }
    let labels: [&[&str]; 7] = [
        &["tcp"],
        &["udp"],
        &["dns", "udp"],
        &["tcp", "tls"],
        &["http", "tcp"],
        &["icmp"],
        &[],
    ];
    for k in 0..3_000 {
        let src = &pool[usize::try_from(next() % 1_200).unwrap()];
        let dst = if k % 100 == 0 {
            src
        } else {
            &pool[usize::try_from(next() % 1_200).unwrap()]
        };
        let r = next();
        let protocols: &[&str] = match r % 60 {
            0 => &["ssh", "tcp"],
            1 => &["netbios", "smb", "tcp"],
            n => labels[usize::try_from(n % 7).unwrap()],
        };
        out.push(StoreRecord::Conversation(conv(
            src,
            dst,
            (r >> 8) % 6 * 100,
            (r >> 16) % 4 * 10,
            protocols,
        )));
    }
    // 60 small hosts of a fourth country, never keyed: its expandable hosts, talking to each
    // other and to the others.
    for (i, other) in pool.iter().take(60).enumerate() {
        let ip = format!("203.0.113.{}", i + 1);
        out.push(StoreRecord::Host(host(&ip, "public", Some("JP"), &[])));
        let next_jp = format!("203.0.113.{}", (i + 1) % 60 + 1);
        out.push(StoreRecord::Conversation(conv(
            &ip,
            &next_jp,
            1,
            0,
            &["udp"],
        )));
        out.push(StoreRecord::Conversation(conv(&ip, other, 0, 1, &["udp"])));
    }
    out
}

/// One row as text (`|` between the values, `NULL` for null).
fn row_text(values: &[Value]) -> String {
    values
        .iter()
        .map(|v| match v {
            Value::Null => "NULL".to_owned(),
            Value::Integer(n) => n.to_string(),
            Value::Real(f) => f.to_string(),
            Value::Text(s) => s.clone(),
            Value::Blob(b) => format!("{b:?}"),
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// Every table of the step, rows sorted.
fn dump_tables(conn: &Connection) -> Vec<(String, Vec<String>)> {
    TABLES
        .iter()
        .map(|table| {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let width = stmt.column_count();
            let mut rows: Vec<String> = stmt
                .query_map([], |r| {
                    let values: Vec<Value> = (0..width).map(|i| r.get(i).unwrap()).collect();
                    Ok(row_text(&values))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows.sort();
            ((*table).to_owned(), rows)
        })
        .collect()
}

#[derive(Default)]
struct RefHost {
    country: Option<String>,
    category: String,
    traffic: i64,
    mask: u16,
    bytes: i64,
    rank: Option<i64>,
    crank: Option<i64>,
    keyed: bool,
}

impl RefHost {
    fn node(&self, ip: &str) -> String {
        match (&self.country, self.keyed) {
            (_, true) => format!("h:{ip}"),
            (Some(cc), false) => format!("k:{cc}"),
            (None, false) => "other".to_owned(),
        }
    }

    fn cnode(&self) -> String {
        match (&self.country, self.category.as_str()) {
            (Some(cc), _) => format!("c:{cc}"),
            (None, "public") => "unknown".to_owned(),
            _ => "local".to_owned(),
        }
    }

    fn expandable(&self) -> bool {
        !self.keyed && self.crank.is_some_and(|c| c <= i64::from(EXPAND_HOSTS))
    }
}

/// A conversation of the reference: ends, bytes, packets, flows, labels and groups.
type RefConv = (String, String, i64, i64, i64, i64, Vec<String>, u16);
/// (a, b, mask, category a, category b, IPv6).
type RefEdgeKey = (String, String, u16, String, String, bool);
/// (country, x, x is the client, other node, other expandable host, mask, categories, IPv6).
type RefExpandKey = (
    String,
    String,
    bool,
    String,
    String,
    u16,
    String,
    String,
    bool,
);

#[derive(Default)]
struct RefSums {
    fwd: i64,
    rev: i64,
    packets: i64,
    flows: i64,
    conversations: i64,
    labels: BTreeSet<String>,
}

impl RefSums {
    fn values(&self) -> Vec<Value> {
        vec![
            Value::Integer(self.fwd),
            Value::Integer(self.rev),
            Value::Integer(self.packets),
            Value::Integer(self.flows),
            Value::Integer(self.conversations),
            Value::Text(serde_json::to_string(&self.labels).unwrap()),
        ]
    }
}

/// The step written plainly, everything in memory (the rules of ADR-018), as sorted rows of
/// each table: the reference the bounded step must match.
#[allow(clippy::too_many_lines)] // One reference pipeline.
fn reference(conn: &Connection) -> Vec<(String, Vec<String>)> {
    let text = |s: &str| Value::Text(s.to_owned());
    let mut hosts: BTreeMap<String, RefHost> = BTreeMap::new();
    let mut stmt = conn
        .prepare(
            "SELECT h.ip, h.country, coalesce(h.category, ''), \
             coalesce(t.bytes_sent, 0) + coalesce(t.bytes_received, 0) \
             FROM hosts h LEFT JOIN host_traffic t ON t.ip = h.ip",
        )
        .unwrap();
    for r in stmt
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
    {
        let (ip, country, category, traffic) = r.unwrap();
        let h = RefHost {
            country,
            category,
            traffic,
            ..RefHost::default()
        };
        hosts.insert(ip, h);
    }
    let mut stmt = conn
        .prepare(
            "SELECT src_ip, dst_ip, bytes_fwd, bytes_rev, packets_fwd + packets_rev, flows, \
             protocols FROM conversations",
        )
        .unwrap();
    let convs: Vec<RefConv> = stmt
        .query_map([], |r| {
            let labels: Vec<String> = serde_json::from_str(&r.get::<_, String>(6)?).unwrap();
            let mask = labels.iter().fold(0, |m, l| {
                m | ProtocolGroup::ALL
                    .into_iter()
                    .find(|g| g.labels().contains(&l.as_str()))
                    .unwrap_or(ProtocolGroup::Other)
                    .bit()
            });
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                labels,
                mask,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut groups = [0_i64; ProtocolGroup::ALL.len()];
    for (src, dst, fwd, rev, _, _, _, mask) in &convs {
        let ends: &[&String] = if src == dst { &[src] } else { &[src, dst] };
        for ip in ends {
            let h = hosts.entry((*ip).clone()).or_default();
            h.bytes += fwd + rev;
            h.mask |= mask;
            h.rank = Some(0);
        }
        for (i, g) in ProtocolGroup::ALL.iter().enumerate() {
            if mask & g.bit() != 0 {
                groups[i] += 1;
            }
        }
    }
    // Ranks: most bytes first, then address.
    let mut order: Vec<String> = hosts
        .iter()
        .filter(|(_, h)| h.rank.is_some())
        .map(|(ip, _)| ip.clone())
        .collect();
    order.sort_by(|a, b| hosts[b].bytes.cmp(&hosts[a].bytes).then_with(|| a.cmp(b)));
    let mut per_country: HashMap<String, i64> = HashMap::new();
    let max = MAX_NODES as usize;
    for (rank, ip) in order.iter().enumerate() {
        let h = hosts.get_mut(ip).unwrap();
        h.rank = Some(i64::try_from(rank).unwrap() + 1);
        h.keyed = rank < max;
        if let Some(cc) = &h.country {
            let n = per_country.entry(cc.clone()).or_default();
            *n += 1;
            h.crank = Some(*n).filter(|n| *n <= i64::from(EXPAND_HOSTS));
        }
    }
    for g in ProtocolGroup::ALL {
        let firsts: Vec<String> = order
            .iter()
            .filter(|ip| hosts[*ip].mask & g.bit() != 0)
            .take(max)
            .cloned()
            .collect();
        for ip in firsts {
            hosts.get_mut(&ip).unwrap().keyed = true;
        }
    }
    // Stored ranks: keyed hosts and the first hosts of each country only (0 for the others).
    for h in hosts.values_mut() {
        if h.rank.is_some() && !h.keyed && h.crank.is_none() {
            h.rank = Some(0);
        }
    }

    let mut edges: BTreeMap<RefEdgeKey, RefSums> = BTreeMap::new();
    let mut country_edges: BTreeMap<RefEdgeKey, RefSums> = BTreeMap::new();
    let mut expand: BTreeMap<RefExpandKey, RefSums> = BTreeMap::new();
    for (src, dst, fwd, rev, packets, flows, labels, mask) in &convs {
        let (s, d) = (&hosts[src], &hosts[dst]);
        let six = src.contains(':') || dst.contains(':');
        let add = |sums: &mut RefSums| {
            sums.fwd += fwd;
            sums.rev += rev;
            sums.packets += packets;
            sums.flows += flows;
            sums.conversations += 1;
            sums.labels.extend(labels.iter().cloned());
        };
        let (sc, dc) = (s.category.clone(), d.category.clone());
        add(edges
            .entry((s.node(src), d.node(dst), *mask, sc.clone(), dc.clone(), six))
            .or_default());
        add(country_edges
            .entry((s.cnode(), d.cnode(), *mask, sc, dc, six))
            .or_default());
        for (x, other, x_is_src) in [(src, dst, true), (dst, src, false)] {
            let (hx, ho) = (&hosts[x], &hosts[other]);
            if !hx.expandable() || (src == dst && !x_is_src) {
                continue;
            }
            let other_ip = if ho.expandable() {
                other.clone()
            } else {
                String::new()
            };
            add(expand
                .entry((
                    hx.country.clone().unwrap(),
                    x.clone(),
                    x_is_src,
                    ho.node(other),
                    other_ip,
                    *mask,
                    hx.category.clone(),
                    ho.category.clone(),
                    six,
                ))
                .or_default());
        }
    }

    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let sorted = |mut rows: Vec<String>| {
        rows.sort();
        rows
    };
    out.push((
        "network_hosts".to_owned(),
        sorted(
            hosts
                .iter()
                .map(|(ip, h)| {
                    row_text(&[
                        text(ip),
                        h.country.as_deref().map_or(Value::Null, text),
                        text(&h.category),
                        Value::Integer(ip.contains(':').into()),
                        Value::Integer(h.mask.into()),
                        Value::Integer(h.bytes),
                        Value::Integer(h.traffic),
                        h.rank.map_or(Value::Null, Value::Integer),
                        h.crank.map_or(Value::Null, Value::Integer),
                        Value::Integer(h.keyed.into()),
                        text(&h.node(ip)),
                        text(&h.cnode()),
                    ])
                })
                .collect(),
        ),
    ));
    for (table, map) in [
        ("network_edges", &edges),
        ("network_country_edges", &country_edges),
    ] {
        let rows = map
            .iter()
            .map(|((a, b, mask, cat_a, cat_b, six), sums)| {
                let mut v = vec![
                    text(a),
                    text(b),
                    Value::Integer((*mask).into()),
                    text(cat_a),
                    text(cat_b),
                    Value::Integer((*six).into()),
                ];
                v.extend(sums.values());
                row_text(&v)
            })
            .collect();
        out.push((table.to_owned(), sorted(rows)));
    }
    let rows = expand
        .iter()
        .map(
            |((cc, x, x_is_src, other, other_ip, mask, cat_x, cat_o, six), sums)| {
                let mut v = vec![
                    text(cc),
                    text(x),
                    Value::Integer((*x_is_src).into()),
                    text(other),
                    text(other_ip),
                    Value::Integer((*mask).into()),
                    text(cat_x),
                    text(cat_o),
                    Value::Integer((*six).into()),
                ];
                v.extend(sums.values());
                row_text(&v)
            },
        )
        .collect();
    out.push(("network_expand".to_owned(), sorted(rows)));
    let mut counts: BTreeMap<(String, String, String, bool, u16), i64> = BTreeMap::new();
    for (ip, h) in &hosts {
        let node = if h.keyed {
            "keyed".to_owned()
        } else {
            h.node(ip)
        };
        *counts
            .entry((
                node,
                h.cnode(),
                h.category.clone(),
                ip.contains(':'),
                h.mask,
            ))
            .or_default() += 1;
    }
    let rows = counts
        .iter()
        .map(|((node, cnode, category, six, mask), n)| {
            row_text(&[
                text(node),
                text(cnode),
                text(category),
                Value::Integer((*six).into()),
                Value::Integer((*mask).into()),
                Value::Integer(*n),
            ])
        })
        .collect();
    out.push(("network_host_counts".to_owned(), sorted(rows)));
    let rows = ProtocolGroup::ALL
        .iter()
        .zip(groups)
        .map(|(g, n)| row_text(&[text(g.as_str()), Value::Integer(n)]))
        .collect();
    out.push(("network_protocols".to_owned(), sorted(rows)));
    out.push(("network_ends".to_owned(), Vec::new()));
    out
}

#[test]
fn the_step_matches_the_plain_reference_and_ignores_the_order() {
    let records = random_records();
    let a = db();
    for r in records.iter().cloned() {
        insert(&a, r);
    }
    let stats = build::run(&a).unwrap();
    let tables = dump_tables(&a);
    assert_eq!(tables, reference(&a));
    // The cases the data must cover: keyed by a group beyond the overall top, hosts folded
    // per country, expandable hosts (also on both ends), conversations with themselves.
    let count = |sql: &str| -> i64 { a.query_row(sql, [], |r| r.get(0)).unwrap() };
    assert!(count("SELECT count(*) FROM network_hosts WHERE keyed = 1 AND rank > 150") > 0);
    assert!(count("SELECT count(*) FROM network_hosts WHERE node LIKE 'k:%' AND rank = 0") > 0);
    assert!(count("SELECT count(*) FROM network_hosts WHERE node = 'other' AND rank = 0") > 0);
    assert!(count("SELECT count(*) FROM network_hosts WHERE rank IS NULL AND traffic > 0") > 0);
    assert!(count("SELECT count(*) FROM network_expand") > 0);
    assert!(count("SELECT count(*) FROM network_expand WHERE other_ip <> ''") > 0);
    assert!(count("SELECT count(*) FROM conversations WHERE src_ip = dst_ip") > 0);
    assert!(stats.expand > 0 && stats.label_sets >= 9, "{stats:?}");

    // Idempotent.
    build::run(&a).unwrap();
    assert_eq!(dump_tables(&a), tables);
    // Independent of the arrival order of the records.
    let b = db();
    for r in records.into_iter().rev() {
        insert(&b, r);
    }
    build::run(&b).unwrap();
    assert_eq!(dump_tables(&b), tables);
}

#[test]
fn host_roles_come_from_the_servers_view() {
    let conn = db();
    for (ip, port) in [
        ("10.0.0.1", 53),
        ("10.0.0.1", 389),
        ("10.0.0.1", 88),
        ("10.0.0.2", 445),
    ] {
        insert(
            &conn,
            StoreRecord::OpenPort(OpenPortRow {
                ip: ip.parse().unwrap(),
                transport: 6,
                port,
                evidence: "syn_ack".to_owned(),
                service: None,
                detected: None,
                banner: None,
                first_ts: 0,
                last_ts: 0,
            }),
        );
    }
    let ips: Vec<IpAddr> = ["10.0.0.1", "10.0.0.3"]
        .iter()
        .map(|ip| ip.parse().unwrap())
        .collect();
    let roles = host_roles(&conn, &ips).unwrap();
    assert_eq!(roles.len(), 1, "only the asked hosts having a role");
    assert_eq!(roles[&ips[0]], ["dns", "kerberos", "ldap"]);
    assert!(host_roles(&conn, &[]).unwrap().is_empty());
}

#[test]
fn the_step_declares_every_network_table() {
    // Otherwise an upgraded session keeps listing them as added after its import (ADR-013).
    let conn = db();
    let step = crate::finalize::SESSION_FINALIZERS
        .iter()
        .find(|f| f.id == "network")
        .unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'network\\_%' ESCAPE '\\'")
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(tables.len(), TABLES.len());
    for t in &tables {
        assert!(step.fills.contains(&t.as_str()), "{t}");
    }
}
