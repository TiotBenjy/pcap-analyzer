use std::fmt::Write as _;

use rusqlite::Connection;

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
    let p = plan(ORPHANS_SQL, &[&ALL_GROUPS, &None::<String>, &true, &30]);
    assert!(
        p.contains("network_hosts_traffic") && !p.contains("TEMP B-TREE"),
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
    let mut conn = db();
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
    // In a transaction, as `run_finalizers` does.
    let t = Instant::now();
    let tx = conn.transaction().unwrap();
    finalize(&tx).unwrap();
    tx.commit().unwrap();
    println!("conversations={count} finalize={:?}", t.elapsed());
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
