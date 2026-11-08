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
fn queries_scan_conversations_once_and_use_indexes() {
    let conn = db();
    two_hundred(&conn);
    let plan = |sql: &str, params: &[&dyn ToSql]| -> String {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows = stmt
            .query_map(params_from_iter(params.iter()), |r| r.get::<_, String>(3))
            .unwrap();
        rows.map(Result::unwrap).collect::<Vec<_>>().join("\n")
    };
    let p = FilterParams::new(&GraphFilter::default()).unwrap();
    let hosts = "[]".to_owned();
    let sql = group_sql(&host_key("src"), &host_key("dst"));
    let edges = plan(&sql, &p.with(&[&hosts, &hosts]));
    assert_eq!(edges.matches("SCAN c").count(), 1, "{edges}");
    assert!(
        !edges.contains("SCAN hs") && !edges.contains("SCAN hd"),
        "{edges}"
    );
    assert!(edges.contains("sqlite_autoindex_hosts_1"), "{edges}");

    // Detail of a host: indexed lookups only.
    let detail = plan(
        "SELECT dst_ip FROM conversations WHERE src_ip = ?1 \
         UNION ALL SELECT src_ip FROM conversations WHERE dst_ip = ?1",
        &[&"192.168.1.1"],
    );
    assert!(!detail.contains("SCAN"), "{detail}");
    assert!(detail.contains("conversations_dst_ip"), "{detail}");
    let ports = plan(
        "SELECT port FROM open_ports WHERE ip = ?1 ORDER BY port, transport LIMIT 50",
        &[&"192.168.1.1"],
    );
    assert!(!ports.contains("SCAN"), "{ports}");
}
