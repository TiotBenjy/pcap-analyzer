use std::net::{IpAddr, Ipv4Addr};

use rusqlite::Connection;

use super::*;
use crate::migrate::migrate;
use crate::query::{Page, PageRequest};
use crate::range::{ModuleRows, TimeRange};
use crate::schema::SESSION_SCHEMA;

const S: i64 = 1_000_000_000;

fn db() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn, &SESSION_SCHEMA).unwrap();
    conn
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn connection(
    flow_id: i64,
    client: IpAddr,
    server: IpAddr,
    first: i64,
    last: i64,
) -> MqttConnectionRow {
    MqttConnectionRow {
        flow_id,
        first_ts: first * S,
        last_ts: last * S,
        client_ip: client,
        client_port: 50_000,
        server_ip: server,
        server_port: 1883,
        transport: "tcp",
        ws_path: None,
        ws_host: None,
        ws_subprotocol: None,
        ws_close_code: None,
        ws_compressed: false,
        version: Some(4),
        bridge: false,
        partial: false,
        protocol_name: Some("MQTT".to_owned()),
        client_id: Some(format!("dev-{flow_id}")),
        assigned_client_id: None,
        clean_start: Some(true),
        keep_alive: Some(60),
        server_keep_alive: None,
        session_expiry: None,
        username: None,
        password: None,
        password_len: None,
        auth_method: None,
        auth: Some("none"),
        will_topic: None,
        will_qos: None,
        will_retain: None,
        will_payload_len: None,
        will_payload: None,
        connect_props: Vec::new(),
        connack_ts: Some(first * S),
        connack_code: Some(0),
        session_present: Some(false),
        connack_props: Vec::new(),
        login: Some("accepted"),
        end_kind: "disconnect",
        disconnect_ts: None,
        disconnect_by: None,
        disconnect_reason: None,
        broker_software: None,
        packets_c2s: 3,
        packets_s2c: 1,
        publish_c2s: 2,
        publish_s2c: 0,
        payload_bytes_c2s: 10,
        payload_bytes_s2c: 0,
        subscribe_count: 0,
        pings: 0,
        last_ping_ts: None,
        bytes_c2s: 100,
        bytes_s2c: 50,
        stored_packets: 2,
        packets_truncated: false,
        malformed: 0,
        protocol_errors: 0,
        gaps: 0,
    }
}

fn topic(
    flow_id: i64,
    dir: &'static str,
    topic: &str,
    messages: u64,
    first: i64,
) -> MqttTopicFlowRow {
    MqttTopicFlowRow {
        flow_id,
        dir,
        topic: topic.to_owned(),
        messages,
        payload_bytes: messages * 10,
        first_ts: first * S,
        last_ts: (first + 1) * S,
        qos: [messages, 0, 0],
        retained: 0,
        max_payload: 10,
    }
}

fn publish(flow_id: i64, seq: u32, ts: i64, topic: &str) -> MqttPacketRow {
    MqttPacketRow {
        flow_id,
        seq,
        ts: ts * S,
        dir: "c",
        ptype: 3,
        flags: 0,
        packet_id: None,
        qos: Some(0),
        retain: false,
        dup: false,
        topic: Some(topic.to_owned()),
        topic_alias: None,
        topic_source: Some("name"),
        size: 20,
        payload_len: Some(5),
        payload: Some(b"hello".to_vec()),
        payload_format: None,
        content_type: None,
        reason_code: None,
        reason_string: None,
        ack_state: Some("none"),
        ack_reason: None,
        ack_ns: None,
        filters: Vec::new(),
        props: Vec::new(),
        malformed: false,
    }
}

fn insert(conn: &Connection, rows: Vec<MqttRow>) {
    for r in rows {
        r.insert(conn).unwrap();
    }
}

/// Three connections: a sensor publishing under `a/b`, a second one under `a/c` and `/x`, and a
/// public client rejected five times plus once accepted by a LAN broker (one row each).
fn fixture() -> Connection {
    let conn = db();
    let lan = v4(192, 168, 1, 40);
    let public = v4(82, 165, 30, 12);
    conn.execute_batch(
        "INSERT INTO hosts (ip, first_ts, last_ts, category) VALUES \
         ('82.165.30.12', 0, 1, 'public'), ('91.198.174.12', 0, 1, 'public'), \
         ('192.168.1.40', 0, 1, 'private'), ('192.168.1.60', 0, 1, 'private');",
    )
    .unwrap();
    let mut c1 = connection(1, v4(192, 168, 1, 60), lan, 10, 20);
    c1.username = Some("sensor".to_owned());
    c1.password = Some("pw-fixture".to_owned());
    c1.auth = Some("password");
    let c2 = connection(2, v4(192, 168, 1, 60), public, 30, 40);
    let mut rows = vec![
        MqttRow::Connection(Box::new(c1)),
        MqttRow::Connection(Box::new(c2)),
        MqttRow::TopicFlow(topic(1, "c", "a/b", 3, 10)),
        MqttRow::TopicFlow(topic(1, "c", "a/b/c", 1, 11)),
        MqttRow::TopicFlow(topic(2, "c", "a/c", 2, 30)),
        MqttRow::TopicFlow(topic(2, "b", "a/c", 4, 31)),
        MqttRow::TopicFlow(topic(2, "c", "/x", 1, 32)),
        MqttRow::TopicFlow(topic(2, "c", "a/b!", 1, 33)),
        MqttRow::TopicFlow(topic(2, "c", "", 7, 33)),
        MqttRow::Packet(Box::new(publish(1, 2, 10, "a/b"))),
        MqttRow::Packet(Box::new(publish(1, 3, 11, "a/b/c"))),
        MqttRow::Packet(Box::new(publish(2, 2, 30, "a/c"))),
        MqttRow::Subscription(MqttSubscriptionRow {
            flow_id: 2,
            seq: 1,
            idx: 0,
            ts: 30 * S,
            filter: "#".to_owned(),
            qos: 0,
            options: 0,
            granted: Some(0),
            shared_group: None,
            wildcard: true,
            unsubscribed_ts: None,
        }),
    ];
    for i in 0..6 {
        let mut c = connection(10 + i, v4(91, 198, 174, 12), lan, 50 + i, 50 + i);
        c.client_id = Some("probe".to_owned());
        if i < 5 {
            c.login = Some("rejected");
            c.connack_code = Some(5);
        }
        rows.push(MqttRow::Connection(Box::new(c)));
    }
    insert(&conn, rows);
    finalize(&conn).unwrap();
    conn
}

#[test]
fn levels_are_bounded() {
    assert_eq!(levels("a/b/c"), vec!["a", "b", "c"]);
    assert_eq!(levels("/x"), vec!["", "x"]);
    assert_eq!(levels("a//b"), vec!["a", "", "b"]);
    let deep = (0..40).map(|i| i.to_string()).collect::<Vec<_>>().join("/");
    let l = levels(&deep);
    assert_eq!(l.len(), MAX_DEPTH);
    assert!(l.last().unwrap().contains('/'));
}

/// A row of `mqtt_topics` in the snapshot.
type Node = (String, Option<String>, i64, bool, i64, i64, i64, i64);

#[test]
fn topic_tree_of_the_step() {
    let conn = fixture();
    let nodes: Vec<Node> = conn
        .prepare(
            "SELECT path, parent, depth, is_topic, children, topics, messages_pub, messages_del \
             FROM mqtt_topics ORDER BY path",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    insta::assert_debug_snapshot!(nodes);
    // Idempotent.
    finalize(&conn).unwrap();
    let n: i64 = conn
        .query_row("SELECT count(*) FROM mqtt_topics", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, i64::try_from(nodes.len()).unwrap());
}

#[test]
fn children_with_and_without_range() {
    let conn = fixture();
    let names = |page: Page<TopicNode>| -> Vec<(String, u64, u64, u64)> {
        page.items
            .into_iter()
            .map(|n| (n.name, n.topics, n.messages_pub, n.children))
            .collect()
    };
    let root = topic_children(&conn, None, None, &PageRequest::first(100)).unwrap();
    assert_eq!(
        names(root),
        vec![(String::new(), 1, 1, 1), ("a".to_owned(), 4, 7, 3)]
    );
    let a = topic_children(&conn, Some("a"), None, &PageRequest::first(100)).unwrap();
    assert_eq!(
        names(a),
        vec![
            ("b".to_owned(), 2, 4, 1),
            ("b!".to_owned(), 1, 1, 0),
            ("c".to_owned(), 1, 2, 0)
        ]
    );
    // Covering range: same answer; narrow range: only the second connection's topics.
    let all = TimeRange::new(0, 100 * S).unwrap();
    let a_all = topic_children(&conn, Some("a"), Some(all), &PageRequest::first(100)).unwrap();
    assert_eq!(names(a_all).len(), 3);
    let late = TimeRange::new(30 * S, 40 * S).unwrap();
    let a_late = topic_children(&conn, Some("a"), Some(late), &PageRequest::first(100)).unwrap();
    assert_eq!(
        names(a_late),
        vec![("b!".to_owned(), 1, 1, 0), ("c".to_owned(), 1, 2, 0)]
    );
    // Pages without duplicate.
    let first = topic_children(&conn, Some("a"), Some(all), &PageRequest::first(2)).unwrap();
    let rest = topic_children(
        &conn,
        Some("a"),
        Some(all),
        &PageRequest {
            limit: 2,
            cursor: first.next_cursor.clone(),
        },
    )
    .unwrap();
    assert_eq!(first.items.len() + rest.items.len(), 3);
    assert!(rest.next_cursor.is_none());
}

#[test]
fn filter_matching() {
    assert!(topic_matches("#", "a/b"));
    assert!(topic_matches("a/#", "a"));
    assert!(topic_matches("a/+/c", "a/b/c"));
    assert!(!topic_matches("a/+", "a/b/c"));
    assert!(!topic_matches("#", "$SYS/broker/version"));
    assert!(topic_matches("$SYS/#", "$SYS/broker/version"));
    assert!(topic_matches("$share/g/a/+", "a/b"));
    assert!(topic_matches("+/x", "/x"));
}

#[test]
fn topic_detail_lists_peers() {
    let conn = fixture();
    let d = topic_detail(&conn, "a/c", None).unwrap().unwrap();
    assert_eq!((d.node.messages_pub, d.node.messages_del), (2, 4));
    assert!(d.node.is_topic);
    assert_eq!(d.publishers.len(), 1);
    assert_eq!(d.subscribers.len(), 1);
    assert_eq!(d.subscribers[0].filter, "#");
    assert_eq!(d.recent.len(), 1);
    let b = topic_detail(&conn, "a/b", None).unwrap().unwrap();
    assert_eq!(b.node.topics, 2);
    assert_eq!(b.recent.len(), 2);
    assert!(topic_detail(&conn, "nothing", None).unwrap().is_none());
}

#[test]
fn connections_filters_and_signals() {
    let conn = fixture();
    let all = ConnectionFilter::default();
    assert_eq!(count_connections(&conn, &all).unwrap(), 8);
    let page = connections_page(&conn, &all, &PageRequest::first(100)).unwrap();
    assert_eq!(page.items.len(), 8);
    assert_eq!(page.items.iter().filter(|e| e.auth_failures).count(), 5);
    let with = |signal| {
        count_connections(
            &conn,
            &ConnectionFilter {
                signal: Some(signal),
                ..ConnectionFilter::default()
            },
        )
        .unwrap()
    };
    assert_eq!(with(Signal::Anonymous), 2);
    assert_eq!(with(Signal::PublicBroker), 1);
    assert_eq!(with(Signal::ExposedBroker), 1);
    assert_eq!(with(Signal::Wildcard), 1);
    assert_eq!(with(Signal::AuthFailures), 5);
    assert_eq!(with(Signal::CleartextCredentials), 1);
    let groups = signals(&conn, None).unwrap();
    assert_eq!(groups.len(), 6);
    let failures = groups
        .iter()
        .find(|g| g.signal == Signal::AuthFailures)
        .unwrap();
    assert_eq!(failures.items.len(), 1);
    assert_eq!(failures.items[0].connections, 5);
    // Clients and brokers.
    let clients = clients_page(&conn, &GroupFilter::default(), &PageRequest::first(2)).unwrap();
    assert_eq!(clients.items.len(), 2);
    let more = clients_page(
        &conn,
        &GroupFilter::default(),
        &PageRequest {
            limit: 2,
            cursor: clients.next_cursor.clone(),
        },
    )
    .unwrap();
    assert_eq!(more.items.len(), 1);
    assert_eq!(count_clients(&conn, &GroupFilter::default()).unwrap(), 3);
    let probe = more
        .items
        .iter()
        .chain(&clients.items)
        .find(|c| c.key == "id:probe")
        .unwrap();
    assert_eq!((probe.connections, probe.rejected), (6, 5));
    let brokers = brokers_page(&conn, &GroupFilter::default(), &PageRequest::first(1)).unwrap();
    assert_eq!(brokers.items[0].connections, 7);
    assert_eq!(brokers.items[0].public_clients_accepted, 1);
    let second = brokers_page(
        &conn,
        &GroupFilter::default(),
        &PageRequest {
            limit: 1,
            cursor: brokers.next_cursor.clone(),
        },
    )
    .unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());
    // Range: overlap.
    let r = TimeRange::new(0, 25 * S).unwrap();
    let ranged = ConnectionFilter {
        range: Some(r),
        ..ConnectionFilter::default()
    };
    assert_eq!(count_connections(&conn, &ranged).unwrap(), 1);
    assert_eq!(ModuleRows::Mqtt.count(&conn, r).unwrap(), 1);
    let s = stats(&conn, None).unwrap();
    assert_eq!(
        (
            s.connections,
            s.accepted,
            s.rejected,
            s.brokers,
            s.public_brokers
        ),
        (8, 3, 5, 2, 1)
    );
    assert_eq!(s.topics, 5);
}

#[test]
fn password_only_in_the_detail() {
    let conn = fixture();
    let d = connection_detail(&conn, 1).unwrap().unwrap();
    assert_eq!(d.password.as_deref(), Some("pw-fixture"));
    assert!(d.entry.has_password);
    assert!(connection_detail(&conn, 999).unwrap().is_none());
    // The list never reads the secrets table.
    let page =
        connections_page(&conn, &ConnectionFilter::default(), &PageRequest::first(10)).unwrap();
    assert!(!format!("{page:?}").contains("pw-fixture"));
    let n: i64 = conn
        .query_row("SELECT count(*) FROM mqtt_connect_secrets", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn messages_and_packets() {
    let conn = fixture();
    let all = MessageFilter::default();
    assert_eq!(count_messages(&conn, &all).unwrap(), 3);
    let prefix = MessageFilter {
        prefix: Some("a/b".to_owned()),
        ..MessageFilter::default()
    };
    assert_eq!(count_messages(&conn, &prefix).unwrap(), 2);
    let page = messages_page(&conn, &prefix, &PageRequest::first(10)).unwrap();
    assert_eq!(
        page.items[0].peer.as_ref().unwrap().client_id.as_deref(),
        Some("dev-1")
    );
    let packets =
        packets_page(&conn, 1, &PacketFilter::default(), &PageRequest::first(10)).unwrap();
    assert_eq!(packets.items.len(), 2);
    assert_eq!(
        count_packets(&conn, 1, &PacketFilter::default()).unwrap(),
        2
    );
}
