//! Tests of the `mqtt` analyzer over synthetic captures (real flow layer).

use std::fmt::Write as _;

use netsift_dissect::mqtt::{PacketType, Version};
use netsift_fixtures::Scenario;
use netsift_fixtures::mqtt::wire::{ConnectSpec, Mqtt};
use netsift_fixtures::mqtt::{self as fx, SHOWCASE, mqtt_hosts};
use netsift_fixtures::scenario::TcpOptions;

use super::conn::render_secret;
use super::{
    AckState, AuthKind, Dir, EndKind, Login, MqttAnalyzer, MqttConnection, MqttPacket, MqttRecord,
    MqttSubscription, MqttTopicStat, TopicSource,
};
use crate::record::{Credential, Record, SecretState};
use crate::registry::AnalyzerConfig;
use crate::testutil::run;

#[derive(Default)]
struct Out {
    conns: Vec<MqttConnection>,
    packets: Vec<MqttPacket>,
    topics: Vec<MqttTopicStat>,
    subs: Vec<MqttSubscription>,
    creds: Vec<Credential>,
}

fn records(sc: &Scenario) -> Out {
    let mut analyzer = MqttAnalyzer::new(&AnalyzerConfig::default());
    let mut out = Out::default();
    for r in run(&mut analyzer, sc.packets()) {
        match r {
            Record::Mqtt(MqttRecord::Connection(c)) => out.conns.push(*c),
            Record::Mqtt(MqttRecord::Packet(p)) => out.packets.push(*p),
            Record::Mqtt(MqttRecord::Topic(t)) => out.topics.push(t),
            Record::Mqtt(MqttRecord::Subscription(s)) => out.subs.push(s),
            Record::Credential(c) => out.creds.push(c),
            other => panic!("unexpected record {other:?}"),
        }
    }
    out.conns.sort_by_key(|c| c.flow_id);
    out.packets.sort_by_key(|p| (p.flow_id, p.seq));
    out.topics
        .sort_by(|a, b| (a.flow_id, a.dir, &a.topic).cmp(&(b.flow_id, b.dir, &b.topic)));
    out.subs.sort_by_key(|s| (s.flow_id, s.seq, s.idx));
    out.creds.sort_by_key(|c| (c.flow_id, c.ts));
    out
}

fn packets_of(out: &Out, c: &MqttConnection) -> Vec<MqttPacket> {
    out.packets
        .iter()
        .filter(|p| p.flow_id == c.flow_id)
        .cloned()
        .collect()
}

/// One line per connection and per stored packet (no secret).
fn render(out: &Out) -> String {
    let opt = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".to_owned());
    let mut s = String::new();
    for c in &out.conns {
        let _ = writeln!(
            s,
            "== {}:{} -> {}:{} v={} partial={} id={} user={} auth={} login={} code={:?} end={} \
             pub={}/{} bytes={}/{} subs={} pings={} stored={} malformed={} errors={} gaps={} \
             software={}",
            c.client.ip,
            c.client.port,
            c.server.ip,
            c.server.port,
            c.version.map_or("-", Version::label),
            c.partial,
            opt(&c.client_id),
            opt(&c.username),
            c.auth.map_or("-", AuthKind::as_str),
            c.login.map_or("-", Login::as_str),
            c.connack_code,
            c.end_kind.as_str(),
            c.publish_c2s,
            c.publish_s2c,
            c.payload_bytes_c2s,
            c.payload_bytes_s2c,
            c.subscribe_count,
            c.pings,
            c.stored_packets,
            c.malformed,
            c.protocol_errors,
            c.gaps,
            opt(&c.broker_software),
        );
        for p in packets_of(out, c) {
            let filters: Vec<String> = p
                .filters
                .iter()
                .map(|f| format!("{}:{:#04x}:{:?}", f.filter, f.options, f.granted))
                .collect();
            let _ = writeln!(
                s,
                "  {} {} {} id={:?} qos={:?} r={} d={} topic={} src={:?} alias={:?} size={} \
                 payload={:?} ack={:?}/{:?} reason={:?} filters=[{}] props={:?}",
                p.seq,
                p.dir.as_str(),
                p.ptype,
                p.packet_id,
                p.qos,
                p.retain,
                p.dup,
                opt(&p.topic),
                p.topic_source.map(TopicSource::as_str),
                p.topic_alias,
                p.size,
                p.payload_len,
                p.ack_state.map(AckState::as_str),
                p.ack_reason,
                p.reason_code,
                filters.join(","),
                p.props,
            );
        }
    }
    s
}

fn showcase() -> Scenario {
    let mut sc = Scenario::new();
    fx::mqtt_showcase(&mut sc);
    sc
}

#[test]
fn showcase_snapshot() {
    let out = records(&showcase());
    insta::assert_snapshot!(render(&out));
}

#[test]
fn showcase_counts() {
    let out = records(&showcase());
    assert_eq!(out.conns.len() as u64, SHOWCASE.connections);
    let count = |l: Option<Login>| out.conns.iter().filter(|c| c.login == l).count() as u64;
    assert_eq!(count(Some(Login::Accepted)), SHOWCASE.accepted);
    assert_eq!(count(Some(Login::Rejected)), SHOWCASE.rejected);
    assert_eq!(count(None), SHOWCASE.no_answer);
    // One credential per CONNECT carrying a user name (the attempts all differ).
    assert_eq!(out.creds.len() as u64, SHOWCASE.credentials);
    // The non-MQTT flows are not taken for MQTT.
    assert!(out.conns.iter().all(|c| c.server.port != 2000));
    assert!(
        out.conns
            .iter()
            .all(|c| c.client.ip != mqtt_hosts::legacy().ip || c.server.port == 1883)
    );
}

#[test]
fn sensor_qos_acks_will_and_subscription() {
    let mut sc = Scenario::new();
    fx::sensor_session(
        &mut sc,
        mqtt_hosts::sensor(),
        mqtt_hosts::broker(),
        "s3-fixture",
    );
    let out = records(&sc);
    let [c] = out.conns.as_slice() else {
        panic!("{:?}", out.conns)
    };
    assert_eq!(c.version, Some(Version::V311));
    assert_eq!(c.client_id.as_deref(), Some("sensor-01"));
    assert_eq!(c.keep_alive, Some(60));
    assert_eq!(
        c.will_topic.as_deref(),
        Some("plant/line1/sensor-01/status")
    );
    assert_eq!(c.will_payload.as_deref(), Some(&b"offline"[..]));
    assert_eq!((c.will_qos, c.will_retain), (Some(1), Some(true)));
    assert_eq!(c.auth, Some(AuthKind::Password));
    assert_eq!(c.login, Some(Login::Accepted));
    assert_eq!(c.end_kind, EndKind::Disconnect);
    assert_eq!(c.disconnect_by, Some(Dir::Client));
    assert_eq!(c.pings, 2);
    assert_eq!((c.publish_c2s, c.publish_s2c), (4, 1));
    // The password is there, never in Debug.
    assert_eq!(c.password.as_deref(), Some("s3-fixture"));
    assert!(!format!("{c:?}").contains("s3-fixture"));
    let packets = packets_of(&out, c);
    let publish: Vec<&MqttPacket> = packets
        .iter()
        .filter(|p| p.ptype == PacketType::Publish)
        .collect();
    let acks: Vec<_> = publish
        .iter()
        .map(|p| (p.topic.as_deref().unwrap(), p.ack_state))
        .collect();
    assert_eq!(
        acks,
        vec![
            ("plant/line1/temperature", Some(AckState::None)),
            ("plant/line1/humidity", Some(AckState::Acked)),
            ("plant/line1/alarm", Some(AckState::Acked)),
            ("plant/line1/sensor-01/status", Some(AckState::Acked)),
            ("plant/line1/sensor-01/cmd", Some(AckState::Acked)),
        ]
    );
    // Acknowledgements and pings are merged or counted, not stored.
    assert!(packets.iter().all(|p| !matches!(
        p.ptype,
        PacketType::Puback
            | PacketType::Pubrec
            | PacketType::Pubrel
            | PacketType::Pubcomp
            | PacketType::Suback
            | PacketType::Pingreq
            | PacketType::Pingresp
    )));
    let sub = packets
        .iter()
        .find(|p| p.ptype == PacketType::Subscribe)
        .unwrap();
    assert_eq!(sub.filters[0].granted, Some(1));
    assert_eq!(out.subs.len(), 1);
    assert_eq!(out.subs[0].granted, Some(1));
    assert!(!out.subs[0].wildcard);
    // Credential: plaintext, accepted.
    let [cred] = out.creds.as_slice() else {
        panic!()
    };
    assert_eq!(cred.kind, "mqtt");
    assert_eq!(cred.secret_state, SecretState::Plaintext);
    assert_eq!(cred.username.as_deref(), Some("sensor-01"));
    assert!(
        cred.details
            .contains(&("result".to_owned(), "accepted".to_owned()))
    );
    assert!(!format!("{cred:?}").contains("s3-fixture"));
}

#[test]
fn v5_properties_and_topic_aliases() {
    let mut sc = Scenario::new();
    fx::plc_session(
        &mut sc,
        mqtt_hosts::plc(),
        mqtt_hosts::broker(),
        "plc-fixture",
    );
    let out = records(&sc);
    let [c] = out.conns.as_slice() else { panic!() };
    assert_eq!(c.version, Some(Version::V5));
    assert_eq!(c.client_id.as_deref(), Some(""));
    assert_eq!(c.assigned_client_id.as_deref(), Some("auto-7f3a"));
    assert_eq!(c.session_expiry, Some(3600));
    assert!(
        c.connect_props
            .contains(&("user_property".to_owned(), "site: north".to_owned()))
    );
    assert_eq!(c.disconnect_by, Some(Dir::Broker));
    assert_eq!(c.disconnect_reason, Some(0x8E));
    assert_eq!(c.protocol_errors, 0);
    let packets = packets_of(&out, c);
    let aliases: Vec<_> = packets
        .iter()
        .filter(|p| p.ptype == PacketType::Publish && p.dir == Dir::Client)
        .map(|p| (p.topic.clone().unwrap(), p.topic_source.unwrap()))
        .collect();
    assert_eq!(
        aliases[..4],
        [
            ("plant/line2/pressure".to_owned(), TopicSource::Name),
            ("plant/line2/pressure".to_owned(), TopicSource::Alias),
            ("plant/line2/pressure".to_owned(), TopicSource::Alias),
            ("plant/line2/pressure".to_owned(), TopicSource::Alias),
        ]
    );
    let first = packets
        .iter()
        .find(|p| p.ptype == PacketType::Publish)
        .unwrap();
    assert_eq!(first.content_type.as_deref(), Some("application/json"));
    assert_eq!(first.payload_format, Some(1));
    let flow = packets
        .iter()
        .find(|p| p.topic.as_deref() == Some("plant/line2/flow"))
        .unwrap();
    assert_eq!(flow.ack_state, Some(AckState::Acked));
    assert_eq!(flow.ack_reason, Some(0x10));
    assert!(
        flow.props
            .iter()
            .any(|(k, v)| k == "correlation_data" && v.starts_with("deadbeef"))
    );
    // Topic aggregate: four messages on the aliased topic.
    let agg = out
        .topics
        .iter()
        .find(|t| t.topic.as_deref() == Some("plant/line2/pressure") && t.dir == Dir::Client)
        .unwrap();
    assert_eq!(agg.messages, 4);
    // Shared subscription.
    assert_eq!(out.subs[0].shared_group.as_deref(), Some("hmi"));
    assert_eq!(out.subs[1].options, 0x15);
}

#[test]
fn anonymous_legacy_and_wildcard_dashboard() {
    let mut sc = Scenario::new();
    fx::legacy_session(&mut sc, mqtt_hosts::legacy(), mqtt_hosts::cloud_broker());
    fx::dashboard_session(
        &mut sc,
        mqtt_hosts::dashboard(),
        mqtt_hosts::broker(),
        "d-fixture",
    );
    let out = records(&sc);
    let legacy = &out.conns[0];
    assert_eq!(legacy.version, Some(Version::V31));
    assert_eq!(legacy.protocol_name.as_deref(), Some("MQIsdp"));
    assert_eq!(legacy.auth, Some(AuthKind::None));
    assert_eq!(legacy.login, Some(Login::Accepted));
    let dash = &out.conns[1];
    assert_eq!(
        dash.broker_software.as_deref(),
        Some("mosquitto version 2.0.18")
    );
    let wild: Vec<_> = out
        .subs
        .iter()
        .filter(|s| s.flow_id == dash.flow_id)
        .map(|s| (s.filter.as_str(), s.wildcard, s.unsubscribed_ts.is_some()))
        .collect();
    assert_eq!(wild, vec![("#", true, false), ("$SYS/#", true, true)]);
    // The bidirectional control character of a topic payload stays in the payload bytes only.
    let note = out
        .packets
        .iter()
        .find(|p| p.topic.as_deref() == Some("plant/line1/note"))
        .unwrap();
    assert!(note.payload.as_ref().unwrap().starts_with(b"<script>"));
    assert!(out.creds.iter().all(|c| c.flow_id != Some(legacy.flow_id)));
}

#[test]
fn rejected_logins_and_username_only() {
    let mut sc = Scenario::new();
    fx::brute_force(
        &mut sc,
        mqtt_hosts::remote(),
        mqtt_hosts::broker(),
        &["g1-fixture", "g2-fixture", "g3-fixture", "g4-fixture"],
        "ok-fixture",
    );
    fx::gateway_session(&mut sc, mqtt_hosts::gateway(), mqtt_hosts::broker());
    let out = records(&sc);
    let codes: Vec<_> = out.conns.iter().map(|c| c.connack_code).collect();
    assert_eq!(
        codes,
        vec![Some(4), Some(4), Some(4), Some(0x86), Some(0), Some(0)]
    );
    let rejected: Vec<_> = out
        .creds
        .iter()
        .filter(|c| {
            c.details
                .contains(&("result".to_owned(), "rejected".to_owned()))
        })
        .collect();
    assert_eq!(rejected.len(), 4);
    let gw = out.conns.last().unwrap();
    assert_eq!(gw.server.port, fx::CUSTOM_PORT);
    assert_eq!(gw.auth, Some(AuthKind::Username));
    let cred = out.creds.last().unwrap();
    assert_eq!(cred.secret_state, SecretState::MetadataOnly);
    assert_eq!(cred.secret, None);
    // The accepted brute force ends without DISCONNECT.
    assert_eq!(out.conns[4].end_kind, EndKind::Close);
}

#[test]
fn large_and_split_messages() {
    let mut sc = Scenario::new();
    fx::gateway_session(&mut sc, mqtt_hosts::gateway(), mqtt_hosts::broker());
    let out = records(&sc);
    let [c] = out.conns.as_slice() else { panic!() };
    let topics: Vec<_> = packets_of(&out, c)
        .into_iter()
        .filter(|p| p.ptype == PacketType::Publish)
        .map(|p| {
            (
                p.topic.unwrap(),
                p.payload_len.unwrap(),
                p.payload.unwrap().len(),
            )
        })
        .collect();
    assert_eq!(
        topics,
        vec![
            (
                "firmware/gw-7/image".to_owned(),
                fx::LARGE_PAYLOAD as u64,
                512
            ),
            ("firmware/gw-7/state".to_owned(), 7, 7),
            ("firmware/gw-7/version".to_owned(), 5, 5),
        ]
    );
    assert_eq!(c.pings, 1);
    assert_eq!(c.malformed, 0);
}

#[test]
fn midstream_connection_on_1883() {
    let mut sc = Scenario::new();
    fx::midstream_session(
        &mut sc,
        mqtt_hosts::sensor(),
        mqtt_hosts::broker(),
        "x-fixture",
    );
    let out = records(&sc);
    let [c] = out.conns.as_slice() else {
        panic!("{:?}", out.conns)
    };
    assert!(c.partial);
    assert_eq!(c.version, Some(Version::V311));
    assert_eq!(c.client_id, None);
    assert_eq!(c.login, None);
    let packets = packets_of(&out, c);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].ack_state, Some(AckState::Acked));
    assert_eq!(out.creds.len(), 0);
}

#[test]
fn not_mqtt_is_ignored() {
    let mut sc = Scenario::new();
    fx::not_mqtt(&mut sc, mqtt_hosts::legacy(), mqtt_hosts::broker());
    // A TLS ClientHello-like start on 1883 and an HTTP request on 8080.
    let mut s = sc.tcp_open(
        mqtt_hosts::legacy(),
        mqtt_hosts::broker(),
        &TcpOptions::new(8080),
    );
    s.client_send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    s.close();
    let out = records(&sc);
    assert!(out.conns.is_empty(), "{:?}", out.conns);
}

#[test]
fn lost_segment_resynchronizes() {
    let mut sc = Scenario::new();
    fx::lossy_session(&mut sc, mqtt_hosts::sensor(), mqtt_hosts::broker());
    let out = records(&sc);
    let [c] = out.conns.as_slice() else { panic!() };
    assert!(c.gaps >= 1, "{c:?}");
    let topics: Vec<_> = packets_of(&out, c)
        .into_iter()
        .filter_map(|p| p.topic)
        .collect();
    assert_eq!(topics, vec!["loss/a".to_owned(), "loss/c".to_owned()]);
    assert_eq!(c.end_kind, EndKind::Disconnect);
}

#[test]
fn stored_packets_are_bounded() {
    let mut sc = Scenario::new();
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(
        mqtt_hosts::sensor(),
        mqtt_hosts::broker(),
        &TcpOptions::new(1883),
    );
    s.client_send(&ConnectSpec::v311("bulk").encode());
    s.server_send(&m.connack(false, 0, None));
    let mut burst = Vec::new();
    for i in 0..10_050u32 {
        burst.extend(m.publish(&format!("bulk/{}", i % 3), b"x"));
    }
    s.client_send(&burst);
    s.close();
    let out = records(&sc);
    let [c] = out.conns.as_slice() else { panic!() };
    assert!(c.packets_truncated);
    assert_eq!(c.stored_packets, super::MAX_STORED);
    assert_eq!(c.publish_c2s, 10_050);
    let total: u64 = out.topics.iter().map(|t| t.messages).sum();
    assert_eq!(total, 10_050);
}

#[test]
fn hostile_stream_never_panics() {
    let mut x: u32 = 0x9e37_79b9;
    for round in 0..200 {
        let mut sc = Scenario::new();
        let mut s = sc.tcp_open(
            mqtt_hosts::sensor(),
            mqtt_hosts::broker(),
            &TcpOptions::new(1883),
        );
        let mut data = ConnectSpec::v311("fuzz").encode();
        for _ in 0..(64 + round) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            data.push((x & 0xff) as u8);
        }
        s.client_send(&data);
        s.server_send(&data[..data.len() / 2]);
        s.close();
        let _ = records(&sc);
    }
}

#[test]
fn secrets_are_rendered_as_text_or_hex() {
    assert_eq!(render_secret(b"plain"), ("plain".to_owned(), "utf8"));
    assert_eq!(render_secret(&[0, 255]), ("hex:00ff".to_owned(), "hex"));
}

/// Runs `sc` through an analyzer built with `config`, returns the records and the analyzer
/// (its budgets, once every connection ended).
fn records_with(sc: &Scenario, config: &AnalyzerConfig) -> (Out, MqttAnalyzer) {
    let mut analyzer = MqttAnalyzer::new(config);
    let mut out = Out::default();
    for r in run(&mut analyzer, sc.packets()) {
        match r {
            Record::Mqtt(MqttRecord::Connection(c)) => out.conns.push(*c),
            Record::Mqtt(MqttRecord::Packet(p)) => out.packets.push(*p),
            Record::Mqtt(MqttRecord::Topic(t)) => out.topics.push(t),
            Record::Mqtt(MqttRecord::Subscription(s)) => out.subs.push(s),
            Record::Credential(c) => out.creds.push(c),
            other => panic!("unexpected record {other:?}"),
        }
    }
    out.packets.sort_by_key(|p| (p.flow_id, p.seq));
    (out, analyzer)
}

fn initial_budgets(config: &AnalyzerConfig) -> (usize, usize, usize) {
    (
        config.mqtt.max_pending_bytes,
        config.mqtt.max_buffer_bytes,
        config.mqtt.max_state_bytes,
    )
}

#[test]
fn state_budget_sends_topics_to_the_other_bucket_and_is_given_back() {
    let mut config = AnalyzerConfig::default();
    // Room for two topics of the burst below, not more.
    config.mqtt.max_state_bytes = 2 * (super::conn::ENTRY_COST + 8);
    let mut sc = Scenario::new();
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(
        mqtt_hosts::sensor(),
        mqtt_hosts::broker(),
        &TcpOptions::new(1883),
    );
    s.client_send(&ConnectSpec::v311("many").encode());
    s.server_send(&m.connack(false, 0, None));
    s.client_send(&m.subscribe(1, &[("cmd/#", 0)], None));
    s.server_send(&m.suback(1, &[0]));
    for i in 0..10 {
        s.client_send(&m.publish(&format!("t/{i:05}"), b"x"));
    }
    s.close();
    let (out, analyzer) = records_with(&sc, &config);
    let [c] = out.conns.as_slice() else { panic!() };
    assert!(c.state_dropped >= 8, "{c:?}");
    let named = out.topics.iter().filter(|t| t.topic.is_some()).count();
    assert!(named <= 2, "{:?}", out.topics);
    let other = out.topics.iter().find(|t| t.topic.is_none()).unwrap();
    assert_eq!(other.messages + named as u64, 10);
    // Every byte is given back once the connection ends.
    assert_eq!(analyzer.shared.budgets(), initial_budgets(&config));
}

#[test]
fn buffer_budget_decodes_large_packets_from_a_short_prefix() {
    let mut config = AnalyzerConfig::default();
    config.mqtt.max_buffer_bytes = 0;
    let mut sc = Scenario::new();
    fx::gateway_session(&mut sc, mqtt_hosts::gateway(), mqtt_hosts::broker());
    let (out, analyzer) = records_with(&sc, &config);
    let image = out
        .packets
        .iter()
        .find(|p| p.topic.as_deref() == Some("firmware/gw-7/image"))
        .unwrap();
    assert_eq!(image.payload_len, Some(fx::LARGE_PAYLOAD as u64));
    assert_eq!(image.payload.as_ref().unwrap().len(), 512);
    // The following packets stay aligned.
    assert!(
        out.packets
            .iter()
            .any(|p| p.topic.as_deref() == Some("firmware/gw-7/version"))
    );
    assert_eq!(analyzer.shared.budgets(), initial_budgets(&config));
}

#[test]
fn pending_bounds_emit_without_waiting() {
    // No pending budget: a QoS 1 PUBLISH is emitted at once, its PUBACK stored on its own.
    let mut config = AnalyzerConfig::default();
    config.mqtt.max_pending_bytes = 0;
    let mut sc = Scenario::new();
    fx::sensor_session(
        &mut sc,
        mqtt_hosts::sensor(),
        mqtt_hosts::broker(),
        "p-fixture",
    );
    let (out, analyzer) = records_with(&sc, &config);
    let humidity = out
        .packets
        .iter()
        .find(|p| p.topic.as_deref() == Some("plant/line1/humidity"))
        .unwrap();
    assert_eq!(humidity.ack_state, Some(AckState::Missing));
    assert!(out.packets.iter().any(|p| p.ptype == PacketType::Puback));
    assert_eq!(analyzer.shared.budgets(), initial_budgets(&config));

    // More unacknowledged packets than `MAX_PENDING`: the excess is emitted at once, the rest at
    // the end; every one is stored once.
    let mut sc = Scenario::new();
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(
        mqtt_hosts::sensor(),
        mqtt_hosts::broker(),
        &TcpOptions::new(1883),
    );
    s.client_send(&ConnectSpec::v311("burst").encode());
    s.server_send(&m.connack(false, 0, None));
    let count = super::conn::MAX_PENDING + 50;
    let mut burst = Vec::new();
    for i in 0..count {
        let id = u16::try_from(i + 1).unwrap();
        burst.extend(m.publish_with("q/1", Some(id), 1, false, false, None, b"x"));
    }
    s.client_send(&burst);
    s.close();
    let config = AnalyzerConfig::default();
    let (out, analyzer) = records_with(&sc, &config);
    let publishes: Vec<_> = out
        .packets
        .iter()
        .filter(|p| p.ptype == PacketType::Publish)
        .collect();
    assert_eq!(publishes.len(), count);
    assert!(
        publishes
            .iter()
            .all(|p| p.ack_state == Some(AckState::Missing))
    );
    assert_eq!(analyzer.shared.budgets(), initial_budgets(&config));
}

#[test]
fn probe_of_one_byte_segments_is_bounded() {
    // A CONNECT announcing 60 000 bytes, sent one byte per segment on 1883: given up after
    // `PROBE_MAX_SEGMENTS` segments, without quadratic copies.
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        mqtt_hosts::sensor(),
        mqtt_hosts::broker(),
        &TcpOptions::new(1883),
    );
    let mut connect = vec![0x10];
    connect.extend(netsift_fixtures::mqtt::wire::varint(60_000));
    connect.extend(netsift_fixtures::mqtt::wire::string("MQTT"));
    connect.extend([4, 2, 0, 60]);
    connect.resize(2_000, b'a');
    for b in connect {
        s.client_send(&[b]);
    }
    s.close();
    let start = std::time::Instant::now();
    let (out, analyzer) = records_with(&sc, &AnalyzerConfig::default());
    assert_eq!(out.conns.len(), 0);
    assert_eq!(analyzer.probe_bytes, 0);
    assert!(start.elapsed() < std::time::Duration::from_secs(20));

    // A probe budget smaller than one segment: nothing is probed, nothing is held.
    let mut config = AnalyzerConfig::default();
    config.mqtt.max_probe_bytes = 16;
    let mut sc = Scenario::new();
    fx::sensor_session(
        &mut sc,
        mqtt_hosts::sensor(),
        mqtt_hosts::broker(),
        "b-fixture",
    );
    let (out, analyzer) = records_with(&sc, &config);
    assert_eq!(out.conns.len(), 0);
    assert_eq!(analyzer.probe_bytes, 0);
}

#[test]
fn cleaned_text_stays_within_its_bound() {
    let controls = "\u{1}".repeat(300);
    let cleaned = super::clean(&controls);
    assert!(cleaned.len() <= 300);
    assert!(cleaned.chars().all(|c| c == char::REPLACEMENT_CHARACTER));
    // A short value is never emptied.
    assert_eq!(super::clean("\u{1}"), "\u{fffd}");
    assert_eq!(super::clean("a/\u{202e}b"), "a/\u{fffd}b");
}
