use netsift_fixtures::mqtt::wire::{self, ConnectSpec, Mqtt, Props, WillSpec, prop};

use super::*;

/// Fixed header and body of one encoded packet.
fn split(bytes: &[u8]) -> (FixedHeader, &[u8]) {
    let HeaderStatus::Valid(h) = fixed_header(bytes) else {
        panic!("invalid header: {bytes:?}");
    };
    (h, &bytes[usize::from(h.header_len)..])
}

fn parse(bytes: &[u8], version: Version) -> Result<Packet, ParseError> {
    let (h, body) = split(bytes);
    parse_packet(h, body, version)
}

#[test]
fn fixed_header_lengths_and_flags() {
    assert_eq!(fixed_header(&[]), HeaderStatus::Incomplete);
    assert_eq!(fixed_header(&[0x30]), HeaderStatus::Incomplete);
    assert_eq!(fixed_header(&[0x30, 0x80]), HeaderStatus::Incomplete);
    // Reserved type 0, wrong imposed flags, QoS 3.
    assert_eq!(fixed_header(&[0x00, 0]), HeaderStatus::Invalid);
    assert_eq!(fixed_header(&[0x80, 0]), HeaderStatus::Invalid);
    assert_eq!(fixed_header(&[0x11, 0]), HeaderStatus::Invalid);
    assert_eq!(fixed_header(&[0x36, 0]), HeaderStatus::Invalid);
    // Five bytes of length.
    assert_eq!(
        fixed_header(&[0x30, 0xff, 0xff, 0xff, 0xff, 0x01]),
        HeaderStatus::Invalid
    );
    let HeaderStatus::Valid(max) = fixed_header(&[0x3d, 0xff, 0xff, 0xff, 0x7f]) else {
        panic!()
    };
    assert_eq!(max.remaining, MAX_REMAINING);
    assert_eq!(max.header_len, 5);
    assert_eq!((max.qos(), max.retain(), max.dup()), (2, true, true));
    for n in [
        0u32,
        127,
        128,
        16_383,
        16_384,
        2_097_151,
        2_097_152,
        MAX_REMAINING,
    ] {
        let mut b = vec![0xC0];
        b.extend(wire::varint(n));
        let HeaderStatus::Valid(h) = fixed_header(&b) else {
            panic!("{n}")
        };
        assert_eq!(h.remaining, n);
        assert_eq!(usize::from(h.header_len), b.len());
    }
}

#[test]
fn connect_of_each_version() {
    let v31 = ConnectSpec::v31("legacy").encode();
    let Ok(Packet::Connect(c)) = parse(&v31, Version::V311) else {
        panic!()
    };
    assert_eq!(c.version, Some(Version::V31));
    assert_eq!(c.protocol_name, "MQIsdp");
    assert!(c.exact && c.clean_start && c.username.is_none());

    let mut spec = ConnectSpec::v311("sensor-01").login("user", Some("pass-fixture"));
    spec.will = Some(WillSpec {
        topic: "a/status".into(),
        payload: b"offline".to_vec(),
        qos: 1,
        retain: true,
        props: Props::new(),
    });
    spec.keep_alive = 30;
    let Ok(Packet::Connect(c)) = parse(&spec.encode(), Version::V5) else {
        panic!()
    };
    assert_eq!(c.version, Some(Version::V311));
    assert_eq!(c.keep_alive, 30);
    assert_eq!(c.client_id.value, "sensor-01");
    assert_eq!(c.username.as_ref().unwrap().value, "user");
    assert_eq!(c.password.as_deref(), Some(&b"pass-fixture"[..]));
    let will = c.will.as_ref().unwrap();
    assert_eq!(
        (will.topic.value.as_str(), will.qos, will.retain),
        ("a/status", 1, true)
    );
    assert_eq!(will.payload.bytes, b"offline");
    assert!(c.exact);
    // The password never reaches Debug.
    assert!(!format!("{c:?}").contains("pass-fixture"));

    let mut v5 = ConnectSpec::v5("").login("plc", Some("x"));
    v5.props = Props::new()
        .u32(prop::SESSION_EXPIRY, 3600)
        .u16(prop::TOPIC_ALIAS_MAXIMUM, 10)
        .pair(prop::USER_PROPERTY, "site", "north")
        .bin(0x16, b"secret auth data")
        .str(0x15, "SCRAM-SHA-256");
    let Ok(Packet::Connect(c)) = parse(&v5.encode(), Version::V311) else {
        panic!()
    };
    assert_eq!(c.version, Some(Version::V5));
    assert_eq!(c.properties.session_expiry, Some(3600));
    assert_eq!(c.properties.topic_alias_maximum, Some(10));
    assert_eq!(c.properties.auth_method.as_deref(), Some("SCRAM-SHA-256"));
    assert_eq!(c.properties.auth_data_len, Some(16));
    assert_eq!(
        c.properties.user_properties,
        vec![("site".to_owned(), "north".to_owned())]
    );
    assert!(c.client_id.value.is_empty() && c.exact);
}

#[test]
fn connect_rules() {
    // Bridge bit on the level.
    let mut spec = ConnectSpec::v311("bridge");
    spec.level = 0x84;
    let Ok(Packet::Connect(c)) = parse(&spec.encode(), Version::V311) else {
        panic!()
    };
    assert!(c.bridge);
    assert_eq!(c.version, Some(Version::V311));
    // Password without user name: a protocol error in 3.1.1, allowed in 5.0.
    let mut spec = ConnectSpec::v311("p");
    spec.password = Some(b"pw".to_vec());
    let Ok(Packet::Connect(c)) = parse(&spec.encode(), Version::V311) else {
        panic!()
    };
    assert!(c.protocol_error);
    let mut spec = ConnectSpec::v5("p");
    spec.password = Some(b"pw".to_vec());
    let Ok(Packet::Connect(c)) = parse(&spec.encode(), Version::V311) else {
        panic!()
    };
    assert!(!c.protocol_error);
    // Wrong name for the level, unknown level.
    let mut spec = ConnectSpec::v311("x");
    spec.name = "MQIsdp";
    assert_eq!(
        parse(&spec.encode(), Version::V311),
        Err(ParseError::Unsupported)
    );
    let mut spec = ConnectSpec::v311("x");
    spec.level = 6;
    assert_eq!(
        parse(&spec.encode(), Version::V311),
        Err(ParseError::Unsupported)
    );
    // Reserved flag bit, will QoS 3, will QoS without will.
    for flags in [0x03, 0x1E, 0x08, 0x20] {
        let mut body = wire::string("MQTT");
        body.extend([4, flags, 0, 60]);
        body.extend(wire::string("c"));
        if flags & 0x04 != 0 {
            body.extend(wire::string("t"));
            body.extend(wire::binary(b"p"));
        }
        let bytes = wire::packet(0x10, &body);
        assert_eq!(
            parse(&bytes, Version::V311),
            Err(ParseError::Malformed),
            "{flags:#x}"
        );
    }
    // Trailing byte: decoded, but not exact.
    let mut body = ConnectSpec::v311("c").encode();
    body.push(0);
    body[1] += 1;
    let Ok(Packet::Connect(c)) = parse(&body, Version::V311) else {
        panic!()
    };
    assert!(!c.exact);
    assert_eq!(starts_connect(&body), Some(false));
}

#[test]
fn detection_of_a_first_connect() {
    let connect = ConnectSpec::v311("c").login("u", Some("p")).encode();
    assert_eq!(starts_connect(&connect), Some(true));
    // Undecided until the packet is complete.
    for n in 1..connect.len() {
        assert_eq!(starts_connect(&connect[..n]), None, "{n}");
    }
    assert_eq!(starts_connect(b"GET / HTTP/1.1\r\n"), Some(false));
    assert_eq!(starts_connect(&[0x16, 0x03, 0x01]), Some(false));
    assert_eq!(starts_connect(&[0x30, 2, 0, 0]), Some(false));
    let mut fake = vec![0x10, 12];
    fake.extend(wire::string("HTTP"));
    fake.extend([4, 2, 0, 60, 0, 2, b'x', b'y']);
    assert_eq!(starts_connect(&fake), Some(false));
    // A CONNECT longer than the decoded prefix (large will message) is judged on its start.
    let mut spec = ConnectSpec::v311("big");
    spec.will = Some(WillSpec {
        topic: "w".into(),
        payload: vec![7; 60_000],
        qos: 0,
        retain: false,
        props: Props::new(),
    });
    let mut big = spec.encode();
    assert_eq!(starts_connect(&big), Some(true));
    big.truncate(1000);
    assert_eq!(starts_connect(&big), None);
}

#[test]
fn connack_and_reason_codes() {
    let Ok(Packet::Connack(c)) = parse(&Mqtt::V311.connack(true, 4, None), Version::V311) else {
        panic!()
    };
    assert!(c.session_present);
    assert_eq!(c.code, 4);
    let props = Props::new()
        .str(prop::ASSIGNED_CLIENT_ID, "auto-1")
        .byte(prop::MAXIMUM_QOS, 1)
        .str(prop::REASON_STRING, "ok");
    let Ok(Packet::Connack(c)) = parse(&Mqtt::V5.connack(false, 0x86, Some(&props)), Version::V5)
    else {
        panic!()
    };
    assert_eq!(c.code, 0x86);
    assert_eq!(c.properties.assigned_client_id.as_deref(), Some("auto-1"));
    assert_eq!(c.properties.maximum_qos, Some(1));
    assert_eq!(c.properties.reason_string.as_deref(), Some("ok"));
    // Reserved acknowledge flags.
    assert_eq!(
        parse(&[0x20, 2, 0x02, 0], Version::V311),
        Err(ParseError::Malformed)
    );
}

#[test]
fn publish_qos_and_properties() {
    let m = Mqtt::V311;
    let Ok(Packet::Publish(p)) = parse(&m.publish("a/b", b"hello"), Version::V311) else {
        panic!()
    };
    assert_eq!(p.topic.value, "a/b");
    assert_eq!(p.packet_id, None);
    assert_eq!(p.payload.bytes, b"hello");
    assert_eq!(p.payload.len, 5);
    let bytes = m.publish_with("a", Some(7), 2, true, true, None, b"x");
    let (h, _) = split(&bytes);
    assert_eq!((h.qos(), h.retain(), h.dup()), (2, true, true));
    let Ok(Packet::Publish(p)) = parse(&bytes, Version::V311) else {
        panic!()
    };
    assert_eq!(p.packet_id, Some(7));
    // Packet id 0 and wildcards are not allowed.
    assert_eq!(
        parse(
            &m.publish_with("a", Some(0), 1, false, false, None, b""),
            Version::V311
        ),
        Err(ParseError::Malformed)
    );
    assert_eq!(
        parse(&m.publish("a/#", b""), Version::V311),
        Err(ParseError::Malformed)
    );

    let props = Props::new()
        .u16(prop::TOPIC_ALIAS, 1)
        .str(prop::CONTENT_TYPE, "application/json")
        .byte(prop::PAYLOAD_FORMAT, 1)
        .u32(prop::MESSAGE_EXPIRY, 30)
        .str(prop::RESPONSE_TOPIC, "r")
        .bin(prop::CORRELATION_DATA, &[1; 40])
        .varint(prop::SUBSCRIPTION_ID, 300);
    let bytes = Mqtt::V5.publish_with("", None, 0, false, false, Some(&props), b"{}");
    let Ok(Packet::Publish(p)) = parse(&bytes, Version::V5) else {
        panic!()
    };
    assert_eq!(p.topic.value, "");
    let pr = &p.properties;
    assert_eq!(pr.topic_alias, Some(1));
    assert_eq!(pr.content_type.as_deref(), Some("application/json"));
    assert_eq!(pr.payload_format, Some(1));
    assert_eq!(pr.message_expiry, Some(30));
    assert_eq!(pr.response_topic.as_deref(), Some("r"));
    let corr = pr.correlation_data.as_ref().unwrap();
    assert_eq!((corr.bytes.len(), corr.len), (MAX_CORRELATION, 40));
    assert_eq!(pr.subscription_ids, vec![300]);
    assert_eq!(p.payload.bytes, b"{}");
    // The same bytes read as 3.1.1: the property length is payload.
    let Ok(Packet::Publish(p)) = parse(&bytes, Version::V311) else {
        panic!()
    };
    assert!(p.payload.len > 2);
}

#[test]
fn large_publish_from_a_prefix() {
    let payload = vec![0xAB; 1_000_000];
    let bytes = Mqtt::V311.publish("big/file", &payload);
    let (h, body) = split(&bytes);
    let prefix = &body[..MAX_PACKET_PREFIX];
    let Ok(Packet::Publish(p)) = parse_packet(h, prefix, Version::V311) else {
        panic!()
    };
    assert_eq!(p.topic.value, "big/file");
    assert_eq!(p.payload.len, 1_000_000);
    assert_eq!(p.payload.bytes.len(), MAX_EXCERPT);
}

#[test]
#[allow(clippy::many_single_char_names)]
fn acks_subscriptions_and_disconnect() {
    let m = Mqtt::V5;
    let Ok(Packet::Puback(a)) = parse(&m.ack(4, 9, Some(0x10)), Version::V5) else {
        panic!()
    };
    assert_eq!((a.packet_id, a.reason), (9, Some(0x10)));
    let Ok(Packet::Pubrel(a)) = parse(&Mqtt::V311.ack(6, 3, None), Version::V311) else {
        panic!()
    };
    assert_eq!((a.packet_id, a.reason), (3, None));

    let bytes = m.subscribe(
        1,
        &[("$share/g/a/+", 1), ("b/#", 0x15)],
        Some(&Props::new().varint(prop::SUBSCRIPTION_ID, 4)),
    );
    let Ok(Packet::Subscribe(s)) = parse(&bytes, Version::V5) else {
        panic!()
    };
    assert_eq!(s.packet_id, 1);
    assert_eq!(s.properties.subscription_ids, vec![4]);
    assert_eq!(s.filters.len(), 2);
    assert_eq!(s.filters[1].filter.value, "b/#");
    assert_eq!(s.filters[1].qos(), 1);
    assert_eq!(s.filters[1].options, 0x15);
    // 5.0 options are reserved bits in 3.1.1.
    let v3 = Mqtt::V311.subscribe(1, &[("b/#", 0x15)], None);
    assert_eq!(parse(&v3, Version::V311), Err(ParseError::Malformed));
    let Ok(Packet::Suback(s)) = parse(&m.suback(1, &[1, 0x87]), Version::V5) else {
        panic!()
    };
    assert_eq!(s.codes, vec![1, 0x87]);
    let Ok(Packet::Unsubscribe(u)) = parse(&m.unsubscribe(2, &["a", "b"]), Version::V5) else {
        panic!()
    };
    assert_eq!(u.filters.len(), 2);
    let Ok(Packet::Unsuback(u)) = parse(&Mqtt::V311.unsuback(2, &[]), Version::V311) else {
        panic!()
    };
    assert_eq!(u.codes, Vec::<u8>::new());

    let reason = Props::new().str(prop::REASON_STRING, "taken over");
    let Ok(Packet::Disconnect(d)) = parse(&m.disconnect(Some(0x8E), Some(&reason)), Version::V5)
    else {
        panic!()
    };
    assert_eq!(d.reason, Some(0x8E));
    assert_eq!(d.properties.reason_string.as_deref(), Some("taken over"));
    assert!(matches!(
        parse(&[0xC0, 0], Version::V311),
        Ok(Packet::Pingreq)
    ));
    assert!(matches!(
        parse(&[0xD0, 0], Version::V311),
        Ok(Packet::Pingresp)
    ));
    // AUTH exists in 5.0 only.
    assert_eq!(
        parse(&[0xF0, 0], Version::V311),
        Err(ParseError::Unsupported)
    );
    assert!(matches!(
        parse(&[0xF0, 0], Version::V5),
        Ok(Packet::Auth(_))
    ));
}

#[test]
fn hostile_inputs() {
    // String longer than the packet.
    assert_eq!(
        parse(&[0x30, 3, 0, 9, b'a'], Version::V311),
        Err(ParseError::Malformed)
    );
    // Invalid UTF-8 and U+0000 in a topic.
    assert_eq!(
        parse(&[0x30, 5, 0, 2, 0xff, 0xfe, b'x'], Version::V311),
        Err(ParseError::Malformed)
    );
    assert_eq!(
        parse(&[0x30, 4, 0, 2, b'a', 0], Version::V311),
        Err(ParseError::Malformed)
    );
    // Property length past the packet, unknown property id (kept as an error flag).
    assert_eq!(
        parse(&[0x30, 5, 0, 1, b'a', 0x7f, 1], Version::V5),
        Err(ParseError::Malformed)
    );
    let Ok(Packet::Publish(p)) = parse(&[0x30, 7, 0, 1, b'a', 2, 0x7e, 0, b'p'], Version::V5)
    else {
        panic!()
    };
    assert!(p.properties.error);
    assert_eq!(p.payload.bytes, b"p");
    // Property varint of five bytes.
    assert_eq!(
        parse(
            &[0x30, 9, 0, 1, b'a', 0xff, 0xff, 0xff, 0xff, 0x01, 0],
            Version::V5
        ),
        Err(ParseError::Malformed)
    );
    // Empty SUBSCRIBE filter, QoS 3 option.
    assert_eq!(
        parse(&[0x82, 5, 0, 1, 0, 0, 0], Version::V311),
        Err(ParseError::Malformed)
    );
    assert_eq!(
        parse(&[0x82, 6, 0, 1, 0, 1, b'a', 3], Version::V311),
        Err(ParseError::Malformed)
    );
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut x: u32 = 0x1234_5678;
    for _ in 0..20_000 {
        let mut buf = Vec::new();
        for _ in 0..(x % 48) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            buf.push((x & 0xff) as u8);
        }
        if let HeaderStatus::Valid(h) = fixed_header(&buf) {
            let body = buf.get(usize::from(h.header_len)..).unwrap_or_default();
            for v in [Version::V31, Version::V311, Version::V5] {
                let _ = parse_packet(h, body, v);
            }
        }
        let _ = starts_connect(&buf);
    }
}
