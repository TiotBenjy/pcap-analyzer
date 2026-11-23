//! MQTT connections (TCP 1883 and a non-standard port) for the MQTT view: an encoder of control
//! packets for MQTT 3.1 (`MQIsdp`), 3.1.1 and 5.0 ([`wire`]), and scenarios: telemetry with every
//! `QoS` and a will message, a 5.0 client with properties and topic aliases, an anonymous legacy
//! client of a public broker, a dashboard subscribed to `#` and `$SYS/#`, repeated rejected
//! logins from a public address then an accepted one, a username-only gateway on port 11883 with a
//! 1 MiB message, a connection whose start was not captured, and non-MQTT traffic that must not
//! be taken for MQTT.
//!
//! Hosts are invented: RFC 1918 addresses, and two arbitrary addresses of public space for the
//! remote broker and the remote client (no meaning attached). Every password is a fake,
//! fixture-only value.

use crate::packet::Host;
use crate::scenario::{Scenario, TcpOptions, TcpSession};
use crate::time::NS_PER_MS;

/// MQTT port.
pub const PORT: u16 = 1883;
/// Port of the gateway's broker (detected by its CONNECT).
pub const CUSTOM_PORT: u16 = 11883;

/// Encoder of MQTT control packets (OASIS MQTT 3.1.1 and 5.0).
pub mod wire {
    /// Variable byte integer.
    pub fn varint(mut n: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = u8::try_from(n % 128).expect("below 128");
            n /= 128;
            if n > 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                return out;
            }
        }
    }

    /// Two-byte length, then the bytes.
    pub fn binary(b: &[u8]) -> Vec<u8> {
        let len = u16::try_from(b.len()).expect("field fits in 65535 bytes");
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(b);
        out
    }

    /// UTF-8 string field.
    pub fn string(s: &str) -> Vec<u8> {
        binary(s.as_bytes())
    }

    /// A packet: first byte (type and flags), remaining length, body.
    pub fn packet(first: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![first];
        out.extend(varint(u32::try_from(body.len()).expect("packet fits")));
        out.extend_from_slice(body);
        out
    }

    /// MQTT 5.0 property list builder.
    #[derive(Debug, Clone, Default)]
    pub struct Props(Vec<u8>);

    impl Props {
        pub fn new() -> Self {
            Self::default()
        }

        #[must_use]
        pub fn byte(mut self, id: u8, v: u8) -> Self {
            self.0.extend([id, v]);
            self
        }

        #[must_use]
        pub fn u16(mut self, id: u8, v: u16) -> Self {
            self.0.push(id);
            self.0.extend(v.to_be_bytes());
            self
        }

        #[must_use]
        pub fn u32(mut self, id: u8, v: u32) -> Self {
            self.0.push(id);
            self.0.extend(v.to_be_bytes());
            self
        }

        #[must_use]
        pub fn varint(mut self, id: u8, v: u32) -> Self {
            self.0.push(id);
            self.0.extend(varint(v));
            self
        }

        #[must_use]
        pub fn str(mut self, id: u8, v: &str) -> Self {
            self.0.push(id);
            self.0.extend(string(v));
            self
        }

        #[must_use]
        pub fn bin(mut self, id: u8, v: &[u8]) -> Self {
            self.0.push(id);
            self.0.extend(binary(v));
            self
        }

        #[must_use]
        pub fn pair(mut self, id: u8, k: &str, v: &str) -> Self {
            self.0.push(id);
            self.0.extend(string(k));
            self.0.extend(string(v));
            self
        }

        /// Length then properties.
        pub fn encode(&self) -> Vec<u8> {
            let mut out = varint(u32::try_from(self.0.len()).expect("properties fit"));
            out.extend_from_slice(&self.0);
            out
        }
    }

    /// Will message of a CONNECT.
    #[derive(Debug, Clone)]
    pub struct WillSpec {
        pub topic: String,
        pub payload: Vec<u8>,
        pub qos: u8,
        pub retain: bool,
        pub props: Props,
    }

    /// Fields of a CONNECT.
    #[derive(Debug, Clone)]
    pub struct ConnectSpec {
        /// `MQIsdp` (level 3) or `MQTT` (4, 5).
        pub name: &'static str,
        pub level: u8,
        pub client_id: String,
        pub clean: bool,
        pub keep_alive: u16,
        pub username: Option<String>,
        pub password: Option<Vec<u8>>,
        pub will: Option<WillSpec>,
        pub props: Props,
    }

    impl ConnectSpec {
        /// MQTT 3.1.1 CONNECT with a clean session and a 60 s keep alive.
        pub fn v311(client_id: &str) -> Self {
            Self {
                name: "MQTT",
                level: 4,
                client_id: client_id.to_owned(),
                clean: true,
                keep_alive: 60,
                username: None,
                password: None,
                will: None,
                props: Props::new(),
            }
        }

        /// MQTT 5.0 CONNECT.
        pub fn v5(client_id: &str) -> Self {
            Self {
                level: 5,
                ..Self::v311(client_id)
            }
        }

        /// MQTT 3.1 CONNECT (`MQIsdp`).
        pub fn v31(client_id: &str) -> Self {
            Self {
                name: "MQIsdp",
                level: 3,
                ..Self::v311(client_id)
            }
        }

        #[must_use]
        pub fn login(mut self, user: &str, password: Option<&str>) -> Self {
            self.username = Some(user.to_owned());
            self.password = password.map(|p| p.as_bytes().to_vec());
            self
        }

        fn is_v5(&self) -> bool {
            self.level & 0x7F == 5
        }

        pub fn encode(&self) -> Vec<u8> {
            let mut body = string(self.name);
            body.push(self.level);
            let mut flags = 0u8;
            if self.clean {
                flags |= 0x02;
            }
            if let Some(w) = &self.will {
                flags |= 0x04 | (w.qos << 3);
                if w.retain {
                    flags |= 0x20;
                }
            }
            if self.password.is_some() {
                flags |= 0x40;
            }
            if self.username.is_some() {
                flags |= 0x80;
            }
            body.push(flags);
            body.extend(self.keep_alive.to_be_bytes());
            if self.is_v5() {
                body.extend(self.props.encode());
            }
            body.extend(string(&self.client_id));
            if let Some(w) = &self.will {
                if self.is_v5() {
                    body.extend(w.props.encode());
                }
                body.extend(string(&w.topic));
                body.extend(binary(&w.payload));
            }
            if let Some(u) = &self.username {
                body.extend(string(u));
            }
            if let Some(p) = &self.password {
                body.extend(binary(p));
            }
            packet(0x10, &body)
        }
    }

    /// Encoder for one protocol version (5.0 adds properties and reason codes).
    #[derive(Debug, Clone, Copy)]
    pub struct Mqtt {
        pub v5: bool,
    }

    impl Mqtt {
        pub const V311: Self = Self { v5: false };
        pub const V5: Self = Self { v5: true };

        fn props(self, props: Option<&Props>) -> Vec<u8> {
            if self.v5 {
                props.cloned().unwrap_or_default().encode()
            } else {
                Vec::new()
            }
        }

        pub fn connack(self, session_present: bool, code: u8, props: Option<&Props>) -> Vec<u8> {
            let mut body = vec![u8::from(session_present), code];
            body.extend(self.props(props));
            packet(0x20, &body)
        }

        #[allow(clippy::too_many_arguments)]
        pub fn publish_with(
            self,
            topic: &str,
            packet_id: Option<u16>,
            qos: u8,
            retain: bool,
            dup: bool,
            props: Option<&Props>,
            payload: &[u8],
        ) -> Vec<u8> {
            let mut first = 0x30 | (qos << 1);
            if retain {
                first |= 1;
            }
            if dup {
                first |= 8;
            }
            let mut body = string(topic);
            if let Some(id) = packet_id {
                body.extend(id.to_be_bytes());
            }
            body.extend(self.props(props));
            body.extend_from_slice(payload);
            packet(first, &body)
        }

        /// `QoS` 0 PUBLISH.
        pub fn publish(self, topic: &str, payload: &[u8]) -> Vec<u8> {
            self.publish_with(topic, None, 0, false, false, None, payload)
        }

        /// PUBACK (4), PUBREC (5), PUBREL (6) or PUBCOMP (7), with a 5.0 reason code.
        pub fn ack(self, ptype: u8, id: u16, reason: Option<u8>) -> Vec<u8> {
            let first = (ptype << 4) | if ptype == 6 { 2 } else { 0 };
            let mut body = id.to_be_bytes().to_vec();
            if self.v5
                && let Some(r) = reason
            {
                body.push(r);
            }
            packet(first, &body)
        }

        pub fn subscribe(self, id: u16, filters: &[(&str, u8)], props: Option<&Props>) -> Vec<u8> {
            let mut body = id.to_be_bytes().to_vec();
            body.extend(self.props(props));
            for (f, o) in filters {
                body.extend(string(f));
                body.push(*o);
            }
            packet(0x82, &body)
        }

        pub fn suback(self, id: u16, codes: &[u8]) -> Vec<u8> {
            let mut body = id.to_be_bytes().to_vec();
            body.extend(self.props(None));
            body.extend_from_slice(codes);
            packet(0x90, &body)
        }

        pub fn unsubscribe(self, id: u16, filters: &[&str]) -> Vec<u8> {
            let mut body = id.to_be_bytes().to_vec();
            body.extend(self.props(None));
            for f in filters {
                body.extend(string(f));
            }
            packet(0xA2, &body)
        }

        pub fn unsuback(self, id: u16, codes: &[u8]) -> Vec<u8> {
            let mut body = id.to_be_bytes().to_vec();
            if self.v5 {
                body.extend(self.props(None));
                body.extend_from_slice(codes);
            }
            packet(0xB0, &body)
        }

        pub fn pingreq(self) -> Vec<u8> {
            vec![0xC0, 0]
        }

        pub fn pingresp(self) -> Vec<u8> {
            vec![0xD0, 0]
        }

        pub fn disconnect(self, reason: Option<u8>, props: Option<&Props>) -> Vec<u8> {
            let mut body = Vec::new();
            if self.v5
                && let Some(r) = reason
            {
                body.push(r);
                body.extend(self.props(props));
            }
            packet(0xE0, &body)
        }
    }

    /// Property identifiers used by the scenarios.
    pub mod prop {
        pub const PAYLOAD_FORMAT: u8 = 0x01;
        pub const MESSAGE_EXPIRY: u8 = 0x02;
        pub const CONTENT_TYPE: u8 = 0x03;
        pub const RESPONSE_TOPIC: u8 = 0x08;
        pub const CORRELATION_DATA: u8 = 0x09;
        pub const SUBSCRIPTION_ID: u8 = 0x0B;
        pub const SESSION_EXPIRY: u8 = 0x11;
        pub const ASSIGNED_CLIENT_ID: u8 = 0x12;
        pub const REASON_STRING: u8 = 0x1F;
        pub const RECEIVE_MAXIMUM: u8 = 0x21;
        pub const TOPIC_ALIAS_MAXIMUM: u8 = 0x22;
        pub const TOPIC_ALIAS: u8 = 0x23;
        pub const MAXIMUM_QOS: u8 = 0x24;
        pub const RETAIN_AVAILABLE: u8 = 0x25;
        pub const USER_PROPERTY: u8 = 0x26;
    }
}

use wire::{ConnectSpec, Mqtt, Props, WillSpec, prop};

/// Hosts of the MQTT connections.
pub mod mqtt_hosts {
    use super::Host;
    use crate::scenarios::hosts;

    /// LAN broker, 192.168.1.40.
    pub fn broker() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x40], [192, 168, 1, 40])
    }

    /// Remote broker in public address space (arbitrary address), reached through the router.
    pub fn cloud_broker() -> Host {
        Host::v4(hosts::router().mac, [82, 165, 30, 12])
    }

    /// Temperature sensor, 192.168.1.60.
    pub fn sensor() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x60], [192, 168, 1, 60])
    }

    /// PLC speaking MQTT 5.0, 192.168.1.61.
    pub fn plc() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x61], [192, 168, 1, 61])
    }

    /// Legacy gateway (MQTT 3.1), 192.168.1.62.
    pub fn legacy() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x62], [192, 168, 1, 62])
    }

    /// Gateway of the non-standard port, 192.168.1.63.
    pub fn gateway() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x63], [192, 168, 1, 63])
    }

    /// Dashboard (the analyst workstation), 192.168.1.10.
    pub fn dashboard() -> Host {
        hosts::workstation()
    }

    /// Remote client in public address space (arbitrary address), through the router.
    pub fn remote() -> Host {
        Host::v4(hosts::router().mac, [91, 198, 174, 12])
    }
}

/// Expected results of [`mqtt_showcase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShowcaseCounts {
    pub connections: u64,
    pub accepted: u64,
    pub rejected: u64,
    /// Connections without CONNACK (the one picked up in the middle).
    pub no_answer: u64,
    /// Rows of `credentials` (identical observations folded).
    pub credentials: u64,
    /// Distinct broker endpoints (address, port).
    pub brokers: u64,
}

/// Counts of [`mqtt_showcase`].
pub const SHOWCASE: ShowcaseCounts = ShowcaseCounts {
    connections: 13,
    accepted: 6,
    rejected: 6,
    no_answer: 1,
    credentials: 11,
    brokers: 3,
};

const GAP_NS: i64 = 40 * NS_PER_MS;

fn pause(s: &mut TcpSession<'_>) {
    s.scenario().advance(GAP_NS);
}

/// Telemetry sensor (3.1.1): login with a will message, a command subscription, PUBLISH at `QoS`
/// 0, 1 and 2 with their acknowledgements, a retained status, pings, a command from the broker,
/// then DISCONNECT.
pub fn sensor_session(sc: &mut Scenario, client: Host, broker: Host, password: &str) {
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(client, broker, &TcpOptions::new(PORT));
    let mut connect = ConnectSpec::v311("sensor-01").login("sensor-01", Some(password));
    connect.will = Some(WillSpec {
        topic: "plant/line1/sensor-01/status".into(),
        payload: b"offline".to_vec(),
        qos: 1,
        retain: true,
        props: Props::new(),
    });
    s.client_send(&connect.encode());
    s.server_send(&m.connack(false, 0, None));
    s.client_send(&m.subscribe(1, &[("plant/line1/sensor-01/cmd", 1)], None));
    s.server_send(&m.suback(1, &[1]));
    pause(&mut s);
    s.client_send(&m.publish("plant/line1/temperature", br#"{"t":21.5,"unit":"C"}"#));
    s.client_send(&m.publish_with(
        "plant/line1/humidity",
        Some(2),
        1,
        false,
        false,
        None,
        b"48",
    ));
    s.server_send(&m.ack(4, 2, None));
    s.client_send(&m.publish_with(
        "plant/line1/alarm",
        Some(3),
        2,
        false,
        false,
        None,
        b"door open",
    ));
    s.server_send(&m.ack(5, 3, None));
    s.client_send(&m.ack(6, 3, None));
    s.server_send(&m.ack(7, 3, None));
    s.client_send(&m.publish_with(
        "plant/line1/sensor-01/status",
        Some(4),
        1,
        true,
        false,
        None,
        b"online",
    ));
    s.server_send(&m.ack(4, 4, None));
    for _ in 0..2 {
        s.scenario().advance(500 * NS_PER_MS);
        s.client_send(&m.pingreq());
        s.server_send(&m.pingresp());
    }
    s.server_send(&m.publish_with(
        "plant/line1/sensor-01/cmd",
        Some(7),
        1,
        false,
        false,
        None,
        b"reboot",
    ));
    s.client_send(&m.ack(4, 7, None));
    s.client_send(&m.disconnect(None, None));
    s.close();
}

/// PLC (5.0): empty client id (assigned by the broker), session expiry, topic alias maximum and
/// user property; a shared subscription and a filtered one; a PUBLISH setting topic alias 1 then
/// three PUBLISH by alias only; a PUBACK "no matching subscribers"; a delivery carrying a
/// subscription identifier; DISCONNECT by the broker with a reason string.
pub fn plc_session(sc: &mut Scenario, client: Host, broker: Host, password: &str) {
    let m = Mqtt::V5;
    let mut s = sc.tcp_open(client, broker, &TcpOptions::new(PORT));
    let mut connect = ConnectSpec::v5("").login("plc", Some(password));
    connect.props = Props::new()
        .u32(prop::SESSION_EXPIRY, 3600)
        .u16(prop::RECEIVE_MAXIMUM, 20)
        .u16(prop::TOPIC_ALIAS_MAXIMUM, 10)
        .pair(prop::USER_PROPERTY, "site", "north");
    s.client_send(&connect.encode());
    let connack = Props::new()
        .str(prop::ASSIGNED_CLIENT_ID, "auto-7f3a")
        .u16(prop::TOPIC_ALIAS_MAXIMUM, 5)
        .byte(prop::MAXIMUM_QOS, 1)
        .byte(prop::RETAIN_AVAILABLE, 1);
    s.server_send(&m.connack(false, 0, Some(&connack)));
    s.client_send(&m.subscribe(
        1,
        &[("$share/hmi/plant/+/setpoint", 1), ("plant/line2/#", 0x15)],
        Some(&Props::new().varint(prop::SUBSCRIPTION_ID, 4)),
    ));
    s.server_send(&m.suback(1, &[1, 1]));
    pause(&mut s);
    let first = Props::new()
        .u16(prop::TOPIC_ALIAS, 1)
        .str(prop::CONTENT_TYPE, "application/json")
        .byte(prop::PAYLOAD_FORMAT, 1)
        .u32(prop::MESSAGE_EXPIRY, 30)
        .pair(prop::USER_PROPERTY, "unit", "bar");
    s.client_send(&m.publish_with(
        "plant/line2/pressure",
        None,
        0,
        false,
        false,
        Some(&first),
        br#"{"p":4.2}"#,
    ));
    for i in 0..3 {
        let alias = Props::new().u16(prop::TOPIC_ALIAS, 1);
        let payload = format!("{{\"p\":4.{}}}", 3 + i);
        s.client_send(&m.publish_with("", None, 0, false, false, Some(&alias), payload.as_bytes()));
    }
    let request = Props::new()
        .str(prop::RESPONSE_TOPIC, "plant/line2/flow/reply")
        .bin(prop::CORRELATION_DATA, &[0xde, 0xad, 0xbe, 0xef]);
    s.client_send(&m.publish_with(
        "plant/line2/flow",
        Some(9),
        1,
        false,
        false,
        Some(&request),
        b"12.5",
    ));
    s.server_send(&m.ack(4, 9, Some(0x10)));
    let delivery = Props::new().varint(prop::SUBSCRIPTION_ID, 4);
    s.server_send(&m.publish_with(
        "plant/line2/setpoint",
        Some(11),
        1,
        false,
        false,
        Some(&delivery),
        b"4.0",
    ));
    s.client_send(&m.ack(4, 11, Some(0)));
    let reason = Props::new().str(prop::REASON_STRING, "session taken over");
    s.server_send(&m.disconnect(Some(0x8E), Some(&reason)));
    s.close();
}

/// Legacy gateway (3.1, `MQIsdp`) of a public broker, anonymous, sending a binary payload.
pub fn legacy_session(sc: &mut Scenario, client: Host, broker: Host) {
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(client, broker, &TcpOptions::new(PORT));
    s.client_send(&ConnectSpec::v31("legacy-gw").encode());
    s.server_send(&m.connack(false, 0, None));
    let raw: Vec<u8> = (0u8..64).map(|i| i.wrapping_mul(37) ^ 0x80).collect();
    s.client_send(&m.publish("telemetry/legacy-gw/raw", &raw));
    s.client_send(&m.disconnect(None, None));
    s.close();
}

/// Dashboard subscribed to every topic (`#`) and to `$SYS/#`: the broker version (retained), a
/// few deliveries (one with markup and a bidirectional control character), then UNSUBSCRIBE.
pub fn dashboard_session(sc: &mut Scenario, client: Host, broker: Host, password: &str) {
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(client, broker, &TcpOptions::new(PORT));
    s.client_send(
        &ConnectSpec::v311("dashboard")
            .login("dashboard", Some(password))
            .encode(),
    );
    s.server_send(&m.connack(false, 0, None));
    s.client_send(&m.subscribe(1, &[("#", 0), ("$SYS/#", 0)], None));
    s.server_send(&m.suback(1, &[0, 0]));
    s.server_send(&m.publish_with(
        "$SYS/broker/version",
        None,
        0,
        true,
        false,
        None,
        b"mosquitto version 2.0.18",
    ));
    s.server_send(&m.publish_with(
        "$SYS/broker/clients/connected",
        None,
        0,
        true,
        false,
        None,
        b"4",
    ));
    pause(&mut s);
    s.server_send(&m.publish("plant/line1/temperature", br#"{"t":21.5,"unit":"C"}"#));
    s.server_send(&m.publish("plant/line1/humidity", b"48"));
    s.server_send(&m.publish(
        "plant/line1/note",
        "<script>alert(1)</script> \u{202e}txt.exe".as_bytes(),
    ));
    s.server_send(&m.publish("plant/line2/pressure", br#"{"p":4.2}"#));
    s.client_send(&m.unsubscribe(2, &["$SYS/#"]));
    s.server_send(&m.unsuback(2, &[]));
    s.client_send(&m.disconnect(None, None));
    s.close();
}

/// Six rejected logins from a public address (3.1.1 code 4, then 5.0 reason 0x86), then an
/// accepted one that publishes a set point and drops the connection without DISCONNECT.
pub fn brute_force(
    sc: &mut Scenario,
    client: Host,
    broker: Host,
    guesses: &[&str],
    password: &str,
) {
    for (i, guess) in guesses.iter().enumerate() {
        let v5 = i >= 3;
        let m = if v5 { Mqtt::V5 } else { Mqtt::V311 };
        let mut s = sc.tcp_open(client, broker, &TcpOptions::new(PORT));
        let spec = if v5 {
            ConnectSpec::v5("probe")
        } else {
            ConnectSpec::v311("probe")
        };
        s.client_send(&spec.login("admin", Some(guess)).encode());
        s.server_send(&m.connack(false, if v5 { 0x86 } else { 4 }, None));
        s.close();
        sc.advance(300 * NS_PER_MS);
    }
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(client, broker, &TcpOptions::new(PORT));
    s.client_send(
        &ConnectSpec::v311("probe")
            .login("admin", Some(password))
            .encode(),
    );
    s.server_send(&m.connack(false, 0, None));
    s.client_send(&m.publish("plant/line1/setpoint", b"99"));
    s.close();
}

/// Size of the large message of [`gateway_session`].
pub const LARGE_PAYLOAD: usize = 1024 * 1024;

/// Gateway on [`CUSTOM_PORT`] with a user name and no password: a 1 MiB firmware image (many
/// segments), then a PUBLISH sent one byte per segment, and two packets in one segment.
pub fn gateway_session(sc: &mut Scenario, client: Host, broker: Host) {
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(client, broker, &TcpOptions::new(CUSTOM_PORT));
    s.client_send(&ConnectSpec::v311("gw-7").login("gw", None).encode());
    s.server_send(&m.connack(false, 0, None));
    let image: Vec<u8> = (0..LARGE_PAYLOAD)
        .map(|i| u8::try_from(i % 251).expect("below 251"))
        .collect();
    s.client_send(&m.publish("firmware/gw-7/image", &image));
    for b in m.publish("firmware/gw-7/state", b"flashed") {
        s.client_send(&[b]);
    }
    let mut both = m.publish("firmware/gw-7/version", b"1.4.2");
    both.extend(m.pingreq());
    s.client_send(&both);
    s.server_send(&m.pingresp());
    s.client_send(&m.disconnect(None, None));
    s.close();
}

/// A connection on 1883 whose handshake, CONNECT and CONNACK were not captured: a `QoS` 1
/// PUBLISH and its PUBACK, then pings.
pub fn midstream_session(sc: &mut Scenario, client: Host, broker: Host, password: &str) {
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(client, broker, &TcpOptions::new(PORT));
    s.client_send(
        &ConnectSpec::v311("sensor-02")
            .login("sensor-02", Some(password))
            .encode(),
    );
    s.server_send(&m.connack(true, 0, None));
    let cut = s.scenario().len();
    s.client_send(&m.publish_with(
        "plant/line3/temperature",
        Some(21),
        1,
        false,
        false,
        None,
        b"19.0",
    ));
    s.server_send(&m.ack(4, 21, None));
    s.client_send(&m.pingreq());
    s.server_send(&m.pingresp());
    let whole = s.close();
    sc.remove_packets(whole.start..cut);
}

/// Traffic that is not MQTT: random binary on 1883, and on another port a stream starting with
/// `0x10` whose protocol name is not MQTT.
pub fn not_mqtt(sc: &mut Scenario, client: Host, server: Host) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(PORT));
    s.client_send(&[0xff, 0x00, 0x13, 0x37, 0x42, 0x99, 0x01]);
    s.server_send(b"go away\r\n");
    s.close();
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(2000));
    let mut fake = vec![0x10, 12];
    fake.extend(wire::string("HTTP"));
    fake.extend([4, 2, 0, 60, 0, 2, b'x', b'y']);
    s.client_send(&fake);
    s.close();
}

/// A session that loses one segment of the client in the middle of a PUBLISH stream: the
/// decoder resynchronizes on the next segment.
pub fn lossy_session(sc: &mut Scenario, client: Host, broker: Host) {
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(client, broker, &TcpOptions::new(PORT));
    s.client_send(&ConnectSpec::v311("lossy").encode());
    s.server_send(&m.connack(false, 0, None));
    s.client_send(&m.publish("loss/a", b"1"));
    let lost = s.client_send(&m.publish("loss/b", &[b'x'; 300]));
    s.client_send(&m.publish("loss/c", b"3"));
    s.client_send(&m.disconnect(None, None));
    s.close();
    sc.remove_packets(lost);
}

/// Every connection of the view, a few seconds apart (counts: [`SHOWCASE`]).
pub fn mqtt_showcase(sc: &mut Scenario) {
    use mqtt_hosts::{broker, cloud_broker, dashboard, gateway, legacy, plc, remote, sensor};
    let step = 2_000 * NS_PER_MS;
    sensor_session(sc, sensor(), broker(), "sensor-fixture");
    sc.advance(step);
    plc_session(sc, plc(), broker(), "plc-fixture");
    sc.advance(step);
    legacy_session(sc, legacy(), cloud_broker());
    sc.advance(step);
    dashboard_session(sc, dashboard(), broker(), "dash-fixture");
    sc.advance(step);
    brute_force(
        sc,
        remote(),
        broker(),
        &[
            "admin-guess1-fixture",
            "admin-guess2-fixture",
            "admin-guess3-fixture",
            "admin-guess4-fixture",
            "admin-guess5-fixture",
            "admin-guess6-fixture",
        ],
        "admin-fixture",
    );
    sc.advance(step);
    gateway_session(sc, gateway(), broker());
    sc.advance(step);
    midstream_session(sc, sensor(), broker(), "sensor-fixture");
    sc.advance(step);
    not_mqtt(sc, legacy(), broker());
}

/// One periodic background connection for long demo captures: the sensor reports three values;
/// every other round, the PLC publishes by topic alias.
pub fn mqtt_round(sc: &mut Scenario, round: usize) {
    use mqtt_hosts::{broker, plc, sensor};
    let m = Mqtt::V311;
    let mut s = sc.tcp_open(sensor(), broker(), &TcpOptions::new(PORT));
    s.client_send(
        &ConnectSpec::v311("sensor-01")
            .login("sensor-01", Some("sensor-fixture"))
            .encode(),
    );
    s.server_send(&m.connack(true, 0, None));
    let t = 20 + round % 5;
    s.client_send(&m.publish(
        "plant/line1/temperature",
        format!("{{\"t\":{t}.0,\"unit\":\"C\"}}").as_bytes(),
    ));
    s.client_send(&m.publish_with(
        "plant/line1/humidity",
        Some(1),
        1,
        false,
        false,
        None,
        b"47",
    ));
    s.server_send(&m.ack(4, 1, None));
    s.client_send(&m.pingreq());
    s.server_send(&m.pingresp());
    s.client_send(&m.disconnect(None, None));
    s.close();
    if round.is_multiple_of(2) {
        let m = Mqtt::V5;
        let mut s = sc.tcp_open(plc(), broker(), &TcpOptions::new(PORT));
        let connect = ConnectSpec::v5("plc-line2").login("plc", Some("plc-fixture"));
        s.client_send(&connect.encode());
        s.server_send(&m.connack(false, 0, None));
        let set = Props::new().u16(prop::TOPIC_ALIAS, 3);
        s.client_send(&m.publish_with(
            "plant/line2/pressure",
            None,
            0,
            false,
            false,
            Some(&set),
            b"{\"p\":4.1}",
        ));
        s.client_send(&m.publish_with("", None, 0, false, false, Some(&set), b"{\"p\":4.0}"));
        s.client_send(&m.disconnect(Some(0), None));
        s.close();
    }
}
