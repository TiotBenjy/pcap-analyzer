//! SNMP v1 / v2c community strings (RFC 1157, RFC 3416), parsed with `snmp-parser`.
//!
//! The community travels in clear in every message. The manager (client) is the sender of
//! requests to UDP 161 and the receiver of their responses; traps and informs go to UDP 162,
//! from the agent. `SNMPv3` (user-based security) carries no community and is ignored.

use std::net::IpAddr;

use netsift_flow::{Endpoint, FlowId};
use snmp_parser::{PduType, SnmpGenericMessage, parse_snmp_generic_message};

use super::text::{MAX_SECRET, clip};
use crate::record::{Credential, SecretState};

/// Agent port (requests) and trap port.
pub(crate) const AGENT_PORT: u16 = 161;
pub(crate) const TRAP_PORT: u16 = 162;
/// Longest datagram parsed.
const MAX_DATAGRAM: usize = 65_535;

/// A community observed in one datagram. `Debug` redacts the community.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Community {
    pub version: &'static str,
    pub pdu: &'static str,
    pub value: String,
}

impl std::fmt::Debug for Community {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Community")
            .field("version", &self.version)
            .field("pdu", &self.pdu)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Parses an SNMP v1/v2c message and returns its community (`None`: not SNMP v1/v2c, empty
/// community or malformed).
pub(crate) fn parse(payload: &[u8]) -> Option<Community> {
    if payload.is_empty() || payload.len() > MAX_DATAGRAM {
        return None;
    }
    let (_, msg) = parse_snmp_generic_message(payload).ok()?;
    let (version, msg) = match msg {
        SnmpGenericMessage::V1(m) => ("v1", m),
        SnmpGenericMessage::V2(m) => ("v2c", m),
        SnmpGenericMessage::V3(_) => return None,
    };
    if msg.community.is_empty() {
        return None;
    }
    Some(Community {
        version,
        pdu: pdu_label(msg.pdu.pdu_type()),
        value: clip(&msg.community, MAX_SECRET),
    })
}

fn pdu_label(t: PduType) -> &'static str {
    match t {
        PduType::GetRequest => "get-request",
        PduType::GetNextRequest => "get-next-request",
        PduType::Response => "response",
        PduType::SetRequest => "set-request",
        PduType::TrapV1 => "trap",
        PduType::GetBulkRequest => "get-bulk-request",
        PduType::InformRequest => "inform-request",
        PduType::TrapV2 => "trap-v2",
        PduType::Report => "report",
        _ => "other",
    }
}

/// Orients a datagram: (client, server), where the server is the agent (161) or the trap
/// receiver (162). `None` when neither port is an SNMP port.
pub(crate) fn orient(src: (IpAddr, u16), dst: (IpAddr, u16)) -> Option<(Endpoint, Endpoint)> {
    let ep = |(ip, port): (IpAddr, u16)| Endpoint { ip, port };
    if dst.1 == AGENT_PORT || dst.1 == TRAP_PORT {
        Some((ep(src), ep(dst)))
    } else if src.1 == AGENT_PORT || src.1 == TRAP_PORT {
        Some((ep(dst), ep(src)))
    } else {
        None
    }
}

/// The credential of a community.
pub(crate) fn credential(
    c: Community,
    flow: Option<FlowId>,
    client: Endpoint,
    server: Endpoint,
    ts: i64,
) -> Credential {
    Credential {
        source_protocol: "snmp",
        kind: "snmp",
        flow_id: flow,
        client: Some(client),
        server: Some(server),
        ts,
        username: None,
        domain: None,
        workstation: None,
        secret_state: SecretState::Plaintext,
        secret: Some(c.value),
        hashcat_mode: None,
        hashcat_line: None,
        details: vec![
            ("version".to_owned(), c.version.to_owned()),
            ("pdu".to_owned(), c.pdu.to_owned()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsift_fixtures::proto::snmp::{PduType as Fx, SnmpMessage, SnmpValue, SnmpVersion};

    fn message(version: SnmpVersion, community: &str, pdu: Fx) -> Vec<u8> {
        SnmpMessage {
            version,
            community: community.to_owned(),
            pdu,
            request_id: 7,
            error_status: 0,
            error_index: 0,
            varbinds: vec![(vec![1, 3, 6, 1, 2, 1, 1, 1, 0], SnmpValue::Null)],
        }
        .encode()
    }

    #[test]
    fn communities_of_v1_and_v2c() {
        let c = parse(&message(SnmpVersion::V2c, "public", Fx::GetRequest)).unwrap();
        assert_eq!(
            (c.version, c.pdu, c.value.as_str()),
            ("v2c", "get-request", "public")
        );
        let c = parse(&message(SnmpVersion::V1, "private", Fx::SetRequest)).unwrap();
        assert_eq!(
            (c.version, c.pdu, c.value.as_str()),
            ("v1", "set-request", "private")
        );
        assert!(parse(&message(SnmpVersion::V2c, "", Fx::GetRequest)).is_none());
    }

    #[test]
    fn hostile_datagrams_never_panic() {
        let good = message(SnmpVersion::V2c, "public", Fx::GetRequest);
        for cut in 0..good.len() {
            let _ = parse(good.get(..cut).unwrap());
        }
        for len in 0..128usize {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 37 % 256).unwrap())
                .collect();
            let _ = parse(&data);
        }
        // A huge announced length.
        let _ = parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, 0x01]);
    }

    #[test]
    fn orientation_follows_the_agent_port() {
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let (c, s) = orient((a, 50_000), (b, 161)).unwrap();
        assert_eq!((c.ip, s.ip, s.port), (a, b, 161));
        let (c, s) = orient((b, 161), (a, 50_000)).unwrap();
        assert_eq!((c.ip, s.ip), (a, b));
        assert!(orient((a, 1), (b, 2)).is_none());
    }
}
