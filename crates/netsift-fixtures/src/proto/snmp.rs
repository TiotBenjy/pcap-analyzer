//! SNMP v1 / v2c messages (RFC 1157, RFC 3416), BER-encoded.

use std::net::Ipv4Addr;

use super::der;

/// Protocol version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnmpVersion {
    V1,
    V2c,
}

impl SnmpVersion {
    fn code(self) -> i64 {
        match self {
            Self::V1 => 0,
            Self::V2c => 1,
        }
    }
}

/// PDU type (context-specific constructed tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PduType {
    GetRequest,
    GetNextRequest,
    Response,
    SetRequest,
}

impl PduType {
    fn tag(self) -> u8 {
        match self {
            Self::GetRequest => 0xa0,
            Self::GetNextRequest => 0xa1,
            Self::Response => 0xa2,
            Self::SetRequest => 0xa3,
        }
    }
}

/// Variable binding value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpValue {
    Null,
    Integer(i64),
    OctetString(Vec<u8>),
    Oid(Vec<u32>),
    IpAddress(Ipv4Addr),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
}

impl SnmpValue {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Null => der::null(),
            Self::Integer(v) => der::integer_i64(*v),
            Self::OctetString(v) => der::octet_string(v),
            Self::Oid(arcs) => der::oid(arcs),
            Self::IpAddress(ip) => der::tlv(0x40, &ip.octets()),
            Self::Counter32(v) => application_unsigned(0x41, *v),
            Self::Gauge32(v) => application_unsigned(0x42, *v),
            Self::TimeTicks(v) => application_unsigned(0x43, *v),
        }
    }
}

fn application_unsigned(tag: u8, v: u32) -> Vec<u8> {
    let mut int = der::integer_unsigned(&v.to_be_bytes());
    if let Some(first) = int.first_mut() {
        *first = tag;
    }
    int
}

/// A complete SNMP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpMessage {
    pub version: SnmpVersion,
    pub community: String,
    pub pdu: PduType,
    pub request_id: i32,
    pub error_status: i32,
    pub error_index: i32,
    pub varbinds: Vec<(Vec<u32>, SnmpValue)>,
}

impl SnmpMessage {
    pub fn encode(&self) -> Vec<u8> {
        let bindings: Vec<Vec<u8>> = self
            .varbinds
            .iter()
            .map(|(oid, value)| der::sequence(&[&der::oid(oid), &value.encode()]))
            .collect();
        let binding_refs: Vec<&[u8]> = bindings.iter().map(Vec::as_slice).collect();
        let pdu_body = [
            der::integer_i64(i64::from(self.request_id)),
            der::integer_i64(i64::from(self.error_status)),
            der::integer_i64(i64::from(self.error_index)),
            der::sequence(&binding_refs),
        ]
        .concat();
        der::sequence(&[
            &der::integer_i64(self.version.code()),
            &der::octet_string(self.community.as_bytes()),
            &der::tlv(self.pdu.tag(), &pdu_body),
        ])
    }
}
