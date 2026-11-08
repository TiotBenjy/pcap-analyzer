//! The `servers` analyzer: infrastructure protocols whose servers are not visible elsewhere.
//!
//! - DHCP / BOOTP (UDP 67/68): every message, client and server side (server role: OFFER and
//!   ACK; client host names, option 12, are paired with the leased address at the end of the
//!   import, in SQL, because a broadcast REQUEST and its ACK land on different shards);
//! - NTP (UDP 123): server responses (mode 4), with stratum and reference;
//! - Kerberos (88): KDC replies (AS-REP, TGS-REP, KRB-ERROR) over UDP and TCP, recognized by
//!   their minimal ASN.1 header (`netsift_dissect::kerberos`), with the realm.
//!
//! The other roles of the Servers view (DNS, LDAP, SMB, HTTP) are derived at read time from the
//! tables of their own analyzers: nothing is counted here, every record is one observation.
//!
//! Bounds: TCP Kerberos replies are framed by their length prefix; only the first
//! [`ServersConfig::max_kerberos_head`] bytes of a message are kept (the realm comes early), the
//! rest is skipped by count. At most [`ServersConfig::max_kerberos_flows`] TCP flows are tracked
//! per shard. A gap in a stream abandons that flow (no resynchronization on a binary protocol).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use netsift_dissect::{Decoded, dhcp, kerberos, ntp};
use netsift_flow::{Direction, FlowCtx, FlowId, PacketCtx, StreamCtx};

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::Record;
use crate::registry::AnalyzerConfig;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const NTP_PORT: u16 = 123;
const KERBEROS_PORT: u16 = 88;
const UDP: u8 = 17;
const TCP: u8 = 6;

/// Settings of the `servers` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServersConfig {
    /// TCP Kerberos flows tracked at once per shard.
    pub max_kerberos_flows: usize,
    /// Bytes kept from the start of each TCP Kerberos message.
    pub max_kerberos_head: usize,
}

impl Default for ServersConfig {
    fn default() -> Self {
        Self {
            max_kerberos_flows: 4096,
            max_kerberos_head: 2048,
        }
    }
}

/// A record of the `servers` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerRecord {
    /// One DHCP or BOOTP message (boxed: much larger than the others).
    Dhcp(Box<DhcpSeen>),
    /// One NTP server response.
    Ntp(NtpSeen),
    /// One KDC reply.
    Kerberos(KdcReplySeen),
}

/// One DHCP / BOOTP message (`dhcp_messages`). Unset addresses (`0.0.0.0`) are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpSeen {
    pub ts: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    /// 1 request (client or relay), 2 reply (server or relay).
    pub op: u8,
    /// DHCP message type label (`discover`, `offer`, `request`, `ack`...), `None` for BOOTP.
    pub message_type: Option<&'static str>,
    pub xid: u32,
    pub client_mac: Option<[u8; 6]>,
    pub ciaddr: Option<Ipv4Addr>,
    pub yiaddr: Option<Ipv4Addr>,
    pub siaddr: Option<Ipv4Addr>,
    pub giaddr: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_s: Option<u32>,
    pub hostname: Option<String>,
}

/// One NTP server response (mode 4) (`ntp_responses`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpSeen {
    pub ts: i64,
    pub server: IpAddr,
    pub client: IpAddr,
    pub version: u8,
    pub stratum: u8,
    /// Readable reference identifier (`GPS`, upstream address...), possibly empty.
    pub reference: String,
}

/// Kind of a KDC reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdcReply {
    AsRep,
    TgsRep,
    Error,
}

impl KdcReply {
    /// Stable label stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsRep => "as_rep",
            Self::TgsRep => "tgs_rep",
            Self::Error => "error",
        }
    }

    fn of(kind: kerberos::MessageKind) -> Option<Self> {
        match kind {
            kerberos::MessageKind::AsRep => Some(Self::AsRep),
            kerberos::MessageKind::TgsRep => Some(Self::TgsRep),
            kerberos::MessageKind::KrbError => Some(Self::Error),
            _ => None,
        }
    }
}

/// One KDC reply (`kerberos_replies`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcReplySeen {
    pub ts: i64,
    pub server: IpAddr,
    pub client: IpAddr,
    /// 6 TCP, 17 UDP.
    pub transport: u8,
    pub kind: KdcReply,
    pub realm: Option<String>,
    /// KRB-ERROR code.
    pub error_code: Option<i32>,
}

/// Framing state of the server-to-client direction of a TCP Kerberos flow.
#[derive(Debug, Default)]
struct KdcStream {
    /// Length prefix bytes collected so far.
    prefix: Vec<u8>,
    /// Bytes of the current message still to come.
    remaining: u64,
    /// First bytes of the current message.
    head: Vec<u8>,
    /// The current message was already parsed (head full).
    parsed: bool,
    /// Not Kerberos framing, or a gap: the rest of the flow is ignored.
    dead: bool,
}

/// See the module documentation.
#[derive(Debug)]
pub struct ServersAnalyzer {
    config: ServersConfig,
    kdc: HashMap<FlowId, KdcStream>,
}

impl ServersAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("servers");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            config: config.servers.clone(),
            kdc: HashMap::new(),
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }
}

fn set(addr: Ipv4Addr) -> Option<Ipv4Addr> {
    (!addr.is_unspecified()).then_some(addr)
}

fn dhcp_record(ts: i64, src_ip: IpAddr, dst_ip: IpAddr, msg: dhcp::Message) -> DhcpSeen {
    DhcpSeen {
        ts,
        src_ip,
        dst_ip,
        op: msg.op,
        message_type: msg.message_type.map(dhcp::MessageType::as_str),
        xid: msg.xid,
        client_mac: msg.client_mac(),
        ciaddr: set(msg.ciaddr),
        yiaddr: set(msg.yiaddr),
        siaddr: set(msg.siaddr),
        giaddr: set(msg.giaddr),
        server_id: msg.server_id,
        requested_ip: msg.requested_ip,
        subnet_mask: msg.subnet_mask,
        routers: msg.routers,
        dns_servers: msg.dns_servers,
        lease_s: msg.lease_time,
        hostname: msg.hostname,
    }
}

/// Emits the KDC reply found in `message`, if any.
fn emit_kdc(
    message: &[u8],
    ts: i64,
    server: IpAddr,
    client: IpAddr,
    transport: u8,
    out: &mut dyn RecordSink,
) {
    let Some(msg) = kerberos::parse(message) else {
        return;
    };
    let Some(kind) = KdcReply::of(msg.kind) else {
        return;
    };
    out.emit(Record::Server(ServerRecord::Kerberos(KdcReplySeen {
        ts,
        server,
        client,
        transport,
        kind,
        realm: msg.realm,
        error_code: msg.error_code,
    })));
}

impl KdcStream {
    /// Consumes server-to-client bytes; calls `found` with the head of each message once it is
    /// complete or full. `false` when the stream is not Kerberos framing (abandon it).
    fn feed(&mut self, mut data: &[u8], max_head: usize, found: &mut dyn FnMut(&[u8])) -> bool {
        while !data.is_empty() {
            if self.remaining == 0 {
                let need = 4 - self.prefix.len();
                let (take, rest) = data.split_at(need.min(data.len()));
                self.prefix.extend_from_slice(take);
                data = rest;
                if self.prefix.len() < 4 {
                    return true;
                }
                let Some(len) = kerberos::tcp_record_len(&self.prefix) else {
                    return false;
                };
                self.prefix.clear();
                self.remaining = u64::from(len);
                self.head.clear();
                self.parsed = false;
                continue;
            }
            let n = usize::try_from(self.remaining)
                .unwrap_or(usize::MAX)
                .min(data.len());
            let (chunk, rest) = data.split_at(n);
            data = rest;
            self.remaining -= n as u64;
            if !self.parsed {
                let room = max_head.saturating_sub(self.head.len());
                self.head
                    .extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or_default());
                if self.remaining == 0 || self.head.len() >= max_head {
                    found(&self.head);
                    self.parsed = true;
                    self.head = Vec::new();
                }
            }
        }
        true
    }

    /// Head of a message cut by the end of the flow, if one was being collected.
    fn pending(&self) -> Option<&[u8]> {
        (!self.dead && !self.parsed && !self.head.is_empty()).then_some(self.head.as_slice())
    }
}

impl Analyzer for ServersAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        if pkt.udp().is_none() {
            return;
        }
        let (Some((sport, dport)), Some(ip)) = (pkt.ports(), pkt.ip()) else {
            return;
        };
        let ts = ctx.ts_ns;
        let dhcp_ports = (sport == DHCP_CLIENT_PORT && dport == DHCP_SERVER_PORT)
            || (sport == DHCP_SERVER_PORT
                && (dport == DHCP_CLIENT_PORT || dport == DHCP_SERVER_PORT));
        if dhcp_ports {
            if let Some(msg) = dhcp::parse(pkt.payload) {
                let seen = dhcp_record(ts, ip.src, ip.dst, msg);
                out.emit(Record::Server(ServerRecord::Dhcp(Box::new(seen))));
            }
        } else if sport == NTP_PORT {
            if let Some(h) = ntp::parse(pkt.payload)
                && h.mode == ntp::mode::SERVER
            {
                out.emit(Record::Server(ServerRecord::Ntp(NtpSeen {
                    ts,
                    server: ip.src,
                    client: ip.dst,
                    version: h.version,
                    stratum: h.stratum,
                    reference: h.reference(ip.src.is_ipv6()),
                })));
            }
        } else if sport == KERBEROS_PORT {
            emit_kdc(pkt.payload, ts, ip.src, ip.dst, UDP, out);
        }
    }

    fn on_stream(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        if ctx.key.server.port != KERBEROS_PORT || dir != Direction::ToClient {
            return;
        }
        if !self.kdc.contains_key(&ctx.id) && self.kdc.len() >= self.config.max_kerberos_flows {
            return;
        }
        let stream = self.kdc.entry(ctx.id).or_default();
        if ctx.gap_before != 0 {
            // A dead stream keeps no buffer.
            *stream = KdcStream {
                dead: true,
                ..KdcStream::default()
            };
        }
        if stream.dead {
            return;
        }
        let (server, client, ts) = (ctx.key.server.ip, ctx.key.client.ip, ctx.ts_ns);
        let mut found = |head: &[u8]| emit_kdc(head, ts, server, client, TCP, out);
        if !stream.feed(data, self.config.max_kerberos_head, &mut found) {
            *stream = KdcStream {
                dead: true,
                ..KdcStream::default()
            };
        }
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        if let Some(stream) = self.kdc.remove(&ctx.id)
            && let Some(head) = stream.pending()
        {
            let (server, client) = (ctx.key.server.ip, ctx.key.client.ip);
            emit_kdc(head, ctx.last_ts_ns, server, client, TCP, out);
        }
    }

    fn finish(&mut self, _out: &mut dyn RecordSink) {
        // Flows all end before `finish` (their pending heads are emitted by `on_flow_end`).
        self.kdc.clear();
    }
}

#[cfg(test)]
mod tests;
