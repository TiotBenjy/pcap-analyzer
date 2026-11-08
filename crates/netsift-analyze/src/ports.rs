//! The `ports` analyzer: services seen answering in the capture (no active scan).
//!
//! A port of a host is recorded as open when:
//! - **TCP, SYN-ACK**: the host sends a SYN-ACK from it ([`PortEvidence::SynAck`]), whatever
//!   the orientation of the flow. A SYN answered by a RST is a closed port: nothing is recorded;
//! - **TCP, server data**: on a connection picked up midstream (handshake not captured), the
//!   side that looks like the server ([`midstream_server`]) sends data
//!   ([`PortEvidence::ServerData`]);
//! - **UDP reply**: the server of a UDP flow (the side that did not send the first datagram)
//!   answers from its port ([`PortEvidence::UdpReply`]), unless its port looks less like a
//!   service port than the client's ([`service_score`]): a flow picked up midstream starts with
//!   a datagram of the real server (QUIC from 443 to an ephemeral port), whose client would
//!   otherwise be taken for a listening service. Such a flow records nothing.
//!
//! The first server data of a TCP connection identifies its service by content
//! ([`detect_service`]: http, tls, ssh, smb...). Greeting protocols (FTP, SMTP, POP3, IMAP,
//! VNC) are only recognized, and their first line kept as a banner (at most [`MAX_BANNER`]
//! bytes), when the server speaks first: `+OK` after a client command is Redis, not POP3.
//!
//! Observations are pre-aggregated per shard in a bounded map (key: host, transport, port) and
//! flushed like the `core` hosts; the store merges them commutatively (first/last time min/max,
//! evidence: the strongest by [`PortEvidence::rank`]; service and banner: non-NULL wins, then
//! the smallest), so the result depends neither on the number of shards nor on flush moments.
//! Client counts come from `flows` at read time.

use std::collections::HashMap;
use std::net::IpAddr;

use netsift_dissect::{Decoded, TcpFlags, TcpInfo, Transport};
use netsift_flow::{Direction, Endpoint, FlowCtx, FlowId, FlowKey, PacketCtx, StreamCtx};

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::classify::ip_proto;
use crate::geo::AddressCategory;
use crate::record::Record;
use crate::registry::AnalyzerConfig;
use crate::services::iana_service;

/// Longest banner kept, in bytes.
pub const MAX_BANNER: usize = 256;

/// Settings of the `ports` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortsConfig {
    /// Maximum number of open ports aggregated per shard before a flush.
    pub max_pending: usize,
    /// Pending observations are flushed when packet time advances this much (ns).
    pub flush_interval_ns: i64,
    /// Maximum number of TCP connections tracked per shard (handshake seen, first server data
    /// inspected). Beyond, new connections are only checked for SYN-ACKs.
    pub max_tracked_flows: usize,
}

impl Default for PortsConfig {
    fn default() -> Self {
        Self {
            max_pending: 16_384,
            flush_interval_ns: 60 * 1_000_000_000,
            max_tracked_flows: 1 << 20,
        }
    }
}

/// Why a port is considered open, weakest first (merges keep the strongest, see
/// [`PortEvidence::rank`]; the store applies the same ranking).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PortEvidence {
    /// Data sent by the server side of a connection whose handshake was not captured.
    ServerData,
    /// UDP datagram sent back to the client of a flow.
    UdpReply,
    /// SYN-ACK sent from the port.
    SynAck,
}

impl PortEvidence {
    /// Strength of the evidence: `syn_ack` (2) > `udp_reply` (1) > `server_data` (0).
    pub const fn rank(self) -> u8 {
        match self {
            Self::ServerData => 0,
            Self::UdpReply => 1,
            Self::SynAck => 2,
        }
    }

    /// Stable label stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerData => "server_data",
            Self::SynAck => "syn_ack",
            Self::UdpReply => "udp_reply",
        }
    }
}

/// An open port observed between `first_ts` and `last_ts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPortSeen {
    pub ip: IpAddr,
    /// IP protocol number (6 TCP, 17 UDP).
    pub transport: u8,
    pub port: u16,
    pub evidence: PortEvidence,
    /// Service identified by content (`http`, `tls`, `ssh`...).
    pub detected: Option<&'static str>,
    /// First line of a greeting (SSH, FTP, SMTP...), printable ASCII.
    pub banner: Option<String>,
    pub first_ts: i64,
    pub last_ts: i64,
}

impl OpenPortSeen {
    /// IANA service name of the port, from the embedded registry.
    pub fn iana(&self) -> Option<&'static str> {
        iana_service(self.transport, self.port)
    }

    /// Merges another observation of the same port (store rules).
    fn merge(&mut self, other: Self) {
        self.first_ts = self.first_ts.min(other.first_ts);
        self.last_ts = self.last_ts.max(other.last_ts);
        if other.evidence.rank() > self.evidence.rank() {
            self.evidence = other.evidence;
        }
        self.detected = min_some(self.detected, other.detected);
        self.banner = min_some(self.banner.take(), other.banner);
    }
}

/// "Non-empty wins, then the smallest" (the store rule for nullable columns).
fn min_some<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// State of a tracked TCP connection.
#[allow(clippy::struct_excessive_bools)] // Independent facts about one connection.
#[derive(Debug, Clone, Copy)]
struct TcpTrack {
    /// The first packet seen was neither a SYN nor a SYN-ACK.
    midstream: bool,
    /// A SYN-ACK was seen.
    syn_ack: bool,
    /// The client sent data before the first server data (the server did not speak first).
    client_spoke: bool,
    /// The first server data was inspected (or the server side cannot be told).
    inspected: bool,
}

type PortKey = (IpAddr, u8, u16);

/// See the module documentation.
#[derive(Debug)]
pub struct PortsAnalyzer {
    config: PortsConfig,
    pending: HashMap<PortKey, OpenPortSeen>,
    tcp: HashMap<FlowId, TcpTrack>,
    /// Packet time of the last flush (or of the first observation).
    since: Option<i64>,
}

impl PortsAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("ports");

    pub fn new(config: &AnalyzerConfig) -> Self {
        let mut config = config.ports.clone();
        config.max_pending = config.max_pending.max(1);
        config.flush_interval_ns = config.flush_interval_ns.max(0);
        Self {
            config,
            pending: HashMap::new(),
            tcp: HashMap::new(),
            since: None,
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    fn record(&mut self, seen: OpenPortSeen, out: &mut dyn RecordSink) {
        let since = *self.since.get_or_insert(seen.last_ts);
        let key = (seen.ip, seen.transport, seen.port);
        let full =
            self.pending.len() >= self.config.max_pending && !self.pending.contains_key(&key);
        if full || seen.last_ts.saturating_sub(since) >= self.config.flush_interval_ns {
            self.flush(out);
            self.since = Some(seen.last_ts);
        }
        match self.pending.get_mut(&key) {
            Some(known) => known.merge(seen),
            None => {
                self.pending.insert(key, seen);
            }
        }
    }

    fn flush(&mut self, out: &mut dyn RecordSink) {
        let mut ports: Vec<_> = self.pending.drain().collect();
        // Deterministic emission order (the store merge does not need it; tests do).
        ports.sort_unstable_by_key(|(key, _)| *key);
        for (_, seen) in ports {
            out.emit(Record::OpenPort(seen));
        }
    }

    fn on_tcp(
        &mut self,
        ctx: &PacketCtx,
        id: FlowId,
        src: IpAddr,
        tcp: &TcpInfo,
        out: &mut dyn RecordSink,
    ) {
        let syn = tcp.flags.contains(TcpFlags::SYN);
        let syn_ack =
            syn && tcp.flags.contains(TcpFlags::ACK) && !tcp.flags.contains(TcpFlags::RST);
        if syn_ack && tcp.src_port != 0 && answers(src) {
            self.record(
                OpenPortSeen {
                    ip: src,
                    transport: ip_proto::TCP,
                    port: tcp.src_port,
                    evidence: PortEvidence::SynAck,
                    detected: None,
                    banner: None,
                    first_ts: ctx.ts_ns,
                    last_ts: ctx.ts_ns,
                },
                out,
            );
        }
        if let Some(track) = self.tcp.get_mut(&id) {
            track.syn_ack |= syn_ack;
        } else if self.tcp.len() < self.config.max_tracked_flows {
            self.tcp.insert(
                id,
                TcpTrack {
                    midstream: !syn,
                    syn_ack,
                    client_spoke: false,
                    inspected: false,
                },
            );
        }
    }
}

/// True when a packet from `ip` can be an answer of a listening service.
fn answers(ip: IpAddr) -> bool {
    !matches!(
        AddressCategory::of(ip),
        AddressCategory::Broadcast | AddressCategory::Multicast | AddressCategory::Unspecified
    )
}

/// How much a port looks like a service port: 2 below 1024, 1 for other ports registered at
/// IANA below the dynamic range, 0 otherwise.
pub fn service_score(port: u16) -> u8 {
    match port {
        0 => 0,
        1..1024 => 2,
        _ => u8::from(port < 49_152 && iana_service(ip_proto::TCP, port).is_some()),
    }
}

/// Server side of a TCP connection picked up midstream (its orientation is only the sender of
/// the first packet seen): the endpoint whose port looks more like a service port, `None` when
/// both look alike.
pub fn midstream_server(key: &FlowKey) -> Option<Endpoint> {
    let (a, b) = (
        service_score(key.client.port),
        service_score(key.server.port),
    );
    match a.cmp(&b) {
        std::cmp::Ordering::Greater => Some(key.client),
        std::cmp::Ordering::Less => Some(key.server),
        std::cmp::Ordering::Equal => None,
    }
}

/// Service identified from the first bytes sent by a TCP server, `port` breaking ties between
/// protocols with the same greeting (FTP and SMTP both start with `220`). Greeting protocols
/// (FTP, SMTP, POP3, IMAP, VNC) are only recognized when `server_first`: the server sent this
/// before any client data.
pub fn detect_service(data: &[u8], port: u16, server_first: bool) -> Option<&'static str> {
    let starts = |p: &[u8]| data.starts_with(p);
    if starts(b"HTTP/1.") || starts(b"HTTP/2") {
        return Some("http");
    }
    if starts(b"SSH-") {
        return Some("ssh");
    }
    if starts(b"RTSP/1.") {
        return Some("rtsp");
    }
    // TLS record: content type 20..=23, version 3.x (SSL 3.0 to TLS 1.3 on the wire).
    if let Some(&[kind, 3, minor]) = data.get(..3)
        && (20..=23).contains(&kind)
        && minor <= 4
    {
        return Some("tls");
    }
    // NetBIOS session message carrying SMB1 (0xff), SMB2/3 (0xfe) or an encrypted SMB3 (0xfd).
    if let Some(&[0, _, _, _, marker, b'S', b'M', b'B']) = data.get(..8)
        && matches!(marker, 0xfd..=0xff)
    {
        return Some("smb");
    }
    if !server_first {
        return None;
    }
    if starts(b"RFB ") {
        return Some("vnc");
    }
    if starts(b"+OK") {
        return Some("pop3");
    }
    if starts(b"* OK") || starts(b"* PREAUTH") {
        return Some("imap");
    }
    if let Some(&[b'2', b'2', b'0', sep]) = data.get(..4)
        && (sep == b' ' || sep == b'-')
    {
        let line = first_line(data).to_ascii_uppercase();
        let has = |w: &str| line.windows(w.len()).any(|x| x == w.as_bytes());
        return if has("FTP") {
            Some("ftp")
        } else if has("SMTP") || has("MAIL") {
            Some("smtp")
        } else {
            match port {
                21 | 990 => Some("ftp"),
                25 | 465 | 587 => Some("smtp"),
                _ => None,
            }
        };
    }
    None
}

/// Bytes of the first line (without CR / LF), at most [`MAX_BANNER`] bytes.
fn first_line(data: &[u8]) -> &[u8] {
    let end = data
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(data.len())
        .min(MAX_BANNER);
    data.get(..end).unwrap_or(&[])
}

/// Banner of a greeting protocol: its first line, non-printable bytes replaced by `.`.
pub fn banner(data: &[u8], service: Option<&str>) -> Option<String> {
    if !matches!(
        service,
        Some("ssh" | "ftp" | "smtp" | "pop3" | "imap" | "vnc")
    ) {
        return None;
    }
    let line: String = first_line(data)
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect();
    let line = line.trim().to_owned();
    (!line.is_empty()).then_some(line)
}

impl Analyzer for PortsAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        let (Some(flow), Some(ip)) = (ctx.flow, pkt.ip()) else {
            return;
        };
        match pkt.transport {
            Some(Transport::Tcp(tcp)) => self.on_tcp(ctx, flow.id, ip.src, &tcp, out),
            Some(Transport::Udp(udp)) => {
                let server = flow.key.server;
                if flow.dir == Direction::ToClient
                    && ip.src == server.ip
                    && udp.src_port == server.port
                    && server.port != 0
                    && service_score(server.port) >= service_score(flow.key.client.port)
                    && answers(server.ip)
                {
                    self.record(
                        OpenPortSeen {
                            ip: server.ip,
                            transport: ip_proto::UDP,
                            port: server.port,
                            evidence: PortEvidence::UdpReply,
                            detected: None,
                            banner: None,
                            first_ts: ctx.ts_ns,
                            last_ts: ctx.ts_ns,
                        },
                        out,
                    );
                }
            }
            _ => {}
        }
    }

    fn on_stream(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        if data.is_empty() || ctx.key.proto != ip_proto::TCP {
            return;
        }
        let Some(track) = self.tcp.get_mut(&ctx.id) else {
            return;
        };
        if track.inspected {
            return;
        }
        let (server, evidence) = if track.midstream {
            let Some(server) = midstream_server(&ctx.key) else {
                track.inspected = true;
                return;
            };
            (server, PortEvidence::ServerData)
        } else if track.syn_ack {
            // The SYN-ACK already proved the port open: this only adds the service.
            (ctx.key.server, PortEvidence::SynAck)
        } else {
            // Handshake started by a SYN whose SYN-ACK was not captured: the server answering
            // with data accepted the connection.
            (ctx.key.server, PortEvidence::ServerData)
        };
        let from_server = match dir {
            Direction::ToClient => server == ctx.key.server,
            Direction::ToServer => server == ctx.key.client,
        };
        if !from_server {
            track.client_spoke = true;
            return;
        }
        track.inspected = true;
        let server_first = !track.client_spoke;
        if !answers(server.ip) {
            return;
        }
        let detected = if ctx.gap_before == 0 {
            detect_service(data, server.port, server_first)
        } else {
            None
        };
        let banner = if ctx.gap_before == 0 {
            banner(data, detected)
        } else {
            None
        };
        self.record(
            OpenPortSeen {
                ip: server.ip,
                transport: ip_proto::TCP,
                port: server.port,
                evidence,
                detected,
                banner,
                first_ts: ctx.ts_ns,
                last_ts: ctx.ts_ns,
            },
            out,
        );
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, _out: &mut dyn RecordSink) {
        self.tcp.remove(&ctx.id);
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        self.flush(out);
        self.since = None;
        self.tcp.clear();
    }
}

/// Merges records the way the store does (tests and diagnostics), sorted by key.
pub fn merge_ports(records: &[Record]) -> Vec<OpenPortSeen> {
    let mut ports: std::collections::BTreeMap<PortKey, OpenPortSeen> =
        std::collections::BTreeMap::new();
    for r in records {
        if let Record::OpenPort(p) = r {
            match ports.get_mut(&(p.ip, p.transport, p.port)) {
                Some(known) => known.merge(p.clone()),
                None => {
                    ports.insert((p.ip, p.transport, p.port), p.clone());
                }
            }
        }
    }
    ports.into_values().collect()
}

#[cfg(test)]
mod tests;
