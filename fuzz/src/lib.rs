//! Helpers shared by the fuzz targets (`fuzz_targets/`) and the seed generator
//! (`examples/gen_corpus.rs`):
//!
//! - input framings ([`segments`], [`frames`], [`conversation`]) and their encoders, so that
//!   seeds built from `netsift-fixtures` traffic decode exactly as the targets read them;
//! - a raw IPv4 frame builder ([`tcp_frame`], [`udp_frame`]);
//! - drivers that feed analyzers through the same entry points as the engine: the
//!   [`Analyzer`] trait directly ([`drive_stream`]) or a [`FlowTable`] ([`drive_flow`],
//!   [`run_frames`]).
//!
//! Every loop is bounded ([`MAX_ITEMS`]): one run stays short whatever the input.

use std::net::{IpAddr, Ipv4Addr};

use netsift_analyze::dissect::linktype;
use netsift_analyze::flow::{
    DirStats, Direction, EndReason, Endpoint, FlowConfig, FlowCtx, FlowId, FlowKey, FlowSink,
    FlowTable, PacketCtx, StreamCtx, TcpState,
};
use netsift_analyze::{Analyzer, AnalyzerConfig, BlobRef, Record, RecordSink, Registry};

/// Most segments, frames or packets taken from one input.
pub const MAX_ITEMS: usize = 512;
/// Most records kept by a [`Sink`] (the rest is counted, then dropped).
pub const MAX_RECORDS: usize = 100_000;
/// Base packet time of the drivers: 2026-01-01T00:00:00Z.
pub const BASE_TS_NS: i64 = 1_767_225_600_000_000_000;
const MS: i64 = 1_000_000;
/// Largest TCP payload put in one crafted frame.
const MAX_TCP_PAYLOAD: usize = 8192;

// --- framings ------------------------------------------------------------------------------

/// One piece of a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    pub to_server: bool,
    /// Bytes lost just before `data` (0: none).
    pub gap: u64,
    pub data: &'a [u8],
}

/// Conversation framing. Per segment: a flags byte (bit 0: sent by the server, bit 1: a gap
/// byte follows), a little-endian `u16` length, the optional gap byte, then the data
/// (truncated to what is left of the input).
pub fn segments(mut data: &[u8]) -> Vec<Segment<'_>> {
    let mut out = Vec::new();
    while out.len() < MAX_ITEMS {
        let [flags, lo, hi, rest @ ..] = data else {
            break;
        };
        let len = usize::from(u16::from_le_bytes([*lo, *hi]));
        let (gap, rest) = if flags & 2 != 0 {
            match rest {
                [g, tail @ ..] => (u64::from(*g), tail),
                [] => break,
            }
        } else {
            (0, rest)
        };
        let take = len.min(rest.len());
        let (seg, tail) = rest.split_at(take);
        out.push(Segment {
            to_server: flags & 1 == 0,
            gap,
            data: seg,
        });
        data = tail;
    }
    out
}

/// Appends `data` in the [`segments`] framing (split into several segments when longer than
/// `u16::MAX`; the gap goes on the first one).
pub fn push_segment(out: &mut Vec<u8>, to_server: bool, gap: u8, data: &[u8]) {
    let mut gap = Some(gap).filter(|&g| g > 0);
    let pieces: Vec<&[u8]> = if data.is_empty() {
        vec![data]
    } else {
        data.chunks(usize::from(u16::MAX)).collect()
    };
    for piece in pieces {
        let mut flags = u8::from(!to_server);
        if gap.is_some() {
            flags |= 2;
        }
        out.push(flags);
        let len = u16::try_from(piece.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_le_bytes());
        if let Some(g) = gap.take() {
            out.push(g);
        }
        out.extend_from_slice(piece);
    }
}

/// One captured frame of a [`frames`] input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Time step before this frame, see [`step_ns`].
    pub step: u8,
    pub data: &'a [u8],
}

/// Frame sequence framing. Per frame: a time step byte ([`step_ns`]), a little-endian `u16`
/// length, then the frame bytes.
pub fn frames(mut data: &[u8]) -> Vec<Frame<'_>> {
    let mut out = Vec::new();
    while out.len() < MAX_ITEMS {
        let [step, lo, hi, rest @ ..] = data else {
            break;
        };
        let len = usize::from(u16::from_le_bytes([*lo, *hi]));
        let (frame, tail) = rest.split_at(len.min(rest.len()));
        out.push(Frame {
            step: *step,
            data: frame,
        });
        data = tail;
    }
    out
}

/// Appends one frame in the [`frames`] framing (frames longer than `u16::MAX` are cut).
pub fn push_frame(out: &mut Vec<u8>, step: u8, data: &[u8]) {
    let data = data.get(..usize::from(u16::MAX)).unwrap_or(data);
    out.push(step);
    let len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
}

/// Packet time advance of a frame step: `0..=239` forward by 10 ms steps, `240..=254` backward
/// by 1 ms steps (the flow table must tolerate small backward jumps), `255` forward by 400 s
/// (beyond every flow timeout).
pub fn step_ns(step: u8) -> i64 {
    match step {
        0..=239 => i64::from(step) * 10 * MS,
        240..=254 => -i64::from(step - 239) * MS,
        255 => 400_000 * MS,
    }
}

/// Server ports of the TCP conversations ([`conversation`]).
pub const TCP_PORTS: [u16; 20] = [
    21, 23, 25, 53, 80, 88, 110, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 3268, 8080, 8443,
];
/// Server ports of the UDP conversations ([`conversation`]).
pub const UDP_PORTS: [u16; 12] = [53, 67, 68, 88, 123, 137, 138, 161, 162, 389, 5353, 5355];

/// Head of a conversation input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conversation {
    pub udp: bool,
    pub client_port: u16,
    pub server_port: u16,
    /// TCP: the three-way handshake is sent first.
    pub handshake: bool,
    /// TCP: both sides send a FIN at the end.
    pub close: bool,
}

/// Conversation input: a selector byte (bit 7: UDP, low bits: index into [`TCP_PORTS`] or
/// [`UDP_PORTS`]), the client port (big-endian, 0 means 49152), an options byte (bit 0: TCP
/// handshake, bit 1: TCP close), then [`segments`].
pub fn conversation(data: &[u8]) -> Option<(Conversation, &[u8])> {
    let [sel, hi, lo, opts, rest @ ..] = data else {
        return None;
    };
    let udp = sel & 0x80 != 0;
    let index = usize::from(sel & 0x7f);
    let server_port = if udp {
        UDP_PORTS.get(index % UDP_PORTS.len())
    } else {
        TCP_PORTS.get(index % TCP_PORTS.len())
    };
    let client_port = match u16::from_be_bytes([*hi, *lo]) {
        0 => 49152,
        p => p,
    };
    let conv = Conversation {
        udp,
        client_port,
        server_port: *server_port?,
        handshake: opts & 1 != 0,
        close: opts & 2 != 0,
    };
    Some((conv, rest))
}

/// Encodes the head of a [`conversation`] input; `None` when the server port is in neither table.
pub fn conversation_head(conv: &Conversation) -> Option<[u8; 4]> {
    let table: &[u16] = if conv.udp { &UDP_PORTS } else { &TCP_PORTS };
    let index = table.iter().position(|&p| p == conv.server_port)?;
    let mut sel = u8::try_from(index).ok()?;
    if conv.udp {
        sel |= 0x80;
    }
    let [hi, lo] = conv.client_port.to_be_bytes();
    Some([
        sel,
        hi,
        lo,
        u8::from(conv.handshake) | (u8::from(conv.close) << 1),
    ])
}

// --- raw IPv4 frames (LINKTYPE_RAW) --------------------------------------------------------

/// Client address of the crafted conversations.
pub const CLIENT_IP: [u8; 4] = [10, 0, 0, 1];
/// Server address of the crafted conversations.
pub const SERVER_IP: [u8; 4] = [10, 0, 0, 2];

/// TCP flags of [`tcp_frame`].
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + l4.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(20 + l4.len());
    out.extend_from_slice(&[0x45, 0]);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
    out.extend_from_slice(&src);
    out.extend_from_slice(&dst);
    out.extend_from_slice(l4);
    out
}

/// Raw IPv4 + TCP frame (checksums left at zero: the decoder does not check them).
pub fn tcp_frame(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut l4 = Vec::with_capacity(20 + payload.len());
    l4.extend_from_slice(&src.1.to_be_bytes());
    l4.extend_from_slice(&dst.1.to_be_bytes());
    l4.extend_from_slice(&seq.to_be_bytes());
    l4.extend_from_slice(&ack.to_be_bytes());
    l4.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    l4.extend_from_slice(payload);
    ipv4(src.0, dst.0, 6, &l4)
}

/// Raw IPv4 + UDP frame (checksum zero: "not computed" for UDP over IPv4).
pub fn udp_frame(src: ([u8; 4], u16), dst: ([u8; 4], u16), payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let mut l4 = Vec::with_capacity(8 + payload.len());
    l4.extend_from_slice(&src.1.to_be_bytes());
    l4.extend_from_slice(&dst.1.to_be_bytes());
    l4.extend_from_slice(&len.to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    l4.extend_from_slice(payload);
    ipv4(src.0, dst.0, 17, &l4)
}

// --- record sink and analyzer fan-out ------------------------------------------------------

/// Collects records like the engine's shard buffer, and accepts every blob (with a fake digest)
/// so that the code paths using a stored object run too.
#[derive(Debug, Default)]
pub struct Sink {
    pub records: Vec<Record>,
    pub dropped: usize,
}

impl RecordSink for Sink {
    fn emit(&mut self, record: Record) {
        if self.records.len() < MAX_RECORDS {
            self.records.push(record);
        } else {
            self.dropped += 1;
        }
    }

    fn put_blob(&mut self, data: &[u8]) -> Option<BlobRef> {
        Some(BlobRef {
            sha256: [0xab; 32],
            size: u64::try_from(data.len()).unwrap_or(u64::MAX),
        })
    }
}

/// Analyzer settings of the targets: defaults, plus HTTP body storage (object extraction).
pub fn analyzer_config() -> AnalyzerConfig {
    let mut config = AnalyzerConfig::default();
    config.http.store_bodies = true;
    config
}

/// Every built-in analyzer, as instantiated for one engine shard.
pub fn builtin_analyzers() -> Vec<Box<dyn Analyzer>> {
    Registry::builtin(analyzer_config()).build_shard()
}

/// Flow events fanned out to analyzers, as the engine's shard does.
pub struct Fanout<'a> {
    pub analyzers: &'a mut [Box<dyn Analyzer>],
    pub sink: &'a mut Sink,
}

impl FlowSink for Fanout<'_> {
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &netsift_analyze::dissect::Decoded<'_>) {
        for a in self.analyzers.iter_mut() {
            a.on_packet(ctx, pkt, self.sink);
        }
    }

    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        for a in self.analyzers.iter_mut() {
            a.on_stream(ctx, dir, data, self.sink);
        }
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx) {
        for a in self.analyzers.iter_mut() {
            a.on_flow_end(ctx, self.sink);
        }
    }
}

/// Ends the capture: `finish` of every analyzer.
pub fn finish(analyzers: &mut [Box<dyn Analyzer>], sink: &mut Sink) {
    for a in analyzers.iter_mut() {
        a.finish(sink);
    }
}

fn endpoint(ip: [u8; 4], port: u16) -> Endpoint {
    Endpoint {
        ip: IpAddr::V4(Ipv4Addr::from(ip)),
        port,
    }
}

/// Feeds `segs` straight into [`Analyzer::on_stream`] as one TCP flow from `client_port` to
/// `server_port` (gaps reported in [`StreamCtx::gap_before`]), then ends the flow and the
/// capture.
pub fn drive_stream(
    analyzers: &mut [Box<dyn Analyzer>],
    client_port: u16,
    server_port: u16,
    segs: &[Segment<'_>],
    sink: &mut Sink,
) {
    let key = FlowKey {
        proto: 6,
        client: endpoint(CLIENT_IP, client_port),
        server: endpoint(SERVER_IP, server_port),
    };
    let id = FlowId::from_first_frame(0);
    let mut ts = BASE_TS_NS;
    for (frame, seg) in (0u64..).zip(segs) {
        ts += MS;
        let ctx = StreamCtx {
            ts_ns: ts,
            chunk_id: 0,
            frame,
            id,
            key,
            gap_before: seg.gap,
        };
        let dir = if seg.to_server {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        for a in analyzers.iter_mut() {
            a.on_stream(&ctx, dir, seg.data, sink);
        }
    }
    let end = FlowCtx {
        id,
        key,
        first_ts_ns: BASE_TS_NS,
        last_ts_ns: ts,
        to_server: DirStats::default(),
        to_client: DirStats::default(),
        tcp_state: Some(TcpState::Closed),
        end: EndReason::Closed,
    };
    for a in analyzers.iter_mut() {
        a.on_flow_end(&end, sink);
    }
    finish(analyzers, sink);
}

/// Crafts the frames of a conversation (raw IPv4): TCP with coherent sequence numbers (a
/// segment gap skips sequence space, as a lost segment would), or one UDP datagram per segment.
pub fn conversation_frames(conv: &Conversation, segs: &[Segment<'_>]) -> Vec<Vec<u8>> {
    let client = (CLIENT_IP, conv.client_port);
    let server = (SERVER_IP, conv.server_port);
    let mut out = Vec::new();
    if conv.udp {
        for seg in segs {
            let (src, dst) = if seg.to_server {
                (client, server)
            } else {
                (server, client)
            };
            out.push(udp_frame(src, dst, seg.data));
        }
        return out;
    }
    use tcp_flags::{ACK, FIN, PSH, SYN};
    let (c_isn, s_isn) = (1_000u32, 5_000_000u32);
    let (mut c_next, mut s_next) = (c_isn.wrapping_add(1), s_isn.wrapping_add(1));
    if conv.handshake {
        out.push(tcp_frame(client, server, c_isn, 0, SYN, &[]));
        out.push(tcp_frame(server, client, s_isn, c_next, SYN | ACK, &[]));
        out.push(tcp_frame(client, server, c_next, s_next, ACK, &[]));
    }
    for seg in segs {
        let gap = u32::try_from(seg.gap).unwrap_or(0);
        let pieces: Vec<&[u8]> = if seg.data.is_empty() {
            vec![&[]]
        } else {
            seg.data.chunks(MAX_TCP_PAYLOAD).collect()
        };
        for (i, piece) in pieces.into_iter().enumerate() {
            let len = u32::try_from(piece.len()).unwrap_or(0);
            let skip = if i == 0 { gap } else { 0 };
            if seg.to_server {
                c_next = c_next.wrapping_add(skip);
                out.push(tcp_frame(client, server, c_next, s_next, ACK | PSH, piece));
                c_next = c_next.wrapping_add(len);
            } else {
                s_next = s_next.wrapping_add(skip);
                out.push(tcp_frame(server, client, s_next, c_next, ACK | PSH, piece));
                s_next = s_next.wrapping_add(len);
            }
        }
    }
    if conv.close {
        out.push(tcp_frame(client, server, c_next, s_next, FIN | ACK, &[]));
        out.push(tcp_frame(
            server,
            client,
            s_next,
            c_next.wrapping_add(1),
            FIN | ACK,
            &[],
        ));
    }
    out
}

/// Runs a conversation through a flow table into `analyzers`, then ends the capture.
pub fn drive_flow(
    analyzers: &mut [Box<dyn Analyzer>],
    conv: &Conversation,
    segs: &[Segment<'_>],
    sink: &mut Sink,
) {
    let frames = conversation_frames(conv, segs);
    let mut table = FlowTable::new(FlowConfig::default());
    let mut fanout = Fanout { analyzers, sink };
    let mut ts = BASE_TS_NS;
    for (frame, data) in (0u64..).zip(&frames) {
        ts += MS;
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        table.process(ts, 0, frame, linktype::RAW, len, data, &mut fanout);
    }
    table.finish(&mut fanout);
    finish(fanout.analyzers, fanout.sink);
}

/// Runs captured frames (time order as given) through a flow table into `sink`.
pub fn run_frames<'f>(
    table: &mut FlowTable,
    sink: &mut dyn FlowSink,
    frames: impl IntoIterator<Item = (i64, u32, &'f [u8])>,
) {
    for (frame, (ts, linktype, data)) in (0u64..).zip(frames) {
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        table.process(ts, 0, frame, linktype, len, data, sink);
    }
    table.finish(sink);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_round_trip() {
        let mut buf = Vec::new();
        push_segment(&mut buf, true, 0, b"hello");
        push_segment(&mut buf, false, 7, b"world");
        let segs = segments(&buf);
        assert_eq!(
            segs,
            vec![
                Segment {
                    to_server: true,
                    gap: 0,
                    data: b"hello"
                },
                Segment {
                    to_server: false,
                    gap: 7,
                    data: b"world"
                },
            ]
        );
    }

    #[test]
    fn conversation_head_round_trip() {
        let conv = Conversation {
            udp: true,
            client_port: 68,
            server_port: 67,
            handshake: false,
            close: false,
        };
        let head = conversation_head(&conv).unwrap();
        assert_eq!(conversation(&head).unwrap().0, conv);
    }
}
