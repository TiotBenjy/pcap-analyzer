//! Recording sink and helpers shared by the flow-table integration tests.
#![allow(dead_code)]

use std::fmt::Write as _;

use netsift_dissect::{Decoded, Transport};
use netsift_fixtures::Packet;
use netsift_flow::{
    Direction, EndReason, FlowConfig, FlowCtx, FlowId, FlowSink, FlowTable, PacketCtx, StreamCtx,
};

pub const S: i64 = 1_000_000_000;
pub const MS: i64 = 1_000_000;

/// One sink call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Packet {
        ctx: PacketCtx,
        /// Short description of the decoded packet.
        summary: String,
        payload: Vec<u8>,
    },
    Stream {
        ctx: StreamCtx,
        dir: Direction,
        data: Vec<u8>,
    },
    End(FlowCtx),
}

/// Records every sink call in order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Recorder {
    pub events: Vec<Event>,
}

fn summary(pkt: &Decoded<'_>) -> String {
    let ip = pkt.ip().map_or("-".to_owned(), |ip| {
        format!("{}>{} p{}", ip.src, ip.dst, ip.protocol)
    });
    let l4 = match &pkt.transport {
        Some(Transport::Tcp(t)) => format!("tcp {}>{} {:?}", t.src_port, t.dst_port, t.flags),
        Some(Transport::Udp(u)) => format!("udp {}>{}", u.src_port, u.dst_port),
        Some(Transport::Icmpv4(i) | Transport::Icmpv6(i)) => format!("icmp t{}", i.icmp_type),
        None => "-".to_owned(),
    };
    format!("{ip} {l4} len={}", pkt.payload.len())
}

impl FlowSink for Recorder {
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>) {
        self.events.push(Event::Packet {
            ctx: *ctx,
            summary: summary(pkt),
            payload: pkt.payload.to_vec(),
        });
    }

    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        self.events.push(Event::Stream {
            ctx: *ctx,
            dir,
            data: data.to_vec(),
        });
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx) {
        self.events.push(Event::End(*ctx));
    }
}

impl Recorder {
    pub fn ends(&self) -> Vec<FlowCtx> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::End(c) => Some(*c),
                _ => None,
            })
            .collect()
    }

    pub fn packets(&self) -> Vec<(PacketCtx, String, Vec<u8>)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Packet {
                    ctx,
                    summary,
                    payload,
                } => Some((*ctx, summary.clone(), payload.clone())),
                _ => None,
            })
            .collect()
    }

    /// Concatenated stream of one flow and direction, and the non-zero gaps reported.
    pub fn stream(&self, id: FlowId, dir: Direction) -> (Vec<u8>, Vec<u64>) {
        let mut data = Vec::new();
        let mut gaps = Vec::new();
        for e in &self.events {
            if let Event::Stream {
                ctx,
                dir: d,
                data: bytes,
            } = e
                && ctx.id == id
                && *d == dir
            {
                if ctx.gap_before > 0 {
                    gaps.push(ctx.gap_before);
                }
                data.extend_from_slice(bytes);
            }
        }
        (data, gaps)
    }

    /// The only flow that ended; panics otherwise.
    pub fn single_flow(&self) -> FlowCtx {
        let ends = self.ends();
        assert_eq!(ends.len(), 1, "exactly one flow expected: {ends:#?}");
        ends[0]
    }

    /// Checks that every flow id seen in packets and streams ends exactly once, after its last
    /// packet and stream event.
    pub fn assert_ends_once(&self) {
        let mut ended: Vec<FlowId> = Vec::new();
        for e in &self.events {
            match e {
                Event::Packet { ctx, .. } => {
                    if let Some(f) = ctx.flow {
                        assert!(!ended.contains(&f.id), "packet after the end of {:?}", f.id);
                    }
                }
                Event::Stream { ctx, .. } => {
                    assert!(
                        !ended.contains(&ctx.id),
                        "stream after the end of {:?}",
                        ctx.id
                    );
                }
                Event::End(c) => {
                    assert!(!ended.contains(&c.id), "flow {:?} ended twice", c.id);
                    ended.push(c.id);
                }
            }
        }
        for e in &self.events {
            if let Event::Packet { ctx, .. } = e
                && let Some(f) = ctx.flow
            {
                assert!(ended.contains(&f.id), "flow {:?} never ended", f.id);
            }
        }
    }

    /// Compact text rendering for snapshots.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let t0 = self.events.iter().find_map(|e| match e {
            Event::Packet { ctx, .. } => Some(ctx.ts_ns),
            _ => None,
        });
        let rel = |ts: i64| (ts - t0.unwrap_or(ts)) / 1_000;
        let dir = |d: Direction| match d {
            Direction::ToServer => "c>s",
            Direction::ToClient => "s>c",
        };
        for e in &self.events {
            match e {
                Event::Packet { ctx, summary, .. } => {
                    let flow = ctx.flow.map_or("-".to_owned(), |f| {
                        format!("{:016x} {}", f.id.0, dir(f.dir))
                    });
                    writeln!(
                        out,
                        "pkt +{}us {flow} wire={} {summary}",
                        rel(ctx.ts_ns),
                        ctx.wire_len
                    )
                    .unwrap();
                }
                Event::Stream { ctx, dir: d, data } => {
                    let text: String = data
                        .iter()
                        .take(24)
                        .map(|&b| {
                            if b.is_ascii_graphic() || b == b' ' {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    writeln!(
                        out,
                        "stream +{}us {:016x} {} gap={} len={} {text:?}",
                        rel(ctx.ts_ns),
                        ctx.id.0,
                        dir(*d),
                        ctx.gap_before,
                        data.len()
                    )
                    .unwrap();
                }
                Event::End(c) => {
                    writeln!(
                        out,
                        "end {:016x} p{} {}:{} > {}:{} +{}us..+{}us c>s {}p/{}B s>c {}p/{}B {:?} {:?}",
                        c.id.0,
                        c.key.proto,
                        c.key.client.ip,
                        c.key.client.port,
                        c.key.server.ip,
                        c.key.server.port,
                        rel(c.first_ts_ns),
                        rel(c.last_ts_ns),
                        c.to_server.packets,
                        c.to_server.bytes,
                        c.to_client.packets,
                        c.to_client.bytes,
                        c.tcp_state,
                        c.end
                    )
                    .unwrap();
                }
            }
        }
        out
    }
}

/// Feeds `packets` (chunk 0, wire length = captured length) to a new table, then finishes.
pub fn run(packets: &[Packet], config: FlowConfig) -> Recorder {
    let mut table = FlowTable::new(config);
    let mut rec = Recorder::default();
    feed(&mut table, packets, &mut rec);
    table.finish(&mut rec);
    assert_eq!(table.active_flows(), 0);
    rec.assert_ends_once();
    rec
}

/// Feeds `packets` without finishing.
pub fn feed(table: &mut FlowTable, packets: &[Packet], rec: &mut Recorder) {
    for p in packets {
        let len = u32::try_from(p.data.len()).unwrap();
        table.process(p.ts_ns, p.interface, p.linktype, len, &p.data, rec);
    }
}

/// Frames stamped `start + i * gap`.
pub fn timed(frames: Vec<Vec<u8>>, start: i64, gap: i64) -> Vec<Packet> {
    frames
        .into_iter()
        .enumerate()
        .map(|(i, f)| netsift_fixtures::craft::packet(start + i64::try_from(i).unwrap() * gap, f))
        .collect()
}

pub fn ends_with(rec: &Recorder, reason: EndReason) -> usize {
    rec.ends().iter().filter(|c| c.end == reason).count()
}
