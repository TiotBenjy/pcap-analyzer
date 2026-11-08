//! The `connections` analyzer: traffic between hosts, for the Connections view.
//!
//! Every finished flow is folded into:
//! - its **conversation**, keyed by (client IP, server IP) where the client is the initiator of
//!   the flow (`FlowKey::client`): bytes and packets per direction, number of flows, part of
//!   DNS traffic (the "Include DNS" switch of the view), first and last packet times and the
//!   set of protocol labels ([`classify_flow`]);
//! - the **traffic of each of its two hosts** (bytes and packets sent and received), from
//!   which the view ranks source and destination countries.
//!
//! Both are pre-aggregated per shard in bounded maps and flushed as additive deltas (when a
//! map is full, when packet time advances by `flush_interval_ns`, and at the end): the store
//! adds them up, so the result depends neither on the number of shards nor on flush moments.
//! Rankings (top N, countries) are computed in SQL at read time.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use netsift_flow::FlowCtx;

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::classify::{AppProto, classify_flow};
use crate::record::Record;
use crate::registry::AnalyzerConfig;

/// Settings of the `connections` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionsConfig {
    /// Maximum number of conversations (and of hosts) aggregated per shard before a flush.
    pub max_pending: usize,
    /// Pending deltas are flushed when packet time advances this much (ns).
    pub flush_interval_ns: i64,
}

impl Default for ConnectionsConfig {
    fn default() -> Self {
        Self {
            max_pending: 16_384,
            flush_interval_ns: 60 * 1_000_000_000,
        }
    }
}

/// Traffic of one or more flows from `client` (initiator) to `server` (additive delta).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationDelta {
    pub client: IpAddr,
    pub server: IpAddr,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Client -> server.
    pub bytes_fwd: u64,
    /// Server -> client.
    pub bytes_rev: u64,
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub flows: u64,
    /// Part of `bytes_fwd` / `bytes_rev` carried by DNS flows.
    pub dns_bytes_fwd: u64,
    pub dns_bytes_rev: u64,
    pub dns_flows: u64,
    /// Protocol labels of the flows, sorted and deduplicated.
    pub protocols: Vec<AppProto>,
}

/// Traffic sent and received by one host (additive delta).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostTrafficDelta {
    pub ip: IpAddr,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

#[derive(Debug, Clone)]
struct PendingConversation {
    first_ts: i64,
    last_ts: i64,
    bytes_fwd: u64,
    bytes_rev: u64,
    packets_fwd: u64,
    packets_rev: u64,
    flows: u64,
    dns_bytes_fwd: u64,
    dns_bytes_rev: u64,
    dns_flows: u64,
    protocols: BTreeSet<AppProto>,
}

#[derive(Debug, Clone, Copy, Default)]
struct PendingHost {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
}

/// See the module documentation.
#[derive(Debug)]
pub struct ConnectionsAnalyzer {
    max_pending: usize,
    flush_interval_ns: i64,
    conversations: HashMap<(IpAddr, IpAddr), PendingConversation>,
    hosts: HashMap<IpAddr, PendingHost>,
    /// Packet time of the last flush (or of the first flow end).
    since: Option<i64>,
}

impl ConnectionsAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("connections");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            max_pending: config.connections.max_pending.max(1),
            flush_interval_ns: config.connections.flush_interval_ns.max(0),
            conversations: HashMap::new(),
            hosts: HashMap::new(),
            since: None,
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    fn host(&mut self, ip: IpAddr, sent: (u64, u64), received: (u64, u64)) {
        let h = self.hosts.entry(ip).or_default();
        h.bytes_sent = h.bytes_sent.saturating_add(sent.0);
        h.packets_sent = h.packets_sent.saturating_add(sent.1);
        h.bytes_received = h.bytes_received.saturating_add(received.0);
        h.packets_received = h.packets_received.saturating_add(received.1);
    }

    fn flush(&mut self, out: &mut dyn RecordSink) {
        let mut conversations: Vec<_> = self.conversations.drain().collect();
        // Deterministic emission order (the store merge does not need it; tests do).
        conversations.sort_unstable_by_key(|(key, _)| *key);
        for ((client, server), c) in conversations {
            out.emit(Record::Conversation(ConversationDelta {
                client,
                server,
                first_ts: c.first_ts,
                last_ts: c.last_ts,
                bytes_fwd: c.bytes_fwd,
                bytes_rev: c.bytes_rev,
                packets_fwd: c.packets_fwd,
                packets_rev: c.packets_rev,
                flows: c.flows,
                dns_bytes_fwd: c.dns_bytes_fwd,
                dns_bytes_rev: c.dns_bytes_rev,
                dns_flows: c.dns_flows,
                protocols: c.protocols.into_iter().collect(),
            }));
        }
        let mut hosts: Vec<_> = self.hosts.drain().collect();
        hosts.sort_unstable_by_key(|(ip, _)| *ip);
        for (ip, h) in hosts {
            out.emit(Record::HostTraffic(HostTrafficDelta {
                ip,
                bytes_sent: h.bytes_sent,
                bytes_received: h.bytes_received,
                packets_sent: h.packets_sent,
                packets_received: h.packets_received,
            }));
        }
    }
}

impl Analyzer for ConnectionsAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        let since = *self.since.get_or_insert(ctx.last_ts_ns);
        let key = (ctx.key.client.ip, ctx.key.server.ip);
        let full = (self.conversations.len() >= self.max_pending
            && !self.conversations.contains_key(&key))
            || self.hosts.len().saturating_add(2) > self.max_pending.saturating_mul(2);
        if full || ctx.last_ts_ns.saturating_sub(since) >= self.flush_interval_ns {
            self.flush(out);
            self.since = Some(ctx.last_ts_ns);
        }

        let proto = classify_flow(&ctx.key);
        let dns = proto == AppProto::Dns;
        let (fwd, rev) = (ctx.to_server, ctx.to_client);
        let c = self
            .conversations
            .entry(key)
            .or_insert_with(|| PendingConversation {
                first_ts: ctx.first_ts_ns,
                last_ts: ctx.last_ts_ns,
                bytes_fwd: 0,
                bytes_rev: 0,
                packets_fwd: 0,
                packets_rev: 0,
                flows: 0,
                dns_bytes_fwd: 0,
                dns_bytes_rev: 0,
                dns_flows: 0,
                protocols: BTreeSet::new(),
            });
        c.first_ts = c.first_ts.min(ctx.first_ts_ns);
        c.last_ts = c.last_ts.max(ctx.last_ts_ns);
        c.bytes_fwd = c.bytes_fwd.saturating_add(fwd.bytes);
        c.bytes_rev = c.bytes_rev.saturating_add(rev.bytes);
        c.packets_fwd = c.packets_fwd.saturating_add(fwd.packets);
        c.packets_rev = c.packets_rev.saturating_add(rev.packets);
        c.flows = c.flows.saturating_add(1);
        if dns {
            c.dns_bytes_fwd = c.dns_bytes_fwd.saturating_add(fwd.bytes);
            c.dns_bytes_rev = c.dns_bytes_rev.saturating_add(rev.bytes);
            c.dns_flows = c.dns_flows.saturating_add(1);
        }
        c.protocols.insert(proto);

        self.host(
            ctx.key.client.ip,
            (fwd.bytes, fwd.packets),
            (rev.bytes, rev.packets),
        );
        self.host(
            ctx.key.server.ip,
            (rev.bytes, rev.packets),
            (fwd.bytes, fwd.packets),
        );
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        self.flush(out);
        self.since = None;
    }
}

/// Merges records the way the store does (tests and diagnostics): conversations by
/// (client, server), host traffic by IP, sorted by key.
pub fn merge_connections(records: &[Record]) -> (Vec<ConversationDelta>, Vec<HostTrafficDelta>) {
    let mut conversations: std::collections::BTreeMap<(IpAddr, IpAddr), ConversationDelta> =
        std::collections::BTreeMap::new();
    let mut hosts: std::collections::BTreeMap<IpAddr, HostTrafficDelta> =
        std::collections::BTreeMap::new();
    for r in records {
        match r {
            Record::Conversation(d) => {
                let m = conversations
                    .entry((d.client, d.server))
                    .or_insert_with(|| ConversationDelta {
                        bytes_fwd: 0,
                        bytes_rev: 0,
                        packets_fwd: 0,
                        packets_rev: 0,
                        flows: 0,
                        dns_bytes_fwd: 0,
                        dns_bytes_rev: 0,
                        dns_flows: 0,
                        protocols: Vec::new(),
                        ..d.clone()
                    });
                m.first_ts = m.first_ts.min(d.first_ts);
                m.last_ts = m.last_ts.max(d.last_ts);
                m.bytes_fwd = m.bytes_fwd.saturating_add(d.bytes_fwd);
                m.bytes_rev = m.bytes_rev.saturating_add(d.bytes_rev);
                m.packets_fwd = m.packets_fwd.saturating_add(d.packets_fwd);
                m.packets_rev = m.packets_rev.saturating_add(d.packets_rev);
                m.flows = m.flows.saturating_add(d.flows);
                m.dns_bytes_fwd = m.dns_bytes_fwd.saturating_add(d.dns_bytes_fwd);
                m.dns_bytes_rev = m.dns_bytes_rev.saturating_add(d.dns_bytes_rev);
                m.dns_flows = m.dns_flows.saturating_add(d.dns_flows);
                m.protocols.extend(&d.protocols);
                m.protocols.sort_unstable();
                m.protocols.dedup();
            }
            Record::HostTraffic(h) => {
                let m = hosts.entry(h.ip).or_insert(HostTrafficDelta {
                    ip: h.ip,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                });
                m.bytes_sent = m.bytes_sent.saturating_add(h.bytes_sent);
                m.bytes_received = m.bytes_received.saturating_add(h.bytes_received);
                m.packets_sent = m.packets_sent.saturating_add(h.packets_sent);
                m.packets_received = m.packets_received.saturating_add(h.packets_received);
            }
            _ => {}
        }
    }
    (
        conversations.into_values().collect(),
        hosts.into_values().collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::net::Ipv4Addr;

    use netsift_flow::{DirStats, EndReason, Endpoint, FlowId, FlowKey, TcpState};

    use super::*;

    fn flow(
        proto: u8,
        client: [u8; 4],
        server: [u8; 4],
        port: u16,
        ts: i64,
        fwd: (u64, u64),
        rev: (u64, u64),
    ) -> FlowCtx {
        let key = FlowKey {
            proto,
            client: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::from(client)),
                port: 50_000,
            },
            server: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::from(server)),
                port,
            },
        };
        FlowCtx {
            id: FlowId::derive(&key, ts),
            key,
            first_ts_ns: ts,
            last_ts_ns: ts + 10,
            to_server: DirStats {
                bytes: fwd.0,
                packets: fwd.1,
            },
            to_client: DirStats {
                bytes: rev.0,
                packets: rev.1,
            },
            tcp_state: (proto == 6).then_some(TcpState::Closed),
            end: EndReason::Closed,
        }
    }

    fn flows() -> Vec<FlowCtx> {
        vec![
            flow(
                6,
                [10, 0, 0, 1],
                [8, 8, 4, 4],
                443,
                100,
                (500, 5),
                (9_000, 8),
            ),
            flow(17, [10, 0, 0, 1], [8, 8, 4, 4], 53, 200, (70, 1), (120, 1)),
            flow(
                6,
                [10, 0, 0, 1],
                [8, 8, 4, 4],
                80,
                300,
                (300, 3),
                (4_000, 4),
            ),
            flow(6, [8, 8, 4, 4], [10, 0, 0, 1], 22, 400, (100, 2), (50, 1)),
            flow(1, [10, 0, 0, 2], [10, 0, 0, 1], 0, 500, (84, 1), (84, 1)),
        ]
    }

    fn run(config: &AnalyzerConfig, flows: &[FlowCtx]) -> Vec<Record> {
        let mut a = ConnectionsAnalyzer::new(config);
        let mut out = Vec::new();
        for f in flows {
            a.on_flow_end(f, &mut out);
        }
        a.finish(&mut out);
        out
    }

    fn render(records: &[Record]) -> String {
        let (conversations, hosts) = merge_connections(records);
        let mut s = String::new();
        for c in conversations {
            let protocols: Vec<_> = c.protocols.iter().map(|p| p.as_str()).collect();
            writeln!(
                s,
                "{} -> {} {}..{} bytes={}/{} packets={}/{} flows={} dns={}/{}/{} {protocols:?}",
                c.client,
                c.server,
                c.first_ts,
                c.last_ts,
                c.bytes_fwd,
                c.bytes_rev,
                c.packets_fwd,
                c.packets_rev,
                c.flows,
                c.dns_bytes_fwd,
                c.dns_bytes_rev,
                c.dns_flows
            )
            .unwrap();
        }
        for h in hosts {
            writeln!(
                s,
                "host {} sent={}/{} received={}/{}",
                h.ip, h.bytes_sent, h.packets_sent, h.bytes_received, h.packets_received
            )
            .unwrap();
        }
        s
    }

    #[test]
    fn flows_fold_into_oriented_conversations() {
        insta::assert_snapshot!(render(&run(&AnalyzerConfig::default(), &flows())));
    }

    #[test]
    fn results_do_not_depend_on_flush_settings() {
        let tiny = AnalyzerConfig {
            connections: ConnectionsConfig {
                max_pending: 1,
                flush_interval_ns: 0,
            },
            ..AnalyzerConfig::default()
        };
        let small = run(&tiny, &flows());
        let large = run(&AnalyzerConfig::default(), &flows());
        assert!(small.len() > large.len(), "tiny maps flush more often");
        assert_eq!(render(&small), render(&large));
    }

    #[test]
    fn host_totals_balance() {
        let (conversations, hosts) = merge_connections(&run(&AnalyzerConfig::default(), &flows()));
        let sent: u64 = hosts.iter().map(|h| h.bytes_sent).sum();
        let received: u64 = hosts.iter().map(|h| h.bytes_received).sum();
        let total: u64 = conversations
            .iter()
            .map(|c| c.bytes_fwd + c.bytes_rev)
            .sum();
        assert_eq!(sent, total);
        assert_eq!(received, total);
    }
}
