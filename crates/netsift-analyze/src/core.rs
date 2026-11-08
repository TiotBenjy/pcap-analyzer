//! The built-in `core` analyzer: traffic time series, hosts and flows.
//!
//! - `timeseries`: packets and wire bytes per one-second bucket and [`AppProto`], aggregated in
//!   memory and flushed when the bucket changes (or at [`Analyzer::finish`]). Counted from
//!   `on_packet`, i.e. after IP defragmentation: a reassembled datagram counts once (with the
//!   wire length reported by the flow table) and fragments of a datagram never completed are
//!   not counted. The engine's global counters (packets and bytes read, report, `meta`) are
//!   computed on raw frames instead, so their totals may differ slightly;
//! - `hosts`: IP addresses with their unicast MAC addresses and first/last packet times,
//!   aggregated in memory and flushed periodically (packet time) or when the map is full,
//!   with the address category and, when a country database is loaded
//!   ([`AnalyzerConfig::geo`]), the country (looked up at flush time, cached by `GeoDb`);
//! - `flows`: one summary per finished flow, with its application protocol.
//!
//! Every record is mergeable in any order, so the result does not depend on the number of
//! shards nor on flush moments.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use netsift_dissect::{Decoded, MacAddr, Network};
use netsift_flow::{FlowCtx, PacketCtx};

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::classify::{AppProto, classify_packet, flow_app_proto};
use crate::geo::{AddressCategory, GeoDb};
use crate::record::{FlowSummary, HostSeen, Record, TrafficSample};
use crate::registry::AnalyzerConfig;

const NS_PER_SEC: i64 = 1_000_000_000;

/// Maximum number of MAC addresses kept per host (same bound as the `hosts` table).
pub const MAX_MACS_PER_HOST: usize = 16;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counter {
    bytes: u64,
    packets: u64,
}

#[derive(Debug, Clone)]
struct PendingHost {
    macs: BTreeSet<[u8; 6]>,
    first_ts: i64,
    last_ts: i64,
}

/// See the module documentation.
#[derive(Debug)]
pub struct CoreAnalyzer {
    max_pending_hosts: usize,
    host_flush_interval_ns: i64,
    /// Current one-second bucket and its counters.
    bucket: Option<i64>,
    counters: BTreeMap<AppProto, Counter>,
    hosts: HashMap<IpAddr, PendingHost>,
    /// Packet time of the last host flush (or of the first packet).
    hosts_since: Option<i64>,
    geo: Option<Arc<GeoDb>>,
}

impl CoreAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("core");

    pub fn new(config: &AnalyzerConfig) -> Self {
        Self {
            max_pending_hosts: config.core.max_pending_hosts.max(1),
            host_flush_interval_ns: config.core.host_flush_interval_ns.max(0),
            bucket: None,
            counters: BTreeMap::new(),
            hosts: HashMap::new(),
            hosts_since: None,
            geo: config.geo.clone(),
        }
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }

    fn count(&mut self, ts_ns: i64, proto: AppProto, wire_len: u32, out: &mut dyn RecordSink) {
        let bucket = ts_ns.div_euclid(NS_PER_SEC);
        if self.bucket != Some(bucket) {
            self.flush_timeseries(out);
            self.bucket = Some(bucket);
        }
        let c = self.counters.entry(proto).or_default();
        c.bytes = c.bytes.saturating_add(u64::from(wire_len));
        c.packets = c.packets.saturating_add(1);
    }

    fn flush_timeseries(&mut self, out: &mut dyn RecordSink) {
        let Some(bucket_s) = self.bucket else { return };
        for (proto, c) in std::mem::take(&mut self.counters) {
            out.emit(Record::Timeseries(TrafficSample {
                bucket_s,
                proto,
                bytes: c.bytes,
                packets: c.packets,
            }));
        }
    }

    fn observe(&mut self, ts_ns: i64, ip: IpAddr, mac: Option<MacAddr>, out: &mut dyn RecordSink) {
        if ip.is_unspecified() {
            return;
        }
        let since = *self.hosts_since.get_or_insert(ts_ns);
        let full = self.hosts.len() >= self.max_pending_hosts && !self.hosts.contains_key(&ip);
        if full || ts_ns.saturating_sub(since) >= self.host_flush_interval_ns {
            self.flush_hosts(out);
            self.hosts_since = Some(ts_ns);
        }
        let host = self.hosts.entry(ip).or_insert(PendingHost {
            macs: BTreeSet::new(),
            first_ts: ts_ns,
            last_ts: ts_ns,
        });
        host.first_ts = host.first_ts.min(ts_ns);
        host.last_ts = host.last_ts.max(ts_ns);
        if let Some(mac) = mac.filter(|m| !m.is_multicast() && m.0 != [0; 6]) {
            host.macs.insert(mac.0);
            if host.macs.len() > MAX_MACS_PER_HOST {
                host.macs.pop_last();
            }
        }
    }

    fn flush_hosts(&mut self, out: &mut dyn RecordSink) {
        let mut hosts: Vec<_> = self.hosts.drain().collect();
        // Deterministic emission order (the store merge does not need it; tests do).
        hosts.sort_unstable_by_key(|(ip, _)| *ip);
        for (ip, h) in hosts {
            out.emit(Record::Host(HostSeen {
                ip,
                macs: h.macs.into_iter().collect(),
                names: Vec::new(),
                category: AddressCategory::of(ip),
                country: self.geo.as_ref().and_then(|g| g.country(ip)),
                first_ts: h.first_ts,
                last_ts: h.last_ts,
            }));
        }
    }
}

impl Analyzer for CoreAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        self.count(ctx.ts_ns, classify_packet(ctx, pkt), ctx.wire_len, out);
        match &pkt.network {
            Some(Network::Ip(ip)) => {
                self.observe(ctx.ts_ns, ip.src, pkt.link.src_mac, out);
                self.observe(ctx.ts_ns, ip.dst, pkt.link.dst_mac, out);
            }
            Some(Network::Arp(arp)) => {
                if let Some(ip) = arp.sender_ip {
                    self.observe(ctx.ts_ns, ip, arp.sender_mac, out);
                }
            }
            None => {}
        }
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        out.emit(Record::Flow(FlowSummary {
            flow: *ctx,
            app_proto: flow_app_proto(&ctx.key),
        }));
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        self.flush_timeseries(out);
        self.bucket = None;
        self.flush_hosts(out);
        self.hosts_since = None;
    }
}

/// Merges records the way the store does (tests and diagnostics): sums time series by
/// `(bucket, proto)`, unites hosts by IP. Flows are kept as they are.
#[allow(clippy::match_wildcard_for_single_variants)] // records of the other analyzers
pub fn merge_core(records: &[Record]) -> (Vec<TrafficSample>, Vec<HostSeen>, Vec<FlowSummary>) {
    let mut ts: BTreeMap<(i64, AppProto), Counter> = BTreeMap::new();
    let mut hosts: BTreeMap<IpAddr, HostSeen> = BTreeMap::new();
    let mut flows = Vec::new();
    for r in records {
        match r {
            Record::Timeseries(s) => {
                let c = ts.entry((s.bucket_s, s.proto)).or_default();
                c.bytes = c.bytes.saturating_add(s.bytes);
                c.packets = c.packets.saturating_add(s.packets);
            }
            Record::Host(h) => match hosts.entry(h.ip) {
                Entry::Vacant(e) => {
                    e.insert(h.clone());
                }
                Entry::Occupied(mut e) => {
                    let m = e.get_mut();
                    m.first_ts = m.first_ts.min(h.first_ts);
                    m.last_ts = m.last_ts.max(h.last_ts);
                    m.macs.extend(&h.macs);
                    m.macs.sort_unstable();
                    m.macs.dedup();
                    m.macs.truncate(MAX_MACS_PER_HOST);
                    m.names.extend(h.names.iter().cloned());
                    m.names.sort_unstable();
                    m.names.dedup();
                    m.category = m.category.min(h.category);
                    // Non-empty wins, then the smallest (the store rule).
                    m.country = match (m.country, h.country) {
                        (Some(known), Some(other)) => Some(known.min(other)),
                        (known, other) => known.or(other),
                    };
                }
            },
            Record::Flow(f) => flows.push(*f),
            // Records of other analyzers.
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }
    let ts = ts
        .into_iter()
        .map(|((bucket_s, proto), c)| TrafficSample {
            bucket_s,
            proto,
            bytes: c.bytes,
            packets: c.packets,
        })
        .collect();
    flows.sort_unstable_by_key(|f| f.flow.id);
    (ts, hosts.into_values().collect(), flows)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::net::Ipv4Addr;

    use netsift_dissect::decode;
    use netsift_fixtures::scenarios::{Kind, generate};
    use netsift_flow::{
        DirStats, Direction, EndReason, Endpoint, FlowId, FlowKey, PacketFlow, TcpState,
    };

    use super::*;

    fn run(core: &mut CoreAnalyzer, packets: &[netsift_fixtures::Packet]) -> Vec<Record> {
        let mut out = Vec::new();
        for p in packets {
            let pkt = decode(p.linktype, &p.data);
            let ctx = PacketCtx {
                ts_ns: p.ts_ns,
                chunk_id: 0,
                frame: 0,
                wire_len: u32::try_from(p.data.len()).unwrap(),
                flow: None,
            };
            core.on_packet(&ctx, &pkt, &mut out);
        }
        core.finish(&mut out);
        out
    }

    fn render(records: &[Record]) -> String {
        let (ts, hosts, flows) = merge_core(records);
        let mut s = String::new();
        for t in ts {
            writeln!(
                s,
                "ts {} {} bytes={} packets={}",
                t.bucket_s, t.proto, t.bytes, t.packets
            )
            .unwrap();
        }
        for h in hosts {
            let macs: Vec<String> = h
                .macs
                .iter()
                .map(|m| {
                    m.iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":")
                })
                .collect();
            let country = h.country.map_or_else(|| "-".to_owned(), |c| c.to_string());
            writeln!(
                s,
                "host {} {} country={country} macs={macs:?} {}..{}",
                h.ip, h.category, h.first_ts, h.last_ts
            )
            .unwrap();
        }
        for f in flows {
            writeln!(s, "flow {:?} {:?}", f.flow.id, f.app_proto).unwrap();
        }
        s
    }

    #[test]
    fn demo_scenario_snapshot() {
        let packets = generate(Kind::Demo, 3, 7);
        let mut core = CoreAnalyzer::new(&AnalyzerConfig::default());
        let records = run(&mut core, &packets);
        insta::assert_snapshot!(render(&records));
    }

    #[test]
    fn timeseries_are_flushed_per_bucket_not_per_packet() {
        let packets = generate(Kind::Demo, 3, 7);
        let mut core = CoreAnalyzer::new(&AnalyzerConfig::default());
        let records = run(&mut core, &packets);
        let samples = records
            .iter()
            .filter(|r| matches!(r, Record::Timeseries(_)))
            .count();
        let (merged, _, _) = merge_core(&records);
        // Packets are in time order: one sample per (bucket, proto), never one per packet.
        assert_eq!(samples, merged.len());
        assert!(samples < packets.len());
        let total: u64 = merged.iter().map(|s| s.packets).sum();
        assert_eq!(total, packets.len() as u64);
        let bytes: u64 = merged.iter().map(|s| s.bytes).sum();
        assert_eq!(
            bytes,
            packets.iter().map(|p| p.data.len() as u64).sum::<u64>()
        );
    }

    #[test]
    fn results_do_not_depend_on_flush_settings() {
        let packets = generate(Kind::Demo, 4, 3);
        let mut default = CoreAnalyzer::new(&AnalyzerConfig::default());
        let tiny_config = AnalyzerConfig {
            core: crate::registry::CoreConfig {
                max_pending_hosts: 1,
                host_flush_interval_ns: 0,
            },
            ..AnalyzerConfig::default()
        };
        let mut tiny = CoreAnalyzer::new(&tiny_config);
        assert_eq!(
            render(&run(&mut default, &packets)),
            render(&run(&mut tiny, &packets))
        );
    }

    fn flow_key() -> FlowKey {
        FlowKey {
            proto: 6,
            client: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                port: 51_000,
            },
            server: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 80)),
                port: 8080,
            },
        }
    }

    #[test]
    fn packets_of_a_flow_use_the_flow_label() {
        let key = flow_key();
        let frame = generate(Kind::Dns, 1, 1).remove(0);
        let pkt = decode(frame.linktype, &frame.data);
        let ctx = PacketCtx {
            ts_ns: 5 * NS_PER_SEC,
            chunk_id: 0,
            frame: 0,
            wire_len: 100,
            flow: Some(PacketFlow {
                id: FlowId::derive(&key, 0),
                key,
                dir: Direction::ToServer,
            }),
        };
        let mut core = CoreAnalyzer::new(&AnalyzerConfig::default());
        let mut out = Vec::new();
        core.on_packet(&ctx, &pkt, &mut out);
        core.finish(&mut out);
        let (ts, _, _) = merge_core(&out);
        assert_eq!(
            ts,
            vec![TrafficSample {
                bucket_s: 5,
                proto: AppProto::Http,
                bytes: 100,
                packets: 1
            }]
        );
    }

    #[test]
    fn flow_end_emits_a_summary() {
        let key = flow_key();
        let ctx = FlowCtx {
            id: FlowId::derive(&key, 1),
            key,
            first_ts_ns: 1,
            last_ts_ns: 2,
            to_server: DirStats {
                packets: 3,
                bytes: 300,
            },
            to_client: DirStats::default(),
            tcp_state: Some(TcpState::Closed),
            end: EndReason::Closed,
        };
        let mut core = CoreAnalyzer::new(&AnalyzerConfig::default());
        let mut out = Vec::new();
        core.on_flow_end(&ctx, &mut out);
        core.finish(&mut out);
        assert_eq!(
            out,
            vec![Record::Flow(FlowSummary {
                flow: ctx,
                app_proto: Some(AppProto::Http)
            })]
        );
    }

    fn geo_config() -> AnalyzerConfig {
        let bytes = netsift_geo::test_util::MmdbBuilder::new()
            .network(IpAddr::V4(Ipv4Addr::new(81, 0, 0, 0)), 8, "FR")
            // Documentation range: reserved, never looked up.
            .network(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24, "DE")
            .build();
        AnalyzerConfig {
            geo: Some(Arc::new(GeoDb::from_bytes(bytes).unwrap())),
            ..AnalyzerConfig::default()
        }
    }

    #[test]
    fn hosts_carry_category_and_country() {
        let mut sc = netsift_fixtures::Scenario::new();
        let public = netsift_fixtures::Host::v4(
            netsift_fixtures::scenarios::hosts::router().mac,
            [81, 2, 3, 4],
        );
        sc.http_get(
            netsift_fixtures::scenarios::hosts::workstation(),
            public,
            &netsift_fixtures::scenario::HttpGet::default(),
        );
        sc.http_get(
            netsift_fixtures::scenarios::hosts::workstation(),
            netsift_fixtures::scenarios::hosts::web_server(),
            &netsift_fixtures::scenario::HttpGet::default(),
        );
        let packets = sc.into_packets();

        let mut with_geo = CoreAnalyzer::new(&geo_config());
        let (_, hosts, _) = merge_core(&run(&mut with_geo, &packets));
        let summary: Vec<_> = hosts
            .iter()
            .map(|h| {
                (
                    h.ip.to_string(),
                    h.category,
                    h.country.map(|c| c.to_string()),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    "81.2.3.4".to_owned(),
                    AddressCategory::Public,
                    Some("FR".to_owned())
                ),
                ("192.168.1.10".to_owned(), AddressCategory::Private, None),
                ("203.0.113.80".to_owned(), AddressCategory::Reserved, None),
            ]
        );

        // Without a database: same categories, no country.
        let mut without = CoreAnalyzer::new(&AnalyzerConfig::default());
        let (_, hosts, _) = merge_core(&run(&mut without, &packets));
        assert_eq!(hosts.len(), 3);
        assert!(hosts.iter().all(|h| h.country.is_none()));
        assert_eq!(
            hosts.iter().map(|h| h.category).collect::<Vec<_>>(),
            summary.iter().map(|s| s.1).collect::<Vec<_>>()
        );
    }

    #[test]
    fn country_merge_prefers_known_then_smallest() {
        let host = |country: Option<&str>| {
            Record::Host(HostSeen {
                ip: IpAddr::V4(Ipv4Addr::new(81, 0, 0, 1)),
                macs: Vec::new(),
                names: Vec::new(),
                category: AddressCategory::Public,
                country: country.and_then(crate::geo::CountryCode::new),
                first_ts: 0,
                last_ts: 0,
            })
        };
        let merged = |records: &[Record]| merge_core(records).1[0].country.map(|c| c.to_string());
        assert_eq!(
            merged(&[host(None), host(Some("FR"))]).as_deref(),
            Some("FR")
        );
        assert_eq!(
            merged(&[host(Some("FR")), host(None)]).as_deref(),
            Some("FR")
        );
        assert_eq!(
            merged(&[host(Some("FR")), host(Some("DE"))]).as_deref(),
            Some("DE")
        );
        assert_eq!(merged(&[host(None), host(None)]), None);
    }

    #[test]
    fn hostile_frames_never_panic() {
        let mut core = CoreAnalyzer::new(&AnalyzerConfig::default());
        let mut out = Vec::new();
        for len in 0..64usize {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 37 % 256).unwrap())
                .collect();
            for linktype in [0, 1, 101, 113, 127, 276] {
                let pkt = decode(linktype, &data);
                let ctx = PacketCtx {
                    ts_ns: i64::MIN + i64::try_from(len).unwrap(),
                    chunk_id: 0,
                    frame: 0,
                    wire_len: u32::MAX,
                    flow: None,
                };
                core.on_packet(&ctx, &pkt, &mut out);
            }
        }
        core.finish(&mut out);
        assert_ne!(out.len(), 0);
    }
}
