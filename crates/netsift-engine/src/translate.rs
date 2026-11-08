//! Translation of analyzer records and chunk-set metadata into store rows.

use netsift_analyze::connections::{ConversationDelta, HostTrafficDelta};
use netsift_analyze::flow::TcpState;
use netsift_analyze::ports::OpenPortSeen;
use netsift_analyze::{FlowSummary, HostSeen, Record, TrafficSample};
use netsift_capture::chunkset::{Anomaly, AnomalyKind, ChunkGroup, ChunkStats, MemberStatus};
use netsift_capture::{CaptureFormat, ReadWarning};
use netsift_store::{
    AnomalyRow, ChunkFormat, ChunkRow, ChunkStatus, ConversationRow, FlowRow, HostRow,
    HostTrafficRow, OpenPortRow, StoreRecord, TimeseriesRow,
};
use serde_json::{Value, json};

/// Store row of an analyzer record. Registration point: each analyzer that adds a [`Record`]
/// variant adds **one arm** in the sorted zone.
pub fn to_store(record: Record) -> StoreRecord {
    match record {
        // --- core ---
        Record::Timeseries(s) => StoreRecord::Timeseries(timeseries_row(&s)),
        Record::Host(h) => StoreRecord::Host(host_row(h)),
        Record::Flow(f) => StoreRecord::Flow(flow_row(&f)),
        // --- analyzers: one arm each, sorted alphabetically ---
        Record::Conversation(c) => StoreRecord::Conversation(conversation_row(&c)),
        Record::HostTraffic(h) => StoreRecord::HostTraffic(host_traffic_row(&h)),
        Record::OpenPort(p) => StoreRecord::OpenPort(open_port_row(p)),
    }
}

/// Approximate memory footprint of a store row, to bound record batches in bytes.
pub fn approx_size(record: &StoreRecord) -> usize {
    let heap = match record {
        StoreRecord::Meta(m) => m.key.len() + m.value.len(),
        StoreRecord::Chunk(c) => {
            c.path.len() + 4 * c.linktypes.len() + c.head_hash.as_ref().map_or(0, String::len)
        }
        // The JSON detail is small and bounded by construction.
        StoreRecord::Anomaly(a) => a.kind.len() + 256,
        StoreRecord::Timeseries(t) => t.proto.len(),
        StoreRecord::Host(h) => {
            6 * h.macs.len()
                + h.names
                    .iter()
                    .map(|n| n.len() + std::mem::size_of::<String>())
                    .sum::<usize>()
        }
        StoreRecord::Flow(f) => {
            f.app_proto.as_ref().map_or(0, String::len)
                + f.tcp_state.as_ref().map_or(0, String::len)
        }
        StoreRecord::Conversation(c) => c.protocols.iter().map(|p| p.len() + 24).sum(),
        StoreRecord::OpenPort(p) => {
            p.evidence.len()
                + p.service.as_ref().map_or(0, String::len)
                + p.detected.as_ref().map_or(0, String::len)
                + p.banner.as_ref().map_or(0, String::len)
        }
        StoreRecord::HostTraffic(_) => 0,
        // Rows of analyzers: a conservative estimate until they provide their own.
        _ => 1024,
    };
    std::mem::size_of::<StoreRecord>() + heap
}

fn timeseries_row(s: &TrafficSample) -> TimeseriesRow {
    TimeseriesRow {
        bucket_s: s.bucket_s,
        proto: s.proto.as_str().to_owned(),
        bytes: s.bytes,
        packets: s.packets,
    }
}

fn host_row(h: HostSeen) -> HostRow {
    HostRow {
        ip: h.ip,
        macs: h.macs,
        names: h.names,
        country: h.country.map(|c| c.as_str().to_owned()),
        category: Some(h.category.as_str().to_owned()),
        first_ts: h.first_ts,
        last_ts: h.last_ts,
    }
}

/// Stable label of a TCP state (`flows.tcp_state`).
pub fn tcp_state_label(state: TcpState) -> &'static str {
    match state {
        TcpState::SynSent => "syn_sent",
        TcpState::SynReceived => "syn_received",
        TcpState::Established => "established",
        TcpState::Closing => "closing",
        TcpState::Closed => "closed",
        TcpState::Reset => "reset",
        TcpState::Midstream => "midstream",
    }
}

fn flow_row(f: &FlowSummary) -> FlowRow {
    let c = &f.flow;
    FlowRow {
        // Flow ids are non-negative by construction (`FlowId::derive`).
        id: c.id.0.unsigned_abs(),
        transport: c.key.proto,
        src_ip: c.key.client.ip,
        src_port: c.key.client.port,
        dst_ip: c.key.server.ip,
        dst_port: c.key.server.port,
        first_ts: c.first_ts_ns,
        last_ts: c.last_ts_ns,
        bytes_fwd: c.to_server.bytes,
        bytes_rev: c.to_client.bytes,
        packets_fwd: c.to_server.packets,
        packets_rev: c.to_client.packets,
        app_proto: f.app_proto.map(|p| p.as_str().to_owned()),
        tcp_state: c.tcp_state.map(|s| tcp_state_label(s).to_owned()),
    }
}

fn conversation_row(c: &ConversationDelta) -> ConversationRow {
    ConversationRow {
        src_ip: c.client,
        dst_ip: c.server,
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
        protocols: c.protocols.iter().map(|p| p.as_str().to_owned()).collect(),
    }
}

fn host_traffic_row(h: &HostTrafficDelta) -> HostTrafficRow {
    HostTrafficRow {
        ip: h.ip,
        bytes_sent: h.bytes_sent,
        bytes_received: h.bytes_received,
        packets_sent: h.packets_sent,
        packets_received: h.packets_received,
    }
}

fn open_port_row(p: OpenPortSeen) -> OpenPortRow {
    OpenPortRow {
        ip: p.ip,
        transport: p.transport,
        port: p.port,
        evidence: p.evidence.as_str().to_owned(),
        service: p.iana().map(str::to_owned),
        detected: p.detected.map(str::to_owned),
        banner: p.banner,
        first_ts: p.first_ts,
        last_ts: p.last_ts,
    }
}

fn is_truncated(chunk: u32, anomalies: &[Anomaly]) -> bool {
    anomalies.iter().any(|a| {
        a.chunk == Some(chunk)
            && matches!(a.kind, AnomalyKind::Read(ReadWarning::TruncatedTail { .. }))
    })
}

/// One `chunks` row per member of the group (read, duplicate or ignored). `stats` are the
/// per-chunk statistics of the import (indexed by chunk id), empty before reading.
pub fn chunk_rows(
    group: &ChunkGroup,
    stats: &[ChunkStats],
    anomalies: &[Anomaly],
) -> Vec<ChunkRow> {
    group
        .members
        .iter()
        .enumerate()
        .map(|(index, member)| {
            let id = u32::try_from(index).unwrap_or(u32::MAX);
            let entry = &member.entry;
            let meta = entry.capture();
            let st = stats.get(index);
            let status = match member.status {
                MemberStatus::Active if is_truncated(id, anomalies) => ChunkStatus::Truncated,
                MemberStatus::Active => ChunkStatus::Ok,
                MemberStatus::Duplicate { .. } => ChunkStatus::Duplicate,
                MemberStatus::Skipped => ChunkStatus::Ignored,
            };
            ChunkRow {
                id,
                seq: member.seq.and_then(|s| i64::try_from(s).ok()),
                path: entry.path.to_string_lossy().into_owned(),
                format: meta.map(|m| match m.info.format {
                    CaptureFormat::Pcap => ChunkFormat::Pcap,
                    CaptureFormat::PcapNg => ChunkFormat::PcapNg,
                }),
                compressed: meta.is_some_and(|m| m.info.compressed),
                linktypes: meta.map(|m| m.info.linktypes.clone()).unwrap_or_default(),
                snaplen: meta.and_then(|m| m.info.snaplen),
                first_ts: st.and_then(|s| s.min_ts).or_else(|| entry.first_ts()),
                last_ts: st.and_then(|s| s.max_ts),
                packets: st.map_or(0, |s| s.packets),
                bytes: st.map_or(0, |s| s.captured_bytes),
                file_size: entry.size,
                mtime_ns: entry.mtime_ns,
                head_hash: entry.fingerprint.map(|f| f.to_hex()),
                status,
            }
        })
        .collect()
}

/// `anomalies` row of a continuity finding. `stats` give the start time of the chunk concerned.
pub fn anomaly_row(anomaly: &Anomaly, stats: &[ChunkStats]) -> AnomalyRow {
    anomaly_row_with(anomaly, |c| {
        stats.get(usize::try_from(c).ok()?).and_then(|s| s.min_ts)
    })
}

/// Same as [`anomaly_row`], `chunk_start` giving the start time of a chunk by id (lets the
/// caller look it up without copying every chunk's statistics).
pub fn anomaly_row_with(anomaly: &Anomaly, chunk_start: impl Fn(u32) -> Option<i64>) -> AnomalyRow {
    let chunk_start = anomaly.chunk.and_then(chunk_start);
    let (ts, detail) = match &anomaly.kind {
        AnomalyKind::MissingSequence { first, last } => {
            (chunk_start, json!({ "first": first, "last": last }))
        }
        AnomalyKind::SequenceReused { seq } => (chunk_start, json!({ "seq": seq })),
        AnomalyKind::TimeGap {
            previous,
            gap_ns,
            threshold_ns,
        } => (
            chunk_start,
            json!({ "previous": previous, "gap_ns": gap_ns, "threshold_ns": threshold_ns }),
        ),
        AnomalyKind::Overlap {
            previous,
            overlap_ns,
        } => (
            chunk_start,
            json!({ "previous": previous, "overlap_ns": overlap_ns }),
        ),
        AnomalyKind::Duplicate { of } => (None, json!({ "of": of })),
        AnomalyKind::LinktypeChange { previous, current } => (
            chunk_start,
            json!({ "previous": previous, "current": current }),
        ),
        AnomalyKind::SnaplenChange { previous, current } => (
            chunk_start,
            json!({ "previous": previous, "current": current }),
        ),
        AnomalyKind::EmptyChunk { last } => (None, json!({ "last": last })),
        AnomalyKind::UnreadableChunk { reason, last } => {
            (None, json!({ "reason": reason, "last": last }))
        }
        AnomalyKind::Read(w) => read_warning(w, chunk_start),
        AnomalyKind::ReadError { reason } => (chunk_start, json!({ "reason": reason })),
        AnomalyKind::MergeFanoutLimit { limit } | AnomalyKind::LimitReached { limit } => {
            (None, json!({ "limit": limit }))
        }
        AnomalyKind::OutOfOrder {
            packets,
            max_backstep_ns,
        } => (
            None,
            json!({ "packets": packets, "max_backstep_ns": max_backstep_ns }),
        ),
    };
    AnomalyRow {
        kind: anomaly.kind.code().to_owned(),
        chunk_id: anomaly.chunk,
        ts,
        detail,
    }
}

fn read_warning(w: &ReadWarning, chunk_start: Option<i64>) -> (Option<i64>, Value) {
    match w {
        ReadWarning::TruncatedTail { offset } => (None, json!({ "offset": offset })),
        ReadWarning::TimestampBackwards {
            offset,
            previous_ns,
            ts_ns,
        } => (
            Some(*ts_ns),
            json!({ "offset": offset, "previous_ns": previous_ns, "ts_ns": ts_ns }),
        ),
        ReadWarning::UnknownBlock { offset, block_type } => (
            chunk_start,
            json!({ "offset": offset, "block_type": block_type }),
        ),
        ReadWarning::SkippedRecord { offset, reason } => {
            (chunk_start, json!({ "offset": offset, "reason": reason }))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use netsift_analyze::AppProto;
    use netsift_analyze::flow::{DirStats, EndReason, Endpoint, FlowCtx, FlowId, FlowKey};

    use super::*;

    #[test]
    fn flow_summary_maps_client_to_src() {
        let key = FlowKey {
            proto: 6,
            client: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: 40_000,
            },
            server: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: 443,
            },
        };
        let flow = FlowCtx {
            id: FlowId::derive(&key, 7),
            key,
            first_ts_ns: 7,
            last_ts_ns: 9,
            to_server: DirStats {
                packets: 2,
                bytes: 120,
            },
            to_client: DirStats {
                packets: 1,
                bytes: 60,
            },
            tcp_state: Some(TcpState::Reset),
            end: EndReason::Closed,
        };
        let StoreRecord::Flow(row) = to_store(Record::Flow(FlowSummary {
            flow,
            app_proto: Some(AppProto::Tls),
        })) else {
            panic!("not a flow row");
        };
        assert_eq!(row.id, u64::try_from(flow.id.0).unwrap());
        assert_eq!(row.src_port, 40_000);
        assert_eq!(row.dst_port, 443);
        assert_eq!((row.bytes_fwd, row.bytes_rev), (120, 60));
        assert_eq!((row.packets_fwd, row.packets_rev), (2, 1));
        assert_eq!(row.app_proto.as_deref(), Some("tls"));
        assert_eq!(row.tcp_state.as_deref(), Some("reset"));
    }

    #[test]
    fn anomaly_details_are_json_objects() {
        let kinds = [
            AnomalyKind::MissingSequence { first: 3, last: 4 },
            AnomalyKind::TimeGap {
                previous: 0,
                gap_ns: 10,
                threshold_ns: 5,
            },
            AnomalyKind::Read(ReadWarning::TimestampBackwards {
                offset: 24,
                previous_ns: 10,
                ts_ns: 5,
            }),
            AnomalyKind::EmptyChunk { last: true },
        ];
        let stats = [ChunkStats {
            min_ts: Some(42),
            ..ChunkStats::default()
        }];
        for kind in kinds {
            let row = anomaly_row(
                &Anomaly {
                    chunk: Some(0),
                    kind: kind.clone(),
                },
                &stats,
            );
            assert_eq!(row.kind, kind.code());
            assert!(row.detail.is_object());
        }
        let gap = anomaly_row(
            &Anomaly {
                chunk: Some(0),
                kind: AnomalyKind::TimeGap {
                    previous: 0,
                    gap_ns: 1,
                    threshold_ns: 1,
                },
            },
            &stats,
        );
        assert_eq!(gap.ts, Some(42));
    }
}
