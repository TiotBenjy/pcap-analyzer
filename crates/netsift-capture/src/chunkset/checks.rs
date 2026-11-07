//! Continuity checks: non-blocking anomalies of a chunk group (future `anomalies` table rows).

use super::group::{ChunkGroup, MemberStatus};
use super::inventory::EntryKind;
use crate::source::ReadWarning;

const NANOS_PER_SEC: i64 = 1_000_000_000;

/// Threshold above which the time between two consecutive chunks is reported as a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapThreshold {
    /// Fixed duration in nanoseconds (default: 5 s).
    Fixed { ns: i64 },
    /// `factor` times the median time between consecutive chunks of the group, but never less
    /// than `floor_ns` (avoids flagging every boundary of a continuous capture, whose median
    /// gap is close to zero).
    MedianFactor { factor: u32, floor_ns: i64 },
}

impl Default for GapThreshold {
    fn default() -> Self {
        Self::Fixed {
            ns: 5 * NANOS_PER_SEC,
        }
    }
}

/// Settings of the continuity checks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContinuityConfig {
    pub gap: GapThreshold,
}

/// One continuity finding. `chunk` is the chunk id (index in [`ChunkGroup::members`]) the
/// finding is attached to, `None` for findings about the whole group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    pub chunk: Option<u32>,
    pub kind: AnomalyKind,
}

/// Kinds of continuity findings. None of them stops the import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// Sequence numbers `first..=last` are absent (ring buffer deletion, lost file). Attached to
    /// the chunk that follows the hole.
    MissingSequence { first: u64, last: u64 },
    /// Another file already carries this sequence number with different content (capture
    /// restarted with the same prefix). Both files are read.
    SequenceReused { seq: u64 },
    /// Time between the end of the previous chunks and the start of `chunk` exceeds the
    /// threshold. `previous` is the chunk holding the latest timestamp before the hole.
    TimeGap {
        previous: u32,
        gap_ns: i64,
        threshold_ns: i64,
    },
    /// `chunk` starts before `previous` ends: the chunks are merged by timestamp (k-way merge).
    Overlap { previous: u32, overlap_ns: i64 },
    /// Same size, same first-64-KiB fingerprint and same first timestamp as chunk `of`: ignored.
    Duplicate { of: u32 },
    /// Link types differ from the previous chunk (accepted: each packet keeps its link type).
    LinktypeChange {
        previous: Vec<u32>,
        current: Vec<u32>,
    },
    /// Snapshot length differs from the previous chunk (accepted).
    SnaplenChange {
        previous: Option<u32>,
        current: Option<u32>,
    },
    /// Zero-byte member, ignored. `last` is true when no readable chunk follows it (typically the
    /// file being written when the folder was copied).
    EmptyChunk { last: bool },
    /// Member that cannot be read as a capture (too short, unrecognized, corrupt header),
    /// ignored. `last` as for [`AnomalyKind::EmptyChunk`].
    UnreadableChunk { reason: String, last: bool },
    /// Warning reported by the file reader (truncated tail, timestamps going backwards...).
    Read(ReadWarning),
    /// Reading stopped early on an error; the packets read before it are kept.
    ReadError { reason: String },
    /// More chunks overlap than readers may be open at once: some packets are delivered out of
    /// timestamp order. Group-level.
    MergeFanoutLimit { limit: usize },
    /// Packets were delivered with a timestamp earlier than the previous packet of the merged
    /// output (clock going backwards inside a chunk, or fan-out limit). Group-level, updated in
    /// place: `packets` counts them, `max_backstep_ns` is the largest step back.
    OutOfOrder { packets: u64, max_backstep_ns: i64 },
    /// Anomaly list capped: further findings were dropped. Group-level.
    LimitReached { limit: usize },
}

impl AnomalyKind {
    /// Stable identifier, meant for the `kind` column of the `anomalies` table.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingSequence { .. } => "missing_sequence",
            Self::SequenceReused { .. } => "sequence_reused",
            Self::TimeGap { .. } => "time_gap",
            Self::Overlap { .. } => "overlap",
            Self::Duplicate { .. } => "duplicate",
            Self::LinktypeChange { .. } => "linktype_change",
            Self::SnaplenChange { .. } => "snaplen_change",
            Self::EmptyChunk { .. } => "empty_chunk",
            Self::UnreadableChunk { .. } => "unreadable_chunk",
            Self::Read(ReadWarning::TruncatedTail { .. }) => "truncated_tail",
            Self::Read(ReadWarning::TimestampBackwards { .. }) => "timestamp_backwards",
            Self::Read(ReadWarning::UnknownBlock { .. }) => "unknown_block",
            Self::Read(ReadWarning::SkippedRecord { .. }) => "skipped_record",
            Self::ReadError { .. } => "read_error",
            Self::MergeFanoutLimit { .. } => "merge_fanout_limit",
            Self::OutOfOrder { .. } => "out_of_order",
            Self::LimitReached { .. } => "limit_reached",
        }
    }
}

/// Time span of a chunk, from its smallest to its largest packet timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSpan {
    pub chunk: u32,
    pub start_ns: i64,
    pub end_ns: i64,
}

/// Checks that only need the inventory: sequence holes and reuse, duplicates, unreadable
/// members, link type and snaplen changes.
pub(crate) fn static_checks(group: &ChunkGroup) -> Vec<Anomaly> {
    let mut out = Vec::new();
    let last_active = group
        .members
        .iter()
        .rposition(|m| m.status == MemberStatus::Active);

    // Members in group order.
    let mut previous_info: Option<(Vec<u32>, Option<u32>)> = None;
    for (index, member) in group.members.iter().enumerate() {
        let chunk = Some(super::chunk_id(index));
        let last = last_active.is_none_or(|l| index > l);
        match (&member.status, &member.entry.kind) {
            (MemberStatus::Duplicate { of }, _) => out.push(Anomaly {
                chunk,
                kind: AnomalyKind::Duplicate { of: *of },
            }),
            (MemberStatus::Skipped, EntryKind::Empty) => out.push(Anomaly {
                chunk,
                kind: AnomalyKind::EmptyChunk { last },
            }),
            (MemberStatus::Skipped, kind) => out.push(Anomaly {
                chunk,
                kind: AnomalyKind::UnreadableChunk {
                    reason: skip_reason(kind),
                    last,
                },
            }),
            (MemberStatus::Active, EntryKind::Capture(meta)) => {
                let current = (meta.info.linktypes.clone(), meta.info.snaplen);
                if let Some((prev_lt, prev_snap)) = &previous_info {
                    if *prev_lt != current.0 {
                        out.push(Anomaly {
                            chunk,
                            kind: AnomalyKind::LinktypeChange {
                                previous: prev_lt.clone(),
                                current: current.0.clone(),
                            },
                        });
                    }
                    if *prev_snap != current.1 {
                        out.push(Anomaly {
                            chunk,
                            kind: AnomalyKind::SnaplenChange {
                                previous: *prev_snap,
                                current: current.1,
                            },
                        });
                    }
                }
                previous_info = Some(current);
            }
            (MemberStatus::Active, _) => {}
        }
    }

    sequence_checks(group, &mut out);
    out
}

fn skip_reason(kind: &EntryKind) -> String {
    match kind {
        EntryKind::Capture(_) => "capture".into(),
        EntryKind::Empty => "empty file".into(),
        EntryKind::TooShort => "file too short to be a capture".into(),
        EntryKind::Unrecognized => "not a pcap or pcapng file".into(),
        EntryKind::Unreadable { reason } => reason.clone(),
    }
}

/// Holes in the sequence numbers (between the smallest and largest number present: files
/// deleted before the first one cannot be detected) and numbers carried by several files.
fn sequence_checks(group: &ChunkGroup, out: &mut Vec<Anomaly>) {
    // (seq, chunk id) of non-duplicate members carrying a number, in seq order.
    let mut numbered: Vec<(u64, u32)> = group
        .members
        .iter()
        .enumerate()
        .filter(|(_, m)| !matches!(m.status, MemberStatus::Duplicate { .. }))
        .filter_map(|(i, m)| Some((m.seq?, super::chunk_id(i))))
        .collect();
    numbered.sort_unstable();
    for pair in numbered.windows(2) {
        let [(a, _), (b, chunk)] = pair else { continue };
        if a == b {
            out.push(Anomaly {
                chunk: Some(*chunk),
                kind: AnomalyKind::SequenceReused { seq: *b },
            });
        } else if b - a > 1 {
            out.push(Anomaly {
                chunk: Some(*chunk),
                kind: AnomalyKind::MissingSequence {
                    first: a + 1,
                    last: b - 1,
                },
            });
        }
    }
}

/// Time gaps and overlaps between chunks, in reading order (sorted by start time).
///
/// Each chunk is compared with the latest end seen so far (not only the previous chunk), so a
/// long chunk spanning several shorter ones is reported as overlapping all of them.
pub fn timing_checks(spans: &[ChunkSpan], config: &ContinuityConfig) -> Vec<Anomaly> {
    // Reading order (by start time), not sequence order: a tcpdump `-W` ring that wrapped
    // around has its oldest data in a higher-numbered file, which is not an overlap.
    let mut spans = spans.to_vec();
    spans.sort_by_key(|s| (s.start_ns, s.chunk));
    let threshold_ns = gap_threshold(&spans, config.gap);
    let mut out = Vec::new();
    let mut latest: Option<(i64, u32)> = None;
    for span in &spans {
        if let Some((end, previous)) = latest {
            let delta = span.start_ns.saturating_sub(end);
            if delta < 0 {
                out.push(Anomaly {
                    chunk: Some(span.chunk),
                    kind: AnomalyKind::Overlap {
                        previous,
                        overlap_ns: delta.saturating_neg(),
                    },
                });
            } else if delta > threshold_ns {
                out.push(Anomaly {
                    chunk: Some(span.chunk),
                    kind: AnomalyKind::TimeGap {
                        previous,
                        gap_ns: delta,
                        threshold_ns,
                    },
                });
            }
        }
        if latest.is_none_or(|(end, _)| span.end_ns > end) {
            latest = Some((span.end_ns, span.chunk));
        }
    }
    out
}

/// Resolves the gap threshold for a group.
fn gap_threshold(spans: &[ChunkSpan], gap: GapThreshold) -> i64 {
    match gap {
        GapThreshold::Fixed { ns } => ns,
        GapThreshold::MedianFactor { factor, floor_ns } => {
            let mut deltas: Vec<i64> = spans
                .windows(2)
                .filter_map(|w| match w {
                    [a, b] => Some(b.start_ns.saturating_sub(a.end_ns)),
                    _ => None,
                })
                .filter(|d| *d >= 0)
                .collect();
            if deltas.is_empty() {
                return floor_ns;
            }
            deltas.sort_unstable();
            let median = deltas.get(deltas.len() / 2).copied().unwrap_or(0);
            median.saturating_mul(i64::from(factor)).max(floor_ns)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = NANOS_PER_SEC;

    fn span(chunk: u32, start_s: i64, end_s: i64) -> ChunkSpan {
        ChunkSpan {
            chunk,
            start_ns: start_s * S,
            end_ns: end_s * S,
        }
    }

    #[test]
    fn contiguous_chunks_have_no_findings() {
        let spans = [span(0, 0, 10), span(1, 11, 20), span(2, 24, 30)];
        assert_eq!(timing_checks(&spans, &ContinuityConfig::default()), vec![]);
    }

    #[test]
    fn gap_above_fixed_threshold() {
        let spans = [span(0, 0, 10), span(1, 16, 20), span(2, 25, 30)];
        let found = timing_checks(&spans, &ContinuityConfig::default());
        assert_eq!(
            found,
            vec![Anomaly {
                chunk: Some(1),
                kind: AnomalyKind::TimeGap {
                    previous: 0,
                    gap_ns: 6 * S,
                    threshold_ns: 5 * S,
                },
            }]
        );
    }

    #[test]
    fn gap_relative_to_median() {
        let config = ContinuityConfig {
            gap: GapThreshold::MedianFactor {
                factor: 2,
                floor_ns: S,
            },
        };
        // Boundary gaps: 3 s, 3 s, 7 s, 3 s -> median 3 s, threshold 6 s.
        let spans = [
            span(0, 0, 10),
            span(1, 13, 20),
            span(2, 23, 30),
            span(3, 37, 40),
            span(4, 43, 50),
        ];
        let found = timing_checks(&spans, &config);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].chunk, Some(3));
        assert!(matches!(
            found[0].kind,
            AnomalyKind::TimeGap {
                previous: 2,
                threshold_ns,
                ..
            } if threshold_ns == 6 * S
        ));
        // Continuous capture: the floor applies.
        assert_eq!(
            gap_threshold(&[span(0, 0, 1), span(1, 1, 2)], config.gap),
            S
        );
        assert_eq!(gap_threshold(&[], config.gap), S);
    }

    #[test]
    fn overlap_against_latest_end() {
        let spans = [span(0, 0, 100), span(1, 10, 20), span(2, 30, 40)];
        let found = timing_checks(&spans, &ContinuityConfig::default());
        assert_eq!(
            found,
            vec![
                Anomaly {
                    chunk: Some(1),
                    kind: AnomalyKind::Overlap {
                        previous: 0,
                        overlap_ns: 90 * S,
                    },
                },
                Anomaly {
                    chunk: Some(2),
                    kind: AnomalyKind::Overlap {
                        previous: 0,
                        overlap_ns: 70 * S,
                    },
                },
            ]
        );
    }

    #[test]
    fn spans_are_checked_in_time_order() {
        // Sequence order 0, 1, 2 but chunk 2 holds the oldest data (ring buffer wrap-around).
        let spans = [span(0, 10, 20), span(1, 21, 30), span(2, 0, 9)];
        assert_eq!(timing_checks(&spans, &ContinuityConfig::default()), vec![]);
    }

    #[test]
    fn codes_are_stable() {
        assert_eq!(
            AnomalyKind::Read(ReadWarning::TruncatedTail { offset: 0 }).code(),
            "truncated_tail"
        );
        assert_eq!(
            AnomalyKind::MissingSequence { first: 1, last: 1 }.code(),
            "missing_sequence"
        );
    }
}
