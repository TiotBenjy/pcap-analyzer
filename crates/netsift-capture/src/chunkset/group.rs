//! Grouping of inventory entries into chunk sets and ordering inside a set.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use super::checks::{self, Anomaly, AnomalyKind, ContinuityConfig};
use super::inventory::{Inventory, InventoryEntry};
use super::naming;

/// How a group was recognized, by decreasing priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GroupKind {
    /// dumpcap default naming: `prefix_NNNNN_YYYYmmddHHMMSS.ext`.
    Dumpcap,
    /// dumpcap `-b nametimenum:2`: `prefix_YYYYmmddHHMMSS_NNNNN.ext`.
    DumpcapNameTimeNum,
    /// tcpdump `-C`: `name`, `name1`, `name2`, ...
    TcpdumpRotation,
    /// Files sharing a common name prefix (also a lone file).
    CommonPrefix,
    /// Every remaining capture of a directory.
    Folder,
    /// Several groups merged by the caller ([`ChunkGroup::merge`]).
    Merged,
}

/// Role of a member in its group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    /// Read during the import.
    Active,
    /// Same size, fingerprint and first timestamp as member `of`: not read.
    Duplicate { of: u32 },
    /// Not a readable capture (empty, too short, unrecognized, unreadable) but named like a
    /// member of the set: kept to report it and to account for its sequence number.
    Skipped,
}

/// One file of a chunk group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMember {
    pub entry: InventoryEntry,
    /// Sequence number from the file name, when the naming convention has one.
    pub seq: Option<u64>,
    pub status: MemberStatus,
}

/// An ordered chunk set. The chunk id of a member is its index in `members`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkGroup {
    pub kind: GroupKind,
    /// Human-readable name: the prefix or base name, or the directory for folder groups.
    pub label: String,
    pub members: Vec<ChunkMember>,
}

/// Result of [`group`]: candidate chunk sets (the caller picks one, or merges several) and the
/// entries that belong to none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grouping {
    pub groups: Vec<ChunkGroup>,
    /// Non-capture files that match no group (reported, ignored).
    pub ungrouped: Vec<InventoryEntry>,
}

impl ChunkGroup {
    /// Builds a group: orders the members and marks duplicates and non-captures.
    ///
    /// Order: by sequence number (numeric), then first timestamp (files without packets last),
    /// then name and path.
    pub fn new(
        kind: GroupKind,
        label: String,
        entries: Vec<(InventoryEntry, Option<u64>)>,
    ) -> Self {
        let mut members: Vec<ChunkMember> = entries
            .into_iter()
            .map(|(entry, seq)| ChunkMember {
                status: if entry.capture().is_some() {
                    MemberStatus::Active
                } else {
                    MemberStatus::Skipped
                },
                entry,
                seq,
            })
            .collect();
        members.sort_by(member_order);

        let mut seen: HashMap<_, u32> = HashMap::new();
        for (index, member) in members.iter_mut().enumerate() {
            if member.status != MemberStatus::Active {
                continue;
            }
            // Files without packets (identical bare headers) are never duplicates.
            let (Some(fp), Some(first_ts)) = (member.entry.fingerprint, member.entry.first_ts())
            else {
                continue;
            };
            let key = (member.entry.size, fp, first_ts);
            match seen.get(&key) {
                Some(&of) => member.status = MemberStatus::Duplicate { of },
                None => {
                    seen.insert(key, super::chunk_id(index));
                }
            }
        }
        Self {
            kind,
            label,
            members,
        }
    }

    /// Merges several groups into one, ordered by first timestamp (sequence numbers of
    /// different sets are not comparable, so they are dropped).
    pub fn merge(groups: Vec<ChunkGroup>) -> ChunkGroup {
        let label = groups
            .iter()
            .map(|g| g.label.as_str())
            .collect::<Vec<_>>()
            .join(" + ");
        let entries = groups
            .into_iter()
            .flat_map(|g| g.members)
            .map(|m| (m.entry, None))
            .collect();
        ChunkGroup::new(GroupKind::Merged, label, entries)
    }

    /// Members that are read, with their chunk id.
    pub fn active(&self) -> impl Iterator<Item = (u32, &ChunkMember)> {
        self.members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.status == MemberStatus::Active)
            .map(|(i, m)| (super::chunk_id(i), m))
    }

    /// Total size in bytes of the members that are read, for progress reporting.
    pub fn total_bytes(&self) -> u64 {
        self.active()
            .map(|(_, m)| m.entry.size)
            .fold(0, u64::saturating_add)
    }

    /// Paths of the members that are read, in group order.
    pub fn paths(&self) -> Vec<PathBuf> {
        self.active().map(|(_, m)| m.entry.path.clone()).collect()
    }

    /// Continuity anomalies known from the inventory, for a preview before the import:
    /// sequence, duplicates, unreadable members, link type and snaplen changes, reader warnings
    /// and errors met while probing; plus time gaps and overlaps when the inventory ran with
    /// `full_scan`. The authoritative list of an import is [`super::ChunkSetSource::anomalies`].
    pub fn anomalies(&self, config: &ContinuityConfig) -> Vec<Anomaly> {
        let mut out = checks::static_checks(self);
        let mut spans = Vec::new();
        let mut fully_scanned = true;
        for (chunk, member) in self.active() {
            let Some(meta) = member.entry.capture() else {
                continue;
            };
            out.extend(meta.warnings.iter().map(|w| Anomaly {
                chunk: Some(chunk),
                kind: AnomalyKind::Read(w.clone()),
            }));
            if let Some(reason) = &meta.read_error {
                out.push(Anomaly {
                    chunk: Some(chunk),
                    kind: AnomalyKind::ReadError {
                        reason: reason.clone(),
                    },
                });
            }
            match &meta.scan {
                Some(stats) => spans.extend(stats.span(chunk)),
                None => fully_scanned = false,
            }
        }
        if fully_scanned {
            out.extend(checks::timing_checks(&spans, config));
        }
        out
    }
}

/// Pool index of an entry and its sequence number.
type Numbered = (usize, Option<u64>);

fn member_order(a: &ChunkMember, b: &ChunkMember) -> Ordering {
    let ts = |m: &ChunkMember| {
        let ts = m.entry.first_ts();
        (ts.is_none(), ts)
    };
    (a.seq.is_none(), a.seq)
        .cmp(&(b.seq.is_none(), b.seq))
        .then_with(|| ts(a).cmp(&ts(b)))
        .then_with(|| a.entry.name.cmp(&b.entry.name))
        .then_with(|| a.entry.path.cmp(&b.entry.path))
}

/// Groups the entries of an inventory, see [`group_entries`].
pub fn group(inventory: &Inventory) -> Grouping {
    group_entries(inventory.entries.clone())
}

/// Groups entries into chunk sets, by name pattern in this order of priority: dumpcap default,
/// dumpcap nametimenum, tcpdump `-C`, common prefix, whole directory.
///
/// Pattern groups (the first three) also take non-capture files that match their pattern, so an
/// empty or truncated last chunk is reported within its set. Pattern groups must contain at
/// least one capture; tcpdump groups at least two files. dumpcap groups are keyed by prefix
/// only (a recursive inventory joins sub-directories of the same ring); other groups are per
/// directory.
pub fn group_entries(entries: Vec<InventoryEntry>) -> Grouping {
    let mut pool: Vec<Option<InventoryEntry>> = entries.into_iter().map(Some).collect();
    let mut groups = Vec::new();

    let dumpcap = |pool: &[Option<InventoryEntry>],
                   parse: fn(&str) -> Option<naming::DumpcapName>| {
        let mut sets: BTreeMap<String, Vec<Numbered>> = BTreeMap::new();
        for (i, e) in pool.iter().enumerate() {
            if let Some(name) = e.as_ref().and_then(|e| parse(&e.name)) {
                sets.entry(name.prefix)
                    .or_default()
                    .push((i, Some(name.seq)));
            }
        }
        sets
    };
    for (kind, parse) in [
        (GroupKind::Dumpcap, naming::parse_dumpcap as fn(&str) -> _),
        (GroupKind::DumpcapNameTimeNum, naming::parse_nametimenum),
    ] {
        for (label, members) in dumpcap(&pool, parse) {
            take_group(&mut pool, &mut groups, kind, label, &members, 1);
        }
    }

    // tcpdump -C: (directory, base) -> members; the bare base name is number 0.
    let mut rotations: BTreeMap<(PathBuf, String), Vec<Numbered>> = BTreeMap::new();
    for (i, e) in pool.iter().enumerate() {
        let Some(e) = e else { continue };
        if let Some((base, num)) = naming::split_rotation(&e.name) {
            rotations
                .entry((e.dir().to_path_buf(), base.to_owned()))
                .or_default()
                .push((i, Some(num.unwrap_or(0))));
        }
    }
    for ((_, label), members) in rotations {
        take_group(
            &mut pool,
            &mut groups,
            GroupKind::TcpdumpRotation,
            label,
            &members,
            2,
        );
    }

    // Fallback on the remaining captures: common prefix per directory, else the directory.
    let mut by_dir: BTreeMap<PathBuf, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
    for (i, e) in pool.iter().enumerate() {
        let Some(e) = e.as_ref().filter(|e| e.capture().is_some()) else {
            continue;
        };
        by_dir
            .entry(e.dir().to_path_buf())
            .or_default()
            .entry(naming::common_prefix_key(&e.name).to_owned())
            .or_default()
            .push(i);
    }
    for (dir, prefixes) in by_dir {
        let has_set = prefixes.values().any(|m| m.len() > 1);
        if has_set || prefixes.values().map(Vec::len).sum::<usize>() == 1 {
            for (key, members) in prefixes {
                let entries = take(&mut pool, members.iter().map(|&i| (i, None)));
                let label = if key.is_empty() {
                    entries
                        .first()
                        .map(|(e, _)| e.name.clone())
                        .unwrap_or_default()
                } else {
                    key
                };
                groups.push(ChunkGroup::new(GroupKind::CommonPrefix, label, entries));
            }
        } else {
            let all = prefixes.into_values().flatten().map(|i| (i, None));
            let entries = take(&mut pool, all);
            groups.push(ChunkGroup::new(
                GroupKind::Folder,
                dir.display().to_string(),
                entries,
            ));
        }
    }

    groups.sort_by(|a, b| (a.kind, &a.label).cmp(&(b.kind, &b.label)));
    Grouping {
        groups,
        ungrouped: pool.into_iter().flatten().collect(),
    }
}

/// Moves `members` out of the pool into a new group when the group qualifies (at least one
/// capture and `min_len` files).
fn take_group(
    pool: &mut [Option<InventoryEntry>],
    groups: &mut Vec<ChunkGroup>,
    kind: GroupKind,
    label: String,
    members: &[(usize, Option<u64>)],
    min_len: usize,
) {
    let has_capture = members.iter().any(|&(i, _)| {
        pool.get(i)
            .and_then(Option::as_ref)
            .is_some_and(|e| e.capture().is_some())
    });
    if has_capture && members.len() >= min_len {
        let entries = take(pool, members.iter().copied());
        groups.push(ChunkGroup::new(kind, label, entries));
    }
}

fn take(
    pool: &mut [Option<InventoryEntry>],
    members: impl IntoIterator<Item = (usize, Option<u64>)>,
) -> Vec<(InventoryEntry, Option<u64>)> {
    members
        .into_iter()
        .filter_map(|(i, seq)| Some((pool.get_mut(i)?.take()?, seq)))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::chunkset::inventory::{CaptureMeta, EntryKind, Fingerprint};
    use crate::source::{CaptureFormat, CaptureInfo};

    fn capture_at(path: &str, first_ts: i64) -> InventoryEntry {
        let path = Path::new(path);
        InventoryEntry {
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            size: 1000,
            mtime_ns: None,
            fingerprint: Some(Fingerprint::of_bytes(path.to_string_lossy().as_bytes())),
            kind: EntryKind::Capture(CaptureMeta {
                info: CaptureInfo {
                    format: CaptureFormat::Pcap,
                    compressed: false,
                    linktypes: vec![1],
                    snaplen: Some(65535),
                },
                first_ts: Some(first_ts),
                read_error: None,
                warnings: Vec::new(),
                scan: None,
            }),
            path: path.to_path_buf(),
        }
    }

    fn capture(name: &str, first_ts: i64) -> InventoryEntry {
        capture_at(&format!("/d/{name}"), first_ts)
    }

    fn other(name: &str, kind: EntryKind) -> InventoryEntry {
        InventoryEntry {
            kind,
            fingerprint: None,
            size: 0,
            ..capture(name, 0)
        }
    }

    fn names(group: &ChunkGroup) -> Vec<&str> {
        group
            .members
            .iter()
            .map(|m| m.entry.name.as_str())
            .collect()
    }

    fn summary(grouping: &Grouping) -> Vec<(GroupKind, String, Vec<&str>)> {
        grouping
            .groups
            .iter()
            .map(|g| (g.kind, g.label.clone(), names(g)))
            .collect()
    }

    #[test]
    fn dumpcap_sorted_numerically_beyond_99999() {
        let entries = vec![
            capture("cap_100000_20240101120000.pcapng", 30),
            capture("cap_99999_20240101115900.pcapng", 20),
            capture("cap_99998_20240101115800.pcapng", 10),
            capture("cap_100001_20240101120100.pcapng", 40),
        ];
        let grouping = group_entries(entries);
        assert_eq!(
            summary(&grouping),
            vec![(
                GroupKind::Dumpcap,
                "cap".into(),
                vec![
                    "cap_99998_20240101115800.pcapng",
                    "cap_99999_20240101115900.pcapng",
                    "cap_100000_20240101120000.pcapng",
                    "cap_100001_20240101120100.pcapng",
                ]
            )]
        );
        let seqs: Vec<_> = grouping.groups[0].members.iter().map(|m| m.seq).collect();
        assert_eq!(
            seqs,
            vec![Some(99_998), Some(99_999), Some(100_000), Some(100_001)]
        );
    }

    #[test]
    fn patterns_by_priority_and_two_prefixes() {
        let entries = vec![
            capture("a_00002_20240101120000.pcapng", 2),
            capture("a_00001_20240101110000.pcapng.gz", 1),
            capture("b_00001_20240101110000.pcap", 1),
            capture("n_20240101110000_00001.pcapng", 1),
            capture("n_20240101120000_00002.pcapng", 2),
            capture("tcp.pcap2", 3),
            capture("tcp.pcap", 1),
            capture("tcp.pcap1", 2),
            capture("cap-20240101-1300.pcap", 20),
            capture("cap-20240101-1200.pcap", 10),
            capture("lonely.pcap", 5),
        ];
        let grouping = group_entries(entries);
        assert_eq!(
            summary(&grouping),
            vec![
                (
                    GroupKind::Dumpcap,
                    "a".into(),
                    vec![
                        "a_00001_20240101110000.pcapng.gz",
                        "a_00002_20240101120000.pcapng"
                    ]
                ),
                (
                    GroupKind::Dumpcap,
                    "b".into(),
                    vec!["b_00001_20240101110000.pcap"]
                ),
                (
                    GroupKind::DumpcapNameTimeNum,
                    "n".into(),
                    vec![
                        "n_20240101110000_00001.pcapng",
                        "n_20240101120000_00002.pcapng"
                    ]
                ),
                (
                    GroupKind::TcpdumpRotation,
                    "tcp.pcap".into(),
                    vec!["tcp.pcap", "tcp.pcap1", "tcp.pcap2"]
                ),
                (
                    GroupKind::CommonPrefix,
                    "cap".into(),
                    vec!["cap-20240101-1200.pcap", "cap-20240101-1300.pcap"]
                ),
                (
                    GroupKind::CommonPrefix,
                    "lonely".into(),
                    vec!["lonely.pcap"]
                ),
            ]
        );
        assert_eq!(grouping.ungrouped, vec![]);
    }

    #[test]
    fn unrelated_names_form_a_folder_group_ordered_by_time() {
        let entries = vec![
            capture("zeta.pcap", 1),
            capture("alpha.pcapng", 3),
            capture("mid.cap", 2),
            other("README.txt", EntryKind::Unrecognized),
        ];
        let grouping = group_entries(entries);
        assert_eq!(
            summary(&grouping),
            vec![(
                GroupKind::Folder,
                "/d".into(),
                vec!["zeta.pcap", "mid.cap", "alpha.pcapng"]
            )]
        );
        assert_eq!(grouping.ungrouped.len(), 1);
        assert_eq!(grouping.ungrouped[0].name, "README.txt");
    }

    #[test]
    fn single_file_is_its_own_group() {
        let grouping = group_entries(vec![capture("20240101.pcap", 1)]);
        assert_eq!(
            summary(&grouping),
            vec![(
                GroupKind::CommonPrefix,
                "20240101.pcap".into(),
                vec!["20240101.pcap"]
            )]
        );
    }

    #[test]
    fn empty_last_chunk_joins_its_set() {
        let entries = vec![
            capture("cap_00001_20240101110000.pcapng", 1),
            capture("cap_00002_20240101120000.pcapng", 2),
            other("cap_00003_20240101130000.pcapng", EntryKind::Empty),
            other("junk_00001_20240101130000.pcapng", EntryKind::TooShort),
        ];
        let grouping = group_entries(entries);
        assert_eq!(grouping.groups.len(), 1);
        let g = &grouping.groups[0];
        assert_eq!(g.members[2].status, MemberStatus::Skipped);
        assert_eq!(g.active().count(), 2);
        // A pattern set made only of non-captures is not a group.
        assert_eq!(grouping.ungrouped.len(), 1);
        assert_eq!(
            grouping.ungrouped[0].name,
            "junk_00001_20240101130000.pcapng"
        );
    }

    #[test]
    fn tcpdump_needs_two_files_and_groups_per_directory() {
        let entries = vec![
            capture_at("/x/cap.pcap", 1),
            capture_at("/x/cap.pcap1", 2),
            capture_at("/y/cap.pcap", 3),
        ];
        let grouping = group_entries(entries);
        assert_eq!(
            summary(&grouping),
            vec![
                (
                    GroupKind::TcpdumpRotation,
                    "cap.pcap".into(),
                    vec!["cap.pcap", "cap.pcap1"]
                ),
                (GroupKind::CommonPrefix, "cap".into(), vec!["cap.pcap"]),
            ]
        );
    }

    #[test]
    fn duplicates_are_marked_after_the_first() {
        let a = capture("cap_00001_20240101110000.pcapng", 1);
        let mut copy = a.clone();
        copy.path = "/d/sub/cap_00001_20240101110000.pcapng".into();
        let b = capture("cap_00002_20240101120000.pcapng", 2);
        let grouping = group_entries(vec![b, copy, a]);
        let g = &grouping.groups[0];
        assert_eq!(g.members[0].status, MemberStatus::Active);
        assert_eq!(
            g.members[0].entry.path,
            Path::new("/d/cap_00001_20240101110000.pcapng")
        );
        assert_eq!(g.members[1].status, MemberStatus::Duplicate { of: 0 });
        assert_eq!(g.members[2].status, MemberStatus::Active);
        assert_eq!(g.total_bytes(), 2000);
    }

    #[test]
    fn files_without_packets_are_not_duplicates() {
        let mut a = capture("cap_00001_20240101110000.pcapng", 1);
        if let EntryKind::Capture(meta) = &mut a.kind {
            meta.first_ts = None;
        }
        let mut b = a.clone();
        b.name = "cap_00002_20240101110000.pcapng".into();
        b.path = "/d/cap_00002_20240101110000.pcapng".into();
        let grouping = group_entries(vec![a, b]);
        let statuses: Vec<_> = grouping.groups[0]
            .members
            .iter()
            .map(|m| m.status)
            .collect();
        assert_eq!(statuses, vec![MemberStatus::Active, MemberStatus::Active]);
    }

    #[test]
    fn merge_orders_by_time() {
        let grouping = group_entries(vec![
            capture("a_00001_20240101110000.pcapng", 5),
            capture("a_00002_20240101120000.pcapng", 15),
            capture("b_00001_20240101110000.pcapng", 10),
        ]);
        let merged = ChunkGroup::merge(grouping.groups);
        assert_eq!(merged.kind, GroupKind::Merged);
        assert_eq!(merged.label, "a + b");
        assert_eq!(
            names(&merged),
            vec![
                "a_00001_20240101110000.pcapng",
                "b_00001_20240101110000.pcapng",
                "a_00002_20240101120000.pcapng"
            ]
        );
    }

    #[test]
    fn static_anomalies() {
        let mut ethernet = capture("cap_00001_20240101110000.pcapng", 1);
        let mut wifi = capture("cap_00002_20240101120000.pcapng", 2);
        if let EntryKind::Capture(meta) = &mut wifi.kind {
            meta.info.linktypes = vec![127];
            meta.info.snaplen = Some(256);
        }
        if let EntryKind::Capture(meta) = &mut ethernet.kind {
            meta.read_error = Some("boom".into());
        }
        let entries = vec![
            ethernet,
            wifi,
            capture("cap_00005_20240101130000.pcapng", 5),
            capture("cap_00005_20240101140000.pcapng", 6),
            other("cap_00006_20240101150000.pcapng", EntryKind::TooShort),
        ];
        let grouping = group_entries(entries);
        let kinds: Vec<_> = grouping.groups[0]
            .anomalies(&ContinuityConfig::default())
            .into_iter()
            .map(|a| (a.chunk, a.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (
                    Some(1),
                    AnomalyKind::LinktypeChange {
                        previous: vec![1],
                        current: vec![127]
                    }
                ),
                (
                    Some(1),
                    AnomalyKind::SnaplenChange {
                        previous: Some(65535),
                        current: Some(256)
                    }
                ),
                (
                    Some(2),
                    AnomalyKind::LinktypeChange {
                        previous: vec![127],
                        current: vec![1]
                    }
                ),
                (
                    Some(2),
                    AnomalyKind::SnaplenChange {
                        previous: Some(256),
                        current: Some(65535)
                    }
                ),
                (
                    Some(4),
                    AnomalyKind::UnreadableChunk {
                        reason: "file too short to be a capture".into(),
                        last: true
                    }
                ),
                (Some(2), AnomalyKind::MissingSequence { first: 3, last: 4 }),
                (Some(3), AnomalyKind::SequenceReused { seq: 5 }),
                (
                    Some(0),
                    AnomalyKind::ReadError {
                        reason: "boom".into()
                    }
                ),
            ]
        );
    }
}
