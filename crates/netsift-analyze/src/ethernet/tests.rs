use std::collections::BTreeMap;
use std::fmt::Write as _;

use netsift_fixtures::Scenario;
use netsift_fixtures::ethernet::{self as fx, ethernet_showcase, macs};

use super::*;
use crate::testutil::run;

fn hex(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn stacks(v: &[VlanStack]) -> String {
    v.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
}

/// Merges deltas the way the store does (sums, min/max times, sorted bounded unions).
#[derive(Default)]
struct Merged {
    macs: BTreeMap<[u8; 6], MacDelta>,
    pairs: BTreeMap<([u8; 6], [u8; 6]), PairDelta>,
    types: BTreeMap<EtherKey, Volume>,
    vlans: BTreeMap<VlanStack, (u16, Volume)>,
}

fn merge_volume(a: &mut Volume, b: &Volume) {
    a.frames += b.frames;
    a.bytes += b.bytes;
    a.first_ts = a.first_ts.min(b.first_ts);
    a.last_ts = a.last_ts.max(b.last_ts);
}

fn union<T: Ord + Copy>(a: &mut Vec<T>, b: &[T], max: usize) {
    a.extend_from_slice(b);
    a.sort_unstable();
    a.dedup();
    a.truncate(max);
}

fn merge(records: &[Record]) -> Merged {
    let mut m = Merged::default();
    for r in records {
        let Record::Ethernet(r) = r else { continue };
        match r {
            EthernetRecord::Mac(d) => {
                let e = m.macs.entry(d.mac).or_insert_with(|| MacDelta {
                    frames_sent: 0,
                    bytes_sent: 0,
                    frames_received: 0,
                    bytes_received: 0,
                    vlans: Vec::new(),
                    ..d.clone()
                });
                e.frames_sent += d.frames_sent;
                e.bytes_sent += d.bytes_sent;
                e.frames_received += d.frames_received;
                e.bytes_received += d.bytes_received;
                e.first_ts = e.first_ts.min(d.first_ts);
                e.last_ts = e.last_ts.max(d.last_ts);
                union(&mut e.vlans, &d.vlans, MAX_VLANS);
            }
            EthernetRecord::Pair(d) => {
                let e = m.pairs.entry((d.src, d.dst)).or_insert_with(|| PairDelta {
                    frames: 0,
                    bytes: 0,
                    ethertypes: Vec::new(),
                    vlans: Vec::new(),
                    ..d.clone()
                });
                e.frames += d.frames;
                e.bytes += d.bytes;
                e.first_ts = e.first_ts.min(d.first_ts);
                e.last_ts = e.last_ts.max(d.last_ts);
                union(&mut e.ethertypes, &d.ethertypes, MAX_ETHERTYPES);
                union(&mut e.vlans, &d.vlans, MAX_VLANS);
            }
            EthernetRecord::EtherType(k, v) => match m.types.get_mut(k) {
                Some(e) => merge_volume(e, v),
                None => {
                    m.types.insert(*k, *v);
                }
            },
            EthernetRecord::Vlan(s, tpid, v) => match m.vlans.get_mut(s) {
                Some((t, e)) => {
                    *t = (*t).max(*tpid);
                    merge_volume(e, v);
                }
                None => {
                    m.vlans.insert(*s, (*tpid, *v));
                }
            },
        }
    }
    m
}

fn render(m: &Merged) -> String {
    let mut s = String::new();
    for d in m.macs.values() {
        writeln!(
            s,
            "mac {} vendor={:?} registry={:?} sent={}/{} received={}/{} {}..{} vlans=[{}]",
            hex(d.mac),
            d.vendor,
            d.registry.map(Registry::as_str),
            d.frames_sent,
            d.bytes_sent,
            d.frames_received,
            d.bytes_received,
            d.first_ts,
            d.last_ts,
            stacks(&d.vlans)
        )
        .unwrap();
    }
    for d in m.pairs.values() {
        let types: Vec<String> = d.ethertypes.iter().map(|k| format!("{:#06x}", k.0)).collect();
        writeln!(
            s,
            "pair {} -> {} frames={} bytes={} {}..{} types={types:?} vlans=[{}]",
            hex(d.src),
            hex(d.dst),
            d.frames,
            d.bytes,
            d.first_ts,
            d.last_ts,
            stacks(&d.vlans)
        )
        .unwrap();
    }
    for (k, v) in &m.types {
        writeln!(s, "ethertype {:#06x} frames={} bytes={}", k.0, v.frames, v.bytes).unwrap();
    }
    for (stack, (tpid, v)) in &m.vlans {
        writeln!(s, "vlan {stack} tpid={tpid:#06x} frames={} bytes={}", v.frames, v.bytes).unwrap();
    }
    s
}

fn showcase() -> Vec<netsift_fixtures::Packet> {
    let mut sc = Scenario::starting_at(1_000_000_000);
    ethernet_showcase(&mut sc);
    sc.into_packets()
}

fn analyze(config: &AnalyzerConfig, packets: &[netsift_fixtures::Packet]) -> Vec<Record> {
    let mut a = EthernetAnalyzer::new(config);
    run(&mut a, packets)
}

#[test]
fn showcase_snapshot() {
    let records = analyze(&AnalyzerConfig::default(), &showcase());
    insta::assert_snapshot!(render(&merge(&records)));
}

#[test]
fn addresses_pairs_types_and_vlans() {
    let packets = showcase();
    let m = merge(&analyze(&AnalyzerConfig::default(), &packets));

    // Every frame is counted once per EtherType, and once as sent by its source.
    let frames: u64 = m.types.values().map(|v| v.frames).sum();
    assert_eq!(frames, packets.len() as u64);
    let sent: u64 = m.macs.values().map(|d| d.frames_sent).sum();
    assert_eq!(sent, packets.len() as u64);

    let vbox = &m.macs[&macs::VBOX_A];
    assert_eq!(vbox.vendor, Some("PCS Systemtechnik GmbH"));
    assert_eq!(vbox.registry, Some(Registry::MaL));
    assert_eq!(m.macs[&macs::MA_M].registry, Some(Registry::MaM));
    assert_eq!(m.macs[&macs::MA_S].registry, Some(Registry::MaS));
    // Locally administered and broadcast addresses have no vendor.
    assert_eq!(m.macs[&macs::QEMU].vendor, None);
    assert_eq!(m.macs[&macs::RANDOM].vendor, None);
    assert_eq!(m.macs[&macs::BROADCAST].vendor, None);
    assert_eq!(m.macs[&macs::BROADCAST].frames_sent, 0);
    assert_eq!(m.macs[&macs::BROADCAST].frames_received, 2);
    // A group address that belongs to the IEEE 802.1 working group.
    assert_eq!(m.macs[&macs::STP].vendor, Some("IEEE 802.1 Working Group"));

    // 802.1Q and Q-in-Q stacks, with the TPID of the outer tag.
    let v10 = VlanStack::from_ids(&[10]);
    let qinq = VlanStack::from_ids(&[100, 20]);
    assert_eq!(qinq.to_string(), "100.20");
    assert_eq!(m.vlans[&v10].0, fx::TPID_8021Q);
    assert_eq!(m.vlans[&v10].1.frames, 4);
    assert_eq!(m.vlans[&qinq].0, fx::TPID_8021AD);
    assert_eq!(m.vlans[&qinq].1.frames, 2);
    assert_eq!(m.macs[&macs::MA_M].vlans, vec![qinq]);

    // EtherTypes and LLC: IPv4, IPv6, LLDP, the experimental type and spanning tree (DSAP 0x42).
    let keys: Vec<i32> = m.types.keys().map(|k| k.0).collect();
    assert_eq!(keys, vec![0x42, 0x0800, 0x86dd, 0x88b5, 0x88cc]);

    // Directional pairs.
    let p = &m.pairs[&(macs::INTEL, macs::BROADCAST)];
    assert_eq!(p.ethertypes, vec![EtherKey(i32::from(fx::ETHERTYPE_EXPERIMENTAL))]);
    assert_eq!(p.vlans, vec![v10]);
    assert!(m.pairs.contains_key(&(macs::RASPBERRY, macs::INTEL)));
    assert!(m.pairs.contains_key(&(macs::INTEL, macs::RASPBERRY)));
}

#[test]
fn flushes_are_bounded_and_mergeable() {
    // Five rounds an hour apart, with a tiny map: many flushes, same merged result.
    let mut sc = Scenario::starting_at(0);
    for _ in 0..5 {
        ethernet_showcase(&mut sc);
        sc.advance(3_600 * 1_000_000_000);
    }
    let packets = sc.into_packets();
    let big = analyze(&AnalyzerConfig::default(), &packets);
    let mut small = AnalyzerConfig::default();
    small.ethernet.max_pending = 2;
    let tiny = analyze(&small, &packets);
    assert!(tiny.len() > big.len());
    assert_eq!(render(&merge(&big)), render(&merge(&tiny)));
    // Hourly flushes in packet time: several deltas per address with the default bound.
    let vbox_rows = big
        .iter()
        .filter(|r| matches!(r, Record::Ethernet(EthernetRecord::Mac(d)) if d.mac == macs::VBOX_A))
        .count();
    assert_eq!(vbox_rows, 5);
}

#[test]
fn non_ethernet_links_are_ignored() {
    // Raw IP: no link-layer address.
    let mut packets = showcase();
    for p in &mut packets {
        p.linktype = netsift_fixtures::LINKTYPE_RAW;
        p.data.drain(..14);
    }
    assert!(analyze(&AnalyzerConfig::default(), &packets).is_empty());
}

#[test]
fn truncated_frames_count_as_unknown() {
    let mut sc = Scenario::starting_at(0);
    // A VLAN tag cut short: addresses, but no EtherType nor LLC header.
    sc.push_frame([&macs::BROADCAST[..], &macs::INTEL[..], &[0x81, 0x00, 0x00]].concat());
    let m = merge(&analyze(&AnalyzerConfig::default(), &sc.into_packets()));
    assert_eq!(m.types.keys().copied().collect::<Vec<_>>(), vec![EtherKey::UNKNOWN]);
    assert_eq!(m.macs[&macs::INTEL].frames_sent, 1);
}

#[test]
fn bounded_sets_per_pair() {
    let mut sc = Scenario::starting_at(0);
    for vid in 1..=40u16 {
        sc.push_frame(fx::frame(macs::RASPBERRY, macs::INTEL, &[(fx::TPID_8021Q, vid)], 0x88b5, b"x"));
    }
    let m = merge(&analyze(&AnalyzerConfig::default(), &sc.into_packets()));
    assert_eq!(m.pairs[&(macs::INTEL, macs::RASPBERRY)].vlans.len(), MAX_VLANS);
    assert_eq!(m.macs[&macs::INTEL].vlans.len(), MAX_VLANS);
    assert_eq!(m.vlans.len(), 40);
}
