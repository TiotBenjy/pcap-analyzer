//! Helpers that damage or arrange chunk sets, to exercise the continuity checks and the
//! cross-chunk state handling described in `docs/CHUNKED_CAPTURES.md`.

use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;

use crate::packet::Packet;
use crate::proto::dns::DnsType;
use crate::scenario::{DnsExchange, HttpGet, Scenario, TcpOptions};
use crate::scenarios::{EXCHANGE_GAP_NS, hosts};
use crate::split::{SplitBy, SplitOptions, split_to_dir};
use crate::writer::{Encoding, Endian, FileFormat, PcapOptions, PcapPrecision, gzip};

/// Deletes a chunk file (sequence gap, as left by a `-b files:` ring buffer).
pub fn remove_chunk(path: &Path) -> io::Result<()> {
    fs::remove_file(path)
}

/// Copies a chunk under another name in the same directory; returns the new path.
pub fn duplicate_chunk(path: &Path, new_name: &str) -> io::Result<PathBuf> {
    let target = path.with_file_name(new_name);
    fs::copy(path, &target)?;
    Ok(target)
}

/// Creates an empty file named `name` in `dir`.
pub fn create_empty_file(dir: &Path, name: &str) -> io::Result<PathBuf> {
    let path = dir.join(name);
    fs::write(&path, [])?;
    Ok(path)
}

/// Cuts the file in the middle of its last packet record, as when a capture is copied while
/// still being written. Gzip files are decompressed, cut and recompressed (a well-formed
/// gzip stream around a truncated capture). Returns the new uncompressed capture length.
pub fn truncate_last_packet(path: &Path) -> io::Result<u64> {
    let bytes = fs::read(path)?;
    let compressed = bytes.starts_with(&[0x1f, 0x8b]);
    let raw = if compressed {
        let mut out = Vec::new();
        GzDecoder::new(bytes.as_slice()).read_to_end(&mut out)?;
        out
    } else {
        bytes
    };
    let (offset, len) = last_record(&raw)?;
    let keep = offset + (len / 2).max(1);
    let cut = raw.get(..keep).unwrap_or_default();
    fs::write(path, if compressed { gzip(cut)? } else { cut.to_vec() })?;
    Ok(keep as u64)
}

/// Offset and length of the last packet record of a pcap or pcapng file.
fn last_record(raw: &[u8]) -> io::Result<(usize, usize)> {
    let bad = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, msg.to_owned());
    let magic = read_u32(raw, 0, Endian::Little).ok_or_else(|| bad("file too short"))?;
    let mut last = None;
    match magic {
        0xa1b2_c3d4 | 0xa1b2_3c4d | 0xd4c3_b2a1 | 0x4d3c_b2a1 => {
            let endian = if matches!(magic, 0xa1b2_c3d4 | 0xa1b2_3c4d) {
                Endian::Little
            } else {
                Endian::Big
            };
            let mut off = 24;
            while let Some(incl) = read_u32(raw, off + 8, endian) {
                let len = 16 + incl as usize;
                if off + len > raw.len() {
                    break;
                }
                last = Some((off, len));
                off += len;
            }
        }
        0x0a0d_0d0a => {
            let endian = match read_u32(raw, 8, Endian::Little) {
                Some(0x1a2b_3c4d) => Endian::Little,
                _ => Endian::Big,
            };
            let mut off = 0;
            while let (Some(kind), Some(len)) =
                (read_u32(raw, off, endian), read_u32(raw, off + 4, endian))
            {
                let len = len as usize;
                if len < 12 || off + len > raw.len() {
                    break;
                }
                if matches!(kind, 2 | 3 | 6) {
                    last = Some((off, len));
                }
                off += len;
            }
        }
        _ => return Err(bad("not a pcap or pcapng file")),
    }
    last.ok_or_else(|| bad("no packet record"))
}

fn read_u32(raw: &[u8], off: usize, endian: Endian) -> Option<u32> {
    let b: [u8; 4] = raw.get(off..off + 4)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u32::from_le_bytes(b),
        Endian::Big => u32::from_be_bytes(b),
    })
}

/// Encoding cycle mixing every container variant: pcapng, pcap (us), pcapng.gz,
/// pcap (ns).gz and big-endian pcap.
pub fn mixed_encodings() -> Vec<Encoding> {
    vec![
        Encoding::pcapng(),
        Encoding::pcap(),
        Encoding::pcapng().gz(),
        Encoding::pcap_ns().gz(),
        Encoding::from(FileFormat::Pcap(PcapOptions {
            precision: PcapPrecision::Micro,
            endian: Endian::Big,
            ..PcapOptions::default()
        })),
    ]
}

/// Writes two chunk sets with different prefixes into the same directory.
pub fn write_two_prefixes(
    dir: &Path,
    a: (&str, &[Packet]),
    b: (&str, &[Packet]),
    opts: &SplitOptions,
) -> io::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let (_, paths_a) = split_to_dir(dir, a.1, &opts.clone().with_prefix(a.0))?;
    let (_, paths_b) = split_to_dir(dir, b.1, &opts.clone().with_prefix(b.0))?;
    Ok((paths_a, paths_b))
}

/// Traffic of two capture interfaces covering the same time span, packets interleaved in
/// time. Both lists use interface 0 (one file set per interface).
pub fn two_interface_traffic(rounds: usize) -> (Vec<Packet>, Vec<Packet>) {
    let mut a = Scenario::new().with_seed(1);
    // Offset by a quarter of the packet gap so timestamps never collide.
    let mut b = Scenario::starting_at(a.now() + 125_000).with_seed(2);
    for i in 0..rounds {
        let name = format!("host{i}.example.test");
        let ip = [203, 0, 113, u8::try_from(i % 250).unwrap_or_default() + 1];
        a.dns(
            hosts::workstation(),
            hosts::router(),
            &DnsExchange::a(&name, ip),
        );
        b.dns(
            hosts::file_server(),
            hosts::router(),
            &DnsExchange::a(&name, ip),
        );
        a.advance(EXCHANGE_GAP_NS);
        b.advance(EXCHANGE_GAP_NS);
    }
    (a.into_packets(), b.into_packets())
}

/// Merges two interface captures into one list ordered by time (ties keep `a` first);
/// packets of `b` move to interface 1. Suitable for a multi-IDB pcapng file.
pub fn merge_interfaces(a: &[Packet], b: &[Packet]) -> Vec<Packet> {
    let mut merged: Vec<Packet> = a
        .iter()
        .cloned()
        .chain(b.iter().cloned().map(|mut p| {
            p.interface = 1;
            p
        }))
        .collect();
    merged.sort_by_key(|p| (p.ts_ns, p.interface));
    merged
}

/// Two chunk sets (`eth0_*`, `eth1_*`) overlapping in time, one per interface.
pub fn write_overlapping_sets(
    dir: &Path,
    rounds: usize,
    opts: &SplitOptions,
) -> io::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let (a, b) = two_interface_traffic(rounds);
    write_two_prefixes(dir, ("eth0", &a), ("eth1", &b), opts)
}

/// Packets plus the index where a chunk boundary must fall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossChunkCase {
    pub packets: Vec<Packet>,
    /// First packet of the second chunk.
    pub cut: usize,
}

impl CrossChunkCase {
    /// Split criterion that puts the boundary at [`CrossChunkCase::cut`].
    pub fn split_by(&self) -> SplitBy {
        SplitBy::At(vec![self.cut])
    }
}

/// A DNS query at the end of chunk N and its response at the start of chunk N+1, with
/// other transactions on both sides.
pub fn dns_across_chunks() -> CrossChunkCase {
    let mut sc = Scenario::new();
    let ws = hosts::workstation();
    let resolver = hosts::router();
    sc.dns(
        ws,
        resolver,
        &DnsExchange::a("before.example.test", [203, 0, 113, 1]),
    );
    let split = sc.dns(
        ws,
        resolver,
        &DnsExchange::a("split.example.test", [203, 0, 113, 2]).with_id(0x5151),
    );
    sc.dns(
        ws,
        resolver,
        &DnsExchange::new("after.example.test", DnsType::Txt),
    );
    CrossChunkCase {
        packets: sc.into_packets(),
        cut: split.response.unwrap_or(split.query + 1),
    }
}

/// An HTTP request split over several TCP segments, cut between two chunks after its
/// first segment.
pub fn http_request_across_chunks() -> CrossChunkCase {
    let mut sc = Scenario::new();
    let mut tcp = TcpOptions::new(80);
    tcp.mss = 48;
    let get = HttpGet {
        tcp,
        ..HttpGet::default()
    };
    let ex = sc.http_get(hosts::workstation(), hosts::web_server(), &get);
    assert!(ex.request.len() >= 2, "the request spans several segments");
    CrossChunkCase {
        packets: sc.into_packets(),
        cut: ex.request.start + 1,
    }
}
