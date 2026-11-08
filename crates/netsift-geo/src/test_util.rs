//! Minimal `MaxMind` DB writer for tests (feature `test-util`).
//!
//! Written from the public `MaxMind` DB format specification (version 2.0): an IPv6 binary
//! search tree with 24-bit records, the 16-byte data section separator, a data section of
//! `{"country": {"iso_code": ...}}` maps, then the metadata marker and metadata map. IPv4
//! networks are stored under `::/96`, where readers look them up in IPv6 databases.

use std::net::IpAddr;
use std::path::Path;

/// Builds a small country database. Networks must not overlap.
#[derive(Debug, Clone, Default)]
pub struct MmdbBuilder {
    /// `(network bits in the IPv6 tree, prefix length in that tree, country code)`.
    networks: Vec<(u128, u8, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rec {
    Empty,
    Node(usize),
    Data(usize),
}

const MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";

// Data types of the format.
const T_STRING: u8 = 2;
const T_UINT16: u8 = 5;
const T_UINT32: u8 = 6;
const T_MAP: u8 = 7;
const T_UINT64: u8 = 9;
const T_ARRAY: u8 = 11;

impl MmdbBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps `ip/prefix_len` (IPv4 or IPv6) to `country` (stored as given).
    #[must_use]
    pub fn network(mut self, ip: IpAddr, prefix_len: u8, country: &str) -> Self {
        let (bits, len) = match ip {
            IpAddr::V4(v4) => (
                u128::from(u32::from(v4)),
                prefix_len.min(32).saturating_add(96),
            ),
            IpAddr::V6(v6) => (u128::from(v6), prefix_len.min(128)),
        };
        self.networks.push((bits, len, country.to_owned()));
        self
    }

    /// The database file content.
    pub fn build(&self) -> Vec<u8> {
        let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty; 2]];
        let mut data = Vec::new();
        for (bits, len, country) in &self.networks {
            let offset = data.len();
            encode_country(&mut data, country);
            insert(&mut nodes, *bits, *len, offset);
        }
        let node_count = nodes.len();
        let value = |r: Rec| -> u32 {
            let v = match r {
                Rec::Empty => node_count,
                Rec::Node(i) => i,
                Rec::Data(off) => node_count + 16 + off,
            };
            u32::try_from(v).unwrap_or(u32::MAX)
        };
        let mut out = Vec::new();
        for [left, right] in &nodes {
            for r in [*left, *right] {
                out.extend(value(r).to_be_bytes().iter().skip(1));
            }
        }
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(MARKER);
        encode_metadata(&mut out, u32::try_from(node_count).unwrap_or(u32::MAX));
        out
    }

    /// Writes the database to `path`.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.build())
    }
}

fn insert(nodes: &mut Vec<[Rec; 2]>, bits: u128, len: u8, offset: usize) {
    if len == 0 {
        return;
    }
    let mut node = 0usize;
    for depth in 0..len {
        let bit = usize::from((bits >> (127 - u32::from(depth))) & 1 == 1);
        let last = depth + 1 == len;
        let next_index = nodes.len();
        let Some(slot) = nodes.get_mut(node).and_then(|n| n.get_mut(bit)) else {
            return;
        };
        if last {
            *slot = Rec::Data(offset);
            return;
        }
        node = match *slot {
            Rec::Node(i) => i,
            // A deeper network replaces a shorter one (networks must not overlap).
            Rec::Empty | Rec::Data(_) => {
                *slot = Rec::Node(next_index);
                nodes.push([Rec::Empty; 2]);
                next_index
            }
        };
    }
}

fn control(out: &mut Vec<u8>, kind: u8, size: usize) {
    let (first, ext) = if kind <= 7 {
        (kind << 5, None)
    } else {
        (0, Some(kind - 7))
    };
    let (low, extra): (u8, Vec<u8>) = if size < 29 {
        (u8::try_from(size).unwrap_or(0), Vec::new())
    } else if size < 29 + 256 {
        (29, vec![u8::try_from(size - 29).unwrap_or(0)])
    } else if size < 285 + 65_536 {
        (
            30,
            u16::try_from(size - 285)
                .unwrap_or(0)
                .to_be_bytes()
                .to_vec(),
        )
    } else {
        let v = u32::try_from(size - 65_821).unwrap_or(0).to_be_bytes();
        (31, v.iter().skip(1).copied().collect())
    };
    out.push(first | low);
    out.extend(ext);
    out.extend(extra);
}

fn string(out: &mut Vec<u8>, s: &str) {
    control(out, T_STRING, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn uint(out: &mut Vec<u8>, kind: u8, v: u64) {
    let bytes = v.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let minimal = bytes.get(skip..).unwrap_or(&[]);
    control(out, kind, minimal.len());
    out.extend_from_slice(minimal);
}

fn encode_country(out: &mut Vec<u8>, code: &str) {
    control(out, T_MAP, 1);
    string(out, "country");
    control(out, T_MAP, 1);
    string(out, "iso_code");
    string(out, code);
}

fn encode_metadata(out: &mut Vec<u8>, node_count: u32) {
    control(out, T_MAP, 9);
    string(out, "binary_format_major_version");
    uint(out, T_UINT16, 2);
    string(out, "binary_format_minor_version");
    uint(out, T_UINT16, 0);
    string(out, "build_epoch");
    uint(out, T_UINT64, 1_700_000_000);
    string(out, "database_type");
    string(out, "NetSift-Test-Country");
    string(out, "description");
    control(out, T_MAP, 1);
    string(out, "en");
    string(out, "Synthetic country database for tests");
    string(out, "ip_version");
    uint(out, T_UINT16, 6);
    string(out, "languages");
    control(out, T_ARRAY, 1);
    string(out, "en");
    string(out, "node_count");
    uint(out, T_UINT32, u64::from(node_count));
    string(out, "record_size");
    uint(out, T_UINT16, 24);
}
