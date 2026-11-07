//! Capture file writers: libpcap (micro/nanosecond, either endianness), pcapng (SHB + one
//! IDB per interface + EPB, custom `if_tsresol`) and gzip compression.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use flate2::{Compression, GzBuilder};

use crate::packet::{LINKTYPE_ETHERNET, Packet};

/// Byte order of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Endian {
    #[default]
    Little,
    Big,
}

/// Timestamp precision of a libpcap file (selected by its magic number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PcapPrecision {
    /// Magic `a1b2c3d4`.
    #[default]
    Micro,
    /// Magic `a1b23c4d`.
    Nano,
}

/// libpcap writer options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapOptions {
    pub precision: PcapPrecision,
    pub endian: Endian,
    pub snaplen: u32,
}

impl Default for PcapOptions {
    fn default() -> Self {
        Self {
            precision: PcapPrecision::Micro,
            endian: Endian::Little,
            snaplen: 262_144,
        }
    }
}

/// pcapng `if_tsresol` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TsResolution {
    /// Units of 10^-n seconds (6 = microseconds, the pcapng default).
    Pow10(u8),
    /// Units of 2^-n seconds.
    Pow2(u8),
}

impl TsResolution {
    pub const MICRO: Self = Self::Pow10(6);
    pub const NANO: Self = Self::Pow10(9);

    /// Raw option byte (most significant bit selects base 2).
    pub fn option_byte(self) -> u8 {
        match self {
            Self::Pow10(n) => n & 0x7f,
            Self::Pow2(n) => 0x80 | (n & 0x7f),
        }
    }

    /// Converts nanoseconds since the epoch to units of this resolution (truncating).
    pub fn units_from_ns(self, ts_ns: i64) -> io::Result<u64> {
        let ns = u128::try_from(ts_ns).map_err(|_| invalid("negative timestamp"))?;
        let units = match self {
            Self::Pow10(n) if n <= 9 => ns / 10u128.pow(u32::from(9 - n)),
            Self::Pow10(n) => ns * 10u128.pow(u32::from(n.min(38) - 9)),
            Self::Pow2(n) => (ns << n.min(64)) / 1_000_000_000,
        };
        u64::try_from(units).map_err(|_| invalid("timestamp overflows the pcapng resolution"))
    }

    /// Converts units of this resolution back to nanoseconds (truncating).
    pub fn ns_from_units(self, units: u64) -> i64 {
        let units = u128::from(units);
        let ns = match self {
            Self::Pow10(n) if n <= 9 => units * 10u128.pow(u32::from(9 - n)),
            Self::Pow10(n) => units / 10u128.pow(u32::from(n.min(38) - 9)),
            Self::Pow2(n) => (units * 1_000_000_000) >> n.min(64),
        };
        i64::try_from(ns).unwrap_or(i64::MAX)
    }
}

/// pcapng interface description.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
    pub linktype: u32,
    pub snaplen: u32,
    pub tsresol: TsResolution,
    /// `if_name` option.
    pub name: Option<String>,
}

impl Interface {
    /// Ethernet interface with microsecond timestamps.
    pub fn ethernet() -> Self {
        Self {
            linktype: LINKTYPE_ETHERNET,
            snaplen: 262_144,
            tsresol: TsResolution::MICRO,
            name: None,
        }
    }

    #[must_use]
    pub fn with_tsresol(mut self, tsresol: TsResolution) -> Self {
        self.tsresol = tsresol;
        self
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// pcapng writer options.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PcapNgOptions {
    pub endian: Endian,
    /// Interface description blocks, indexed by `Packet::interface`. When empty, one IDB per
    /// interface id `0..=max` is derived from the packets (linktype of the first packet seen
    /// on it, microsecond resolution).
    pub interfaces: Vec<Interface>,
}

/// Container format and its options.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileFormat {
    Pcap(PcapOptions),
    PcapNg(PcapNgOptions),
}

impl FileFormat {
    /// Conventional extension (`pcap` or `pcapng`).
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Pcap(_) => "pcap",
            Self::PcapNg(_) => "pcapng",
        }
    }
}

/// How a file is encoded on disk: container format plus optional gzip compression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Encoding {
    pub format: FileFormat,
    pub gzip: bool,
}

impl Default for Encoding {
    fn default() -> Self {
        Self::pcapng()
    }
}

impl Encoding {
    /// libpcap, microseconds, little endian.
    pub fn pcap() -> Self {
        Self::from(FileFormat::Pcap(PcapOptions::default()))
    }

    /// libpcap, nanoseconds, little endian.
    pub fn pcap_ns() -> Self {
        Self::from(FileFormat::Pcap(PcapOptions {
            precision: PcapPrecision::Nano,
            ..PcapOptions::default()
        }))
    }

    /// pcapng, little endian, interfaces derived from the packets.
    pub fn pcapng() -> Self {
        Self::from(FileFormat::PcapNg(PcapNgOptions::default()))
    }

    /// Same encoding, gzip-compressed.
    #[must_use]
    pub fn gz(mut self) -> Self {
        self.gzip = true;
        self
    }

    /// File extension, including `.gz` when compressed.
    pub fn extension(&self) -> String {
        let ext = self.format.extension();
        if self.gzip {
            format!("{ext}.gz")
        } else {
            ext.to_owned()
        }
    }
}

impl From<FileFormat> for Encoding {
    fn from(format: FileFormat) -> Self {
        Self {
            format,
            gzip: false,
        }
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_owned())
}

fn u32_len(len: usize) -> io::Result<u32> {
    u32::try_from(len).map_err(|_| invalid("length overflows u32"))
}

struct Out<W> {
    w: W,
    endian: Endian,
    pos: u64,
}

impl<W: Write> Out<W> {
    fn bytes(&mut self, b: &[u8]) -> io::Result<()> {
        self.w.write_all(b)?;
        self.pos += b.len() as u64;
        Ok(())
    }

    fn u16(&mut self, v: u16) -> io::Result<()> {
        match self.endian {
            Endian::Little => self.bytes(&v.to_le_bytes()),
            Endian::Big => self.bytes(&v.to_be_bytes()),
        }
    }

    fn u32(&mut self, v: u32) -> io::Result<()> {
        match self.endian {
            Endian::Little => self.bytes(&v.to_le_bytes()),
            Endian::Big => self.bytes(&v.to_be_bytes()),
        }
    }

    fn padded(&mut self, b: &[u8]) -> io::Result<()> {
        self.bytes(b)?;
        self.bytes(&[0u8; 3][..pad4(b.len())])
    }
}

const fn pad4(len: usize) -> usize {
    (4 - len % 4) % 4
}

/// Streaming libpcap writer.
pub struct PcapWriter<W: Write> {
    out: Out<W>,
    opts: PcapOptions,
    linktype: u32,
}

impl<W: Write> PcapWriter<W> {
    /// Writes the global header.
    pub fn new(w: W, opts: PcapOptions, linktype: u32) -> io::Result<Self> {
        let mut out = Out {
            w,
            endian: opts.endian,
            pos: 0,
        };
        let magic = match opts.precision {
            PcapPrecision::Micro => 0xa1b2_c3d4,
            PcapPrecision::Nano => 0xa1b2_3c4d,
        };
        out.u32(magic)?;
        out.u16(2)?;
        out.u16(4)?;
        out.u32(0)?; // thiszone
        out.u32(0)?; // sigfigs
        out.u32(opts.snaplen)?;
        out.u32(linktype)?;
        Ok(Self {
            out,
            opts,
            linktype,
        })
    }

    /// Appends one record; returns its byte offset in the file.
    pub fn write_packet(&mut self, p: &Packet) -> io::Result<u64> {
        if p.linktype != self.linktype {
            return Err(invalid("a pcap file holds a single link type"));
        }
        let len = u32_len(p.data.len())?;
        if len > self.opts.snaplen {
            return Err(invalid("packet longer than the snaplen"));
        }
        let ts = u64::try_from(p.ts_ns).map_err(|_| invalid("negative timestamp"))?;
        let sec = u32::try_from(ts / 1_000_000_000).map_err(|_| invalid("timestamp after 2106"))?;
        let ns = u32::try_from(ts % 1_000_000_000).unwrap_or_default();
        let frac = match self.opts.precision {
            PcapPrecision::Micro => ns / 1000,
            PcapPrecision::Nano => ns,
        };
        let offset = self.out.pos;
        self.out.u32(sec)?;
        self.out.u32(frac)?;
        self.out.u32(len)?;
        self.out.u32(len)?;
        self.out.bytes(&p.data)?;
        Ok(offset)
    }

    pub fn into_inner(self) -> W {
        self.out.w
    }
}

/// Streaming pcapng writer (one section).
pub struct PcapNgWriter<W: Write> {
    out: Out<W>,
    interfaces: Vec<Interface>,
}

const SHB_TYPE: u32 = 0x0a0d_0d0a;
const IDB_TYPE: u32 = 0x0000_0001;
const EPB_TYPE: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
const SHB_LEN: u32 = 28;
const OPT_IF_NAME: u16 = 2;
const OPT_IF_TSRESOL: u16 = 9;

impl<W: Write> PcapNgWriter<W> {
    /// Writes the section header block and one interface description block per interface.
    pub fn new(w: W, endian: Endian, interfaces: Vec<Interface>) -> io::Result<Self> {
        let mut out = Out { w, endian, pos: 0 };
        out.u32(SHB_TYPE)?;
        out.u32(SHB_LEN)?;
        out.u32(BYTE_ORDER_MAGIC)?;
        out.u16(1)?;
        out.u16(0)?;
        out.u32(u32::MAX)?; // section length: -1 (unspecified)
        out.u32(u32::MAX)?;
        out.u32(SHB_LEN)?;
        for iface in &interfaces {
            let len = u32_len(idb_len(iface))?;
            let linktype = u16::try_from(iface.linktype)
                .map_err(|_| invalid("pcapng link types are 16-bit"))?;
            out.u32(IDB_TYPE)?;
            out.u32(len)?;
            out.u16(linktype)?;
            out.u16(0)?;
            out.u32(iface.snaplen)?;
            let options = idb_options(iface);
            for (code, value) in &options {
                out.u16(*code)?;
                out.u16(u16::try_from(value.len()).map_err(|_| invalid("option too long"))?)?;
                out.padded(value)?;
            }
            if !options.is_empty() {
                out.u32(0)?; // opt_endofopt
            }
            out.u32(len)?;
        }
        Ok(Self { out, interfaces })
    }

    /// Appends one enhanced packet block; returns its byte offset in the file.
    pub fn write_packet(&mut self, p: &Packet) -> io::Result<u64> {
        let iface = usize::try_from(p.interface)
            .ok()
            .and_then(|i| self.interfaces.get(i))
            .ok_or_else(|| invalid("packet interface has no IDB"))?;
        if iface.linktype != p.linktype {
            return Err(invalid("packet link type differs from its interface"));
        }
        let units = iface.tsresol.units_from_ns(p.ts_ns)?;
        let caplen = u32_len(p.data.len())?;
        let block_len = u32_len(epb_len(p.data.len()))?;
        let offset = self.out.pos;
        self.out.u32(EPB_TYPE)?;
        self.out.u32(block_len)?;
        self.out.u32(p.interface)?;
        self.out
            .u32(u32::try_from(units >> 32).unwrap_or_default())?;
        self.out
            .u32(u32::try_from(units & 0xffff_ffff).unwrap_or_default())?;
        self.out.u32(caplen)?;
        self.out.u32(caplen)?;
        self.out.padded(&p.data)?;
        self.out.u32(block_len)?;
        Ok(offset)
    }

    pub fn into_inner(self) -> W {
        self.out.w
    }
}

fn idb_options(iface: &Interface) -> Vec<(u16, Vec<u8>)> {
    let mut options = Vec::new();
    if let Some(name) = &iface.name {
        options.push((OPT_IF_NAME, name.as_bytes().to_vec()));
    }
    if iface.tsresol != TsResolution::MICRO {
        options.push((OPT_IF_TSRESOL, vec![iface.tsresol.option_byte()]));
    }
    options
}

fn idb_len(iface: &Interface) -> usize {
    let options = idb_options(iface);
    let opt_len: usize = options
        .iter()
        .map(|(_, v)| 4 + v.len() + pad4(v.len()))
        .sum();
    20 + opt_len + if options.is_empty() { 0 } else { 4 }
}

const fn epb_len(caplen: usize) -> usize {
    32 + caplen + pad4(caplen)
}

/// Interfaces actually written for `packets` under `opts` (see [`PcapNgOptions::interfaces`]).
pub fn resolve_interfaces(opts: &PcapNgOptions, packets: &[Packet]) -> Vec<Interface> {
    if !opts.interfaces.is_empty() {
        return opts.interfaces.clone();
    }
    let count = packets
        .iter()
        .map(|p| p.interface)
        .max()
        .map_or(1, |m| m as usize + 1);
    (0..count)
        .map(|i| {
            let linktype = packets
                .iter()
                .find(|p| p.interface as usize == i)
                .map_or(LINKTYPE_ETHERNET, |p| p.linktype);
            Interface {
                linktype,
                ..Interface::ethernet()
            }
        })
        .collect()
}

/// Size of the file header (pcap global header, or pcapng SHB + IDBs), uncompressed.
pub fn header_size(format: &FileFormat, interfaces: &[Interface]) -> u64 {
    match format {
        FileFormat::Pcap(_) => 24,
        FileFormat::PcapNg(_) => {
            u64::from(SHB_LEN) + interfaces.iter().map(|i| idb_len(i) as u64).sum::<u64>()
        }
    }
}

/// Size of one packet record, uncompressed.
pub fn record_size(format: &FileFormat, p: &Packet) -> u64 {
    match format {
        FileFormat::Pcap(_) => 16 + p.data.len() as u64,
        FileFormat::PcapNg(_) => epb_len(p.data.len()) as u64,
    }
}

/// Encodes `packets` with `interfaces` (pcapng) or the first packet's link type (pcap).
pub fn encode_with_interfaces(
    packets: &[Packet],
    encoding: &Encoding,
    interfaces: &[Interface],
) -> io::Result<Vec<u8>> {
    let raw = match &encoding.format {
        FileFormat::Pcap(opts) => {
            let linktype = packets.first().map_or(LINKTYPE_ETHERNET, |p| p.linktype);
            let mut w = PcapWriter::new(Vec::new(), *opts, linktype)?;
            for p in packets {
                w.write_packet(p)?;
            }
            w.into_inner()
        }
        FileFormat::PcapNg(opts) => {
            let mut w = PcapNgWriter::new(Vec::new(), opts.endian, interfaces.to_vec())?;
            for p in packets {
                w.write_packet(p)?;
            }
            w.into_inner()
        }
    };
    if encoding.gzip { gzip(&raw) } else { Ok(raw) }
}

/// Encodes `packets` into the bytes of a complete capture file.
pub fn encode(packets: &[Packet], encoding: &Encoding) -> io::Result<Vec<u8>> {
    let interfaces = match &encoding.format {
        FileFormat::Pcap(_) => Vec::new(),
        FileFormat::PcapNg(opts) => resolve_interfaces(opts, packets),
    };
    encode_with_interfaces(packets, encoding, &interfaces)
}

/// Writes `packets` to `path` as a complete capture file.
pub fn write_file(path: &Path, packets: &[Packet], encoding: &Encoding) -> io::Result<()> {
    fs::write(path, encode(packets, encoding)?)
}

/// Gzip-compresses `data` deterministically (no file name, zero modification time).
pub fn gzip(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsresol_conversions() {
        let ts = 1_700_000_000_123_456_789;
        assert_eq!(
            TsResolution::MICRO.units_from_ns(ts).unwrap(),
            1_700_000_000_123_456
        );
        assert_eq!(
            TsResolution::NANO.units_from_ns(ts).unwrap(),
            1_700_000_000_123_456_789
        );
        assert_eq!(TsResolution::Pow10(3).option_byte(), 3);
        assert_eq!(TsResolution::Pow2(20).option_byte(), 0x94);
        let units = TsResolution::Pow2(20).units_from_ns(ts).unwrap();
        let back = TsResolution::Pow2(20).ns_from_units(units);
        assert!(ts - back < 1_000, "2^-20 s is below one microsecond");
        assert!(TsResolution::NANO.units_from_ns(-1).is_err());
    }

    #[test]
    fn sizes_match_encoded_lengths() {
        let p = Packet::ethernet(1_700_000_000_000_000_000, vec![0xab; 61]);
        for enc in [Encoding::pcap(), Encoding::pcap_ns(), Encoding::pcapng()] {
            let bytes = encode(std::slice::from_ref(&p), &enc).unwrap();
            let ifaces = match &enc.format {
                FileFormat::PcapNg(o) => resolve_interfaces(o, std::slice::from_ref(&p)),
                FileFormat::Pcap(_) => Vec::new(),
            };
            assert_eq!(
                bytes.len() as u64,
                header_size(&enc.format, &ifaces) + record_size(&enc.format, &p)
            );
        }
        let named = Interface::ethernet()
            .with_name("eth0")
            .with_tsresol(TsResolution::NANO);
        let opts = PcapNgOptions {
            endian: Endian::Big,
            interfaces: vec![named.clone()],
        };
        let bytes = encode(
            std::slice::from_ref(&p),
            &Encoding::from(FileFormat::PcapNg(opts)),
        )
        .unwrap();
        assert_eq!(bytes.len(), 28 + idb_len(&named) + epb_len(p.data.len()));
        assert_eq!(idb_len(&named), 20 + 8 + 8 + 4);
    }

    #[test]
    fn pcap_rejects_mixed_link_types() {
        let mut other = Packet::ethernet(0, vec![0x45; 20]);
        other.linktype = crate::packet::LINKTYPE_RAW;
        let res = encode(
            &[Packet::ethernet(0, vec![0; 14]), other],
            &Encoding::pcap(),
        );
        assert!(res.is_err());
    }
}
