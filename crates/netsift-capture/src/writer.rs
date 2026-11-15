//! pcapng writer for the "Save PCAP" export (`docs/specs/export-pcap.md`).
//!
//! Written from the pcapng specification (IETF draft `draft-ietf-opsawg-pcapng`), not from any
//! existing implementation:
//!
//! - one Section Header Block (little endian, version 1.0, section length unknown), with the
//!   `shb_userappl` option naming the writer;
//! - one Interface Description Block per distinct `(link type, snaplen)` pair, written just
//!   before the first packet that uses it, with `if_tsresol = 9` (nanoseconds);
//! - one Enhanced Packet Block per packet: interface id, 64-bit timestamp in nanoseconds,
//!   captured and original lengths, data padded to 32 bits, no options.
//!
//! Memory is constant: nothing is buffered here beyond the interface table (at most
//! [`MAX_INTERFACES`] entries); wrap the output in a `BufWriter`.

use std::collections::HashMap;
use std::io::{self, Write};

use crate::reader::MAX_PACKET_LEN;

/// Interfaces (distinct link type and snaplen pairs) accepted in one file.
pub const MAX_INTERFACES: usize = 4096;
/// Longest `shb_userappl` value written, in bytes (longer names are cut on a char boundary).
const MAX_USERAPPL: usize = 256;

const BT_SHB: u32 = 0x0A0D_0D0A;
const BT_IDB: u32 = 0x0000_0001;
const BT_EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const OPT_ENDOFOPT: u16 = 0;
const OPT_SHB_USERAPPL: u16 = 4;
const OPT_IF_TSRESOL: u16 = 9;
/// `if_tsresol` value: units of 10^-9 s.
const TSRESOL_NANOS: u8 = 9;
/// Fixed part of an EPB: type, length, interface, timestamp (2), lengths (2), trailing length.
const EPB_FIXED: usize = 32;
/// Size of an IDB: type, length, link type + reserved, snaplen, `if_tsresol` (8), end (4),
/// trailing length.
const IDB_LEN: u32 = 32;

/// Errors of [`PcapNgWriter`].
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// pcapng link types are 16 bits wide.
    #[error("link type {0} does not fit a pcapng interface")]
    LinkType(u32),
    #[error("more than {MAX_INTERFACES} interfaces")]
    TooManyInterfaces,
    #[error("packet of {0} bytes exceeds the {MAX_PACKET_LEN}-byte limit")]
    PacketTooLarge(usize),
}

/// Streaming pcapng writer (one section).
pub struct PcapNgWriter<W: Write> {
    out: W,
    /// Interface id by `(link type, snaplen)`.
    interfaces: HashMap<(u32, u32), u32>,
    packets: u64,
    bytes: u64,
}

impl<W: Write> PcapNgWriter<W> {
    /// Writes the section header. `application` goes into `shb_userappl` (e.g. "NetSift 0.4.0").
    pub fn new(mut out: W, application: &str) -> Result<Self, WriteError> {
        let app = cut(application, MAX_USERAPPL).as_bytes();
        let app_len = u16::try_from(app.len()).unwrap_or(0);
        let app_padded = padded(app.len());
        let options = if app.is_empty() { 0 } else { 4 + app_padded } + 4;
        // type, length, byte-order magic, version, section length, options, trailing length.
        let total = u32::try_from(4 + 4 + 4 + 4 + 8 + options + 4)
            .map_err(|_| WriteError::PacketTooLarge(app.len()))?;
        let mut block = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
        block.extend_from_slice(&BT_SHB.to_le_bytes());
        block.extend_from_slice(&total.to_le_bytes());
        block.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        block.extend_from_slice(&1u16.to_le_bytes());
        block.extend_from_slice(&0u16.to_le_bytes());
        block.extend_from_slice(&(-1i64).to_le_bytes());
        if !app.is_empty() {
            block.extend_from_slice(&OPT_SHB_USERAPPL.to_le_bytes());
            block.extend_from_slice(&app_len.to_le_bytes());
            block.extend_from_slice(app);
            block.resize(block.len() + (app_padded - app.len()), 0);
        }
        block.extend_from_slice(&OPT_ENDOFOPT.to_le_bytes());
        block.extend_from_slice(&0u16.to_le_bytes());
        block.extend_from_slice(&total.to_le_bytes());
        out.write_all(&block)?;
        Ok(Self {
            out,
            interfaces: HashMap::new(),
            packets: 0,
            bytes: u64::from(total),
        })
    }

    /// Writes one packet. `snaplen` is the snapshot length of its source interface (0 when
    /// unknown or unlimited); a negative timestamp (before 1970) is written as 0. The original
    /// length is raised to the captured length when smaller.
    pub fn write_packet(
        &mut self,
        linktype: u32,
        snaplen: u32,
        ts_ns: i64,
        orig_len: u32,
        data: &[u8],
    ) -> Result<(), WriteError> {
        let caplen = u32::try_from(data.len())
            .ok()
            .filter(|&l| l <= MAX_PACKET_LEN)
            .ok_or(WriteError::PacketTooLarge(data.len()))?;
        let interface = self.interface(linktype, snaplen)?;
        let ts = u64::try_from(ts_ns).unwrap_or(0);
        let pad = padded(data.len()) - data.len();
        let total = u32::try_from(EPB_FIXED + data.len() + pad)
            .map_err(|_| WriteError::PacketTooLarge(data.len()))?;
        let mut head = [0u8; 28];
        put(&mut head, 0, BT_EPB);
        put(&mut head, 4, total);
        put(&mut head, 8, interface);
        // Truncation intended: high and low 32-bit halves of the timestamp.
        put(&mut head, 12, (ts >> 32) as u32);
        put(&mut head, 16, (ts & 0xFFFF_FFFF) as u32);
        put(&mut head, 20, caplen);
        put(&mut head, 24, orig_len.max(caplen));
        self.out.write_all(&head)?;
        self.out.write_all(data)?;
        self.out.write_all([0u8; 3].get(..pad).unwrap_or_default())?;
        self.out.write_all(&total.to_le_bytes())?;
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(u64::from(total));
        Ok(())
    }

    /// Packets written so far.
    pub fn packets(&self) -> u64 {
        self.packets
    }

    /// Bytes written so far (headers included).
    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }

    /// Interface description blocks written so far.
    pub fn interfaces(&self) -> usize {
        self.interfaces.len()
    }

    /// Flushes and returns the output.
    pub fn into_inner(mut self) -> Result<W, WriteError> {
        self.out.flush()?;
        Ok(self.out)
    }

    /// Id of the interface of `(linktype, snaplen)`, writing its IDB on first use.
    fn interface(&mut self, linktype: u32, snaplen: u32) -> Result<u32, WriteError> {
        if let Some(&id) = self.interfaces.get(&(linktype, snaplen)) {
            return Ok(id);
        }
        let lt = u16::try_from(linktype).map_err(|_| WriteError::LinkType(linktype))?;
        if self.interfaces.len() >= MAX_INTERFACES {
            return Err(WriteError::TooManyInterfaces);
        }
        let id = u32::try_from(self.interfaces.len()).map_err(|_| WriteError::TooManyInterfaces)?;
        let mut block = Vec::with_capacity(32);
        block.extend_from_slice(&BT_IDB.to_le_bytes());
        block.extend_from_slice(&IDB_LEN.to_le_bytes());
        block.extend_from_slice(&lt.to_le_bytes());
        block.extend_from_slice(&0u16.to_le_bytes()); // reserved
        block.extend_from_slice(&snaplen.to_le_bytes());
        block.extend_from_slice(&OPT_IF_TSRESOL.to_le_bytes());
        block.extend_from_slice(&1u16.to_le_bytes());
        block.extend_from_slice(&[TSRESOL_NANOS, 0, 0, 0]); // value and padding
        block.extend_from_slice(&OPT_ENDOFOPT.to_le_bytes());
        block.extend_from_slice(&0u16.to_le_bytes());
        block.extend_from_slice(&IDB_LEN.to_le_bytes());
        self.out.write_all(&block)?;
        self.bytes = self.bytes.saturating_add(u64::from(IDB_LEN));
        self.interfaces.insert((linktype, snaplen), id);
        Ok(id)
    }
}

/// Little-endian `u32` at a fixed offset of a fixed-size header (offsets are constants).
fn put<const N: usize>(buf: &mut [u8; N], at: usize, value: u32) {
    if let Some(slot) = buf.get_mut(at..at.saturating_add(4)) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

/// `len` rounded up to a multiple of 4.
fn padded(len: usize) -> usize {
    len.div_ceil(4).saturating_mul(4)
}

/// Longest prefix of `s` of at most `max` bytes, cut on a char boundary.
fn cut(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_interface_layout() {
        let mut w = PcapNgWriter::new(Vec::new(), "NS").unwrap();
        w.write_packet(1, 65_535, 1_700_000_000_123_456_789, 70, &[0xAA; 5])
            .unwrap();
        let out = w.into_inner().unwrap();
        // SHB: 28 bytes + userappl option (4 + 4) + end of options (4).
        let shb_len = u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize;
        assert_eq!(shb_len, 40);
        assert_eq!(&out[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
        assert_eq!(&out[8..12], &[0x4D, 0x3C, 0x2B, 0x1A]);
        assert_eq!(&out[24..30], &[4, 0, 2, 0, b'N', b'S']);
        assert_eq!(&out[shb_len - 4..shb_len], &out[4..8]);
        // IDB right after.
        let idb = &out[shb_len..shb_len + 32];
        assert_eq!(&idb[0..4], &[1, 0, 0, 0]);
        assert_eq!(&idb[8..10], &[1, 0]);
        assert_eq!(&idb[12..16], &65_535u32.to_le_bytes());
        assert_eq!(&idb[16..21], &[9, 0, 1, 0, 9]);
        // EPB: 32 + 8 (5 bytes padded).
        let epb = &out[shb_len + 32..];
        assert_eq!(epb.len(), 40);
        assert_eq!(&epb[0..4], &[6, 0, 0, 0]);
        assert_eq!(&epb[20..24], &5u32.to_le_bytes());
        assert_eq!(&epb[24..28], &70u32.to_le_bytes());
        let ts = (u64::from(u32::from_le_bytes(epb[12..16].try_into().unwrap())) << 32)
            | u64::from(u32::from_le_bytes(epb[16..20].try_into().unwrap()));
        assert_eq!(ts, 1_700_000_000_123_456_789);
        assert_eq!(&epb[28..36], &[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0, 0, 0]);
    }

    #[test]
    fn bounds() {
        let mut w = PcapNgWriter::new(Vec::new(), "").unwrap();
        assert!(matches!(
            w.write_packet(70_000, 0, 0, 0, &[]),
            Err(WriteError::LinkType(70_000))
        ));
        // Negative timestamp written as 0, orig_len raised to caplen.
        w.write_packet(1, 0, -5, 0, &[1, 2, 3, 4]).unwrap();
        assert_eq!(w.packets(), 1);
        for snaplen in 1..u32::try_from(MAX_INTERFACES).unwrap() {
            w.write_packet(1, snaplen, 0, 0, &[]).unwrap();
        }
        assert_eq!(w.interfaces(), MAX_INTERFACES);
        assert!(matches!(
            w.write_packet(2, 0, 0, 0, &[]),
            Err(WriteError::TooManyInterfaces)
        ));
        let long = "é".repeat(300);
        assert!(cut(&long, MAX_USERAPPL).len() <= MAX_USERAPPL);
        assert!(PcapNgWriter::new(Vec::new(), &long).is_ok());
    }
}
