//! pcapng: sections (SHB), interfaces (IDB) and packet blocks (EPB, SPB, obsolete PB).
//!
//! - Each SHB starts a new section: the byte order may change and the interface table is reset.
//! - Interfaces carry their link type, snaplen, `if_tsresol` (power of 10 or of 2) and
//!   `if_tsoffset` (seconds added to every timestamp).
//! - A Simple Packet Block has no timestamp: it gets the timestamp of the previous packet of the
//!   same section, or of the file when it is the first of its section, or 0 at the very start.
//!   This keeps the packet order and never produces a `TimestampBackwards` warning by itself.
//! - Name resolution, interface statistics, systemd journal, decryption secrets and custom
//!   blocks are skipped silently; any other block type yields `ReadWarning::UnknownBlock`.

use bytes::Bytes;

use super::{Core, Endian, MAX_BLOCK_LEN, MAX_PACKET_LEN};
use crate::source::{CaptureError, CaptureInfo, PacketSource, RawPacket, ReadWarning};

const SHB_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const BT_IDB: u32 = 0x0000_0001;
const BT_PB: u32 = 0x0000_0002;
const BT_SPB: u32 = 0x0000_0003;
const BT_EPB: u32 = 0x0000_0006;
/// Known block types that carry no packet: skipped without warning.
const IGNORED_BLOCKS: [u32; 6] = [
    0x0000_0004, // Name Resolution Block
    0x0000_0005, // Interface Statistics Block
    0x0000_0009, // systemd Journal Export Block
    0x0000_000a, // Decryption Secrets Block
    0x0000_0bad, // Custom Block (copiable)
    0x4000_0bad, // Custom Block (not copiable)
];

/// Smallest block: type, total length, trailing total length.
const MIN_BLOCK_LEN: u32 = 12;
/// Smallest SHB: header (12) + version (4) + section length (8) + trailer (4).
const MIN_SHB_LEN: u32 = 28;
/// Interfaces kept per section; further IDBs are skipped (bounded memory).
const MAX_INTERFACES: usize = 4096;

const OPT_ENDOFOPT: u16 = 0;
const OPT_IF_TSRESOL: u16 = 9;
const OPT_IF_TSOFFSET: u16 = 14;

/// Returns the section byte order from a byte-order magic, if valid.
pub(super) fn byte_order(bom: &[u8]) -> Option<Endian> {
    match bom {
        [0x1a, 0x2b, 0x3c, 0x4d] => Some(Endian::Big),
        [0x4d, 0x3c, 0x2b, 0x1a] => Some(Endian::Little),
        _ => None,
    }
}

/// Timestamp resolution of an interface (`if_tsresol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsResol {
    /// Units of 10^-n seconds.
    Pow10(u8),
    /// Units of 2^-n seconds.
    Pow2(u8),
}

impl TsResol {
    fn from_option(byte: u8) -> Self {
        if byte & 0x80 == 0 {
            Self::Pow10(byte)
        } else {
            Self::Pow2(byte & 0x7f)
        }
    }
}

/// Converts a raw interface timestamp to nanoseconds since the epoch, `None` on overflow.
fn to_ns(ts: u64, resol: TsResol, offset_s: i64) -> Option<i64> {
    const NANOS: u32 = 9;
    let ns: i128 = match resol {
        TsResol::Pow10(n) if u32::from(n) <= NANOS => {
            i128::from(ts).checked_mul(10i128.checked_pow(NANOS - u32::from(n))?)?
        }
        TsResol::Pow10(n) => match 10u128.checked_pow(u32::from(n) - NANOS) {
            Some(div) => i128::try_from(u128::from(ts).checked_div(div)?).ok()?,
            // Divisor larger than any u64: the value rounds down to 0.
            None => 0,
        },
        TsResol::Pow2(n) => {
            let scaled = u128::from(ts).checked_mul(1_000_000_000)?;
            i128::try_from(scaled.checked_shr(u32::from(n))?).ok()?
        }
    };
    let offset_ns = i128::from(offset_s).checked_mul(1_000_000_000)?;
    i64::try_from(ns.checked_add(offset_ns)?).ok()
}

#[derive(Debug, Clone, Copy)]
struct Interface {
    linktype: u32,
    snaplen: u32,
    resol: TsResol,
    offset_s: i64,
}

pub(super) struct PcapNgReader {
    core: Core,
    endian: Endian,
    /// Interfaces of the current section, by id; `None` for a malformed IDB (keeps numbering).
    interfaces: Vec<Option<Interface>>,
    section_last_ts: Option<i64>,
    /// Outcome of the read-ahead done at open time, so that `info()` already lists the
    /// interfaces declared before the first packet. Errors past the first SHB are deferred to
    /// the first `next_packet` call.
    pending: Option<Result<RawPacket, CaptureError>>,
}

/// Outcome of reading a block.
enum Step {
    Packet(RawPacket),
    Continue,
    Truncated,
}

impl PcapNgReader {
    pub(super) fn open(core: Core) -> Result<Self, CaptureError> {
        let mut reader = Self {
            core,
            endian: Endian::Little,
            interfaces: Vec::new(),
            section_last_ts: None,
            pending: None,
        };
        // The first section header must be valid for the file to open at all.
        let mut head = [0u8; 8];
        if reader.core.input.read_full(&mut head)? < head.len() {
            return Err(reader.core.malformed(0, "truncated section header block"));
        }
        if let Step::Truncated = reader.read_shb(0, head)? {
            return Err(reader.core.malformed(0, "truncated section header block"));
        }
        reader.pending = reader.read_next().transpose();
        Ok(reader)
    }

    fn read_next(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        loop {
            if self.core.done {
                return Ok(None);
            }
            let start = self.core.input.pos;
            let mut head = [0u8; 8];
            let n = self.core.input.read_full(&mut head)?;
            if n == 0 {
                self.core.end_of_stream(start);
                return Ok(None);
            }
            if n < head.len() {
                self.core.truncated(start);
                return Ok(None);
            }
            let step = if head.first_chunk::<4>() == Some(&SHB_MAGIC) {
                self.read_shb(start, head)?
            } else {
                self.read_block(start, head)?
            };
            match step {
                Step::Packet(packet) => return Ok(Some(packet)),
                Step::Continue => {}
                Step::Truncated => {
                    self.core.truncated(start);
                    return Ok(None);
                }
            }
        }
    }

    /// Section Header Block: byte order, version, then everything else is skipped.
    fn read_shb(&mut self, start: u64, head: [u8; 8]) -> Result<Step, CaptureError> {
        let mut bom = [0u8; 4];
        if self.core.input.read_full(&mut bom)? < bom.len() {
            return Ok(Step::Truncated);
        }
        let Some(endian) = byte_order(&bom) else {
            return Err(self
                .core
                .malformed(start, "invalid pcapng byte-order magic"));
        };
        let total = endian.u32_at(&head, 4).unwrap_or(0);
        if total < MIN_SHB_LEN || !total.is_multiple_of(4) || total > MAX_BLOCK_LEN {
            return Err(self
                .core
                .malformed(start, format!("invalid section header length {total}")));
        }
        let mut version = [0u8; 4];
        if self.core.input.read_full(&mut version)? < version.len() {
            return Ok(Step::Truncated);
        }
        let major = endian.u16_at(&version, 0).unwrap_or(0);
        if major != 1 {
            return Err(self
                .core
                .malformed(start, format!("unsupported pcapng major version {major}")));
        }
        // Section length and options are not needed.
        let skip = u64::from(total - 20);
        if self.core.input.skip(skip)? < skip {
            return Ok(Step::Truncated);
        }
        let mut trailer = [0u8; 4];
        if self.core.input.read_full(&mut trailer)? < trailer.len() {
            return Ok(Step::Truncated);
        }
        if endian.u32_at(&trailer, 0) != Some(total) {
            self.core
                .skipped(start, "section header trailing length mismatch");
        }
        self.endian = endian;
        self.interfaces.clear();
        self.section_last_ts = None;
        Ok(Step::Continue)
    }

    /// Any block other than an SHB.
    fn read_block(&mut self, start: u64, head: [u8; 8]) -> Result<Step, CaptureError> {
        let e = self.endian;
        let block_type = e.u32_at(&head, 0).unwrap_or(0);
        let total = e.u32_at(&head, 4).unwrap_or(0);
        if total < MIN_BLOCK_LEN || !total.is_multiple_of(4) || total > MAX_BLOCK_LEN {
            return Err(self.core.malformed(
                start,
                format!("invalid length {total} for block type {block_type:#010x}"),
            ));
        }
        // Body plus trailing length.
        let rest = total - 8;
        let is_known = matches!(block_type, BT_IDB | BT_PB | BT_SPB | BT_EPB);
        if !is_known || rest > MAX_PACKET_LEN.saturating_add(64 * 1024) {
            if self.core.input.skip(u64::from(rest))? < u64::from(rest) {
                return Ok(Step::Truncated);
            }
            if is_known {
                self.core.skipped(
                    start,
                    format!("block of {total} bytes exceeds the size limit"),
                );
            } else if !IGNORED_BLOCKS.contains(&block_type) {
                self.core.warn(ReadWarning::UnknownBlock {
                    offset: start,
                    block_type,
                });
            }
            return Ok(Step::Continue);
        }
        let len = usize::try_from(rest).unwrap_or(usize::MAX);
        let buf = self.core.input.read_vec(len)?;
        if buf.len() < len {
            return Ok(Step::Truncated);
        }
        let Some((body, trailer)) = buf.split_at_checked(len.saturating_sub(4)) else {
            return Ok(Step::Truncated);
        };
        if e.u32_at(trailer, 0) != Some(total) {
            self.core.skipped(start, "block trailing length mismatch");
            return Ok(Step::Continue);
        }
        Ok(match block_type {
            BT_IDB => {
                self.on_idb(start, body);
                Step::Continue
            }
            BT_EPB => self.on_epb(start, body, false),
            BT_PB => self.on_epb(start, body, true),
            _ => self.on_spb(start, body),
        })
    }

    fn on_idb(&mut self, start: u64, body: &[u8]) {
        if self.interfaces.len() >= MAX_INTERFACES {
            self.core.skipped(
                start,
                format!("more than {MAX_INTERFACES} interfaces in one section"),
            );
            return;
        }
        let e = self.endian;
        let (Some(linktype), Some(snaplen)) = (e.u16_at(body, 0), e.u32_at(body, 4)) else {
            self.core
                .skipped(start, "interface description block too short");
            self.interfaces.push(None);
            return;
        };
        let mut iface = Interface {
            linktype: u32::from(linktype),
            snaplen,
            resol: TsResol::Pow10(6),
            offset_s: 0,
        };
        parse_idb_options(e, body.get(8..).unwrap_or_default(), &mut iface);
        self.core.add_linktype(iface.linktype);
        if self.core.info.snaplen.is_none() {
            self.core.info.snaplen = Some(iface.snaplen);
        }
        self.interfaces.push(Some(iface));
    }

    /// Enhanced Packet Block, or the obsolete Packet Block (16-bit interface id + drop count).
    fn on_epb(&mut self, start: u64, body: &[u8], obsolete: bool) -> Step {
        let e = self.endian;
        let iface_id = if obsolete {
            e.u16_at(body, 0).map(u32::from)
        } else {
            e.u32_at(body, 0)
        };
        let fields = (
            iface_id,
            e.u32_at(body, 4),
            e.u32_at(body, 8),
            e.u32_at(body, 12),
            e.u32_at(body, 16),
        );
        let (Some(iface_id), Some(ts_high), Some(ts_low), Some(cap_len), Some(orig_len)) = fields
        else {
            self.core.skipped(start, "packet block too short");
            return Step::Continue;
        };
        let data = usize::try_from(cap_len)
            .ok()
            .and_then(|len| body.get(20..20usize.checked_add(len)?));
        let Some(data) = data else {
            self.core
                .skipped(start, "captured length exceeds the block size");
            return Step::Continue;
        };
        let ts = (u64::from(ts_high) << 32) | u64::from(ts_low);
        let Some(iface) = self.interface(start, iface_id) else {
            return Step::Continue;
        };
        let Some(ts_ns) = to_ns(ts, iface.resol, iface.offset_s) else {
            self.core.skipped(start, "timestamp out of range");
            return Step::Continue;
        };
        self.emit(start, ts_ns, iface.linktype, orig_len, data)
    }

    /// Simple Packet Block: interface 0, no timestamp (see the module documentation).
    fn on_spb(&mut self, start: u64, body: &[u8]) -> Step {
        let Some(orig_len) = self.endian.u32_at(body, 0) else {
            self.core.skipped(start, "simple packet block too short");
            return Step::Continue;
        };
        let Some(iface) = self.interface(start, 0) else {
            return Step::Continue;
        };
        let available = body.len().saturating_sub(4);
        let mut len = usize::try_from(orig_len)
            .unwrap_or(usize::MAX)
            .min(available);
        if iface.snaplen != 0 {
            len = len.min(usize::try_from(iface.snaplen).unwrap_or(usize::MAX));
        }
        let data = body.get(4..4 + len).unwrap_or_default();
        let ts_ns = self.section_last_ts.or(self.core.previous_ts).unwrap_or(0);
        self.emit(start, ts_ns, iface.linktype, orig_len, data)
    }

    fn interface(&mut self, start: u64, id: u32) -> Option<Interface> {
        let found = usize::try_from(id)
            .ok()
            .and_then(|i| self.interfaces.get(i).copied().flatten());
        if found.is_none() {
            self.core.skipped(
                start,
                format!("interface {id} is not described in this section"),
            );
        }
        found
    }

    fn emit(&mut self, start: u64, ts_ns: i64, linktype: u32, orig_len: u32, data: &[u8]) -> Step {
        self.core.check_order(start, ts_ns);
        self.section_last_ts = Some(ts_ns);
        Step::Packet(RawPacket {
            ts_ns,
            chunk_id: 0,
            offset: start,
            linktype,
            orig_len,
            data: Bytes::copy_from_slice(data),
        })
    }
}

/// Reads `if_tsresol` and `if_tsoffset`; a truncated option list simply ends the parsing.
fn parse_idb_options(e: Endian, options: &[u8], iface: &mut Interface) {
    let mut at = 0usize;
    while let (Some(code), Some(len)) = (e.u16_at(options, at), e.u16_at(options, at + 2)) {
        let len = usize::from(len);
        let Some(value) = options.get(at + 4..at + 4 + len) else {
            return;
        };
        match code {
            OPT_ENDOFOPT => return,
            OPT_IF_TSRESOL => {
                if let [byte] = value {
                    iface.resol = TsResol::from_option(*byte);
                }
            }
            OPT_IF_TSOFFSET => {
                if let Some(offset) = e.i64_at(value, 0) {
                    iface.offset_s = offset;
                }
            }
            _ => {}
        }
        // Values are padded to 32 bits.
        at += 4 + len.next_multiple_of(4);
    }
}

impl PacketSource for PcapNgReader {
    fn info(&self) -> &CaptureInfo {
        &self.core.info
    }

    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        if let Some(pending) = self.pending.take() {
            return pending.map(Some);
        }
        self.read_next()
    }

    fn bytes_read(&self) -> u64 {
        self.core.bytes_read()
    }

    fn warnings(&self) -> &[ReadWarning] {
        &self.core.warnings
    }
}

#[cfg(test)]
mod tests {
    use super::{TsResol, to_ns};

    #[test]
    fn converts_power_of_ten_resolutions() {
        assert_eq!(to_ns(1_500_000, TsResol::Pow10(6), 0), Some(1_500_000_000));
        assert_eq!(to_ns(15, TsResol::Pow10(1), 0), Some(1_500_000_000));
        assert_eq!(to_ns(7, TsResol::Pow10(9), 0), Some(7));
        assert_eq!(to_ns(12_345, TsResol::Pow10(12), 0), Some(12));
        assert_eq!(to_ns(u64::MAX, TsResol::Pow10(127), 0), Some(0));
    }

    #[test]
    fn converts_power_of_two_resolutions() {
        assert_eq!(to_ns(3 << 20, TsResol::Pow2(20), 0), Some(3_000_000_000));
        assert_eq!(to_ns(1, TsResol::Pow2(1), 0), Some(500_000_000));
        assert_eq!(to_ns(u64::MAX, TsResol::Pow2(127), 0), Some(0));
    }

    #[test]
    fn applies_offset_and_detects_overflow() {
        assert_eq!(to_ns(1, TsResol::Pow10(0), 10), Some(11_000_000_000));
        assert_eq!(to_ns(1, TsResol::Pow10(0), -1), Some(0));
        assert_eq!(to_ns(u64::MAX, TsResol::Pow10(0), 0), None);
        assert_eq!(to_ns(0, TsResol::Pow10(0), i64::MAX), None);
        assert_eq!(to_ns(0, TsResol::Pow10(0), i64::MIN), None);
    }
}
