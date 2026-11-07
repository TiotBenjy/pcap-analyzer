//! Classic libpcap format: 24-byte global header, then 16-byte record headers.
//!
//! Supported: microsecond (`a1b2c3d4`) and nanosecond (`a1b23c4d`) magics, both byte orders.
//! The `thiszone` field is ignored (always 0 in practice, and ignored by libpcap itself).

use bytes::Bytes;

use super::{Core, Endian, MAX_PACKET_LEN};
use crate::source::{CaptureError, CaptureInfo, PacketSource, RawPacket, ReadWarning};

const GLOBAL_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;
const NANOS_PER_SEC: i64 = 1_000_000_000;

pub(super) struct PcapReader {
    core: Core,
    endian: Endian,
    linktype: u32,
    /// Nanoseconds per unit of the fractional timestamp field (1000 for µs, 1 for ns).
    frac_scale: i64,
}

impl PcapReader {
    pub(super) fn open(mut core: Core) -> Result<Self, CaptureError> {
        let mut header = [0u8; GLOBAL_HEADER_LEN];
        if core.input.read_full(&mut header)? < GLOBAL_HEADER_LEN {
            return Err(core.malformed(0, "truncated pcap global header"));
        }
        let (endian, frac_scale) = match header.first_chunk::<4>() {
            Some([0xd4, 0xc3, 0xb2, 0xa1]) => (Endian::Little, 1000),
            Some([0xa1, 0xb2, 0xc3, 0xd4]) => (Endian::Big, 1000),
            Some([0x4d, 0x3c, 0xb2, 0xa1]) => (Endian::Little, 1),
            Some([0xa1, 0xb2, 0x3c, 0x4d]) => (Endian::Big, 1),
            _ => return Err(core.malformed(0, "invalid pcap magic")),
        };
        let (Some(snaplen), Some(network)) =
            (endian.u32_at(&header, 16), endian.u32_at(&header, 20))
        else {
            return Err(core.malformed(0, "truncated pcap global header"));
        };
        // Low 16 bits: link type; upper bits carry FCS information (ignored).
        let linktype = network & 0xffff;
        core.add_linktype(linktype);
        core.info.snaplen = Some(snaplen);
        Ok(Self {
            core,
            endian,
            linktype,
            frac_scale,
        })
    }
}

impl PacketSource for PcapReader {
    fn info(&self) -> &CaptureInfo {
        &self.core.info
    }

    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        loop {
            if self.core.done {
                return Ok(None);
            }
            let offset = self.core.input.pos;
            let mut header = [0u8; RECORD_HEADER_LEN];
            let n = self.core.input.read_full(&mut header)?;
            if n == 0 {
                self.core.end_of_stream(offset);
                return Ok(None);
            }
            if n < RECORD_HEADER_LEN {
                self.core.truncated(offset);
                return Ok(None);
            }
            let e = self.endian;
            let (Some(ts_sec), Some(ts_frac), Some(incl_len), Some(orig_len)) = (
                e.u32_at(&header, 0),
                e.u32_at(&header, 4),
                e.u32_at(&header, 8),
                e.u32_at(&header, 12),
            ) else {
                self.core.truncated(offset);
                return Ok(None);
            };
            if incl_len > MAX_PACKET_LEN {
                return Err(self.core.malformed(
                    offset,
                    format!("record length {incl_len} exceeds the {MAX_PACKET_LEN} byte limit"),
                ));
            }
            let len = usize::try_from(incl_len).unwrap_or(usize::MAX);
            let data = self.core.input.read_vec(len)?;
            if data.len() < len {
                self.core.truncated(offset);
                return Ok(None);
            }
            let Some(ts_ns) = i64::from(ts_sec)
                .checked_mul(NANOS_PER_SEC)
                .and_then(|s| s.checked_add(i64::from(ts_frac).checked_mul(self.frac_scale)?))
            else {
                self.core.warn(ReadWarning::SkippedRecord {
                    offset,
                    reason: "timestamp out of range".into(),
                });
                continue;
            };
            self.core.check_order(offset, ts_ns);
            return Ok(Some(RawPacket {
                ts_ns,
                chunk_id: 0,
                offset,
                linktype: self.linktype,
                orig_len,
                data: Bytes::from(data),
            }));
        }
    }

    fn bytes_read(&self) -> u64 {
        self.core.bytes_read()
    }

    fn warnings(&self) -> &[ReadWarning] {
        &self.core.warnings
    }
}
