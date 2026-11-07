//! Radiotap pseudo-header and IEEE 802.11 MAC header.

use crate::bytes::{le16, le32, split, u8_at};
use crate::decoded::{Decoded, MacAddr, RadiotapInfo, WifiFrameType, WifiInfo};
use crate::error::{DecodeError, Layer};
use crate::link;

/// Radiotap "Flags" field bits.
const RT_FLAG_FCS: u8 = 0x10;
const RT_FLAG_DATA_PAD: u8 = 0x20;
const RT_FLAG_BAD_FCS: u8 = 0x40;
/// Presence bitmap: another bitmap word follows.
const RT_PRESENT_EXT: u32 = 0x8000_0000;
/// Upper bound on chained presence bitmap words.
const RT_MAX_PRESENT_WORDS: usize = 16;

/// 802.11 frame control flag bits (second byte).
const FC_TO_DS: u8 = 0x01;
const FC_FROM_DS: u8 = 0x02;
const FC_MORE_FRAG: u8 = 0x04;
const FC_RETRY: u8 = 0x08;
const FC_PROTECTED: u8 = 0x40;
const FC_ORDER: u8 = 0x80;

/// Data subtype bits.
const DATA_SUBTYPE_QOS: u8 = 0x08;
const DATA_SUBTYPE_NO_DATA: u8 = 0x04;

/// Radiotap header followed by an 802.11 frame (FCS stripped when flagged).
pub(crate) fn radiotap<'a>(d: &mut Decoded<'a>, data: &'a [u8]) -> Result<(), DecodeError> {
    if data.len() < 8 {
        return Err(DecodeError::truncated(Layer::Radiotap, 8, data.len()));
    }
    if u8_at(data, 0) != Some(0) {
        return Err(DecodeError::malformed(
            Layer::Radiotap,
            "unsupported version",
        ));
    }
    let it_len = le16(data, 2).unwrap_or_default();
    if it_len < 8 {
        return Err(DecodeError::malformed(
            Layer::Radiotap,
            "header length below 8",
        ));
    }
    let (hdr, frame) = split(data, usize::from(it_len), Layer::Radiotap)?;
    let (info, flags) = radiotap_fields(hdr, it_len);
    d.link.radiotap = Some(info);
    d.payload = frame;
    let frame = if info.fcs_present {
        let n = frame.len().checked_sub(4).ok_or(DecodeError::truncated(
            Layer::Ieee80211,
            4,
            frame.len(),
        ))?;
        frame.get(..n).unwrap_or_default()
    } else {
        frame
    };
    d.payload = frame;
    ieee80211(d, frame, flags & RT_FLAG_DATA_PAD != 0)
}

/// Reserves a field of `size` bytes aligned on `align` (relative to the header start).
fn rt_field(cursor: &mut usize, align: usize, size: usize, hdr_len: usize) -> Option<usize> {
    let start = cursor.checked_next_multiple_of(align)?;
    let end = start.checked_add(size)?;
    if end > hdr_len {
        return None;
    }
    *cursor = end;
    Some(start)
}

/// Best-effort extraction of the first standard radiotap fields (TSFT, Flags, Rate,
/// Channel, FHSS, antenna signal). Returns the info and the raw Flags byte.
fn radiotap_fields(hdr: &[u8], it_len: u16) -> (RadiotapInfo, u8) {
    let mut info = RadiotapInfo {
        header_len: it_len,
        fcs_present: false,
        bad_fcs: false,
        channel_mhz: None,
        signal_dbm: None,
    };
    let Some(present) = le32(hdr, 4) else {
        return (info, 0);
    };
    // Skip chained presence words; fields start after the last one.
    let mut cursor = 8usize;
    let mut word = present;
    let mut words = 1usize;
    while word & RT_PRESENT_EXT != 0 {
        if words >= RT_MAX_PRESENT_WORDS {
            return (info, 0);
        }
        let Some(next) = le32(hdr, cursor) else {
            return (info, 0);
        };
        word = next;
        cursor = cursor.saturating_add(4);
        words = words.saturating_add(1);
    }
    let len = hdr.len();
    let mut flags = 0u8;
    // Field layout per the radiotap specification (bit: alignment, size).
    let fields: [(u32, usize, usize); 6] = [
        (0x01, 8, 8), // TSFT
        (0x02, 1, 1), // Flags
        (0x04, 1, 1), // Rate
        (0x08, 2, 4), // Channel: frequency, flags
        (0x10, 1, 2), // FHSS
        (0x20, 1, 1), // Antenna signal (dBm)
    ];
    for (bit, align, size) in fields {
        if present & bit == 0 {
            continue;
        }
        let Some(off) = rt_field(&mut cursor, align, size, len) else {
            break;
        };
        match bit {
            0x02 => flags = u8_at(hdr, off).unwrap_or_default(),
            0x08 => info.channel_mhz = le16(hdr, off),
            0x20 => info.signal_dbm = u8_at(hdr, off).map(|b| i8::from_le_bytes([b])),
            _ => {}
        }
    }
    info.fcs_present = flags & RT_FLAG_FCS != 0;
    info.bad_fcs = flags & RT_FLAG_BAD_FCS != 0;
    (info, flags)
}

fn mac_at(frame: &[u8], off: usize) -> Option<MacAddr> {
    frame.get(off..).and_then(MacAddr::from_slice)
}

/// Control subtypes whose header carries a transmitter address (addr2).
const fn control_has_ta(subtype: u8) -> bool {
    matches!(subtype, 4 | 5 | 8 | 9 | 10 | 11 | 14 | 15)
}

/// IEEE 802.11 MAC frame (without FCS). `data_pad`: radiotap says the header is padded
/// to a multiple of 4 bytes.
pub(crate) fn ieee80211<'a>(
    d: &mut Decoded<'a>,
    frame: &'a [u8],
    data_pad: bool,
) -> Result<(), DecodeError> {
    let (Some(fc0), Some(fc1)) = (u8_at(frame, 0), u8_at(frame, 1)) else {
        return Err(DecodeError::truncated(Layer::Ieee80211, 10, frame.len()));
    };
    if fc0 & 0x03 != 0 {
        return Err(DecodeError::malformed(
            Layer::Ieee80211,
            "unsupported protocol version",
        ));
    }
    let frame_type = match (fc0 >> 2) & 0x03 {
        0 => WifiFrameType::Management,
        1 => WifiFrameType::Control,
        2 => WifiFrameType::Data,
        _ => WifiFrameType::Extension,
    };
    let subtype = fc0 >> 4;
    let mut w = WifiInfo {
        frame_type,
        subtype,
        to_ds: fc1 & FC_TO_DS != 0,
        from_ds: fc1 & FC_FROM_DS != 0,
        more_fragments: fc1 & FC_MORE_FRAG != 0,
        retry: fc1 & FC_RETRY != 0,
        protected: fc1 & FC_PROTECTED != 0,
        addr1: mac_at(frame, 4),
        addr2: None,
        addr3: None,
        addr4: None,
        bssid: None,
        sequence: None,
        fragment: None,
        qos_tid: None,
        amsdu: false,
    };
    let order = fc1 & FC_ORDER != 0;
    let hdr_len = header_len(frame, &mut w, order, data_pad);
    let (da, sa) = derive_addresses(&mut w);
    d.link.wifi = Some(w);
    d.link.dst_mac = da;
    d.link.src_mac = sa;
    let hdr_len = hdr_len?;
    let (_, body) = split(frame, hdr_len, Layer::Ieee80211)?;
    d.payload = body;
    if frame_type != WifiFrameType::Data
        || subtype & DATA_SUBTYPE_NO_DATA != 0
        || w.protected
        || w.amsdu
    {
        return Ok(());
    }
    link::llc(d, body)
}

/// Computes the MAC header length and fills the address / sequence / `QoS` fields that
/// fit in `frame`. Returns a truncation error if the header does not fit.
fn header_len(
    frame: &[u8],
    w: &mut WifiInfo,
    order: bool,
    data_pad: bool,
) -> Result<usize, DecodeError> {
    let truncated = |needed: usize| DecodeError::truncated(Layer::Ieee80211, needed, frame.len());
    match w.frame_type {
        WifiFrameType::Control => {
            let len = if control_has_ta(w.subtype) {
                w.addr2 = mac_at(frame, 10);
                16
            } else {
                10
            };
            if frame.len() < len {
                return Err(truncated(len));
            }
            Ok(len)
        }
        WifiFrameType::Extension => {
            w.addr1 = None;
            Ok(2)
        }
        WifiFrameType::Management | WifiFrameType::Data => {
            w.addr2 = mac_at(frame, 10);
            w.addr3 = mac_at(frame, 16);
            if let Some(sc) = le16(frame, 22) {
                w.sequence = Some(sc >> 4);
                w.fragment = u8::try_from(sc & 0x0f).ok();
            }
            let mut len = 24usize;
            if w.frame_type == WifiFrameType::Data {
                if w.to_ds && w.from_ds {
                    w.addr4 = mac_at(frame, 24);
                    len = 30;
                }
                if w.subtype & DATA_SUBTYPE_QOS != 0 {
                    if let Some(qos) = le16(frame, len) {
                        w.qos_tid = u8::try_from(qos & 0x0f).ok();
                        w.amsdu = qos & 0x0080 != 0;
                    }
                    len = len.saturating_add(2);
                    if order {
                        len = len.saturating_add(4);
                    }
                }
            } else if order {
                len = len.saturating_add(4);
            }
            if data_pad {
                len = len.checked_next_multiple_of(4).unwrap_or(len);
            }
            if frame.len() < len {
                return Err(truncated(len));
            }
            Ok(len)
        }
    }
}

/// Derives (destination, source) and the BSSID from the To/From DS bits.
fn derive_addresses(w: &mut WifiInfo) -> (Option<MacAddr>, Option<MacAddr>) {
    match w.frame_type {
        WifiFrameType::Control | WifiFrameType::Extension => (w.addr1, w.addr2),
        WifiFrameType::Management => {
            w.bssid = w.addr3;
            (w.addr1, w.addr2)
        }
        WifiFrameType::Data => match (w.to_ds, w.from_ds) {
            (false, false) => {
                w.bssid = w.addr3;
                (w.addr1, w.addr2)
            }
            (true, false) => {
                w.bssid = w.addr1;
                (w.addr3, w.addr2)
            }
            (false, true) => {
                w.bssid = w.addr2;
                (w.addr1, w.addr3)
            }
            (true, true) => (w.addr3, w.addr4),
        },
    }
}
