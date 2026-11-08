//! NetBIOS datagram service (UDP 138) and the SMB `\MAILSLOT\BROWSE` browser announcements it
//! carries (RFC 1001/1002, MS-BRWS, MS-CIFS). Parsing only: no allocation is sized from an
//! unchecked length, and every read is bounds-checked.

use super::bytes::{find, le16, le32, slice, u8_at};
use crate::record::AnnouncementKind;

/// NetBIOS datagram types that carry user data (RFC 1002 4.4.1).
const DIRECT_UNIQUE: u8 = 0x10;
const DIRECT_GROUP: u8 = 0x11;
const BROADCAST: u8 = 0x12;

/// Fixed length of a level-two encoded NetBIOS name with an empty scope (RFC 1001 14.1).
const ENCODED_NAME_LEN: usize = 34;

/// Longest browser user data we scan (bounds the mailslot/signature search).
const MAX_SCAN: usize = 2048;

/// A decoded NetBIOS name: up to 15 characters plus a one-byte service suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetbiosName {
    pub name: String,
    pub suffix: u8,
}

impl NetbiosName {
    /// `NAME<XX>` where `XX` is the suffix in upper-case hex.
    pub fn display(&self) -> String {
        format!("{}<{:02X}>", self.name, self.suffix)
    }
}

/// Decodes a level-two NetBIOS name at the start of `data`, returning it and the number of bytes
/// consumed (name field plus scope). `None` when truncated or not a 32-byte encoded name.
fn decode_name(data: &[u8]) -> Option<(NetbiosName, usize)> {
    if u8_at(data, 0)? != 0x20 {
        return None;
    }
    let encoded = slice(data, 1, 32)?;
    let mut raw = [0u8; 16];
    for (i, slot) in raw.iter_mut().enumerate() {
        let hi = u8_at(encoded, 2 * i)?.wrapping_sub(b'A');
        let lo = u8_at(encoded, 2 * i + 1)?.wrapping_sub(b'A');
        *slot = (hi << 4) | (lo & 0x0f);
    }
    let suffix = raw[15];
    let name: String = raw[..15]
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect::<String>()
        .trim_end()
        .to_owned();
    // Skip the scope: labels until a zero-length label (bounded).
    let mut pos = 33;
    let mut guard = 0;
    while guard < 64 {
        let len = usize::from(u8_at(data, pos)?);
        pos = pos.checked_add(1)?;
        if len == 0 {
            break;
        }
        pos = pos.checked_add(len)?;
        guard += 1;
    }
    Some((NetbiosName { name, suffix }, pos))
}

/// Parsed browser announcement (MS-BRWS 2.2) plus its NetBIOS destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub kind: AnnouncementKind,
    pub server_name: String,
    pub destination: NetbiosName,
    pub os_major: u8,
    pub os_minor: u8,
    pub server_type: u32,
    pub comment: String,
}

/// Parses a UDP/138 payload into a browser announcement, when it is one.
pub fn parse_datagram(payload: &[u8]) -> Option<Announcement> {
    let msg_type = u8_at(payload, 0)?;
    if !matches!(msg_type, DIRECT_UNIQUE | DIRECT_GROUP | BROADCAST) {
        return None;
    }
    // Header is 14 bytes, then the source and destination names, then the user data (SMB).
    let (_source, src_len) = decode_name(slice(payload, 14, payload.len().saturating_sub(14))?)?;
    let dest_off = 14_usize.checked_add(src_len)?;
    let (destination, dst_len) = decode_name(payload.get(dest_off..)?)?;
    let user_off = dest_off.checked_add(dst_len)?;
    let user_data = payload.get(user_off..)?;
    let browser = extract_browser_frame(user_data)?;
    let (kind, server_name, os_major, os_minor, server_type, comment) = parse_browser(browser)?;
    Some(Announcement {
        kind,
        server_name,
        destination,
        os_major,
        os_minor,
        server_type,
        comment,
    })
}

/// Follows the SMB1 `SMB_COM_TRANSACTION` (`\MAILSLOT\BROWSE`) to its data bytes, falling back to
/// the bytes right after the mailslot name.
fn extract_browser_frame(smb: &[u8]) -> Option<&[u8]> {
    // SMB1 header: "\xffSMB" then command byte.
    if slice(smb, 0, 4)? != b"\xffSMB" || u8_at(smb, 4)? != 0x25 {
        return None;
    }
    let mailslot = find(smb, b"\\MAILSLOT\\BROWSE\0", MAX_SCAN)?;
    // Preferred: DataOffset (byte 57) / DataCount (byte 55), both from the SMB header start.
    if let (Some(count), Some(offset)) = (le16(smb, 55), le16(smb, 57))
        && let Some(data) = slice(smb, usize::from(offset), usize::from(count))
        && usize::from(offset) >= mailslot
    {
        return Some(data);
    }
    // Fallback: just after the mailslot name.
    smb.get(mailslot + b"\\MAILSLOT\\BROWSE\0".len()..)
}

/// Decodes the browser frame body (opcode, version, server type, comment).
fn parse_browser(frame: &[u8]) -> Option<(AnnouncementKind, String, u8, u8, u32, String)> {
    let kind = match u8_at(frame, 0)? {
        0x01 => AnnouncementKind::Host,
        0x0c => AnnouncementKind::Domain,
        0x0f => AnnouncementKind::LocalMaster,
        _ => return None,
    };
    let server_name = ascii_z(slice(frame, 6, 16)?);
    let os_major = u8_at(frame, 22)?;
    let os_minor = u8_at(frame, 23)?;
    let server_type = le32(frame, 24)?;
    let comment = ascii_z(frame.get(32..)?);
    Some((kind, server_name, os_major, os_minor, server_type, comment))
}

/// ASCII up to the first NUL, trailing spaces trimmed.
fn ascii_z(data: &[u8]) -> String {
    data.iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// Smallest UDP/138 payload that could hold a datagram header and two empty-scope names.
pub const MIN_DATAGRAM_LEN: usize = 14 + ENCODED_NAME_LEN + ENCODED_NAME_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use netsift_fixtures::proto::netbios::{
        self, HostAnnouncement, NetbiosName as FxName, SUFFIX_WORKSTATION,
    };

    fn datagram(ann: &HostAnnouncement, src: [u8; 4]) -> Vec<u8> {
        let smb = netbios::smb_mailslot_browse(&ann.encode());
        let source = FxName::new(ann.server_name.clone(), SUFFIX_WORKSTATION);
        netbios::netbios_group_datagram(1, src.into(), &source, &ann.destination(), &smb)
    }

    #[test]
    fn parses_a_host_announcement() {
        let ann = HostAnnouncement::default();
        let payload = datagram(&ann, [192, 168, 1, 50]);
        let parsed = parse_datagram(&payload).expect("announcement");
        assert_eq!(parsed.kind, AnnouncementKind::Host);
        assert_eq!(parsed.server_name, "FILESRV01");
        assert_eq!(parsed.destination.name, "WORKGROUP");
        assert_eq!(parsed.destination.suffix, netbios::SUFFIX_MASTER_BROWSER);
        assert_eq!((parsed.os_major, parsed.os_minor), (10, 0));
        assert_eq!(parsed.server_type, ann.server_type);
        assert_eq!(parsed.comment, "Synthetic file server");
    }

    #[test]
    fn rejects_truncated_and_non_datagrams() {
        let ann = HostAnnouncement::default();
        let full = datagram(&ann, [10, 0, 0, 1]);
        for n in 0..full.len() {
            // Must never panic, and never fabricate an announcement from a short buffer.
            let _ = parse_datagram(&full[..n]);
        }
        assert!(parse_datagram(&[]).is_none());
        assert!(parse_datagram(&[0xff; 4]).is_none());
    }
}
