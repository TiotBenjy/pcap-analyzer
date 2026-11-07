//! NetBIOS over TCP/IP (RFC 1001/1002): name service (UDP/137), datagram service (UDP/138)
//! and the SMB browser `\MAILSLOT\BROWSE` announcements carried over it (MS-BRWS, MS-CIFS).

use std::net::Ipv4Addr;

/// NetBIOS suffix of a workstation service.
pub const SUFFIX_WORKSTATION: u8 = 0x00;
/// NetBIOS suffix of a file server service.
pub const SUFFIX_SERVER: u8 = 0x20;
/// NetBIOS suffix of the local master browser of a workgroup.
pub const SUFFIX_MASTER_BROWSER: u8 = 0x1d;
/// NetBIOS suffix of the browser election service of a workgroup.
pub const SUFFIX_BROWSER_ELECTION: u8 = 0x1e;

/// `SV_TYPE_WORKSTATION`.
pub const SV_TYPE_WORKSTATION: u32 = 0x0000_0001;
/// `SV_TYPE_SERVER`.
pub const SV_TYPE_SERVER: u32 = 0x0000_0002;
/// `SV_TYPE_PRINTQ_SERVER`.
pub const SV_TYPE_PRINTQ_SERVER: u32 = 0x0000_0200;
/// `SV_TYPE_NT`.
pub const SV_TYPE_NT: u32 = 0x0000_1000;
/// `SV_TYPE_POTENTIAL_BROWSER`.
pub const SV_TYPE_POTENTIAL_BROWSER: u32 = 0x0001_0000;
/// `SV_TYPE_MASTER_BROWSER`.
pub const SV_TYPE_MASTER_BROWSER: u32 = 0x0004_0000;

const NB_TYPE: u16 = 0x0020;
const CLASS_IN: u16 = 1;

/// A NetBIOS name: up to 15 characters plus a one-byte suffix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetbiosName {
    pub name: String,
    pub suffix: u8,
}

impl NetbiosName {
    pub fn new(name: impl Into<String>, suffix: u8) -> Self {
        Self {
            name: name.into(),
            suffix,
        }
    }

    /// Level-two encoded name (RFC 1001 14.1): length byte 32, the 32 half-ASCII characters,
    /// and the empty scope terminator.
    pub fn encode(&self) -> [u8; 34] {
        let mut raw = [b' '; 16];
        for (dst, src) in raw.iter_mut().zip(self.name.bytes().take(15)) {
            *dst = src.to_ascii_uppercase();
        }
        if let Some(last) = raw.last_mut() {
            *last = self.suffix;
        }
        let mut out = [0u8; 34];
        if let Some(first) = out.first_mut() {
            *first = 32;
        }
        for (i, b) in raw.iter().enumerate() {
            if let Some(slot) = out.get_mut(1 + 2 * i) {
                *slot = b'A' + (b >> 4);
            }
            if let Some(slot) = out.get_mut(2 + 2 * i) {
                *slot = b'A' + (b & 0x0f);
            }
        }
        out
    }
}

fn nbns_header(id: u16, flags: u16, qd: u16, an: u16, ar: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    for v in [id, flags, qd, an, 0, ar] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

fn push_nb_rdata(out: &mut Vec<u8>, ttl: u32, group: bool, addr: Ipv4Addr) {
    out.extend_from_slice(&NB_TYPE.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&6u16.to_be_bytes());
    let nb_flags: u16 = if group { 0x8000 } else { 0x0000 };
    out.extend_from_slice(&nb_flags.to_be_bytes());
    out.extend_from_slice(&addr.octets());
}

/// Broadcast name query (opcode 0, RD, B).
pub fn nbns_name_query(id: u16, name: &NetbiosName) -> Vec<u8> {
    let mut out = nbns_header(id, 0x0110, 1, 0, 0);
    out.extend_from_slice(&name.encode());
    out.extend_from_slice(&NB_TYPE.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// Positive name query response (R, AA, RD) giving `addr` for `name`.
pub fn nbns_name_query_response(id: u16, name: &NetbiosName, ttl: u32, addr: Ipv4Addr) -> Vec<u8> {
    let mut out = nbns_header(id, 0x8500, 0, 1, 0);
    out.extend_from_slice(&name.encode());
    push_nb_rdata(&mut out, ttl, false, addr);
    out
}

/// Broadcast name registration request (opcode 5, RD, B) for `name` -> `addr`.
pub fn nbns_name_registration(
    id: u16,
    name: &NetbiosName,
    ttl: u32,
    addr: Ipv4Addr,
    group: bool,
) -> Vec<u8> {
    let mut out = nbns_header(id, 0x2910, 1, 0, 1);
    out.extend_from_slice(&name.encode());
    out.extend_from_slice(&NB_TYPE.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&[0xc0, 0x0c]);
    push_nb_rdata(&mut out, ttl, group, addr);
    out
}

/// NetBIOS `DIRECT_GROUP` datagram (type 0x11, first fragment, B-node).
pub fn netbios_group_datagram(
    dgm_id: u16,
    source_ip: Ipv4Addr,
    source: &NetbiosName,
    destination: &NetbiosName,
    user_data: &[u8],
) -> Vec<u8> {
    let mut out = vec![0x11, 0x02];
    out.extend_from_slice(&dgm_id.to_be_bytes());
    out.extend_from_slice(&source_ip.octets());
    out.extend_from_slice(&138u16.to_be_bytes());
    let length = u16::try_from(34 + 34 + user_data.len()).expect("datagram fits in u16");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // packet offset
    out.extend_from_slice(&source.encode());
    out.extend_from_slice(&destination.encode());
    out.extend_from_slice(user_data);
    out
}

/// SMB1 `SMB_COM_TRANSACTION` request writing `data` to the mailslot `\MAILSLOT\BROWSE`.
pub fn smb_mailslot_browse(data: &[u8]) -> Vec<u8> {
    const MAILSLOT: &[u8] = b"\\MAILSLOT\\BROWSE\0";
    // 32-byte header + word count + 17 words + byte count.
    const DATA_OFFSET: u16 = 32 + 1 + 34 + 2 + 17;
    let data_len = u16::try_from(data.len()).expect("mailslot data fits in u16");

    let mut out = Vec::with_capacity(usize::from(DATA_OFFSET) + data.len());
    out.extend_from_slice(b"\xffSMB");
    out.push(0x25); // SMB_COM_TRANSACTION
    out.extend_from_slice(&[0; 4]); // status
    out.push(0); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // flags2
    out.extend_from_slice(&[0; 12]); // pid high, security features, reserved
    out.extend_from_slice(&[0; 8]); // tid, pid low, uid, mid

    out.push(17); // word count
    for word in [0u16, data_len, 0, 0] {
        out.extend_from_slice(&word.to_le_bytes()); // total param/data, max param/data
    }
    out.extend_from_slice(&[0, 0]); // max setup count, reserved
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u32.to_le_bytes()); // timeout
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    for word in [0u16, DATA_OFFSET, data_len, DATA_OFFSET] {
        out.extend_from_slice(&word.to_le_bytes()); // param count/offset, data count/offset
    }
    out.extend_from_slice(&[3, 0]); // setup count, reserved
    for word in [1u16, 1, 2] {
        out.extend_from_slice(&word.to_le_bytes()); // mailslot write, priority, class 2
    }
    let byte_count = u16::try_from(MAILSLOT.len() + data.len()).expect("byte count fits in u16");
    out.extend_from_slice(&byte_count.to_le_bytes());
    out.extend_from_slice(MAILSLOT);
    out.extend_from_slice(data);
    out
}

/// Browser announcement kind (MS-BRWS 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnnouncementKind {
    /// `HostAnnouncement` (opcode 1), sent to `<workgroup><1D>`.
    Host,
    /// `LocalMasterAnnouncement` (opcode 15), sent to `<workgroup><1E>`.
    LocalMaster,
}

/// Content of a browser announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAnnouncement {
    pub kind: AnnouncementKind,
    pub server_name: String,
    pub workgroup: String,
    pub os_major: u8,
    pub os_minor: u8,
    /// `SV_TYPE_*` flags.
    pub server_type: u32,
    pub comment: String,
    pub periodicity_ms: u32,
    pub update_count: u8,
}

impl Default for HostAnnouncement {
    fn default() -> Self {
        Self {
            kind: AnnouncementKind::Host,
            server_name: "FILESRV01".to_owned(),
            workgroup: "WORKGROUP".to_owned(),
            os_major: 10,
            os_minor: 0,
            server_type: SV_TYPE_WORKSTATION
                | SV_TYPE_SERVER
                | SV_TYPE_PRINTQ_SERVER
                | SV_TYPE_NT
                | SV_TYPE_POTENTIAL_BROWSER,
            comment: "Synthetic file server".to_owned(),
            periodicity_ms: 720_000,
            update_count: 0,
        }
    }
}

impl HostAnnouncement {
    /// Browser frame (the mailslot payload).
    pub fn encode(&self) -> Vec<u8> {
        let opcode = match self.kind {
            AnnouncementKind::Host => 0x01,
            AnnouncementKind::LocalMaster => 0x0f,
        };
        let mut out = vec![opcode, self.update_count];
        out.extend_from_slice(&self.periodicity_ms.to_le_bytes());
        let mut name = [0u8; 16];
        for (dst, src) in name.iter_mut().zip(self.server_name.bytes().take(15)) {
            *dst = src.to_ascii_uppercase();
        }
        out.extend_from_slice(&name);
        out.extend_from_slice(&[self.os_major, self.os_minor]);
        out.extend_from_slice(&self.server_type.to_le_bytes());
        out.extend_from_slice(&[15, 1]); // browser protocol version
        out.extend_from_slice(&0xaa55u16.to_le_bytes());
        out.extend_from_slice(self.comment.as_bytes());
        out.push(0);
        out
    }

    /// NetBIOS name the announcement is addressed to.
    pub fn destination(&self) -> NetbiosName {
        let suffix = match self.kind {
            AnnouncementKind::Host => SUFFIX_MASTER_BROWSER,
            AnnouncementKind::LocalMaster => SUFFIX_BROWSER_ELECTION,
        };
        NetbiosName::new(self.workgroup.clone(), suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_level_encoding() {
        // RFC 1001 example: "FRED" padded with spaces, suffix 0x20 (space).
        let enc = NetbiosName::new("fred", 0x20).encode();
        assert_eq!(&enc[..1], &[32]);
        assert_eq!(&enc[1..33], b"EGFCEFEECACACACACACACACACACACACA");
        assert_eq!(enc[33], 0);
    }

    #[test]
    fn mailslot_layout() {
        let smb = smb_mailslot_browse(&[1, 2, 3]);
        assert_eq!(&smb[..4], b"\xffSMB");
        assert_eq!(&smb[69..86], b"\\MAILSLOT\\BROWSE\0");
        assert_eq!(&smb[86..], &[1, 2, 3]);
    }
}
