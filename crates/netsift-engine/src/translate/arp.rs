//! Translation of the `arp` analyzer records.

use netsift_analyze::arp::ArpMessage;
use netsift_store::arp::ArpRow;

pub(super) fn arp_row(m: ArpMessage) -> ArpRow {
    ArpRow {
        ts: m.ts_ns,
        frame: m.frame,
        operation: m.operation,
        kind: m.kind.as_str(),
        sender_mac: m.sender_mac,
        sender_ip: m.sender_ip,
        target_mac: m.target_mac,
        target_ip: m.target_ip,
        unsolicited: m.unsolicited,
        binds: m.binds,
    }
}
