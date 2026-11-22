//! Translation of the `ssdp` analyzer's records into `ssdp_messages` rows (folded into
//! `ssdp_devices` by the store).

use netsift_analyze::ssdp::SsdpRecord;
use netsift_store::ssdp::SsdpRow;

pub(super) fn ssdp_row(r: SsdpRecord) -> SsdpRow {
    let device_type = r.message.device_type().map(str::to_owned);
    let m = r.message;
    SsdpRow {
        ts: r.ts,
        src_ip: r.src.ip,
        src_port: r.src.port,
        dst_ip: r.dst.ip,
        dst_port: r.dst.port,
        multicast: r.multicast,
        kind: m.kind.as_str().to_owned(),
        nts: m.nts,
        status: m.status,
        target: m.target,
        usn: m.usn,
        uuid: m.uuid,
        server: m.server,
        user_agent: m.user_agent,
        location: m.location,
        max_age: m.max_age,
        mx: m.mx,
        size: u64::try_from(m.size).unwrap_or(u64::MAX),
        raw: m.raw,
        raw_truncated: m.raw_truncated,
        device_type,
    }
}
