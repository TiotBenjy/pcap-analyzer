//! Translation of the `servers` analyzer's records into `dhcp_messages`, `ntp_responses` and
//! `kerberos_replies` rows.

use netsift_analyze::servers::{DhcpSeen, ServerRecord};
use netsift_store::servers::{DhcpRow, KerberosRow, NtpRow, ServerRow};

pub(super) fn server_row(record: ServerRecord) -> ServerRow {
    match record {
        ServerRecord::Dhcp(d) => ServerRow::Dhcp(Box::new(dhcp_row(*d))),
        ServerRecord::Ntp(n) => ServerRow::Ntp(NtpRow {
            ts: n.ts,
            server_ip: n.server,
            client_ip: n.client,
            version: n.version,
            stratum: n.stratum,
            reference: n.reference,
        }),
        ServerRecord::Kerberos(k) => ServerRow::Kerberos(KerberosRow {
            ts: k.ts,
            server_ip: k.server,
            client_ip: k.client,
            kind: k.kind.as_str().to_owned(),
            realm: k.realm,
            error_code: k.error_code,
        }),
    }
}

fn dhcp_row(d: DhcpSeen) -> DhcpRow {
    DhcpRow {
        ts: d.ts,
        src_ip: d.src_ip,
        dst_ip: d.dst_ip,
        op: d.op,
        msg_type: d.message_type.map(str::to_owned),
        xid: d.xid,
        client_mac: d.client_mac,
        ciaddr: d.ciaddr,
        yiaddr: d.yiaddr,
        siaddr: d.siaddr,
        giaddr: d.giaddr,
        server_id: d.server_id,
        requested_ip: d.requested_ip,
        subnet_mask: d.subnet_mask,
        routers: d.routers,
        dns_servers: d.dns_servers,
        lease_s: d.lease_s,
        hostname: d.hostname,
    }
}
