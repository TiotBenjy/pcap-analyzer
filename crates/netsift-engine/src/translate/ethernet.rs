//! Translation of the `ethernet` analyzer's records into `eth_macs`, `eth_pairs`, `eth_types`
//! and `eth_vlans` rows.

use netsift_analyze::ethernet::{EthernetRecord, Volume};
use netsift_analyze::oui;
use netsift_store::ethernet::{EthMacRow, EthPairRow, EthVlanRow, EthVolume, EthernetRow};

fn volume(v: Volume) -> EthVolume {
    EthVolume {
        frames: v.frames,
        bytes: v.bytes,
        first_ts: v.first_ts,
        last_ts: v.last_ts,
    }
}

pub(super) fn ethernet_row(record: EthernetRecord) -> EthernetRow {
    match record {
        EthernetRecord::Mac(m) => {
            let class = oui::classify(m.mac);
            EthernetRow::Mac(EthMacRow {
                mac: m.mac,
                vendor: m.vendor.map(str::to_owned),
                registry: m.registry.map(|r| r.as_str().to_owned()),
                kind: class.kind.as_str().to_owned(),
                local: class.local,
                group: class.group.map(|g| g.as_str().to_owned()),
                frames_sent: m.frames_sent,
                bytes_sent: m.bytes_sent,
                frames_received: m.frames_received,
                bytes_received: m.bytes_received,
                first_ts: m.first_ts,
                last_ts: m.last_ts,
                vlans: m.vlans.iter().map(ToString::to_string).collect(),
            })
        }
        EthernetRecord::Pair(p) => EthernetRow::Pair(EthPairRow {
            src: p.src,
            dst: p.dst,
            frames: p.frames,
            bytes: p.bytes,
            first_ts: p.first_ts,
            last_ts: p.last_ts,
            ethertypes: p.ethertypes.iter().map(|k| k.0).collect(),
            vlans: p.vlans.iter().map(ToString::to_string).collect(),
        }),
        EthernetRecord::EtherType(key, v) => EthernetRow::Type(key.0, volume(v)),
        EthernetRecord::Vlan(stack, outer_tpid, v) => EthernetRow::Vlan(EthVlanRow {
            ids: stack.ids().to_vec(),
            outer_tpid,
            volume: volume(v),
        }),
    }
}
