//! Country database (`netsift_geo`, over `maxminddb`): a `.mmdb` or `.mmdb.gz` file as given by
//! the user, decoded and queried. The first 16 bytes double as a looked-up IPv6 address.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use netsift_geo::{GeoDb, decode_database};

fuzz_target!(|data: &[u8]| {
    let Ok(bytes) = decode_database(data.to_vec()) else {
        return;
    };
    let Ok(db) = GeoDb::with_cache_capacity(bytes, 16) else {
        return;
    };
    let _ = (db.database_type().len(), db.build_epoch());
    let mut probes = vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(81, 2, 69, 142)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        IpAddr::V6(
            "2001:4860:4860::8888"
                .parse()
                .unwrap_or(Ipv6Addr::LOCALHOST),
        ),
    ];
    if let Some(raw) = data.get(..16).and_then(|b| <[u8; 16]>::try_from(b).ok()) {
        probes.push(IpAddr::V6(Ipv6Addr::from(raw)));
        if let Some(v4) = data.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) {
            probes.push(IpAddr::V4(Ipv4Addr::from(v4)));
        }
    }
    for ip in probes {
        let _ = db.country(ip);
    }
});
