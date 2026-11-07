//! Helpers shared by the integration tests.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};

use netsift_store::{FlowRow, HostRow, TimeseriesRow};

pub fn flow(id: u64, first_ts: i64, bytes: u64) -> FlowRow {
    FlowRow {
        id,
        transport: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 40_000,
        dst_ip: "2001:db8::1".parse().unwrap(),
        dst_port: 443,
        first_ts,
        last_ts: first_ts + 1_000,
        bytes_fwd: bytes,
        bytes_rev: 0,
        packets_fwd: 1,
        packets_rev: 0,
        app_proto: Some("tls".into()),
        tcp_state: Some("established".into()),
    }
}

pub fn host(ip: &str, first_ts: i64, last_ts: i64) -> HostRow {
    HostRow {
        ip: ip.parse().unwrap(),
        macs: Vec::new(),
        names: Vec::new(),
        country: None,
        category: None,
        first_ts,
        last_ts,
    }
}

pub fn ts(bucket_s: i64, proto: &str, bytes: u64, packets: u64) -> TimeseriesRow {
    TimeseriesRow {
        bucket_s,
        proto: proto.into(),
        bytes,
        packets,
    }
}
