//! Protocols of the Servers view: DHCP, NTP and Kerberos (`netsift_dissect::{dhcp, ntp,
//! kerberos}`), each parser run on the whole input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::dissect::{dhcp, kerberos, ntp};

fuzz_target!(|data: &[u8]| {
    if let Some(m) = dhcp::parse(data) {
        let _ = m.client_mac();
        let _ = format!("{m:?}");
    }
    if let Some(h) = ntp::parse(data) {
        let _ = h.reference(false);
        let _ = h.reference(true);
    }
    if let Some(m) = kerberos::parse(data) {
        let _ = format!("{m:?}");
    }
    // Kerberos over TCP: 4-byte record marker, then the message.
    if let Some(len) = kerberos::tcp_record_len(data)
        && let Some(msg) = data
            .get(4..)
            .and_then(|m| m.get(..m.len().min(len as usize)))
    {
        let _ = kerberos::parse(msg);
    }
});
