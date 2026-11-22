//! Protocols of the Servers view: DHCP, NTP and Kerberos (`netsift_dissect::{dhcp, ntp,
//! kerberos}`), and SSDP (`netsift_analyze::ssdp::parser`), each parser run on the whole input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::dissect::{dhcp, kerberos, ntp};
use netsift_analyze::ssdp::parser as ssdp;

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
    // Never fails; every text field stays bounded.
    let m = ssdp::parse(data);
    assert!(m.raw.len() <= 3 * ssdp::MAX_RAW);
    assert!(m.server.as_ref().is_none_or(|s| s.len() <= ssdp::MAX_FIELD));
    let _ = m.device_type();
    // Kerberos over TCP: 4-byte record marker, then the message.
    if let Some(len) = kerberos::tcp_record_len(data)
        && let Some(msg) = data
            .get(4..)
            .and_then(|m| m.get(..m.len().min(len as usize)))
    {
        let _ = kerberos::parse(msg);
    }
});
