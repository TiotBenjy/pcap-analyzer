//! Protocols of the Servers view: DHCP, NTP and Kerberos (`netsift_dissect::{dhcp, ntp,
//! kerberos}`), SSDP (`netsift_analyze::ssdp::parser`) and SIP with its SDP body
//! (`netsift_dissect::{sip, sdp}`, datagram and TCP framing), each parser run on the whole input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_analyze::dissect::{dhcp, kerberos, ntp, sdp, sip};
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
    // SIP: a datagram, then the same bytes framed as a TCP stream; every field stays bounded.
    if let Some(m) = sip::parse(data) {
        assert!(m.raw.len() <= 3 * sip::MAX_RAW);
        assert!(
            m.call_id
                .as_ref()
                .is_none_or(|c| c.len() <= sip::MAX_CALL_ID)
        );
        let _ = (m.method(), m.status(), m.software());
        if let Some(s) = &m.sdp {
            assert!(s.media.len() <= sdp::MAX_MEDIA);
            assert!(s.media.iter().all(|x| x.codecs.len() <= sdp::MAX_CODECS));
        }
    }
    let mut stream = data;
    for _ in 0..8 {
        stream = stream.get(sip::keepalive_len(stream)..).unwrap_or_default();
        match sip::message_len(stream) {
            Ok(Some(n)) if n > 0 => {
                assert!(n <= sip::MAX_MESSAGE);
                let _ = sip::parse(stream.get(..n).unwrap_or_default());
                stream = stream.get(n..).unwrap_or_default();
            }
            _ => break,
        }
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
