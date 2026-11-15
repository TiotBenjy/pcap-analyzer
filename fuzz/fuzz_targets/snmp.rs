//! SNMP v1 / v2c communities (`credentials::snmp`, over `snmp-parser`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| netsift_analyze::fuzz::snmp(data));
