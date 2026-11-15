//! NTLMSSP messages and hashcat lines (`smb::ntlmssp`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| netsift_analyze::fuzz::ntlmssp(data));
