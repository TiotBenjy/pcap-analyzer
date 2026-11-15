//! SMB1 / SMB2 PDUs over NBSS and NetBIOS browser datagrams (`smb::message`, `smb::browser`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| netsift_analyze::fuzz::smb(data));
