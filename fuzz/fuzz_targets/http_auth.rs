//! HTTP credentials (`http::auth`): Basic, NTLM / Negotiate, forms and query strings.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = netsift_analyze::fuzz::http_auth(data);
});
