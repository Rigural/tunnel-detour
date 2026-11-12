//! Full-size API documents are separate from the mixed DNS-sized corpus.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Err(error) = tunnel_detour_service::fuzz_adguard_api_response(bytes) {
        panic!("API parser oracle failed: {error}");
    }
});
