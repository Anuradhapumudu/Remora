//! Arbitrary bytes into every message decoder: no panic, ever.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_proto::messages::{decode_envelope, decode_host_hello, decode_viewer_hello};

fuzz_target!(|data: &[u8]| {
    let _ = decode_viewer_hello(data);
    let _ = decode_host_hello(data);
    let _ = decode_envelope(data);
});
