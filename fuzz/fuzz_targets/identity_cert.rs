//! Arbitrary bytes into the IdentityCert parser and verifier: no panic; a
//! parsed cert re-encodes to exactly the bytes it came from.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_crypto::identity::IdentityCert;

fuzz_target!(|data: &[u8]| {
    if let Ok(cert) = IdentityCert::decode(data) {
        assert_eq!(cert.encode(), data);
        let _ = cert.verify();
    }
});
