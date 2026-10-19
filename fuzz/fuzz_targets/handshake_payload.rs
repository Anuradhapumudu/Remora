//! Arbitrary bytes into the decrypted msg2/msg3 payload parser (cert ‖ C_r
//! or cert ‖ n_i): no panic; accepted payloads are exactly cert ‖ 32 bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_crypto::noise::decode_handshake_payload;

fuzz_target!(|data: &[u8]| {
    if let Ok((cert, tail)) = decode_handshake_payload(data) {
        let enc = cert.encode();
        assert_eq!(enc.len() + 32, data.len());
        assert_eq!(&data[..enc.len()], enc.as_slice());
        assert_eq!(&data[enc.len()..], &tail);
    }
});
