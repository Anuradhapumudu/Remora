//! Arbitrary datagrams into MediaReceiver::open with a live key: no panic,
//! nothing forged is accepted (the fuzzer cannot produce a valid tag), and
//! the receiver keeps working afterwards.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_crypto::media::{MediaReceiver, MediaSender};
use remora_crypto::secret::MediaKey;
use remora_proto::datagram::{DatagramHeader, DatagramKind};

fuzz_target!(|data: &[u8]| {
    let key = MediaKey::from_bytes([0x5A; 32]);
    let mut r = MediaReceiver::new();
    if r.add_key(1, key.clone()).is_err() {
        return;
    }
    assert!(r.open(data).is_err());
    let mut s = MediaSender::new(1, key);
    let h = DatagramHeader {
        kind: DatagramKind::PointerMotion,
        flags: 0,
        key_id: 1,
        counter: 0,
        stream_id: 0,
        layer_id: 0,
    };
    if let Ok(d) = s.seal(h, b"ok") {
        assert!(r.open(&d).is_ok());
    }
});
