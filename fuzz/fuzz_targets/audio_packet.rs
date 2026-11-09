//! phase4.8-criteria A3: arbitrary decrypted audio bodies. No panic; what
//! is accepted stays within the limits and encodes back to the same bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_proto::audio::{AUDIO_BODY_HEADER_LEN, AudioPacket, MAX_OPUS_BYTES};

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = AudioPacket::parse(data) {
        assert!(!p.data.is_empty() && p.data.len() <= MAX_OPUS_BYTES);
        assert_eq!(p.encode(), data, "parse/encode round trip");
        assert_eq!(data.len(), AUDIO_BODY_HEADER_LEN + p.data.len());
    }
});
