//! phase4.8-criteria A3 / §7: what a hostile host could make the viewer's
//! Opus decoder (libopus, C) do. Arbitrary bytes are cut into audio bodies
//! by the real parser and fed to the real decoder, with lost packets
//! (concealment) mixed in, on one decoder so its state carries over. No
//! panic, and never more than one 20 ms frame out.
//!
//! libopus is compiled by its own build (cmake) without the fuzzer's
//! coverage instrumentation: this exercises it, but coverage guidance
//! comes from our Rust code only. Stated, not hidden.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_codec::audio::{AudioDecoder, CHANNELS, FRAME};
use remora_proto::audio::AudioPacket;

fuzz_target!(|data: &[u8]| {
    let Ok(mut dec) = AudioDecoder::new() else { return };
    let mut rest = data;
    // Each step: one control byte (low bit: a lost packet first; the rest,
    // times 9: the body length, up to 1 143 so the 1 000-byte Opus limit
    // and beyond are reached), then that many bytes as an audio body.
    while let Some((&ctl, tail)) = rest.split_first() {
        if ctl & 1 == 1 {
            let pcm = dec.conceal().expect("concealment never fails");
            assert!(pcm.len() <= FRAME * CHANNELS);
        }
        let n = (usize::from(ctl >> 1) * 9).min(tail.len());
        let (body, after) = tail.split_at(n);
        rest = after;
        if let Ok(p) = AudioPacket::parse(body) {
            if let Ok(pcm) = dec.decode(&p.data) {
                assert!(pcm.len() <= FRAME * CHANNELS);
            }
        }
    }
});
