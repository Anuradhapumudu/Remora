//! Arbitrary bytes, pushed in arbitrary chunk sizes, never panic; every frame
//! returned is within the limit.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_proto::frame::FrameDecoder;

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, rest)) = data.split_first() else { return };
    let mut d = FrameDecoder::new(300);
    for part in rest.chunks(usize::from(chunk).max(1)) {
        match d.push(part) {
            Ok(frames) => assert!(frames.iter().all(|f| !f.is_empty() && f.len() <= 300)),
            Err(_) => break,
        }
    }
});
