//! Phase 4 M6: arbitrary fragment sequences into the video reassembler.
//! Input = repeated (flags u8, len u16 BE, body[len]). After every push:
//! no panic, the byte budget and open-frame limit hold, every delivered
//! frame is within FRAME_MAX, and delivered frame IDs strictly increase.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_proto::limits::{FRAME_MAX, MAX_OPEN_FRAMES, REASSEMBLY_BYTES_MAX};
use remora_proto::video::{ReassemblyEvent, Reassembler};

fuzz_target!(|data: &[u8]| {
    let mut r = Reassembler::new();
    let mut last: Option<u32> = None;
    let mut rest = data;
    while rest.len() >= 3 {
        let flags = rest[0];
        let len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
        rest = &rest[3..];
        let body = &rest[..len.min(rest.len())];
        rest = &rest[body.len()..];
        for ev in r.push(flags, body) {
            if let ReassemblyEvent::Frame(f) = ev {
                assert!(f.data.len() <= FRAME_MAX);
                assert!(last.is_none_or(|l| f.frame_id > l), "frames go forward");
                last = Some(f.frame_id);
            }
        }
        assert!(r.bytes_in_flight() <= REASSEMBLY_BYTES_MAX);
        assert!(r.open_frames() <= MAX_OPEN_FRAMES);
    }
});
