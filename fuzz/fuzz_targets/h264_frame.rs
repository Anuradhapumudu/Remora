//! Phase 4 M7: arbitrary bytes as H.264 frames from a hostile authenticated
//! host, through the checks that run before the decoder. Input = a 4-byte
//! size limit (width u16 BE, height u16 BE), then repeated (len u16 BE,
//! frame[len]) through one `DecodeGate`, every 7th frame followed by a
//! simulated decode error. Checked after every frame: no panic; anything
//! admitted is within the limit, keyframes carry an in-limit SPS and a PPS,
//! the AVCC form is exactly the NAL units with 4-byte lengths; and
//! `parse_sps` alone never panics on any NAL unit.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_codec::h264::{DecodeGate, MAX_HEIGHT, MAX_WIDTH, SizeLimit, parse_sps};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let w = u32::from(u16::from_be_bytes([data[0], data[1]]));
    let h = u32::from(u16::from_be_bytes([data[2], data[3]]));
    let limit = SizeLimit::new(w, h);
    assert!(limit.max_width() <= MAX_WIDTH && limit.max_height() <= MAX_HEIGHT);
    let mut gate = DecodeGate::new(limit);
    let mut rest = &data[4..];
    let mut n = 0u32;
    while rest.len() >= 2 {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[2..];
        let frame = &rest[..len.min(rest.len())];
        rest = &rest[frame.len()..];
        let _ = parse_sps(frame);
        if let Ok(a) = gate.admit(frame) {
            let f = &a.frame;
            assert!(!gate.waiting_for_keyframe());
            if f.keyframe {
                let (_, info) = f.sps.expect("keyframe has an SPS");
                assert!(f.pps.is_some());
                assert!(info.width <= limit.max_width() && info.height <= limit.max_height());
                assert!(info.width > 0 && info.height > 0);
            } else {
                assert!(f.sps.is_none() && f.pps.is_none() && !a.reconfigure);
            }
            let avcc = f.to_avcc();
            let expect: usize = f.nals.iter().map(|n| 4 + n.len()).sum();
            assert_eq!(avcc.len(), expect);
            assert!(avcc.len() <= frame.len() + 4 * f.nals.len());
        }
        n += 1;
        if n % 7 == 0 {
            gate.decode_failed();
            assert!(gate.waiting_for_keyframe());
        }
    }
});
