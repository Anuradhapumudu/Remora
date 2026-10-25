//! M7 (phase4-criteria §5) on the real decoder: a malicious authenticated
//! host sends a hostile bitstream to VideoToolbox through `VtDecoder`.
//!
//! PASS if: sizes over the limit are refused **before** a decoder session
//! is created; every decoder error comes back as an error (so the viewer
//! asks for a keyframe); nothing crashes; no single decode call takes more
//! than 5 s (watchdog); and a real keyframe afterwards decodes again.
//! Memory: `m7_decode_memory.rs` (its own process, so other tests'
//! allocations do not count).
//!
//! Real frames come from the hardware encoder (`VtEncoder` +
//! `SyntheticSource`); GitHub's macOS runner hardware-encodes (step 1).
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::vt::*;
use common::*;
use remora_codec::h264::{Refusal, SizeLimit, StreamError};
use remora_codec::{DecodeError, VtDecoder};

#[test]
fn m7_real_stream_round_trip_decodes_every_frame() {
    let frames = encode(1280, 720, 60, 0);
    let dec = VtDecoder::new(SizeLimit::new(1280, 720));
    let (dec, results) = decode_all(dec, frames.into_iter().map(|f| f.1).collect());
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r.as_ref(), Ok(&(1280, 720)), "frame {i}");
    }
    let s = dec.stats();
    assert_eq!((s.decoded, s.failed, s.refused), (60, 0, 0), "{s:?}");
    assert_eq!(s.sessions_created, 1, "{s:?}");
}

#[test]
fn m7_oversized_sps_is_refused_before_the_decoder_is_configured() {
    // A real 1080p keyframe to a viewer whose limit is 720p.
    let frames = encode(1920, 1080, 2, 0);
    let mut dec = VtDecoder::new(SizeLimit::new(1280, 720));
    let r = dec.decode(0, &frames[0].1);
    assert!(
        matches!(
            r,
            Err(DecodeError::Refused(Refusal::Malformed(
                StreamError::TooLarge { .. }
            )))
        ),
        "{r:?}"
    );
    // Over 8K for any viewer.
    let mut dec8k = VtDecoder::new(SizeLimit::default());
    let r = dec8k.decode(0, &keyframe(&Sps::sized(481, 270)));
    assert!(
        matches!(
            r,
            Err(DecodeError::Refused(Refusal::Malformed(
                StreamError::TooLarge { .. }
            )))
        ),
        "{r:?}"
    );
    for d in [&dec, &dec8k] {
        let s = d.stats();
        assert_eq!(s.sessions_created, 0, "a decoder was configured: {s:?}");
        assert_eq!((s.refused, s.decoded), (1, 0), "{s:?}");
    }
    // The P frame after a refused keyframe is refused too, unread.
    let r = dec.decode(1, &frames[1].1);
    assert!(
        matches!(r, Err(DecodeError::Refused(Refusal::WaitingForKeyframe))),
        "{r:?}"
    );
}

#[test]
fn m7_random_bytes_and_random_slices_never_crash_or_hang() {
    let real = encode(640, 360, 4, 0);
    let (sps, pps) = parameter_sets(&real[0].1);
    let mut x = 0x2545_F491_4F6C_DD1D;
    let mut inputs = Vec::new();
    for i in 0..600 {
        let len = 1 + (xorshift(&mut x) % 4000) as usize;
        let body = random_bytes(&mut x, len);
        inputs.push(match i % 4 {
            // Plain random bytes.
            0 => body,
            // A keyframe with real SPS/PPS and a random IDR slice: reaches
            // VideoToolbox, which must cope.
            1 => {
                let mut idr = vec![0x65];
                idr.extend_from_slice(&body);
                annexb(&[&sps, &pps, &idr])
            }
            // A random P slice after it.
            2 => {
                let mut p = vec![0x41];
                p.extend_from_slice(&body);
                annexb(&[&p])
            }
            // A real frame now and then, so the decoder is in every state.
            // (i / 4 walks through all of them, keyframe included.)
            _ => real[(i / 4) % real.len()].1.clone(),
        });
    }
    inputs.push(real[0].1.clone());
    let (dec, results) = decode_all(VtDecoder::new(SizeLimit::default()), inputs);
    assert_eq!(
        results.last().unwrap().as_ref(),
        Ok(&(640, 360)),
        "a real keyframe decodes after the hostile run"
    );
    let s = dec.stats();
    assert!(s.refused + s.failed > 0, "nothing was rejected: {s:?}");
    println!("M7 random: {s:?}");
}

#[test]
fn m7_truncated_nal_units_never_crash_or_hang() {
    let real = encode(640, 360, 8, 0);
    let mut inputs = Vec::new();
    for (k, p) in [(0, 1), (0, 5)] {
        let key = &real[k].1;
        let next = &real[p].1;
        for cut in (5..key.len()).step_by(1 + key.len() / 97) {
            inputs.push(key[..cut].to_vec());
            inputs.push(next.clone());
        }
        for cut in (1..next.len()).step_by(1 + next.len() / 31) {
            inputs.push(key.clone());
            inputs.push(next[..cut].to_vec());
        }
    }
    inputs.push(real[0].1.clone());
    let n = inputs.len();
    let (dec, results) = decode_all(VtDecoder::new(SizeLimit::default()), inputs);
    assert_eq!(results[n - 1].as_ref(), Ok(&(640, 360)));
    let s = dec.stats();
    assert!(s.refused + s.failed > 0, "{s:?}");
    println!("M7 truncated: {} inputs, {s:?}", n);
}

#[test]
fn m7_after_a_decode_error_the_decoder_waits_for_a_keyframe() {
    let real = encode(640, 360, 3, 0);
    let (sps, pps) = parameter_sets(&real[0].1);
    let mut dec = VtDecoder::new(SizeLimit::default());
    dec.decode(0, &real[0].1).unwrap();
    // An IDR slice made of zero bytes (no emulation prevention needed:
    // 0x00 runs are framing, so use 0x01) that the decoder rejects.
    let bad = annexb(&[&sps, &pps, &[0x65, 0x01, 0x01, 0x01]]);
    let r = dec.decode(1, &bad);
    assert!(r.is_err(), "decoder accepted a 3-byte IDR slice: {r:?}");
    let r = dec.decode(2, &real[1].1);
    assert!(
        matches!(r, Err(DecodeError::Refused(Refusal::WaitingForKeyframe))),
        "P frame after an error must wait for a keyframe: {r:?}"
    );
    assert!(dec.decode(3, &real[0].1).is_ok());
    assert!(dec.decode(4, &real[1].1).is_ok());
}

#[test]
fn m7_a_missing_frame_waits_for_a_keyframe() {
    // Frame 2 never arrives (lost, given up by the reassembler, or dropped
    // because the decoder was busy): frame 3 predicts from a picture the
    // decoder never saw, and VideoToolbox need not report that as an
    // error. A gap in frame ids is treated like a decode error.
    let real = encode(640, 360, 4, 0);
    let mut dec = VtDecoder::new(SizeLimit::default());
    dec.decode(0, &real[0].1).unwrap();
    dec.decode(1, &real[1].1).unwrap();
    let r = dec.decode(3, &real[3].1);
    assert!(
        matches!(r, Err(DecodeError::Refused(Refusal::WaitingForKeyframe))),
        "{r:?}"
    );
    // A repeated id is a gap too (the reassembler never delivers one).
    let mut again = VtDecoder::new(SizeLimit::default());
    again.decode(0, &real[0].1).unwrap();
    again.decode(1, &real[1].1).unwrap();
    assert!(again.decode(1, &real[2].1).is_err(), "repeated frame id");
    // The next keyframe, whatever its id, starts a new chain.
    assert!(dec.decode(9, &real[0].1).is_ok());
    assert!(dec.decode(10, &real[1].1).is_ok());
    // Ids wrap: u32::MAX is followed by 0.
    let mut wrap = VtDecoder::new(SizeLimit::default());
    wrap.decode(u32::MAX, &real[0].1).unwrap();
    assert!(wrap.decode(0, &real[1].1).is_ok());
}

#[test]
fn m7_a_decoded_frame_never_prints_its_pixels() {
    let real = encode(640, 360, 1, 0);
    let mut dec = VtDecoder::new(SizeLimit::default());
    let f = dec.decode(42, &real[0].1).unwrap();
    let s = format!("{f:?}");
    assert_eq!(s, "DecodedFrame { frame_id: 42, width: 640, height: 360 }");
}

/// M7 "memory bounded", checked by counting instead of measuring
/// (phase4-criteria §12, owner 2026-10-22): the decoder's own objects —
/// decoder sessions and decoded pictures — are counted while they exist,
/// so a leak of either shows on any machine, the CI VM included.
#[test]
fn m7_live_sessions_and_pictures_are_counted() {
    let real = encode(640, 360, 2, 0);
    let mut dec = VtDecoder::new(SizeLimit::default());
    assert_eq!(live(&dec), (0, 0), "nothing before the first keyframe");
    let picture = dec.decode(0, &real[0].1).unwrap();
    assert_eq!(live(&dec), (1, 1), "one session, one picture held");
    drop(picture);
    assert_eq!(live(&dec), (1, 0), "the picture is gone when dropped");
    // A keyframe whose slice is garbage: a new session is configured, the
    // decode fails, and the failed session is dropped.
    let (sps, pps) = parameter_sets(&real[0].1);
    let mut idr = vec![0x65];
    idr.extend_from_slice(&random_bytes(&mut 0x1234_5678_9ABC_DEF1, 2000));
    assert!(dec.decode(1, &annexb(&[&sps, &pps, &idr])).is_err());
    assert_eq!(live(&dec).0, 0, "a failed session is not kept");
}

fn live(dec: &VtDecoder) -> (u64, u64) {
    let s = dec.stats();
    (s.sessions_alive, s.pictures_alive)
}
