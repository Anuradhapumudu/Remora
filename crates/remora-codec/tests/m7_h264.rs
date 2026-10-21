//! M7 (phase4-criteria §5), the part that runs on every OS: the checks an
//! H.264 frame from an authenticated (but possibly malicious) host passes
//! before any byte of it reaches the decoder. The decoder half is
//! `m7_hostile_decode.rs` (macOS, VideoToolbox).
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use remora_codec::h264::{
    DecodeGate, MAX_HEIGHT, MAX_NALS_PER_FRAME, MAX_PARAMETER_SET, MAX_WIDTH, Refusal, SizeLimit,
    SpsInfo, StreamError, parse_frame, parse_sps,
};

fn info(nal: &[u8]) -> SpsInfo {
    parse_sps(nal).unwrap_or_else(|e| panic!("{e}"))
}

// ------------------------------------------------------------------ SPS --

#[test]
fn m7_sps_size_with_cropping() {
    // VideoToolbox's 1080p: 120 × 68 macroblocks, 4 crop units (8 rows) off.
    let i = info(&Sps::default().nal());
    assert_eq!((i.width, i.height), (1920, 1080));
    assert_eq!((i.coded_width, i.coded_height), (1920, 1088));
    assert_eq!((i.profile_idc, i.level_idc, i.sps_id), (66, 40, 0));
    // Phase 4's capture size, no crop.
    let i = info(&Sps::sized(120, 78).nal());
    assert_eq!((i.width, i.height, i.coded_height), (1920, 1248, 1248));
    // Left/right/top crop count too.
    let s = Sps {
        crop: Some((1, 2, 3, 4)),
        ..Sps::default()
    };
    let i = info(&s.nal());
    assert_eq!((i.width, i.height), (1920 - 6, 1088 - 14));
}

#[test]
fn m7_sps_fields_before_the_size_are_read_not_guessed() {
    // High profile with scaling lists and POC type 1: every variable-length
    // field before the size must be consumed, or the size is read from the
    // wrong bits.
    let s = Sps {
        scaling_lists: true,
        poc_type: 1,
        poc_cycle: vec![3, -7, 0, 12],
        sps_id: 5,
        ..Sps::sized(80, 45).high()
    };
    let i = info(&s.nal());
    assert_eq!(
        (i.width, i.height, i.profile_idc, i.sps_id),
        (1280, 720, 100, 5)
    );
    let s = Sps {
        poc_type: 0,
        ..Sps::sized(40, 30)
    };
    assert_eq!(info(&s.nal()).width, 640);
}

#[test]
fn m7_sps_field_coding_doubles_the_height() {
    // frame_mbs_only = 0: height is in field-pair map units (×2), and a
    // vertical crop unit is 4 rows.
    let s = Sps {
        frame_mbs_only: false,
        crop: Some((0, 0, 0, 2)),
        ..Sps::sized(120, 34)
    };
    let i = info(&s.nal());
    assert_eq!((i.coded_height, i.height), (1088, 1080));
}

#[test]
fn m7_sps_features_remora_never_sends_are_refused() {
    let refused = |s: Sps, why: &str| {
        let r = parse_sps(&s.nal());
        assert!(matches!(r, Err(StreamError::Sps(_))), "{why}: {r:?}");
    };
    refused(
        Sps {
            profile_idc: 244,
            ..Sps::default()
        },
        "High 4:4:4",
    );
    refused(
        Sps {
            chroma_format_idc: 3,
            ..Sps::default().high()
        },
        "4:4:4 chroma",
    );
    refused(
        Sps {
            chroma_format_idc: 0,
            ..Sps::default().high()
        },
        "monochrome",
    );
    refused(
        Sps {
            bit_depth_minus8: 2,
            ..Sps::default().high()
        },
        "10-bit",
    );
    refused(
        Sps {
            sps_id: 32,
            ..Sps::default()
        },
        "sps_id > 31",
    );
    refused(
        Sps {
            poc_type: 3,
            ..Sps::default()
        },
        "poc type 3",
    );
    refused(
        Sps {
            poc_type: 1,
            poc_cycle: vec![1; 256],
            ..Sps::default()
        },
        "256-entry POC cycle",
    );
    refused(
        Sps {
            crop: Some((960, 0, 0, 0)),
            ..Sps::default()
        },
        "cropped to nothing",
    );
    // Main and High 4:2:0 8-bit are fine.
    for p in [77, 100] {
        let s = Sps {
            profile_idc: p,
            ..Sps::default()
        };
        assert_eq!(info(&s.nal()).width, 1920, "profile {p}");
    }
}

#[test]
fn m7_sps_that_is_not_an_sps_or_is_cut_short_is_refused() {
    assert!(parse_sps(&[]).is_err());
    assert!(parse_sps(&pps(0, 0)).is_err(), "a PPS");
    let nal = Sps::default().nal();
    for len in 0..nal.len() - 1 {
        assert!(parse_sps(&nal[..len]).is_err(), "cut at {len}");
    }
    // An Exp-Golomb code longer than 32 bits.
    let mut w = BitWriter::default();
    w.u(8, 66).u(8, 0).u(8, 40).u(40, 0).u(1, 1);
    assert!(parse_sps(&w.nal(0x67)).is_err());
}

#[test]
fn m7_sps_longer_than_the_limit_is_refused_before_it_is_read() {
    let mut nal = Sps::default().nal();
    nal.resize(MAX_PARAMETER_SET + 1, 0);
    assert_eq!(parse_sps(&nal), Err(StreamError::ParameterSetTooLarge));
    nal.truncate(MAX_PARAMETER_SET);
    assert!(parse_sps(&nal).is_ok());
}

// --------------------------------------------------------------- limits --

fn too_large(frame: &[u8], limit: SizeLimit) -> bool {
    matches!(parse_frame(frame, limit), Err(StreamError::TooLarge { .. }))
}

#[test]
fn m7_size_limit_is_clamped_to_8k() {
    let l = SizeLimit::new(10_000, 9_000);
    assert_eq!((l.max_width(), l.max_height()), (MAX_WIDTH, MAX_HEIGHT));
    let l = SizeLimit::new(1280, 720);
    assert_eq!((l.max_width(), l.max_height()), (1280, 720));
    assert_eq!(SizeLimit::default(), SizeLimit::new(MAX_WIDTH, MAX_HEIGHT));
}

#[test]
fn m7_pictures_over_8k_are_refused_and_8k_is_not() {
    let any = SizeLimit::default();
    // 7680 × 4320 = 480 × 270 macroblocks exactly.
    assert!(parse_frame(&keyframe(&Sps::sized(480, 270)), any).is_ok());
    assert!(too_large(&keyframe(&Sps::sized(481, 270)), any), "wider");
    assert!(too_large(&keyframe(&Sps::sized(480, 271)), any), "taller");
    // Absurd sizes: 2^16 macroblocks wide (would overflow 32-bit pixels).
    assert!(too_large(&keyframe(&Sps::sized(1 << 16, 1)), any));
    assert!(too_large(&keyframe(&Sps::sized(1 << 31, 1 << 31)), any));
    // Field coding doubles the height: 136 field-pair units = 4352 rows.
    let s = Sps {
        frame_mbs_only: false,
        ..Sps::sized(480, 136)
    };
    assert!(too_large(&keyframe(&s), any), "field-coded height");
}

#[test]
fn m7_pictures_over_the_viewers_limit_are_refused() {
    let hd = SizeLimit::new(1280, 720);
    assert!(parse_frame(&keyframe(&Sps::sized(80, 45)), hd).is_ok());
    assert!(too_large(&keyframe(&Sps::sized(81, 45)), hd), "1296 wide");
    assert!(too_large(&keyframe(&Sps::sized(80, 46)), hd), "736 tall");
    assert!(too_large(&keyframe(&Sps::default()), hd), "1080p");
    // The coded size counts, not only the cropped one: 1920 × 1088 coded,
    // cropped to 1280 × 720, still makes the decoder allocate 1088 rows.
    let s = Sps {
        crop: Some((320, 0, 0, 184)),
        ..Sps::default()
    };
    assert!(too_large(&keyframe(&s), hd), "big coded, small displayed");
    // A limit that is not a multiple of 16 allows the macroblock padding.
    let l = SizeLimit::new(1920, 1080);
    assert!(parse_frame(&keyframe(&Sps::default()), l).is_ok());
    assert!(
        too_large(&keyframe(&Sps::sized(120, 69)), l),
        "1104 coded rows"
    );
}

// ---------------------------------------------------------------- frame --

fn refused(frame: &[u8]) -> StreamError {
    parse_frame(frame, SizeLimit::default()).expect_err("frame was accepted")
}

#[test]
fn m7_a_keyframe_is_split_into_its_parts() {
    let sps = Sps::default().nal();
    let pps = pps(0, 0);
    let sei: &[u8] = &[0x06, 0x05, 0x01, 0x00, 0x80];
    let frame = annexb(&[&[0x09, 0xF0], &sps, &pps, sei, IDR]);
    let f = parse_frame(&frame, SizeLimit::default()).unwrap();
    assert!(f.keyframe);
    assert_eq!(f.sps.unwrap().0, &sps[..]);
    assert_eq!(f.sps.unwrap().1.height, 1080);
    assert_eq!(f.pps.unwrap(), &pps[..]);
    assert_eq!(f.nals, vec![&[0x09, 0xF0][..], sei, IDR]);
    // AVCC: 4-byte length + NAL, parameter sets left out.
    let mut avcc = vec![0, 0, 0, 2, 0x09, 0xF0, 0, 0, 0, 5];
    avcc.extend_from_slice(sei);
    avcc.extend_from_slice(&[0, 0, 0, 5]);
    avcc.extend_from_slice(IDR);
    assert_eq!(f.to_avcc(), avcc);
}

#[test]
fn m7_start_codes_of_three_and_four_bytes_and_trailing_zeros() {
    let mut frame = vec![0, 0, 1];
    frame.extend_from_slice(SLICE);
    frame.extend_from_slice(&[0, 0, 0, 0, 1]); // trailing_zero_8bits + start code
    frame.extend_from_slice(SLICE);
    frame.extend_from_slice(&[0, 0]); // trailing zeros at the end
    let f = parse_frame(&frame, SizeLimit::default()).unwrap();
    assert!(!f.keyframe);
    assert_eq!(f.nals, vec![SLICE, SLICE]);
    assert_eq!(f.sps, None);
}

#[test]
fn m7_malformed_framing_is_refused() {
    assert_eq!(refused(&[]), StreamError::NoStartCode);
    assert_eq!(refused(&[0x41, 0, 0, 1, 0x41]), StreamError::NoStartCode);
    assert_eq!(refused(&[0, 0, 0, 1]), StreamError::EmptyNal);
    assert_eq!(refused(&[0, 0, 1, 0, 0, 1, 0x41]), StreamError::EmptyNal);
    assert_eq!(
        refused(&annexb(&[&[0xC1, 0x9A]])),
        StreamError::ForbiddenBit
    );
    let many: Vec<&[u8]> = vec![SLICE; MAX_NALS_PER_FRAME + 1];
    assert_eq!(refused(&annexb(&many)), StreamError::TooManyNals);
    let most: Vec<&[u8]> = vec![SLICE; MAX_NALS_PER_FRAME];
    assert!(parse_frame(&annexb(&most), SizeLimit::default()).is_ok());
}

#[test]
fn m7_nal_types_remora_never_sends_are_refused() {
    for t in [0u8, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 19, 20, 21, 23, 31] {
        let nal = [0x60 | t, 0x80];
        assert_eq!(
            refused(&annexb(&[SLICE, &nal])),
            StreamError::NalType(t),
            "type {t}"
        );
    }
}

#[test]
fn m7_parameter_sets_only_with_a_keyframe() {
    let sps = Sps::default().nal();
    let pps = pps(0, 0);
    assert_eq!(
        refused(&annexb(&[IDR])),
        StreamError::KeyframeWithoutParameterSets
    );
    assert_eq!(
        refused(&annexb(&[&sps, IDR])),
        StreamError::KeyframeWithoutParameterSets
    );
    assert_eq!(
        refused(&annexb(&[&pps, IDR])),
        StreamError::KeyframeWithoutParameterSets
    );
    // A size change hidden in a P frame would skip the keyframe check.
    assert_eq!(
        refused(&annexb(&[&sps, &pps, SLICE])),
        StreamError::ParameterSetsOutsideKeyframe
    );
    assert_eq!(
        refused(&annexb(&[&pps, SLICE])),
        StreamError::ParameterSetsOutsideKeyframe
    );
    assert_eq!(
        refused(&annexb(&[&sps, &sps, &pps, IDR])),
        StreamError::RepeatedParameterSet
    );
    assert_eq!(
        refused(&annexb(&[&sps, &pps, &pps, IDR])),
        StreamError::RepeatedParameterSet
    );
    let mut big = pps.clone();
    big.resize(MAX_PARAMETER_SET + 1, 0x80);
    assert_eq!(
        refused(&annexb(&[&sps, &big, IDR])),
        StreamError::ParameterSetTooLarge
    );
}

#[test]
fn m7_slices_must_be_all_idr_or_all_not() {
    let sps = Sps::default().nal();
    let pps = pps(0, 0);
    assert_eq!(
        refused(&annexb(&[&sps, &pps, IDR, SLICE])),
        StreamError::Slices
    );
    assert_eq!(refused(&annexb(&[&[0x09, 0xF0]])), StreamError::Slices);
    assert_eq!(refused(&annexb(&[&sps, &pps])), StreamError::Slices);
    // Two IDR slices (two slice threads) are fine.
    assert!(parse_frame(&annexb(&[&sps, &pps, IDR, IDR]), SizeLimit::default()).is_ok());
}

#[test]
fn m7_pps_must_name_the_sps() {
    let sps = Sps {
        sps_id: 3,
        ..Sps::default()
    };
    let ok = annexb(&[&sps.nal(), &pps(0, 3), IDR]);
    assert!(parse_frame(&ok, SizeLimit::default()).is_ok());
    let r = refused(&annexb(&[&sps.nal(), &pps(0, 2), IDR]));
    assert!(matches!(r, StreamError::Pps(_)), "{r:?}");
    let r = refused(&annexb(&[&sps.nal(), &pps(256, 3), IDR]));
    assert!(matches!(r, StreamError::Pps(_)), "pps_id > 255: {r:?}");
    let r = refused(&annexb(&[&sps.nal(), &[0x68], IDR]));
    assert!(matches!(r, StreamError::Pps(_)), "empty PPS: {r:?}");
}

#[test]
fn m7_an_sps_refusal_is_reported_from_the_frame() {
    let s = Sps {
        bit_depth_minus8: 2,
        ..Sps::default().high()
    };
    assert!(matches!(refused(&keyframe(&s)), StreamError::Sps(_)));
}

#[test]
fn m7_random_bytes_never_panic_and_are_almost_always_refused() {
    // The fuzz target `h264_frame` covers this properly; this is the quick
    // version that runs with every `cargo test`.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut accepted = 0;
    for _ in 0..20_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let len = (x % 64) as usize;
        let bytes: Vec<u8> = (0..len)
            .map(|i| (x.rotate_left(i as u32 * 8) & 0xff) as u8)
            .collect();
        let mut framed = vec![0, 0, 0, 1];
        framed.extend_from_slice(&bytes);
        for f in [&bytes, &framed] {
            if parse_frame(f, SizeLimit::default()).is_ok() {
                accepted += 1;
            }
        }
    }
    // A random byte is a valid non-IDR slice header 1 time in ~16 (types
    // 1/6/9 with nal_ref_idc any): accepted, and the decoder then rejects
    // it, which m7_hostile_decode covers. Bounded, not zero.
    assert!(accepted < 20_000, "accepted {accepted} of 40 000");
}

// ----------------------------------------------------------------- gate --

#[test]
fn m7_gate_waits_for_a_keyframe() {
    let mut g = DecodeGate::new(SizeLimit::default());
    assert!(g.waiting_for_keyframe());
    assert_eq!(g.admit(&annexb(&[SLICE])), Err(Refusal::WaitingForKeyframe));
    let k = keyframe(&Sps::default());
    let a = g.admit(&k).unwrap();
    assert!(a.reconfigure, "first keyframe configures the decoder");
    assert!(!g.waiting_for_keyframe());
    let p = annexb(&[SLICE]);
    let a = g.admit(&p).unwrap();
    assert!(!a.reconfigure);
    assert!(!a.frame.keyframe);
}

#[test]
fn m7_gate_reconfigures_only_when_parameter_sets_change() {
    let mut g = DecodeGate::new(SizeLimit::default());
    let k = keyframe(&Sps::default());
    assert!(g.admit(&k).unwrap().reconfigure);
    assert!(!g.admit(&k).unwrap().reconfigure, "same SPS/PPS again");
    let k720 = keyframe(&Sps::sized(80, 45));
    assert!(g.admit(&k720).unwrap().reconfigure, "new size");
    let other_pps = annexb(&[&Sps::sized(80, 45).nal(), &pps(1, 0), IDR]);
    assert!(g.admit(&other_pps).unwrap().reconfigure, "new PPS");
}

#[test]
fn m7_gate_refusal_or_decode_error_waits_for_the_next_keyframe() {
    let mut g = DecodeGate::new(SizeLimit::new(1280, 720));
    let k = keyframe(&Sps::sized(80, 45));
    g.admit(&k).unwrap();
    let p = annexb(&[SLICE]);
    g.admit(&p).unwrap();
    // A malformed frame: refused, and P frames after it are too.
    assert_eq!(
        g.admit(&[0, 0, 0, 1, 0xC1]),
        Err(Refusal::Malformed(StreamError::ForbiddenBit))
    );
    assert!(g.waiting_for_keyframe());
    assert_eq!(g.admit(&p), Err(Refusal::WaitingForKeyframe));
    // An oversized keyframe is refused and changes nothing.
    let big = keyframe(&Sps::default());
    assert!(matches!(
        g.admit(&big),
        Err(Refusal::Malformed(StreamError::TooLarge { .. }))
    ));
    assert!(g.waiting_for_keyframe());
    // The same keyframe as before: no reconfiguration needed.
    assert!(!g.admit(&k).unwrap().reconfigure);
    g.admit(&p).unwrap();
    // A decode error: wait again.
    g.decode_failed();
    assert!(g.waiting_for_keyframe());
    assert_eq!(g.admit(&p), Err(Refusal::WaitingForKeyframe));
    assert!(!g.admit(&k).unwrap().reconfigure);
    // The decoder could not be configured: the same keyframe reconfigures.
    g.configure_failed();
    assert!(g.waiting_for_keyframe());
    assert_eq!(g.admit(&p), Err(Refusal::WaitingForKeyframe));
    assert!(g.admit(&k).unwrap().reconfigure);
}
