//! P7 (phase4-criteria §4): every drawn frame's number decodes from the
//! drawn pixels, and the numbers strictly increase — drops allowed, **no
//! repeats, no reordering**.
//!
//! The pipeline is the real one after the network: frames numbered by a
//! barcode strip (`SyntheticSource::next_frame_marked`) → hardware encoder
//! → `VtDecoder` → `Renderer` (offscreen, same shader and upload as the
//! window) → read back → barcode. Loss and reordering are simulated by
//! leaving frames out or swapping them before the decoder. The full
//! network path (relay re-injecting packets) repeats this in step 7 (M4).
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use std::sync::mpsc;
use std::time::Duration;

use remora_codec::h264::SizeLimit;
use remora_codec::{EncoderConfig, EncoderEvent, SyntheticSource, VtDecoder, VtEncoder, barcode};
use remora_viewer::render::{Offscreen, Renderer, headless};

const W: u32 = 1280;
const H: u32 = 720;

/// `n` encoded frames, the barcode number of each equal to its index;
/// keyframes at 0 and every `keyframe_every`.
fn encode(n: u64, keyframe_every: u64) -> Vec<Vec<u8>> {
    let cfg = EncoderConfig {
        width: W,
        height: H,
        ..EncoderConfig::default()
    };
    let (tx, rx) = mpsc::channel();
    let sink = Box::new(move |ev: EncoderEvent| {
        if let EncoderEvent::Frame(f) = ev {
            let _ = tx.send((f.seq, f.data));
        }
    });
    let mut enc = VtEncoder::new(cfg, sink).expect("hardware encoder");
    let mut src = SyntheticSource::new(W, H).unwrap();
    for i in 0..n {
        let (number, frame) = src.next_frame_marked().unwrap();
        assert_eq!(u64::from(number), i);
        let key = i % keyframe_every == 0;
        enc.encode(&frame, Duration::from_millis(i * 16), key)
            .unwrap();
    }
    enc.flush().unwrap();
    drop(enc);
    let mut frames: Vec<_> = rx.try_iter().collect();
    frames.sort_by_key(|f| f.0);
    assert_eq!(frames.len() as u64, n);
    frames.into_iter().map(|f| f.1).collect()
}

/// Feeds `(frame_id, frame)` to a decoder; every picture is drawn and the
/// number read back. Returns the numbers in the order they were drawn
/// (`None` = drawn but unreadable).
fn draw_all(inputs: &[(u32, &[u8])]) -> Vec<Option<u32>> {
    let (device, queue) = headless().expect("a Metal adapter (P7 needs a GPU)");
    let mut renderer = Renderer::new(device, queue, wgpu::TextureFormat::Rgba8Unorm);
    let target = Offscreen::new(renderer.device(), W, H);
    let mut dec = VtDecoder::new(SizeLimit::default());
    let mut drawn = Vec::new();
    for &(id, data) in inputs {
        let Ok(picture) = dec.decode(id, data) else {
            continue;
        };
        picture.with_nv12(|nv12| renderer.upload(nv12)).unwrap();
        assert!(renderer.draw(&target.view()));
        let rgba = target.read(renderer.device(), renderer.queue());
        let (w, h) = (W as usize, H as usize);
        drawn.push(barcode::read_rgba(&rgba, w * 4, w, h));
    }
    drawn
}

/// The P7 rule over the drawn sequence.
fn check_p7(drawn: &[Option<u32>]) -> Result<(), String> {
    let mut last: Option<u32> = None;
    for (i, n) in drawn.iter().enumerate() {
        let Some(n) = *n else {
            return Err(format!("drawn frame {i}: barcode unreadable"));
        };
        if let Some(l) = last
            && n <= l
        {
            return Err(format!(
                "drawn frame {i}: number {n} after {l} ({})",
                if n == l { "repeat" } else { "reordered" }
            ));
        }
        last = Some(n);
    }
    Ok(())
}

#[test]
fn p7_every_frame_is_drawn_once_in_order() {
    let frames = encode(90, 30);
    let inputs: Vec<(u32, &[u8])> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| (i as u32, f.as_slice()))
        .collect();
    let drawn = draw_all(&inputs);
    check_p7(&drawn).unwrap();
    assert_eq!(
        drawn,
        (0..90).map(Some).collect::<Vec<_>>(),
        "all 90, each its own number"
    );
}

#[test]
fn p7_after_a_lost_frame_nothing_is_drawn_until_the_next_keyframe() {
    let frames = encode(90, 30);
    // Frames 40 and 41 never arrive.
    let inputs: Vec<(u32, &[u8])> = frames
        .iter()
        .enumerate()
        .filter(|(i, _)| !(40..=41).contains(i))
        .map(|(i, f)| (i as u32, f.as_slice()))
        .collect();
    let drawn = draw_all(&inputs);
    check_p7(&drawn).unwrap();
    let expect: Vec<_> = (0..40).chain(60..90).map(Some).collect();
    assert_eq!(drawn, expect, "a drop, then the keyframe at 60");
}

#[test]
fn p7_frames_out_of_order_are_never_drawn_backwards() {
    let frames = encode(90, 30);
    // 51 arrives before 50; later 70 twice.
    let mut order: Vec<u32> = (0..90).collect();
    order.swap(50, 51);
    order.insert(71, 70);
    let inputs: Vec<(u32, &[u8])> = order
        .iter()
        .map(|&i| (i, frames[i as usize].as_slice()))
        .collect();
    let drawn = draw_all(&inputs);
    check_p7(&drawn).unwrap();
    // 51-before-50 breaks the chain until the keyframe at 60; the second
    // 70 breaks it again, and no keyframe follows (keyframes 0, 30, 60).
    let expect: Vec<_> = (0..50).chain(60..=70).map(Some).collect();
    assert_eq!(drawn, expect);
}

#[test]
fn p7_the_checker_catches_repeats_reordering_and_unreadable_frames() {
    assert!(check_p7(&[Some(1), Some(2), Some(5)]).is_ok());
    assert!(
        check_p7(&[Some(1), Some(1)])
            .unwrap_err()
            .contains("repeat")
    );
    assert!(
        check_p7(&[Some(2), Some(1)])
            .unwrap_err()
            .contains("reordered")
    );
    assert!(
        check_p7(&[Some(1), None])
            .unwrap_err()
            .contains("unreadable")
    );
}
