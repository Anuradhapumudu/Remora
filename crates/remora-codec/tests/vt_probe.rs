//! Phase 4 step 1 (phase4-criteria §8): can THIS machine's VideoToolbox
//! hardware-encode? Run explicitly (it is `#[ignore]`d in normal runs):
//!
//! ```sh
//! cargo test -p remora-codec --test vt_probe -- --ignored --nocapture
//! ```
//!
//! Prints one line `VT_PROBE encode=<ok|unavailable> ...`. On GitHub's
//! macOS runner (a VM) the answer decides whether the Phase 4 media tests
//! run in CI with VideoToolbox or with the test-only pass-through codec.
//! "unavailable" is a valid answer; an encoder that is created but delivers
//! nothing is a FAILURE (that would be a broken encoder, not a missing one).
//! `vt_probe_hardware_decode` (step 5) prints `VT_PROBE decode=...` the
//! same way: it decodes what the encoder produced, through `VtDecoder`.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use std::sync::{Arc, Mutex};
use std::time::Duration;

use remora_codec::h264::SizeLimit;
use remora_codec::{EncoderConfig, EncoderEvent, SyntheticSource, VtDecoder, VtEncoder};

const FRAMES: u64 = 30;

/// What the encoder delivered.
#[derive(Default)]
struct Got {
    frames: u64,
    bytes: usize,
    keyframes: u64,
    dropped_or_failed: u64,
}

#[test]
#[ignore = "probe: run explicitly, see the module docs"]
fn vt_probe_hardware_encode() {
    let cfg = EncoderConfig {
        width: 1280,
        height: 720,
        ..EncoderConfig::default()
    };
    let got = Arc::new(Mutex::new(Got::default()));
    let sink_state = Arc::clone(&got);
    let sink = Box::new(move |ev: EncoderEvent| {
        let mut g = sink_state.lock().unwrap();
        match ev {
            EncoderEvent::Frame(f) => {
                g.frames += 1;
                g.bytes += f.data.len();
                g.keyframes += u64::from(f.keyframe);
            }
            EncoderEvent::Dropped { .. } | EncoderEvent::Error { .. } => g.dropped_or_failed += 1,
        }
    });
    let mut enc = match VtEncoder::new(cfg, sink) {
        Ok(e) => e,
        Err(e) => {
            println!("VT_PROBE encode=unavailable reason={e}");
            return;
        }
    };
    let mut src = SyntheticSource::new(cfg.width, cfg.height).unwrap();
    for i in 0..FRAMES {
        let frame = src.next_frame().unwrap();
        enc.encode(&frame, Duration::from_millis(i * 16), i == 0)
            .unwrap();
    }
    enc.flush().unwrap();
    let g = got.lock().unwrap();
    // The status word comes from the result: a broken encoder must never be
    // summarised as "ok" (seen in the planted no-frames run).
    let status = if g.frames > 0 && g.keyframes >= 1 {
        "ok"
    } else {
        "BROKEN"
    };
    println!(
        "VT_PROBE encode={status} frames={}/{FRAMES} bytes={} keyframes={} dropped_or_failed={}",
        g.frames, g.bytes, g.keyframes, g.dropped_or_failed
    );
    assert!(
        g.frames > 0,
        "hardware encoder was created but produced no frames"
    );
    assert!(g.keyframes >= 1, "the first frame must be a keyframe");
}

#[test]
#[ignore = "probe: run explicitly, see the module docs"]
fn vt_probe_hardware_decode() {
    let cfg = EncoderConfig {
        width: 1280,
        height: 720,
        ..EncoderConfig::default()
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let sink = Box::new(move |ev: EncoderEvent| {
        if let EncoderEvent::Frame(f) = ev {
            let _ = tx.send((f.seq, f.data));
        }
    });
    let mut enc = match VtEncoder::new(cfg, sink) {
        Ok(e) => e,
        Err(e) => {
            // Nothing to decode without an encoder; the encode probe line
            // already says why.
            println!("VT_PROBE decode=untested reason=no encoder: {e}");
            return;
        }
    };
    let mut src = SyntheticSource::new(cfg.width, cfg.height).unwrap();
    for i in 0..FRAMES {
        let frame = src.next_frame().unwrap();
        enc.encode(&frame, Duration::from_millis(i * 16), i == 0)
            .unwrap();
    }
    enc.flush().unwrap();
    drop(enc);
    let mut frames: Vec<_> = rx.try_iter().collect();
    frames.sort_by_key(|f| f.0);
    let mut dec = VtDecoder::new(SizeLimit::default());
    let mut sizes_ok = true;
    for (seq, data) in &frames {
        if let Ok(p) = dec.decode(*seq as u32, data) {
            sizes_ok &= (p.image().width(), p.image().height()) == (cfg.width, cfg.height);
        }
    }
    let s = dec.stats();
    // As for encode: the status word comes from the result.
    let status = if s.decoded == frames.len() as u64 && s.decoded > 0 && sizes_ok {
        "ok"
    } else if s.sessions_created == 0 && s.refused == 0 {
        // The keyframe passed our checks but no decoder session could be
        // created: no decoder on this machine. Frames we refused are our
        // own bug, never "unavailable".
        "unavailable"
    } else {
        "BROKEN"
    };
    println!(
        "VT_PROBE decode={status} frames={}/{} refused={} failed={} sessions={}",
        s.decoded,
        frames.len(),
        s.refused,
        s.failed,
        s.sessions_created
    );
    assert_ne!(
        status, "BROKEN",
        "a decoder was created but did not decode every frame"
    );
}
