//! `remora-host bench-encoder` (Linux): which openh264 settings give the
//! best balance of sharpness, encode time (LP1: p95 ≤ 20 ms) and picture
//! size (large pictures lose more packets on Wi-Fi: LP4)?
//!
//! Captures the live screen through the portal for `--seconds` and gives
//! every picture to one encoder per setting, timing each. Prints times
//! and sizes only — never the picture (INV9); nothing is saved or sent.
//! Pictures that arrive while the encoders are busy are skipped by
//! PipeWire, so the counts can be lower than the screen's frame rate.

use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use anyhow::Context;
use remora_capture::{CaptureConfig, CaptureEvent, PortalCapture, PortalOptions, ScreenCapture};
use remora_codec::{EncoderConfig, EncoderEvent, OpenH264Encoder, OpenH264Tuning};

/// The settings compared (bitrate, finest QP, coarsest QP).
const TUNINGS: [(&str, u32, u8, u8); 5] = [
    ("now 8M qp10-36", 8_000_000, 10, 36),
    ("spike 120k qp0-51", 120_000, 0, 51),
    ("4M qp20-34", 4_000_000, 20, 34),
    ("8M qp18-30", 8_000_000, 18, 30),
    ("2M qp22-36", 2_000_000, 22, 36),
];

#[derive(Default)]
struct Run {
    ms: Vec<f64>,
    bytes: Vec<usize>,
}

fn pct<T: Copy + PartialOrd>(v: &[T], p: f64) -> Option<T> {
    let mut v = v.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let i = ((v.len().checked_sub(1)?) as f64 * p).round() as usize;
    v.get(i).copied()
}

pub(crate) fn run(seconds: u64) -> anyhow::Result<()> {
    let mut cap = PortalCapture::open(
        CaptureConfig {
            show_cursor: true,
            ..CaptureConfig::default()
        },
        PortalOptions {
            restore_token: crate::serve::load_portal_token(),
            control: true, // the saved permission is for screen + control
        },
    )?;
    crate::serve::save_portal_token(cap.take_new_token());
    let runs: Arc<Mutex<Vec<Run>>> =
        Arc::new(Mutex::new(TUNINGS.iter().map(|_| Run::default()).collect()));
    let mut encoders = Vec::new();
    for (i, (_, bps, lo, hi)) in TUNINGS.iter().enumerate() {
        let r = Arc::clone(&runs);
        let enc = OpenH264Encoder::with_tuning(
            EncoderConfig::default(),
            OpenH264Tuning {
                bitrate_bps: *bps,
                qp_min: *lo,
                qp_max: *hi,
            },
            Box::new(move |ev| {
                if let EncoderEvent::Frame(f) = ev
                    && let Ok(mut runs) = r.lock()
                    && let Some(run) = runs.get_mut(i)
                {
                    run.bytes.push(f.data.len());
                }
            }),
        )
        .with_context(|| format!("encoder {i}"))?;
        encoders.push(enc);
    }
    let (done_tx, done_rx) = mpsc::channel();
    let r = Arc::clone(&runs);
    cap.start(Box::new(move |ev| match ev {
        CaptureEvent::Frame(f) => {
            let Some(img) = f.image.as_ref() else { return };
            for (i, enc) in encoders.iter_mut().enumerate() {
                let t = Instant::now();
                let ok = enc.encode(img, Duration::ZERO, false).is_ok();
                let ms = t.elapsed().as_secs_f64() * 1e3;
                if ok
                    && let Ok(mut runs) = r.lock()
                    && let Some(run) = runs.get_mut(i)
                {
                    run.ms.push(ms);
                }
            }
        }
        CaptureEvent::Stopped(e) => {
            let _ = done_tx.send(e.to_string());
        }
        _ => {}
    }))?;
    eprintln!("bench-encoder: measuring for {seconds} s - move things on the screen");
    if let Ok(why) = done_rx.recv_timeout(Duration::from_secs(seconds)) {
        eprintln!("capture stopped early: {why}");
    }
    cap.stop()?;
    let runs = runs
        .lock()
        .map_err(|_| anyhow::anyhow!("results lock poisoned"))?;
    println!(
        "setting              pictures  encode p50/p95 ms   bytes p50 / p95 / max   Mbit/s at 30 fps"
    );
    for ((name, ..), run) in TUNINGS.iter().zip(runs.iter()) {
        let (Some(e50), Some(e95)) = (pct(&run.ms, 0.5), pct(&run.ms, 0.95)) else {
            println!("{name:<20} no pictures");
            continue;
        };
        let b50 = pct(&run.bytes, 0.5).unwrap_or(0);
        let b95 = pct(&run.bytes, 0.95).unwrap_or(0);
        let max = run.bytes.iter().copied().max().unwrap_or(0);
        let avg = run.bytes.iter().sum::<usize>() as f64 / run.bytes.len().max(1) as f64;
        println!(
            "{name:<20} {:>8}  {e50:>6.1} / {e95:<6.1}     {b50:>7} / {b95:>7} / {max:>7}   {:>5.1}",
            run.ms.len(),
            avg * 8.0 * 30.0 / 1e6
        );
    }
    Ok(())
}
