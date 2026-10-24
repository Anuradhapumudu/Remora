//! VideoToolbox helpers shared by the M7 decoder tests (macOS only).

use std::sync::mpsc;
use std::time::Duration;

use remora_codec::h264::SizeLimit;
use remora_codec::{
    EncoderConfig, EncoderEvent, H264Profile, SyntheticSource, VtDecoder, VtEncoder,
};

/// Each decode call: the picture size, or the error as text.
pub(crate) type Outcome = Result<(u32, u32), String>;

/// No single decode call may take longer than this (phase4-criteria M7).
pub(crate) const WATCHDOG: Duration = Duration::from_secs(5);

/// `n` frames from the hardware encoder: frame 0 is a keyframe, and so is
/// every `keyframe_every`-th one (0 = only the first).
pub(crate) fn encode(width: u32, height: u32, n: u64, keyframe_every: u64) -> Vec<(bool, Vec<u8>)> {
    let cfg = EncoderConfig {
        width,
        height,
        profile: H264Profile::ConstrainedBaseline,
        ..EncoderConfig::default()
    };
    let (tx, rx) = mpsc::channel();
    let sink = Box::new(move |ev: EncoderEvent| {
        if let EncoderEvent::Frame(f) = ev {
            let _ = tx.send((f.seq, f.keyframe, f.data));
        }
    });
    let mut enc = VtEncoder::new(cfg, sink).expect("hardware encoder");
    let mut src = SyntheticSource::new(width, height).unwrap();
    for i in 0..n {
        let force = i == 0 || (keyframe_every > 0 && i % keyframe_every == 0);
        enc.encode(
            &src.next_frame().unwrap(),
            Duration::from_millis(i * 16),
            force,
        )
        .unwrap();
    }
    enc.flush().unwrap();
    drop(enc);
    let mut frames: Vec<_> = rx.try_iter().collect();
    frames.sort_by_key(|f| f.0);
    assert_eq!(frames.len() as u64, n, "encoder delivered every frame");
    assert!(frames[0].1, "first frame is a keyframe");
    frames.into_iter().map(|(_, k, d)| (k, d)).collect()
}

/// Runs `inputs` through `dec` on a worker thread; the test fails if any
/// one decode call takes longer than [`WATCHDOG`]. Returns the decoder and
/// each call's result (`Ok` = a picture of that size).
pub(crate) fn decode_all(mut dec: VtDecoder, inputs: Vec<Vec<u8>>) -> (VtDecoder, Vec<Outcome>) {
    let n = inputs.len();
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        for (i, f) in inputs.iter().enumerate() {
            let r = dec
                .decode(i as u32, f)
                .map(|p| (p.image().width(), p.image().height()))
                .map_err(|e| e.to_string());
            tx.send(r).unwrap();
        }
        dec
    });
    let mut results = Vec::with_capacity(n);
    for i in 0..n {
        match rx.recv_timeout(WATCHDOG) {
            Ok(r) => results.push(r),
            Err(_) => panic!("decode call {i} did not return within {WATCHDOG:?}"),
        }
    }
    (worker.join().unwrap(), results)
}

pub(crate) fn xorshift(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

pub(crate) fn random_bytes(x: &mut u64, len: usize) -> Vec<u8> {
    (0..len).map(|_| xorshift(x) as u8).collect()
}

/// The SPS and PPS NAL units of a real keyframe.
pub(crate) fn parameter_sets(key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let f = remora_codec::h264::parse_frame(key, SizeLimit::default()).unwrap();
    (f.sps.unwrap().0.to_vec(), f.pps.unwrap().to_vec())
}
