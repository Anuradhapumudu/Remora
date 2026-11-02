//! A4 (phase4.8-criteria, INV9): the `Debug` form of an audio packet
//! prints its sequence number, time and size, never the Opus bytes, so a
//! `{:?}` in a log line or an error cannot leak sound. Same method as N4
//! for video (`n4_debug.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use remora_proto::audio::{AudioPacket, MAX_OPUS_BYTES};
use remora_testkit::canary::find_windows;

#[test]
fn a4_audio_packets_print_no_sound() {
    let data: Vec<u8> = (0..MAX_OPUS_BYTES)
        .map(|i| (i as u8).wrapping_mul(73).wrapping_add(151))
        .collect();
    let p = AudioPacket {
        seq: 9,
        capture_ts_us: 1_234,
        data: data.clone(),
    };
    let text = format!("{p:?}");
    let leaks = find_windows(&text, "audio", &data, 16);
    assert!(leaks.is_empty(), "AudioPacket prints sound: {leaks:?}");
    assert_eq!(
        text,
        format!("AudioPacket {{ seq: 9, capture_ts_us: 1234, bytes: {MAX_OPUS_BYTES} }}")
    );
}
