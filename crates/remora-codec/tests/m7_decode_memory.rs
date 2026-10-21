//! M7 (phase4-criteria §5): "viewer memory bounded" under a hostile
//! bitstream. Its own test binary, so the footprint measured is this
//! test's alone (tests in one binary share a process).
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::vt::*;
use common::*;
use remora_codec::VtDecoder;
use remora_codec::h264::SizeLimit;

/// Footprint growth allowed between the end of the warm-up and the end of
/// the hostile run (fixed before measuring).
const GROWTH_LIMIT: u64 = 8 * 1024 * 1024;

#[test]
fn m7_memory_stays_bounded_under_a_hostile_stream() {
    let real = encode(640, 360, 4, 0);
    let (sps, pps) = parameter_sets(&real[0].1);
    let mut x = 0x9E37_79B9_7F4A_7C15;
    let mut round = |n: usize| -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let body = random_bytes(&mut x, 2000);
                match i % 3 {
                    0 => {
                        let mut idr = vec![0x65];
                        idr.extend_from_slice(&body);
                        annexb(&[&sps, &pps, &idr])
                    }
                    1 => real[i % real.len()].1.clone(),
                    _ => body,
                }
            })
            .collect()
    };
    let warm = round(300);
    let run = round(3000);
    let (dec, _) = decode_all(VtDecoder::new(SizeLimit::default()), warm);
    let before = footprint();
    let (dec, _) = decode_all(dec, run);
    let after = footprint();
    let s = dec.stats();
    println!(
        "M7 memory: footprint {:.1} MB -> {:.1} MB over 3000 hostile frames, {s:?}",
        before as f64 / 1048576.0,
        after as f64 / 1048576.0
    );
    assert!(
        after <= before + GROWTH_LIMIT,
        "footprint grew {} bytes",
        after - before
    );
}

/// This process's physical footprint (Activity Monitor's "Memory").
fn footprint() -> u64 {
    let out = std::process::Command::new("/usr/bin/footprint")
        .args(["-p", &std::process::id().to_string()])
        .output()
        .expect("footprint");
    let text = String::from_utf8_lossy(&out.stdout);
    let after = text.split("Footprint:").nth(1).expect("Footprint: line");
    let mut it = after.split_whitespace();
    let value: f64 = it.next().unwrap().parse().unwrap();
    let unit = match it.next().unwrap() {
        "B" => 1.0,
        "KB" => 1024.0,
        "MB" => 1048576.0,
        "GB" => 1073741824.0,
        u => panic!("unit {u}"),
    };
    (value * unit) as u64
}
