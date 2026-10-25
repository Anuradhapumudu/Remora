//! M7 (phase4-criteria §5): "viewer memory bounded" under a hostile
//! bitstream. Its own test binary, so the memory measured is this test's
//! alone (tests in one binary share a process).
//!
//! Memory = physical footprint **plus** the IOSurface memory mapped into
//! the process. Decoded pictures live in IOSurfaces, which `footprint`
//! does not count: a planted leak of every decoded picture (~100 MB) left
//! the footprint unchanged, while `vmmap --summary`'s IOSurface region
//! grew from 0.3 MB to 103.5 MB (2026-10-21, phase4-criteria §12).
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::vt::*;
use common::*;
use remora_codec::VtDecoder;
use remora_codec::h264::SizeLimit;

/// Memory growth allowed between the end of the warm-up and the end of
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
                    1 => real[(i / 3) % real.len()].1.clone(),
                    _ => body,
                }
            })
            .collect()
    };
    let warm = round(300);
    let run = round(3000);
    let (dec, _) = decode_all(VtDecoder::new(SizeLimit::default()), warm);
    // Every footprint is read right after decoding, never right after
    // `vmmap`: on GitHub's VM a footprint read just after `vmmap` came out
    // ~50 MB lower than one read a moment before it (66 → 14 MB, three runs
    // out of three), which made the check pass on a meaningless number
    // (phase4-criteria §12). So: footprint first, then `vmmap`.
    let before = (footprint(), iosurfaces());
    // The same 3000 frames in six parts, printing the footprint after each
    // (no `vmmap` in between): a leak keeps growing, warm-up levels off.
    let mut dec = dec;
    let mut run = run.into_iter();
    let mut last = 0;
    for part in 1..=6 {
        let (d, _) = decode_all(dec, run.by_ref().take(500).collect());
        dec = d;
        // Checked on every machine: the decoder's own objects are bounded
        // (pictures are dropped by `decode_all` as they come).
        let s = dec.stats();
        assert!(
            s.sessions_alive <= 1 && s.pictures_alive == 0,
            "after {} frames: {} decoder sessions, {} pictures alive",
            part * 500,
            s.sessions_alive,
            s.pictures_alive
        );
        last = footprint();
        println!(
            "M7 memory after {} frames: footprint {:.1} MB",
            part * 500,
            last as f64 / 1048576.0
        );
    }
    // On a virtual machine the footprint swings by tens of MB on its own
    // (GitHub's VM: 70 … 109 … 61 MB in one run, two readings 5 MB apart
    // with nothing in between), so it cannot measure an 8 MB growth there.
    // The limit is checked on real Macs only, and the test says which
    // (owner decision 2026-10-22, phase4-criteria §12); never skipped
    // silently: CI requires one of the two lines below.
    let vm = virtual_machine();
    let again = footprint();
    if !vm {
        // A measurement that cannot be trusted fails rather than passes:
        // two readings with no work between them must agree.
        assert!(
            last.abs_diff(again) <= 4 * 1024 * 1024,
            "footprint unstable: {last} then {again} bytes with nothing in between"
        );
    }
    let after = (last, iosurfaces());
    let s = dec.stats();
    let mb = |b: u64| b as f64 / 1048576.0;
    println!(
        "M7 memory: footprint {:.1} -> {:.1} MB, IOSurfaces {:.1} -> {:.1} MB \
         over 3000 hostile frames, {s:?}",
        mb(before.0),
        mb(after.0),
        mb(before.1),
        mb(after.1)
    );
    // Diagnosis only (not checked): the footprint right after `vmmap`.
    println!(
        "M7 memory: footprint just after vmmap {:.1} MB",
        mb(footprint())
    );
    let (b, a) = (before.0 + before.1, after.0 + after.1);
    if vm {
        println!(
            "M7 memory limit: NOT checked (virtual machine, kern.hv_vmm_present=1); \
             live decoder sessions and pictures checked"
        );
        return;
    }
    assert!(a <= b + GROWTH_LIMIT, "memory grew {} bytes", a - b);
    println!(
        "M7 memory limit: checked (+{:.1} MB, limit +8 MB); live decoder sessions and pictures checked",
        mb(a.saturating_sub(b))
    );
}

/// Whether this macOS runs in a virtual machine (`sysctl
/// kern.hv_vmm_present`: 1 in a VM, 0 on hardware).
fn virtual_machine() -> bool {
    let out = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.hv_vmm_present"])
        .output()
        .expect("sysctl");
    match String::from_utf8_lossy(&out.stdout).trim() {
        "1" => true,
        "0" => false,
        other => panic!("kern.hv_vmm_present: {other:?}"),
    }
}

/// Size of the IOSurface memory mapped into this process (`vmmap`'s
/// IOSurface region, virtual size), 0 if there is none.
fn iosurfaces() -> u64 {
    let out = std::process::Command::new("/usr/bin/vmmap")
        .args(["--summary", &std::process::id().to_string()])
        .output()
        .expect("vmmap");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("REGION TYPE"), "vmmap printed no summary");
    text.lines()
        .find_map(|l| l.strip_prefix("IOSurface "))
        .map_or(0, |rest| size(rest.split_whitespace().next().unwrap()))
}

/// `304K`, `103.5M`, `1.2G` → bytes.
fn size(v: &str) -> u64 {
    let (num, unit) = v.split_at(v.len() - 1);
    let n: f64 = num.parse().unwrap();
    let mult = match unit {
        "K" => 1024.0,
        "M" => 1048576.0,
        "G" => 1073741824.0,
        _ => return v.parse().unwrap(),
    };
    (n * mult) as u64
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
