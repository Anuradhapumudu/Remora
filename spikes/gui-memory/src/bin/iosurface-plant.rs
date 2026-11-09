//! Spike S1, method check for P5 (owner, 2026-10-26): which memory measure
//! sees a known allocation of IOSurfaces, and which sees ordinary heap?
//!
//!   A. hold 8 IOSurface-backed 3840 × 2160 NV12 pictures that THIS process
//!      creates (the codec's `SyntheticSource`, the host's pool code; ≈ 95 MB)
//!   C. hold 28 pictures DECODED by VideoToolbox (`VtDecoder`, the viewer's
//!      decoder), 1920 × 1248 as in P5 (≈ 3.4 MB each, ≈ 96 MB)
//!   B. a 100 MiB heap buffer, every page written
//!
//! After each step it prints `footprint` (phys_footprint, what P5 counts)
//! and `vmmap --summary`'s IOSurface row (what M7 counts), footprint first
//! (M7 found a footprint read just after `vmmap` can come out wrong).

use std::process::Command;

use std::sync::mpsc;
use std::time::Duration;

use remora_codec::h264::SizeLimit;
use remora_codec::{EncoderConfig, EncoderEvent, H264Profile, SyntheticSource, VtDecoder, VtEncoder};

const W: u32 = 3840;
const H: u32 = 2160;
const PICTURES: usize = 8;

fn footprint_mb() -> f64 {
    let out = Command::new("/usr/bin/footprint").args(["-p", &std::process::id().to_string()]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("Footprint:")).unwrap_or("");
    let mut it = line.split("Footprint:").nth(1).unwrap_or("").split_whitespace();
    let v: f64 = it.next().unwrap_or("0").parse().unwrap();
    match it.next().unwrap_or("MB") {
        "KB" => v / 1024.0,
        "GB" => v * 1024.0,
        "B" => v / 1048576.0,
        _ => v,
    }
}

/// vmmap's IOSurface row: (virtual, resident, dirty) in MB.
fn iosurface_mb() -> (f64, f64, f64) {
    let out = Command::new("/usr/bin/vmmap").args(["--summary", &std::process::id().to_string()]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(rest) = text.lines().find_map(|l| l.strip_prefix("IOSurface ")) else {
        return (0.0, 0.0, 0.0);
    };
    let c: Vec<f64> = rest.split_whitespace().take(3).map(mb).collect();
    (c[0], c[1], c[2])
}

/// `304K`, `103.5M`, `1.2G` → MB.
fn mb(v: &str) -> f64 {
    let (num, unit) = v.split_at(v.len() - 1);
    let n: f64 = num.parse().unwrap_or(0.0);
    match unit {
        "K" => n / 1024.0,
        "M" => n,
        "G" => n * 1024.0,
        _ => v.parse::<f64>().unwrap_or(0.0) / 1048576.0,
    }
}

fn show(step: &str) -> (f64, f64) {
    let f = footprint_mb();
    let (v, r, d) = iosurface_mb();
    println!("{step:<44} footprint {f:7.1} MB | IOSurface virtual {v:7.1} resident {r:7.1} dirty {d:7.1} MB");
    (f, v)
}

fn main() {
    let expected = PICTURES as f64 * f64::from(W * H) * 1.5 / 1048576.0;
    println!("pid {}; plant A = {PICTURES} × {W}×{H} NV12 ≈ {expected:.1} MB (no row padding)", std::process::id());
    let mut src = SyntheticSource::new(W, H).unwrap();
    let (f0, v0) = show("0. baseline (pool created, no picture)");

    let held: Vec<_> = (0..PICTURES).map(|_| src.next_frame().unwrap()).collect();
    let (f1, v1) = show("A. holding 8 IOSurface pictures");
    println!("   delta A: footprint {:+.1} MB, IOSurface virtual {:+.1} MB", f1 - f0, v1 - v0);

    drop(held);
    let (f2, v2) = show("A'. pictures dropped (pool keeps buffers?)");
    drop(src);
    let (f3, v3) = show("A''. pool dropped too");

    // C: pictures decoded by VideoToolbox. Encode first (its pool and
    // encoder are dropped before the baseline), then decode and hold.
    let (cw, ch, n) = (1920u32, 1248u32, 28u64);
    let cfg = EncoderConfig { width: cw, height: ch, profile: H264Profile::ConstrainedBaseline, ..EncoderConfig::default() };
    let (tx, rx) = mpsc::channel();
    let mut enc = VtEncoder::new(
        cfg,
        Box::new(move |ev: EncoderEvent| {
            if let EncoderEvent::Frame(f) = ev {
                let _ = tx.send((f.seq, f.data));
            }
        }),
    )
    .unwrap();
    let mut csrc = SyntheticSource::new(cw, ch).unwrap();
    for i in 0..n {
        enc.encode(&csrc.next_frame().unwrap(), Duration::from_millis(i * 16), i == 0).unwrap();
    }
    enc.flush().unwrap();
    drop(enc);
    drop(csrc);
    let mut stream: Vec<_> = rx.try_iter().collect();
    stream.sort_by_key(|f| f.0);
    let expected_c = n as f64 * f64::from(cw * ch) * 1.5 / 1048576.0;
    println!("plant C = {} decoded {cw}×{ch} NV12 ≈ {expected_c:.1} MB (no row padding)", stream.len());
    let mut dec = VtDecoder::new(SizeLimit::default());
    let (f5, v5) = show("C0. encoder gone, decoder created");
    let decoded: Vec<_> = stream.iter().enumerate().map(|(i, (_, d))| dec.decode(i as u32, d).unwrap()).collect();
    let (f6, v6) = show("C. holding 28 decoded pictures");
    println!("   delta C: footprint {:+.1} MB, IOSurface virtual {:+.1} MB", f6 - f5, v6 - v5);
    drop(decoded);
    drop(dec);
    let (f7, v7) = show("C''. pictures and decoder dropped");

    let mut heap = vec![0u8; 100 << 20];
    for i in (0..heap.len()).step_by(4096) {
        heap[i] = 1;
    }
    let (f4, v4) = show("B. + 100 MiB heap, every page written");
    println!("   delta B: footprint {:+.1} MB, IOSurface virtual {:+.1} MB", f4 - f7, v4 - v7);
    println!("   (A' vs A: footprint {:+.1}, IOSurface {:+.1}; A'' vs A': {:+.1}, {:+.1})", f2 - f1, v2 - v1, f3 - f2, v3 - v2);
    std::hint::black_box(&heap);
}
