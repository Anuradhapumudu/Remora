//! P5 (phase4-criteria §4), the case the owner's 10-minute run did not
//! cover: a viewer window that cannot draw (covered, minimised, on
//! another Space) still receives and uploads every picture. Found
//! 2026-10-23: such a window grew to 2.4 GB in 15 s — each upload's
//! staging copy waited for a `queue.submit` that only a draw makes
//! (wgpu-core 30.0.1 `src/device/queue.rs:1529`: pending writes go out
//! with the next submit, even an empty one).
//!
//! Uploads full-HD pictures with no draw at all and checks the process
//! footprint stays bounded: the leak would add ≈ 3 MB per picture.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use remora_codec::Nv12;
use remora_viewer::render::{Renderer, headless};

const W: u32 = 1920;
const H: u32 = 1080;
const PICTURES: usize = 300;
/// A leak of 300 × 3.1 MB is ≈ 930 MB; GitHub's VM footprint readings
/// swing by ~50 MB (phase4-criteria §12, M7), so 150 MB separates them.
const MAX_GROWTH_MB: f64 = 150.0;
/// How long the GPU may take to finish 300 uploads (≈ 1 GB of copies);
/// far above what the M4 or the VM needs, far below CI's job timeout.
const GPU_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

#[test]
fn p5_pictures_that_are_never_drawn_do_not_pile_up() {
    let (device, queue) = headless().expect("a Metal adapter (the viewer needs a GPU)");
    let mut renderer = Renderer::new(device, queue, wgpu::TextureFormat::Rgba8Unorm);
    let y = vec![0x80u8; (W * H) as usize];
    let uv = vec![0x80u8; (W * H / 2) as usize];
    let picture = Nv12::new(W, H, &y, W as usize, &uv, W as usize).expect("valid planes");
    // Warm up: textures, pipeline, the driver's own pools.
    for _ in 0..20 {
        renderer.upload(&picture);
    }
    let before = footprint_mb();
    for _ in 0..PICTURES {
        renderer.upload(&picture);
    }
    // The question is whether the memory comes back, not how far the
    // uploads ran ahead of the GPU: 300 pictures in ~1.7 s is a burst no
    // window sees (60 a second). On GitHub's VM, whose GPU is slower, the
    // reading right after the burst caught copies still in flight
    // (+274 MB, 2026-10-23). So wait for the GPU first. A real leak is
    // unaffected: copies never sent are never freed, however long we wait.
    // Bounded wait (wgpu-hal 30.0.1 Metal `wait` honours the timeout,
    // `src/metal/device.rs:2041-2044`): a stuck GPU fails the test instead
    // of hanging CI.
    renderer
        .device()
        .poll(wgpu::PollType::Wait {
            submission_index: None,
            timeout: Some(GPU_WAIT),
        })
        .expect("the GPU did not finish the uploads in time");
    let after = footprint_mb();
    let growth = after - before;
    println!("P5 upload memory: {before:.1} -> {after:.1} MB over {PICTURES} undrawn pictures");
    assert!(
        growth <= MAX_GROWTH_MB,
        "{growth:.1} MB more after {PICTURES} uploads with no draw (limit {MAX_GROWTH_MB} MB)"
    );
}

/// `phys_footprint` of this process in MB (Activity Monitor's "Memory").
fn footprint_mb() -> f64 {
    let out = std::process::Command::new("/usr/bin/footprint")
        .args(["-p", &std::process::id().to_string()])
        .output()
        .expect("footprint");
    let text = String::from_utf8_lossy(&out.stdout);
    let after = text.split("Footprint:").nth(1).expect("Footprint: line");
    let mut it = after.split_whitespace();
    let value: f64 = it.next().unwrap().parse().unwrap();
    value
        * match it.next().unwrap() {
            "B" => 1.0 / 1048576.0,
            "KB" => 1.0 / 1024.0,
            "MB" => 1.0,
            "GB" => 1024.0,
            u => panic!("unit {u}"),
        }
}
