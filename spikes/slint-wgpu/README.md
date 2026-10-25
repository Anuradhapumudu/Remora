# Slint + wgpu render spike (throwaway, 2026-10-19)

Owner request: before the Phase 4 criteria, prove that the Slint + wgpu
integration works the way the architecture assumes, and find out whether a
VideoToolbox IOSurface can be shown without a CPU copy. Timebox ~1 hour
(ran 17:24–17:40 UTC).

**Not part of the product.** Own workspace and lockfile (excluded from the
root workspace), so none of its dependencies reach the main crates, and it is
not held to the workspace rules (it uses `unwrap`, and `unsafe` without
`// SAFETY:` comments). Findings are recorded in docs/architecture.md D32.

## Run

```sh
cd spikes/slint-wgpu
cargo run --release -- bench          # zero-copy vs CPU upload, headless
cargo run --release -- verify         # zero-copy pixels == CPU reference
cargo run --release -- verify-plant   # planted wrong chroma plane: must FAIL
cargo run --release -- window         # Slint window, 4 s
cargo run --release -- raw-fifo       # plain winit + wgpu, Fifo, 3 s
cargo run --release -- raw-immediate  # plain winit + wgpu, Immediate, 3 s
```

## Machine

MacBook Air (Mac16,12), Apple M4, macOS 27.0.1, built-in 60 Hz display
(2560 × 1664). **On battery power** (Phase 2 measured on AC; these numbers are
for orientation, Phase 4 re-measures under phase2-criteria §1 conditions).
Frames are 1920 × 1080 NV12 (`420v`), IOSurface-backed CVPixelBuffers, the
same kind VideoToolbox's decoder returns.

Versions: slint 1.18.1 (`unstable-wgpu-30`, femtovg-wgpu renderer), wgpu
30.0.1, winit 0.30.13, objc2-metal / objc2-core-video / objc2-io-surface 0.3.2.

## Results

### 1. Zero-copy IOSurface → wgpu: WORKS

Each NV12 plane is wrapped as a Metal texture with
`-[MTLDevice newTextureWithDescriptor:iosurface:plane:]` (objc2-metal
`MTLDevice.rs:995`), then as a wgpu texture with
`wgpu_hal::metal::Device::texture_from_raw` (wgpu-hal 30.0.1
`src/metal/device.rs:415`) and `wgpu::Device::create_texture_from_hal`
(wgpu 30.0.1 `src/api/device.rs:341`). A shader converts NV12 (BT.709 video
range) to RGBA.

**Correctness, not just speed:** `verify` reads the result back and compares
7 pixels with the same formula computed on the CPU from the buffer's own
bytes: worst channel error **2 / 255 → MATCH**. `verify-plant` feeds a wrong
chroma plane: worst error **255 → MISMATCH, exit 1**. So the GPU really reads
the IOSurface memory (a black or stale texture would have been just as fast).

### 2. Cost per frame (to GPU completion), 300 frames, three runs

| Path | p50 (ms) | p95 (ms) |
|---|---|---|
| Zero-copy: wrap planes + NV12→RGBA pass | 0.39 / 0.39 / 0.99 | 0.54 / 0.77 / 1.26 |
| **CPU upload from the locked CVPixelBuffer** (the real fallback) + same pass | 0.70 / 0.69 / 0.69 | 0.80 / 0.77 / 0.75 |
| CPU upload of a ready NV12 buffer (3.1 MB) + same pass | 0.70 / 0.64 / 0.64 | 1.95 / 0.70 / 0.69 |
| CPU upload of RGBA (8.3 MB), no pass | 1.10 / 1.13 / 1.14 | 1.26 / 1.23 / 1.26 |

Earlier single runs: zero-copy p50 0.40 / 0.39 / 0.78 / 0.95.

Reading: on this unified-memory M4, both paths stay **≈ 1.3 ms p95 or
better**. Zero-copy usually wins at the median (≈ 0.3 ms) but varies more
between runs; the CPU upload is steady. Upload NV12 and convert on the GPU;
never convert to RGBA on the CPU (2.7× the bytes).

### 3. Slint `unstable-wgpu-30`: behaves as documented — with one hard limit

* `BackendSelector::require_wgpu_30(WGPUConfiguration::default())` selected the
  wgpu renderer; the rendering notifier delivered
  `GraphicsAPI::WGPU30 { device, queue, .. }` (Slint's own device), and
  `slint::Image::try_from(wgpu::Texture)` accepted our converted texture. 221
  frames shown in 4 s, each a new zero-copy frame.
* Documented import rules (i-slint-core 1.18.1 `graphics/wgpu_30.rs:104-117`):
  the texture must be `Rgba8Unorm`/`Rgba8UnormSrgb` with `TEXTURE_BINDING |
  RENDER_ATTACHMENT`. So Slint cannot take NV12 planes: we always need our own
  NV12→RGBA pass (measured above, included in the numbers).
* **Slint always waits for vsync.** The femtovg-wgpu renderer hard-codes
  `surface_config.present_mode = wgpu::PresentMode::AutoVsync`
  (i-slint-renderer-femtovg 1.18.1 `wgpu.rs:339`; the Skia renderer does the
  same, `wgpu_30_surface.rs:104`), with no setting to change it. Measured
  frame interval: **p50 16.67 ms, p95 18.16 ms** — locked to the 60 Hz display.
  quality.md §2 says "never `Fifo`"; a Slint-presented video cannot meet that.

### 4. Plain winit + wgpu: can present without vsync

The Metal surface offers `[Fifo, Immediate]` (wgpu-hal enables Immediate via
`CAMetalLayer.displaySyncEnabled = false`, `src/metal/adapter.rs:462`,
`surface.rs:263/337`). Zero-copy frames converted straight into the swapchain
image:

| Present mode | frames in 3 s | frame interval p50 / p95 (ms) |
|---|---|---|
| Fifo | 104 | 16.70 / 17.43 (vsync-paced) |
| Immediate | 928 | 2.21 / 5.32 (not paced) |

(The Fifo run also logged many `Occluded`/`Timeout` acquire skips while the
window first appeared; not investigated — spike.)

**Not verified:** how much sooner pixels reach the glass with Immediate. A
windowed app on macOS still goes through the WindowServer compositor, which
composites at the display refresh. Measuring that needs a camera or a
photodiode; it is a Phase 4 report item, not a claim.

## What this does NOT show

* Real decoder output (VideoToolbox decode) — synthetic IOSurface buffers of
  the same format were used. Buffer lifetime with a decoder pool (the GPU must
  finish reading before the decoder reuses the buffer) is untested.
* Any resolution other than 1920 × 1080, any other Mac, any other OS.
* Slint + our own video surface in the same window (Phase 7 question).
