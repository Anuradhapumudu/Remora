# Phase 2 acceptance criteria — macOS capture + hardware encode

Status: **criteria fixed before any capture code (2026-10-17). Results: not yet measured.**

Rule: thresholds in §2 are not changed after measuring. If one FAILS, work stops
and the failure is reported with the numbers and a proposed design change
(roadmap/owner decides). A threshold may only be changed by a new, dated entry
in §6 explaining why, approved by the owner.

## 1. Test machine and conditions

| Item | Value |
|---|---|
| Machine | Apple M4 (10 cores), 16 GB RAM |
| Display | Built-in Liquid Retina, 2560 × 1664 px, 60 Hz (the only display) |
| OS / SDK | macOS 27.0.1, Xcode 27.1, macOS SDK 27.0 |
| Build | `cargo build --release` (the pinned toolchain, LTO thin) |
| Power | On AC power, Low Power Mode off |
| Load | Only Terminal, the test tool, and (for motion tests) the motion pattern page open |
| Permission | Screen Recording granted to **Terminal.app** (tool runs from Terminal) |

**"1080p60" on this display.** The panel is 16:10.4, not 16:9. We capture the
whole display scaled to **1920 px wide at native aspect = 1920 × 1248**
(2.40 MP — 16 % *more* pixels than 1920 × 1080, so the test is conservative),
pixel format NV12 (`420v`, what the encoder consumes natively), at a requested
60 fps (`minimumFrameInterval` = 1/60 s). For reference, one run is also
reported at exactly 1920 × 1080 (letterboxed).

## 2. Thresholds

| ID | Metric | PASS if | How it is measured |
|---|---|---|---|
| C1 | **Capture delivery** latency | p50 **≤ 4 ms** and p95 **≤ 4 ms** | Per frame: `mach_absolute_time()` at entry of our ScreenCaptureKit output handler − the frame's display time from `SCStreamFrameInfo.displayTime` (same clock). Motion test, 60 s, all `complete` frames. |
| C2 | **Encode** latency | p50 **≤ 6 ms** and p95 **≤ 6 ms** | Per frame: time of VideoToolbox output callback − time of the `VTCompressionSessionEncodeFrame` call for the same frame (matched by presentation timestamp). Motion test, 60 s. |
| C3 | **Host CPU, static screen** | **< 2 %** of one core, averaged over 60 s | CPU time (user + system) consumed during the 60 s by our process **plus** every helper process whose CPU time grows because of the capture (expected: `VTEncoderXPCService`; any other found is listed), ÷ 60 s. Measured with `ps -o cputime` / `proc_pid_rusage` before and after. Cross-checked by a system-wide A/B (60 s idle vs 60 s capturing). "One core" is Activity Monitor's convention — stricter than "% of all 10 cores". |
| C4 | **No memory growth** | footprint(min 10) − footprint(min 1) **≤ 2 MB** and least-squares slope over minutes 1–10 **≤ 0.1 MB/min** | `phys_footprint` (Activity Monitor's "Memory" column) of our process sampled every 10 s during a 10-minute motion capture + encode. Minute 0 excluded (pools warming up). |
| C5 | **Encoder keeps up at 60 fps** | encoded frames **=** captured `complete` frames (**0 dropped**, **0 encoder errors**) **and** captured ≥ **3528** (98 % of 60 s × 60 fps) | 60 s motion test. Counters: frames delivered by SCK by status, frames submitted, frames encoded, frames dropped by our bounded queue, VT errors. If SCK delivers < 3528, that's reported as a capture shortfall even if the encoder kept up. |

p95 is the deciding statistic (a smooth average with spiky tails still stutters).
p99 and max are reported for information.

## 3. Test procedures

All runs use the Phase 2 CLI (deliverable):

```sh
cargo run --release -p remora-host -- bench-capture --seconds 60 --out /tmp/remora.h264
```

1. **Motion test (C1, C2, C5):** open `scripts/macos/motion-pattern.html` in Safari,
   enter full screen (⌃⌘F) so every frame changes (moving bars + frame counter
   drawn with `requestAnimationFrame`), then run the CLI for 60 s.
2. **Static test (C3):** close everything except Terminal, leave the screen
   untouched (no cursor movement, no clock with seconds), run 60 s with
   `--measure-cpu`. A baseline 60 s run without capturing is taken right before.
3. **Soak test (C4):** motion pattern, `--seconds 600 --sample-memory 10`.
4. **Encoder-only reference:** `--synthetic` feeds generated NV12 frames straight
   to the encoder (no capture) to separate encoder limits from capture limits.
5. Each test is run **3 times**; the **worst** run is the one judged.
6. The output `.h264` is checked with `ffprobe` (frame count, resolution,
   profile) and played in QuickTime/IINA to confirm it is a valid stream.

## 4. Questions to answer with evidence (not assumptions)

| ID | Question | Evidence that counts |
|---|---|---|
| Q1 | Does VideoToolbox on the M4 support **4:4:4 encode** (H.264 High 4:4:4 or HEVC Main 4:4:4 / RExt)? | A VT session created with a 4:4:4 source format and the profile set, producing frames whose format description reports 4:4:4 chroma — or the exact error codes returned. Listed encoders from `VTCopyVideoEncoderList`. |
| Q2 | **Gradual intra-refresh** support, or only **long-term reference (LTR)** frames? | `VTSessionCopySupportedPropertyDictionary` dump for the H.264 and HEVC hardware encoders on this machine (which keys exist, e.g. `EnableLTR`, any refresh-related keys), plus a test that enables LTR and requests a refresh from an acknowledged frame. |
| Q3 | Which **ScreenCaptureKit** API path is current and non-deprecated on macOS 27, and does "frames only on change" hold? | SDK 27.0 header availability/deprecation annotations for the APIs we call; on a static screen, counts of `SCFrameStatus.complete` vs `.idle` per second. |
| Q4 | What happens on **display resolution change**, **sleep/wake**, **display unplug**? | Observed callbacks/errors (`stream(_:didStopWithError:)`, frame size changes, status values) in a logged run for each event. Unplug needs an external display — if none is available, reported as **not tested**. |

## 5. Results

*To be filled with measured numbers. Each FAIL stops the phase (see top).*

| ID | p50 | p95 | p99 | max | Other | Verdict |
|---|---|---|---|---|---|---|
| C1 capture delivery | — | — | — | — | — | — |
| C2 encode | — | — | — | — | — | — |
| C3 static CPU | — | | | | | — |
| C4 memory growth | — | | | | | — |
| C5 keeps up | — | | | | | — |

| ID | Answer | Evidence |
|---|---|---|
| Q1 4:4:4 encode | — | — |
| Q2 intra-refresh / LTR | — | — |
| Q3 SCK API path + on-change | — | — |
| Q4 res change / sleep / unplug | — | — |

## 6. Changes to criteria

None.
