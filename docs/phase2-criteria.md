# Phase 2 acceptance criteria — macOS capture + hardware encode

Status: criteria fixed before any capture code (2026-10-17); **C2 revised by owner
decision (§6)**. Results: partial (§5); capture tests wait for Screen Recording permission.

> **These thresholds are PER-CHIP: they apply to the Apple M4 test machine only.**
> Hardware encoders differ. Intel Macs, Windows (NVENC / QuickSync / AMF) and Linux
> (VAAPI) are re-measured in their own phases and may have different floors.
> Nobody may cite an M4 number for another chip.

Rule: thresholds in §2 are not changed after measuring. If one FAILS, work stops
and the failure is reported with the numbers and a proposed design change
(roadmap/owner decides). A threshold may only be changed by a new, dated entry
in §6 explaining why, approved by the owner.

## 1. Test machine and conditions

| Item | Value |
|---|---|
| Machine | Apple M4 (10 cores), 16 GB RAM |
| Display | Built-in Liquid Retina, panel 2560 × 1664 px, 60 Hz (the only display). **Running in a scaled mode: 1470 × 956 pt rendered at 2940 × 1912 px** — capture scales down from 2940 × 1912 |
| OS / SDK | macOS 27.0.1, Xcode 27.1, macOS SDK 27.0 |
| Build | `cargo build --release` (the pinned toolchain, LTO thin) |
| Power | On AC power, Low Power Mode off |
| Load | Only Terminal, the test tool, and (for motion tests) the motion pattern page open |
| Permission | Screen Recording granted to **RemoraDev.app** only (`io.github.anuradhapumudu.Remora.dev`, signed with the local dev identity; launched via `scripts/macos/dev-app.sh run …`). Terminal has no access. |

**"1080p60" on this display.** The panel is 16:10.4, not 16:9. We capture the
whole display scaled to **1920 px wide at native aspect = 1920 × 1248**
(2.40 MP — 16 % *more* pixels than 1920 × 1080, so the test is conservative),
pixel format NV12 (`420v`, what the encoder consumes natively), at a requested
60 fps (`minimumFrameInterval` = 1/60 s). For reference, one run is also
reported at exactly 1920 × 1080 (letterboxed).

## 2. Thresholds

| ID | Metric | PASS if | How it is measured |
|---|---|---|---|
| C1 | **Capture delivery** latency | p50 **≤ 4 ms** and p95 **≤ 4 ms** | Per frame: `mach_absolute_time()` at entry of our ScreenCaptureKit output handler − the frame's display time from `SCStreamFrameInfo.displayTime` (same clock). Motion test, 60 s, **all** `complete` frames, **signed** (a frame delivered before its display time counts as a negative value; none are excluded — see §6 clarification). |
| C2 | **Encode** latency | p95 **≤ 7 ms** (p50 reported) — *revised 2026-10-17, §6* | Per frame: time of VideoToolbox output callback − time of the `VTCompressionSessionEncodeFrame` call for the same frame (matched by presentation timestamp). Motion test, 60 s. |
| C3 | **Host CPU, static screen** | **< 2 %** of one core, averaged over 60 s | CPU time (user + system) consumed during the 60 s by our process **plus** every helper process whose CPU time grows because of the capture (expected: `VTEncoderXPCService`; any other found is listed), ÷ 60 s. Measured with `ps -o cputime` / `proc_pid_rusage` before and after. Cross-checked by a system-wide A/B (60 s idle vs 60 s capturing). "One core" is Activity Monitor's convention — stricter than "% of all 10 cores". |
| C4 | **No memory growth** | footprint(min 10) − footprint(min 1) **≤ 2 MB** and least-squares slope over minutes 1–10 **≤ 0.1 MB/min** | `phys_footprint` (Activity Monitor's "Memory" column) of our process sampled every 10 s during a 10-minute motion capture + encode. Minute 0 excluded (pools warming up). |
| C5 | **Encoder keeps up at 60 fps** | encoded frames **=** captured `complete` frames (**0 dropped**, **0 encoder errors**) **and** captured ≥ **3528** (98 % of 60 s × 60 fps) | 60 s motion test. Counters: frames delivered by SCK by status, frames submitted, frames encoded, frames dropped by our bounded queue, VT errors. If SCK delivers < 3528, that's reported as a capture shortfall even if the encoder kept up. |

p95 is the deciding statistic (a smooth average with spiky tails still stutters).
p99 and max are reported for information.

## 3. Test procedures

All runs use the Phase 2 CLI (deliverable):

```sh
scripts/macos/dev-app.sh run bench-capture --seconds 60 --out /tmp/remora.h264
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

### 5.1 Measured so far (2026-10-17, release build, AC power)

| ID | p50 | p95 | p99 | max | Other | Verdict |
|---|---|---|---|---|---|---|
| C1 capture delivery | — | — | — | — | needs Screen Recording permission | pending |
| C2 encode — **encoder-only reference** (`--synthetic`, 1920×1248, 30 s) | **6.38** | **6.76** | 7.00 | 26.96 | 1801 frames | FAIL vs original 6 ms; **PASS vs revised ≤ 7 ms p95** |
| C2 encode — official motion-capture run | — | — | — | — | | pending |
| C3 static CPU | — | | | | | pending |
| C4 memory growth | — | | | | | pending |
| C5 keeps up — encoder-only reference | | | | | 1801/1801 encoded, 0 dropped, 0 errors, 60.0 fps | PASS (reference) |

Output validity: `ffprobe` decodes all 1801 frames — H.264 Constrained Baseline,
1920×1248, yuv420p.

### 5.2 C2 investigation (encoder-only, `--synthetic`, 15–20 s each, p50 / p95 ms)

| Variant | p50 | p95 | Note |
|---|---|---|---|
| default (Constrained Baseline, 1920×1248, 60 fps) | 6.13–6.40 | 6.51–6.82 | 5 runs |
| `MaximizePowerEfficiency=false` | 6.20 | 6.64 | no real change |
| Constrained High | 6.29 | 6.86 | no change |
| 1920×1080 | 6.45 | 7.83 | not faster |
| 1280×720 | 6.26 | 6.68 | ~same as 1248p → per-frame floor |
| 640×360 | 3.76 | 4.31 | only tiny frames are faster |
| 2560×1664 (native) | 9.92 | 10.47 | |
| 30 / 120 fps | 6.34 / 6.06 | 6.82 / 6.58 | frame rate irrelevant |
| HEVC (low-latency RC) | 6.66 | 7.20 | slower |
| `NumberOfSlices=2` or `4` | — | — | accepted, then **every frame fails** (OSStatus −12910) |
| `RequestedMaxEncoderLatency` (undocumented) | 6.12–6.41 | 6.72–6.92 | accepted, no effect |
| `PrioritizeEncodingSpeedOverQuality` | — | — | **not supported** in low-latency mode on M4 (rejected) |

Conclusion: the M4's H.264 low-latency hardware path has a floor of about
**6.1–6.4 ms p50 / 6.5–6.9 ms p95 for any frame ≥ 720p**. No documented or
undocumented setting found lowers it. Owner decision: §6.

### 5.3 Questions

| ID | Answer | Evidence |
|---|---|---|
| Q1 4:4:4 encode | **Yes in hardware, but NOT in low-latency mode.** Normal rate control: H.264 High 4:4:4 Predictive and HEVC Range Extensions produce real 4:4:4 (`chroma_format_idc = 3`). Low-latency rate control: 4:4:4 input is **silently subsampled** to 4:2:0 (H.264 High, `chroma_format_idc = 1`); no 4:4:4/4:2:2 profile is offered in that mode. | `docs/evidence/phase2-probe-encoder-m4.txt` (SPS parsed by `remora_codec::bitstream`, unit-tested) |
| Q2 intra-refresh / LTR | **Documented API: long-term reference only** (`EnableLTR` + `AcknowledgedLTRTokens` + `ForceLTRRefresh`; no refresh key in SDK 27 headers). The low-latency H.264 encoder **additionally exposes undocumented** `PeriodicRefreshMode` and `MaxRefreshFrameIntervalDuration` (likely gradual refresh). Not yet exercised: an LTR acknowledge/refresh round trip. | Same evidence file (supported-property dump); SDK header grep |
| Q3 SCK API path | **Header part answered:** in SDK 27 the only deprecated ScreenCaptureKit items are `SCStreamType`/`streamType` (unused by us); `SCShareableContent` → `SCContentFilter(display:)` → `SCStreamConfiguration` → `SCStream` + `SCStreamOutput` is current. **Runtime "frames only on change": pending** (needs permission). | `ScreenCaptureKit.framework/Headers` in SDK 27.0 |
| Q4 res change / sleep / unplug | Physical display unplug: **not tested — no external display available** (known gap). Single-display subset: pending (§5.4). | — |

## 6. Changes to criteria

### 2026-10-17 — C2 raised from "p50 and p95 ≤ 6 ms" to "p95 ≤ 7 ms" (owner-approved, option A)

* **Why:** the original 6 ms was an **unmeasured planning estimate** from the
  Phase 1 latency budget (quality.md §2), not a measured requirement.
* **Evidence:** on the M4, the low-latency H.264 hardware encoder has a floor of
  **≈ 6.4 ms p50 / ≈ 6.9 ms p95 at 720p and above**, shown by the 13-variation
  probe in §5.2 (sizes from 640×360 to 2560×1664, 30–120 fps, both H.264
  profiles, HEVC, power-efficiency off, slices, an undocumented latency key).
  Nothing lowered it except shrinking frames to 640×360.
* **What does NOT change:** the end-to-end budget. Remora's added latency
  (capture → encode → send stack → decode → render) must stay **< 20 ms at
  1080p60**. With encode at up to 7 ms, that leaves **≈ 13 ms for capture +
  send stack + decode + render combined**. If the measured end-to-end pipeline
  (Phase 4) exceeds 20 ms, work **STOPS** and is reported; the 20 ms total is
  never raised to absorb it.
* **Scope:** Apple M4 only (see the per-chip note at the top).

### 2026-10-17 — C1 clarification (no threshold change)

The first capture runs showed that **most frames reach our handler *before* the
`displayTime` ScreenCaptureKit attaches** (in one 5 s run: 203 of 245 frames,
typically 5.8 ms early) — `displayTime` is the vsync at which the content goes
to the screen, not the moment it was composited. An early version of the bench
silently discarded those frames, which biased C1. The definition is applied
literally instead: the signed difference for **every** complete frame, ranked
by nearest-rank percentiles; the bench prints an accounting line proving no
frame was dropped. Negative C1 values mean capture delivery is not adding
latency on top of display timing; true glass-to-glass latency is measured with
the test pattern in Phase 4.

## 7. Phase 2 completion checklist

- [ ] C1, C3, C4, C5 measured on the M4 (worst of 3 runs) and recorded in §5
- [ ] Q3 runtime "frames only on change" measured; Q4 events observed
- [ ] **Cleanup (unless the owner decides to keep any of it):**
  - [ ] `tccutil reset ScreenCapture io.github.anuradhapumudu.Remora.dev` (dev app)
  - [ ] `tccutil reset ScreenCapture io.github.anuradhapumudu.Remora` (release app, if it was ever granted)
  - [ ] `scripts/macos/dev-identity.sh remove` (deletes the dev certificate **and** its private key),
        then `scripts/macos/dev-identity.sh status` shows "not present"
  - [ ] Confirm **Terminal** is not in System Settings → Privacy & Security →
        Screen & System Audio Recording (it was never granted; verify it stayed that way)
- [ ] Known gaps carried into docs/roadmap.md ("Known gaps before v0.1")
- [ ] Phase 2 report: commands, numbers vs criteria, limitations
