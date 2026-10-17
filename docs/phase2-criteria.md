# Phase 2 acceptance criteria — macOS capture + hardware encode

Status: criteria fixed before any capture code (2026-10-17); **C2 revised by owner
decision (§6)**. Results: partial (§5); capture tests wait for Screen Recording permission.

**Outcome (2026-10-17): C12, C3, C4, C5 PASS; Q1–Q4 answered (Q4 partly — known gaps). Phase 2 gate passed.**

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
| C1 | **Capture delivery** latency — *reported for information since 2026-10-17 (§6)* | (was: p50 ≤ 4 ms and p95 ≤ 4 ms) | Per frame: `mach_absolute_time()` at entry of our ScreenCaptureKit output handler − the frame's display time from `SCStreamFrameInfo.displayTime` (same clock). Motion test, 60 s, **all** `complete` frames, **signed** (a frame delivered before its display time counts as a negative value; none are excluded — see §6 clarification). |
| C2 | **Encode** latency — *reported for information since 2026-10-17 (§6)* | (was: p95 ≤ 7 ms; FAILED at 7.45 ms) | Per frame: time of VideoToolbox output callback − time of the `VTCompressionSessionEncodeFrame` call for the same frame (matched by presentation timestamp). Motion test, 60 s. |
| **C12** | **Screen change → encoded frame ready** (capture + encode as one segment) — *replaces C1/C2 as the gate, 2026-10-17 (§6)* | p95 **≤ 11 ms** (= the approved C1 4 ms + C2 7 ms budgets; nothing loosened) | Per frame: time of the VideoToolbox output callback − the frame's display time (`SCStreamFrameInfo.displayTime`), matched by encoder sequence number, signed. Motion test, 60 s, every encoded frame. |
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

### 5.1 Official runs (2026-10-17, M4, release build, AC power, RemoraDev.app)

Motion test, 3 × 60 s, motion pattern full screen in Safari, 1920×1248, frame
cap 60 (implemented as a 1/61 s minimum interval — see 5.5). Every run valid
(60.0 fps; accounting line shows no frame dropped from C1). Logs:
`target/phase2-results/motion-{1,2,3}.log`.

| ID | Run 1 | Run 2 | Run 3 | **Worst** | Threshold | Verdict |
|---|---|---|---|---|---|---|
| C1 capture delivery p50 / p95 (ms, signed) | 0.45 / 0.52 | 0.44 / 0.49 | 0.43 / 0.73 | **0.45 / 0.73** | (≤ 4 / ≤ 4) | PASS (info since §6) |
| C2 encode p95 (p50) (ms) | 7.27 (7.06) | 7.16 (7.06) | 7.45 (7.07) | **7.45 (7.07)** | p95 ≤ 7 | **FAILED** (+0.45 ms) — gate replaced by C12, §6 |
| C5 keeps up | 3599 / 3599, 0 dropped, 0 errors | same | same | **3599 ≥ 3528** | | **PASS** |
| **C12** screen change → encoded p95 (p50) (ms) | 7.77 (7.51) | 7.62 (7.51) | 8.14 (7.51) | **8.14 (7.51)** | p95 ≤ 11 | **PASS** |
| C3 static CPU, own + helpers (% of one core) | 1.00 | 0.37 | 0.35 | **1.00** | < 2 % | **PASS** |
| C4 memory growth / slope (3 × 10 min soak, corrected bench) | +0.14 MB / +0.015 MB/min | +0.08 MB / +0.005 MB/min | +0.14 MB / +0.008 MB/min | **+0.14 MB / +0.015 MB/min** | ≤ 2 MB, ≤ 0.1 MB/min | **PASS** |
| C12 during the soak, p95 (p50) (ms) | 10.01 (9.80) | 9.98 (9.77) | 10.01 (9.80) | **10.01 (9.80)** | p95 ≤ 11 | **PASS** — see drift note |

C3 cross-check (clean no-capture baselines, 3 × 60 s): WindowServer used 3.3–3.5 %
without capture vs 1.1–2.2 % with it, so capturing adds no hidden load in macOS's
own processes. Background load present in **every** run, with and without
capture: `appstoreagent` ≈ 97 % and `launchd` ≈ 29 % of one core (macOS's own
work, not Remora). A first baseline set ended after 1–4 s because of a bench bug
(fixed; `invalid/`); a second set was disturbed by the owner using the Mac
(`invalid/disturbed/`).

Output validity: `ffprobe` decodes all frames of the encoder-only runs (H.264
Constrained Baseline, 1920×1248, yuv420p).

Superseded: a first official block ran with the frame cap as an exact 1/60 s
interval (`target/phase2-results/superseded-cap60/`): 57.2 fps (C5 FAIL from a
capture-side shortfall) and C2 p95 9.52–9.55 ms. Two earlier blocks were
INVALID (the motion pattern was not on screen; `invalid/`) and are not counted.

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
| Q3 runtime "frames only on change" | **Holds.** On a still screen, after a startup burst, **0 new frames per second**; ScreenCaptureKit keeps sending ~5–6 `idle` callbacks/s that carry no image (cheap: whole capture ≤ 1 % CPU). | `static-{1,2,3}.log`: e.g. 52 complete / 341 idle callbacks in 60 s |
| Q4 res change / sleep / unplug | Resolution change: capture continues. Display sleep, lid close, captured display removed: **stream stops with −3815 and never resumes on its own** — the host must restart it (§5.4). Physical external-monitor unplug: **not tested — no external display available** (known gap). | §5.4 |

### 5.4 Single-display hotplug subset (Q4)

| Event while capturing | What the stream did | Evidence |
|---|---|---|
| **Resolution / scaling change** 2940×1912 → 2560×1664 → back (same aspect) | **Kept running**; no stop, no error; output stayed 1920×1248 (ScreenCaptureKit scales to the configured size) | `hotplug-resolution.log` |
| **Another display added and removed** (virtual display) while capturing the main one | **Kept running**; no stop, no error | `hotplug-virtual-main.log` |
| **The captured display disappears** (virtual display removed ≈ unplug) | **Stopped** at 21.8 s: `didStopWithError` **−3815** "Failed to find any displays or windows to capture" | `hotplug-virtual-unplug.log` |
| **Display sleep** (`pmset displaysleepnow`, woken by a key ~20 s later; also seen by accident on the idle timer) | **Stopped** at 14.8 s with **−3815**; **did not resume** after wake | `hotplug-display-sleep.log`, `superseded-vec-stats/soak-2.log` |
| **Lid close → open** (Mac slept ≈ 29 s) | **Stopped** at 16.2 s with **−3815**; **did not resume** after opening | `hotplug-lid.log` |

No crash, hang or leak in any case; every stop arrived as a clean delegate
callback.

**Design requirement (for the host, Phase 4/6):** treat −3815 as "the display
went away". Tell the viewer immediately ("host display asleep / unavailable"),
watch for displays becoming available again (wake, unlock, lid open, display
reconfiguration notifications), re-query `SCShareableContent` and start a new
stream, then force a keyframe. Never leave a session silently frozen.

**Still untested, carried to Phase 9 (and docs/roadmap.md known gaps):**
physical external-monitor unplug/replug; capturing an external display while
the lid closes (clamshell mode); mirroring on/off; display arrangement changes
with two real displays; resolution changes that change the aspect ratio; refresh
rate changes (ProMotion/120 Hz panels); HDR on/off; lock screen and fast user
switching while capturing; the virtual display was created with Apple's private
`CGVirtualDisplay`, so real-hardware behaviour may differ.

### 5.5 C2 / C5 diagnosis with real captured frames

| Finding | Evidence |
|---|---|
| **C5 shortfall was our configuration.** `minimumFrameInterval` = exactly 1/60 s made ScreenCaptureKit skip frames arriving a hair early (57.2 fps, zero `idle` callbacks). 1/61 s → 59.9–60.0 fps. Fixed in `remora-capture`. | cap 61 / 120 → 1198–1199 frames per 20 s |
| **Not GPU contention.** Synthetic frames encode at 6.10 / 6.69 ms (p50 / p95) even while Safari animates full screen. | encoder-only run with motion on screen |
| **≈ 1.15 ms of "encode" is the encoder waiting for the GPU to finish the captured surface.** Encoding each frame ~16 ms later (when the next one arrives) gives 5.92 / 6.1–6.4 ms vs 7.07 / 7.4–7.7 ms when encoded immediately — consistent over 4 alternated rounds. That time is really capture (compositing/scaling) cost showing up on the encoder's clock. | `--diag-encode-previous`, 4 × 2 alternated 20 s runs |
| **Unexplained drift.** The same configuration measured C2 p50 ≈ 9.0 ms at 02:56–02:59 and ≈ 7.05 ms from 03:05 on, with no thermal/performance warning recorded. Cause unknown; reported, not hidden. Worst-of-3 judging on the corrected configuration is in 5.1. | `superseded-cap60/` vs later runs; `pmset -g therm` |

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

### 2026-10-17 — C1 and C2 replaced as the gate by C12 "screen change → encoded frame ready" ≤ 11 ms p95 (owner-approved, option A)

**What happened, plainly:** C2 as written (p95 ≤ 7 ms, already revised once from
an unmeasured 6 ms estimate) **FAILED** in the official motion runs at
**7.45 ms p95** (worst of 3; p50 7.07 ms). That failure stands in the record.

**What we did NOT do:** we did **not** raise C2. Raising it to 7.5 ms was
considered and **rejected**: 7.5 was chosen only because the measurement came in
just under it — that is fitting the threshold to the data, and it would have
explained nothing.

**What we did instead — a measurement redesign, with evidence:** the boundary
between "capture" and "encode" does not match where the work happens.
ScreenCaptureKit hands us the surface before the GPU has finished compositing
and scaling it, so the encoder's clock includes that GPU wait. Evidence
(§5.5, finding 3): encoding each frame ~16 ms after it arrives — when its GPU
work is certainly done — cuts the measured "encode" from 7.07 / 7.4–7.7 ms to
5.92 / 6.1–6.4 ms (p50 / p95), consistently over 4 alternated rounds. About
**1.15 ms of "encode" is capture's GPU work**. So capture and encode are gated
as **one segment**: display time → encoded frame ready, **p95 ≤ 11 ms** — exactly
the two budgets already approved (C1 4 ms + C2 7 ms). Nothing is loosened; the
segment simply gets the sum of its parts' budgets, measured where the work
really ends. C1 and C2 are still measured and reported, for information.

**Budget consequence:** the < 20 ms end-to-end total (capture → encode → send
stack → decode → render, 1080p60) **stays fixed**. Capture + encode measured
**8.14 ms p95** (worst of 3), leaving **≈ 11.9 ms for send stack + decode +
render**. If the full pipeline exceeds 20 ms, work stops and is reported; the
20 ms is never raised.

## 6a. Lessons — measurement bugs that would have silently corrupted results

1. **The test stimulus must be verified, not assumed.** Two early motion blocks
   measured the wrong thing: launching RemoraDev via `open` brought it to the
   foreground and switched away from Safari's full-screen Space, and typing in
   Terminal brought Terminal forward — the "motion test" captured a scrolling
   terminal at ~10 fps. Fixes: RemoraDev launches in the background (`open -g`,
   `LSUIElement`), the runner brings the pattern forward before each run, and a
   **validity gate** rejects any motion run below 55 fps as INVALID (not a
   PASS, not a FAIL). Invalid logs are kept apart and never counted.
2. **A frame cap of exactly 1/fps loses frames.** `minimumFrameInterval` =
   1/60 s made ScreenCaptureKit skip frames that arrived a hair early (57.2
   instead of 60 fps), which looked like an encoder/capture shortfall. Fix: the
   interval is 1/(fps+1); the display's refresh still caps the rate.
3. **The instrument must not change what it measures.** C4 measures the bench's
   own memory, but the bench stored every latency sample (3 lists × ~36 000
   frames), so a 10-minute soak "grew" ~0.1 MB/min and failed C4 at
   0.106 MB/min. A/B on the same screen, 4 min each: old bench +0.230 MB/min
   (FAIL), new bench with a fixed 10 µs histogram −0.037 MB/min (PASS).
   Percentiles are now exact to one 10 µs bucket; min/max/mean stay exact.
   Logs: `c4ab-old.log`, `c4ab-new.log`; superseded soak: `superseded-vec-stats/`.
4. **Long tests must keep the display awake.** A 10-minute display-sleep setting
   stopped the capture mid-soak (see §5.4). Test blocks now run under
   `caffeinate -di`.
5. **Never drop samples that don't fit expectations.** An early C1 discarded
   frames delivered before their display time (most of them at the time). C1
   is signed over every frame, with an accounting line proving none are lost.

## 6b. Benchmark hygiene (from the unexplained drift, §5.5 finding 4)

* Every benchmark run records machine state at start and end: thermal and
  performance warnings (`pmset -g therm`), power source and battery
  (`pmset -g batt`), Low Power Mode, uptime, and load averages.
* The runner compares each run with the previous run of the same block and
  **flags** any disagreement > 1 ms in p50 — it never averages it away.
* The drift itself is an open question in docs/roadmap.md "Known gaps"; Phase 4
  checks whether it reappears.
* **Flagged 2026-10-17:** it reappeared within the session — C12 p50 9.83 ms
  (first soak run, 03:37) vs 7.51 ms (motion block, 03:10); C2 p50 9.37 vs 7.07.
  Machine state was identical (AC power, no thermal/performance warning, Low
  Power Mode off). Still unexplained.
* **Pattern across all runs so far** (C2 / C12 p50): fast ≈ 7.07 / 7.51 ms in runs
  that followed idle gaps (03:11, 03:13, 04:26); slow ≈ 9.4–9.6 / 9.8 ms in runs
  that followed sustained capture (02:57 after ~3 min of capture, the 10-minute
  soaks, and 04:31 — the second of two back-to-back 4-minute runs). **Hypothesis,
  not a finding:** this MacBook Air's M4 is fanless, and sustained load may lower
  GPU/media-engine clocks before macOS records any thermal *warning*. The bench now
  records `ProcessInfo.thermalState` and a per-10-second C12 timeline to test it.
  Even the slow state passes C12 (p95 ≤ 10.06 ms), but it leaves only ≈ 1 ms of
  margin and eats ≈ 2.3 ms of the 20 ms end-to-end budget.

## 7. Phase 2 completion checklist

- [x] C12, C3, C4, C5 measured on the M4 (worst of 3 runs) and recorded in §5 (C1/C2 for information)
- [x] Q3 runtime "frames only on change" measured; Q4 events observed (single-display subset)
- [ ] **Cleanup (unless the owner decides to keep any of it):**
  - [ ] `tccutil reset ScreenCapture io.github.anuradhapumudu.Remora.dev` (dev app)
  - [ ] `tccutil reset ScreenCapture io.github.anuradhapumudu.Remora` (release app, if it was ever granted)
  - [ ] `scripts/macos/dev-identity.sh remove` (deletes the dev certificate **and** its private key),
        then `scripts/macos/dev-identity.sh status` shows "not present"
  - [ ] Confirm **Terminal** is not in System Settings → Privacy & Security →
        Screen & System Audio Recording (it was never granted; verify it stayed that way)
- [x] Known gaps carried into docs/roadmap.md ("Known gaps before v0.1")
- [ ] Phase 2 report: commands, numbers vs criteria, limitations
