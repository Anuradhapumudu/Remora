# Phase 4.9 (D-56): Smooth 60 fps — hardware encoding on the Linux host, CPU as the fallback, and no freezes — criteria

**Status: APPROVED by the owner, 2026-11-09**, with the recommended
answer to every decision in §2: Q1 H.264 through RPM Fusion's
`intel-media-driver` (with VP9 through Fedora's driver measured in the
spike as a later option), Q2 `cros-codecs` if the spike shows it works,
Q3 1920 wide cap, Q4 the owner runs the RPM Fusion install commands.
Building starts with §6 step 0 (freeze diagnosis counters) alongside the
final Phase 4.8 live check.

Owner's request (roadmap D-56, 2026-11-02/03): "if the pc have nvidia
amd intel or any graphics can we use them … else we can use the cpu";
"shall we try to increase the fps … stable 60 frames per second";
"when I watching the video … freezing on frames like second and continue
playing and freeze again". Decisions already taken: target **stable 60
fps**; **finish 4.8 first**; the spike **may add RPM Fusion (free +
nonfree) to the laptop and install `intel-media-driver` only**, NVIDIA's
driver stays out.

## 0. What is known (each with what was read)

| Fact | Source (read) |
|---|---|
| The viewer Mac (MacBook Air, Apple M4, Mac16,12) draws at **60.00 Hz**, so more than 60 fps cannot be seen there | `system_profiler SPDisplaysDataType -json`: `"1470 x 956 @ 60.00Hz"`, 2026-11-03 |
| The laptop (i5-12500H, Iris Xe, RTX 3050 on `nouveau`) drives the TV at **1920×1080 @ 120 Hz** over HDMI (TV native 3840×2160) | GNOME `DisplayConfig.GetCurrentState`, `/sys/class/drm/card2-HDMI-A-1/modes`, 2026-11-03 |
| Fedora's Intel driver `libva-intel-media-driver` 26.2.4 encodes **VP9** (profiles 0–3, `VAEntrypointEncSliceLP`) and JPEG — **no H.264, HEVC or AV1 encode** | `vainfo --display drm`, 2026-11-03 |
| Today's encoder is software openh264: capture → encoded p50 26 ms, p95 34 ms at 1080p while the laptop also plays the video; 20–40 fps seen | phase 4.6 `results/phase4.6/measurements.md` |
| **The freezes are probably not the encoder.** The network layer receives a steady 28–37 pictures/s, but 1–3 pictures/s are given up for a missing fragment and each one waits for a keyframe (recovery p50 71 / p95 625 / max 971 ms). Sound on the same connection lost 1 packet in 4 020 | `results/phase4.8/measurements.md` run 3 (`media:` counters) |
| Two candidate causes, **unverified**: quinn drops the *oldest unsent* datagrams when its send buffer is full (quinn-proto 0.11.19 `connection/datagrams.rs:154-161`; default `datagram_send_buffer_size` 1 MiB, `config/transport.rs:396`); or our reassembler abandons a frame whose last fragment is only late (`remora-proto/src/video.rs` `abandon_older`) | source read 2026-11-03 |
| `cros-codecs` 0.0.6 (ChromeOS, BSD-3-Clause, 2025-06-18; ~1.8 M recent downloads) has stateless **VA-API H.264, VP9 and AV1 encoders** (`src/encoder/stateless/{h264,vp9,av1}/vaapi.rs`), Intel low-power entrypoint support, rate control **constant bitrate or constant quality** only (`src/encoder.rs:24-31`), **no intra-refresh**; depends on `cros-libva` 0.0.12, `gbm`, `drm`, `nix`; 78 lines containing `unsafe` in its `src/` | crate source 0.0.6, read 2026-11-03 |

**Not verified yet (the spike's job):** whether `cros-codecs` encodes
H.264 on this laptop once RPM Fusion's `intel-media-driver` is installed,
and how fast; whether the Mac's VideoToolbox decodes VP9 in hardware
(Apple added a VP9 path in recent macOS — **unverified**, to be read and
tried); how GNOME's screencast frame rate behaves at 60 fps on a 120 Hz
output.

## 1. Scope

**In:**

1. **Freezes first (no new dependency):** count, per second, the
   datagrams the host hands to quinn vs those quinn sends (`Connection::
   stats`), and on the viewer *why* each frame was given up (missing
   fragment, superseded, over budget). Fix the cause found (e.g. pace
   keyframe fragments, size quinn's send buffer, let a late frame
   finish). This may remove most of the freezes before any encoder work.
2. **Hardware H.264 on Intel through VA-API**, chosen at run time; the
   software encoder (openh264) stays as the automatic fallback when no
   hardware encoder works ("else we can use the cpu").
3. **A size cap:** pictures wider than 1920 are scaled to 1920 before
   encoding (a 4K screen would otherwise not reach 60 fps), on the GPU
   when the hardware path is used.
4. Faster recovery after a real loss (smaller and quicker recovery
   pictures).

**Out (stated plainly):** NVIDIA NVENC (its driver stays out, owner
2026-11-03); AMD (VA-API would likely work, but there is no AMD machine
to test on — it will be marked untested, not claimed); Windows; the Mac
host (it already uses VideoToolbox in hardware).

## 2. Decisions for the owner (recommendation first)

| # | Question | Recommendation | Why |
|---|---|---|---|
| Q1 | Which hardware path? | **H.264 through RPM Fusion's `intel-media-driver`** (already approved for the spike), with **VP9 through Fedora's own driver** measured in the same spike as a later option | H.264 keeps the Mac's decoder and the protocol unchanged; VP9 needs no third-party repository but adds a decoder on the Mac (new attack surface) and is unverified there |
| Q2 | Which library talks to VA-API? | **`cros-codecs`** if the spike shows it works | Maintained by ChromeOS for exactly this; safe Rust API over libva. Alternatives: GStreamer (large, system plugins) or our own libva bindings (more `unsafe` of our own) |
| Q3 | Size cap | **1920 wide** (keep aspect) | The Mac shows 1470 points wide; 1920 keeps text sharp and makes 60 fps reachable |
| Q4 | Who installs RPM Fusion? | **You type the commands** (they need your password); I give them exactly and read nothing secret | The password is never shared (standing rule) |

## 3. Security requirements (each gets a test seen failing)

| ID | Requirement | Test |
|---|---|---|
| E1 | The hardware encoder only ever receives this computer's own pictures; its output goes through the existing packetizer and sealing (INV2). No new network parser on the host | unit; the M1a sealed-wire test run with the hardware encoder |
| E2 | Falling back to software never weakens anything: same sealing, limits and keyframe rules; the fallback is said once, never silent | unit with a failing fake hardware encoder; plant: fallback that skips a check |
| E3 | Encoded pictures from hardware obey the same size limits as software ones (FRAME_MAX) before they are sent | unit; plant: an oversized frame |
| E4 | Counters added for the freeze diagnosis are numbers only (INV9) | Debug / output tests |
| E5 | If VP9 is ever chosen (Q1): the Mac's VP9 decode path is size-checked before the decoder and fuzzed, like H.264 | fuzz target; only if Q1 changes |

## 4. Targets

| ID | Target |
|---|---|
| F1 | **Stable 60 fps**: playing a 60 fps video full screen on the laptop (1080p), the Mac presents ≥ 57 fps in ≥ 95 % of seconds over 60 s |
| F2 | Hardware encode time p95 ≤ 8 ms per 1080p picture (software today: p95 ~34 ms) |
| F3 | **No freezes**: no presentation gap > 100 ms in 60 s of video, except right after a loss counted on the network; recovery p95 ≤ 150 ms (today 625 ms) |
| F4 | Capture → encoded p95 ≤ 20 ms (phase 4.6 LP1, not met in software) |
| F5 | Laptop CPU used by the host while streaming at least halved compared with software (measured both ways) |
| F6 | Fallback: with the hardware path unavailable, a session still starts and streams in software, saying so once |

## 5. Dependencies

Candidates only, under the 14-day rule and `cargo deny`, documented in
`docs/dependencies.md` in the same commit if adopted: `cros-codecs`
0.0.6, `cros-libva` 0.0.12 (and what they pull in: `gbm`, `drm`, `nix`,
…). System: RPM Fusion `intel-media-driver` on the laptop (owner
decision taken for the spike).

## 6. Build order

0. Freeze diagnosis counters (§1 item 1); live run with the owner; fix
   what they show; re-measure F3.
1. Owner installs RPM Fusion + `intel-media-driver` (exact commands
   given). Spike S-E1 on the laptop: `cros-codecs` H.264 VA-API encode of
   real captured pictures — time, size, CPU; VP9 the same way; a
   VideoToolbox VP9 decode check on the Mac.
2. Criteria finalised with the spike's numbers; owner approval.
3. Hardware encoder behind the existing encoder trait with automatic
   fallback (E1–E3); size cap.
4. Live test: F1–F6; report; roadmap.

## 7. Known limitations (stated plainly)

- The hardware path will be tested on Intel only.
- The Mac cannot show more than 60 fps (60 Hz screen).
- Third-party repository: RPM Fusion's packages are trusted when
  installed (owner's decision, Intel driver only).
- Without intra-refresh in `cros-codecs`, recovery after loss still
  needs a full picture; F3 is met by making that fast, not by avoiding it.
