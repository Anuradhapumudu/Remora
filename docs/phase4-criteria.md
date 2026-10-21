# Phase 4 acceptance criteria — encrypted loopback streaming + wgpu viewer

Status: **APPROVED by the owner 2026-10-19, with R1–R5 and two additions
(§12).** Implementation waits only for the owner's Phase 3 walkthrough report.
Same gate rule as Phases 2 and 3:

* Thresholds are fixed **before** any code and are not changed after measuring.
* If a threshold FAILS, work **stops** and the failure is reported with the
  numbers and a proposed design change. A threshold changes only through a
  new, dated, owner-approved entry in §12.
* **The 20 ms end-to-end budget is never raised** (quality.md §1).
* The thresholds are **per-chip** (Apple M4). No M4 number may be cited for
  another chip.

Phase 4 is mixed in kind: **performance gates** (§4) and **security
invariants as attack tests** (§5, §6), plus the capture
interrupted/resumed/stopped trait change (§7).

## 0. What the render spike changed (architecture.md D32)

The Slint + wgpu spike (`spikes/slint-wgpu`, run 2026-10-19, before this
document as the owner required) answered the questions the render path rests on:

| Question | Answer (M4, 1920 × 1080 NV12) | Consequence for Phase 4 |
|---|---|---|
| Zero-copy IOSurface → wgpu? | **Works.** Pixel-verified (worst error 2/255; a planted wrong plane fails at 255) | Possible, but not needed: see next row |
| Upload + NV12→RGBA cost? | Zero-copy p95 0.54–1.26 ms; **CPU upload from the locked decoder buffer p95 0.75–0.80 ms** (steady) | Render stage budget **1.5 ms p95** (§3), met by the CPU path without new `unsafe` |
| Slint `unstable-wgpu-30` as documented? | Yes: shares its device, accepts a `wgpu::Texture` (RGBA8 only) | Usable for UI later |
| Present without waiting for vsync? | **Not through Slint** (hard-coded `AutoVsync`, 16.67 ms p50 interval). **Yes with our own winit + wgpu surface** (`Immediate`, 2.2 ms p50 interval) | Phase 4 video window uses winit + wgpu directly (R1) |
| Glass-to-glass gain of `Immediate` in a composited window? | **Unverified** (needs a camera) | Display wait stays reported separately (P4), never inside the 20 ms |

## 1. Decisions to approve with this document

| ID | Decision | Why | Alternative |
|---|---|---|---|
| **R1** | Phase 4 viewer = **winit 0.30.13 + wgpu 30.0.1 directly** (architecture D33, proposed). Present mode `Immediate` if offered, else `Fifo` with `desired_maximum_frame_latency = 1`. **No Slint in Phase 4.** | Slint forces vsync (D32); quality.md §2 already says "never `Fifo`" for video | Slint-presented video: +0–16.7 ms refresh wait we cannot remove |
| **R2** | Frames reach wgpu by **CPU upload of NV12 planes from the locked decoder buffer**, through a *safe* accessor in `remora-codec/src/sys/macos.rs`; the NV12→RGB shader runs on the GPU. Zero-copy stays deferred (roadmap D-18). | ≈ 0.8 ms p95 measured; zero-copy would put `unsafe` wgpu-hal calls outside the three FFI crates (an unsafe-policy change) for ≈ 0.3 ms p50 | Zero-copy now, with a policy exception like D19 |
| **R3** | Phase 4 "stats overlay" = **window title + one stderr line per second** (fps, stage p50/p95, drops, loss). A drawn overlay comes with the Slint UI in Phase 7 (roadmap D-17). | No text renderer dependency for one phase | Add a text-rendering crate now |
| **R4** | INV2 is tested on **media** in Phase 4; INV2 for input moves to Phase 6 (roadmap D-1b) | No input path until Phase 6 | — |
| **R5** | winit becomes a **direct** dependency of remora-viewer (today it is only reached through Slint). 0.30.13, released 2026-03-02 (crates.io, checked 2026-10-19), MSRV 1.70. 0.31 is beta only, so it is not used. | Needed for R1 | — |

## 2. Test machine and conditions

As phase2-criteria §1: Apple M4 MacBook Air (Mac16,12), built-in 60 Hz
display, macOS 27.0.1, `cargo build --release`, **AC power** (the spike ran on
battery; its numbers are orientation only), Low Power Mode off, only Terminal
and the tools open. Host and viewer run as **two processes on the same Mac**,
connected over loopback UDP. Capture at 1920 × 1248 (the panel's aspect, as
C12), 60 fps, NV12, HEVC or H.264 as selected by Phase 2 (reported).

**Clock.** Both processes timestamp with `mach_absolute_time()`. That the two
processes see the same clock is an **assumption checked by test P0**, not
asserted.

## 3. The latency budget (20 ms, p95, M4, 1920 × 1248 @ 60)

Endpoints: **start** = the frame's `SCStreamFrameInfo.displayTime` (same as
C12); **end** = the viewer's GPU has *finished* the draw that contains this
frame (`Queue::on_submitted_work_done` callback). This is stricter than
quality.md's "render submit": it includes GPU execution.

| Stage | Budget p95 | Basis |
|---|---|---|
| Capture + encode (screen change → encoded frame ready) | ≤ 11 (C12 gate, unchanged) | **Measured 8.14** (Phase 2) |
| Packetise + FEC + seal + QUIC send | 1.0 | quality.md §2 estimate |
| Loopback network | — | reported |
| Receive + open + reassemble | 0.5 | estimate |
| Decode (VideoToolbox) | 4.0 | quality.md estimate 2–4 |
| Upload + NV12→RGB + draw, to GPU completion | **1.5** | **Spike: ≤ 0.80 p95** (CPU path, 1080p; 1248 has 16 % more pixels) |
| **Sum of budgets after encode** | **7.0** of the ≈ 11.9 remaining | margin ≈ 4.9 ms |
| Display refresh wait | **reported separately** (P4) | not ours; spike: `Immediate` offered |

Stage budgets **locate** an overrun; the **gates** are P1 and P2 below (a sum
of p95s is not the p95 of the sum).

## 4. Performance criteria

| ID | Metric | PASS if | How measured |
|---|---|---|---|
| **P0** | Same clock in both processes | \|offset\| ≤ 50 µs, round trip ≤ 200 µs | Ping-pong of `mach_absolute_time()` over a pipe, 1000 rounds, NTP formula. **Plant:** add 1 ms to one side → must fail |
| **P1** | **End-to-end** (§3 start → end) | p95 **< 20 ms**; p50, p99, max reported | 60 s motion test (phase2 §3 motion page, full screen), every drawn frame, matched by frame ID; 3 runs, worst run counts |
| **P2** | **Encoded frame ready → drawn** (the remaining-budget segment) | p95 **≤ 11.9 ms** | Same runs; per-stage stamps `encode_done`, `sent`, `received_last_fragment`, `decode_done`, `drawn` reported p50/p95 |
| P3 | Viewer keeps up | drawn ≥ **3528** in 60 s (98 %), **0** decode errors, **0** AEAD failures, **0** reassembly drops on clean loopback | Counters on both sides |
| P4 | Display wait (information) | reported, not gated | Interval `drawn` → `present()` returned, and frame interval, for `Immediate` and `Fifo`. Glass-to-glass only if a camera is available (roadmap D-19) |
| P5 | Viewer memory | `phys_footprint` **< 150 MB**, and growth min 1 → min 10 **≤ 2 MB**, slope **≤ 0.1 MB/min** | 10-minute motion session, sampled every 10 s (as C4) |
| P6 | Host CPU while streaming a **static** screen | **< 2 %** of one core over 60 s, including helper processes (as C3) | As C3, now with the net stack running |
| P7 | Frame correctness | every drawn frame's barcode (frame number) decodes; frame numbers strictly increase (drops allowed, **no repeats, no reordering**) | Test pattern with a barcode strip (quality.md §2), read back on the viewer |
| P8 | C12 re-run (roadmap **D-10**) | C12 p95 ≤ 11 ms; p50 reported next to 7.05 and 9.0 ms, with machine state | Phase 2 `bench-capture`, 3 runs |

## 5. INV2 — no media without encryption (attack tests)

INV2 (threat-model): *there is no code path that sends media without
Noise/media-key encryption.* QUIC also encrypts, so **a capture of the UDP
wire alone cannot catch a missing media seal**. M1a therefore checks *our*
layer and M1b the wire.

| ID | Attack / check | PASS if |
|---|---|---|
| **M1a** | Record every QUIC DATAGRAM payload handed to quinn (test hook on the net send path) during a 10 s stream of a test pattern with a 32-byte random **canary** in its pixel rows; also record every encoded frame on the host (pre-seal) | no 16-byte window of any encoded frame and no canary appears in any payload; every payload parses as header ‖ ciphertext ‖ tag and opens only with the media key. **Plant (local, never committed):** make `seal` return the plaintext → test fails naming the frame |
| **M1b** | Same session through a **recording UDP relay** between viewer and host (no root needed) | same windows never appear in any UDP payload; byte entropy over all payloads ≥ 7.99 bits/byte (≥ 1 MB). **Plant:** feed the checker one recorded packet with a frame window spliced in → fails |
| **M2** | Structural: the only media send function takes a `SealedDatagram`, constructible only by `remora_crypto::media` | a `compile_fail` doctest shows `Vec<u8>`/`Bytes` cannot be sent; a policy-scanner rule allows quinn's `send_datagram` in **one** file. **Plant:** a second call site → scanner fails |
| M3 | Media before the session is `Active` (before approval / during the handshake) | host emits **no** media action (sans-IO test over every state); viewer **drops** media datagrams received before `Established` and never feeds them to the decoder (net test injects them) |
| M4 | Replay on the real path: the relay re-injects recorded datagrams (in-window duplicates and older than the window) | dropped and counted; no frame drawn twice (P7 barcode) |
| M5 | Tamper: bit flips in header (AAD), body and tag; unknown `key_id`; truncated datagrams | dropped before decode, counted, session continues; nothing reaches the decoder (decoder-input counter unchanged) |
| M6 | Reassembly limits (protocol §7): `frag_count` > 8192, frame > 8 MiB, > 16 frames open, `frag_index ≥ frag_count`, `frag_count` changing within one frame, zero-length fragment | each rejected **before allocating** (counting allocator: no allocation above the limit); oldest-eviction works. New **fuzz target** for the reassembler, 10 min, 0 crashes |
| M7 | **Malicious authenticated host** sends a hostile bitstream: random bytes, truncated NAL units, parameter sets announcing > negotiated size or > 7680 × 4320 | size refused before decoder configuration; decoder errors handled → keyframe request; no crash, no hang (5 s watchdog), viewer memory bounded. New fuzz target for our NAL/parameter-set parsing. Note: whether VideoToolbox decodes out of process is **unverified** (C12), so we assume it runs in our process |
| M8 | Key use: counters strictly increase per key; rotation at the limit (protocol §6) tested with a lowered limit; host and viewer keys differ | no nonce repeats over 10⁶ packets; rotation happens and old-key packets inside the grace window still open, outside it are dropped |

## 6. INV9 — no pixels in logs or on disk (attack tests)

INV9: *screen pixels are never logged or written to disk* (except the explicit
`capture-to-file` benchmark tool).

| ID | Attack / check | PASS if |
|---|---|---|
| **N1** | Full session (host + viewer) with **trace-level** logging captured (LogCapture and both processes' stderr), canary in the pixels, host encoded frames recorded | no log line contains the canary, any 16-byte window of an encoded frame, or the hex/base64 of either. **Plant:** a `trace!` printing frame bytes → fails |
| **N2** | Run both processes with `HOME`, `TMPDIR`, `XDG_*` and the working directory set to fresh temp dirs; after a 10 s session, walk them | only the expected files exist (key file, config); none contains the canary or a frame window. Files our processes create in the macOS per-user temp and cache dirs (`getconf DARWIN_USER_TEMP_DIR` / `DARWIN_USER_CACHE_DIR`, e.g. Metal shader caches) are **listed in the report** and scanned the same way. **Plant:** a debug `File::create("frame.bin")` → fails |
| **N3** | Static rule in the policy scanner: no `File::create`, `fs::write`, `OpenOptions` in capture, codec, net, session, host, viewer, except an allow-list (remora-app key store; the `capture-to-file` tool) | real workspace passes; **plant** in each crate → fails. policy.rs is in the mutation gate |
| N4 | `Debug` of every frame and datagram type (`CapturedFrame`, `EncodedFrame`, `DecodedFrame`, opened datagram) | prints sizes, IDs, timestamps — never content (test formats each with canary content) |

## 7. Capture: `Interrupted` / `Resumed` / `Stopped` (D17, roadmap D-8)

Trait change (OS-neutral; the session layer never learns the OS):

```rust
pub enum CaptureEvent {
    Frame(CapturedFrame),
    /// Capture paused but expected to come back (the backend keeps trying).
    Interrupted(InterruptReason),
    /// Frames flow again; the next encoded frame is a keyframe.
    Resumed,
    /// Capture will not come back without user action.
    Stopped(CaptureError),
}
pub enum InterruptReason { DisplayUnavailable, AccessLost, Other }
```

* **macOS mapping:** stream error −3815 (display sleep, lid close, display
  removed — Phase 2 measured all three give −3815 and could not tell them
  apart) → `Interrupted(DisplayUnavailable)`; the backend restarts the stream
  when the display is available again → `Resumed`. Permission revoked →
  `Stopped(PermissionDenied)`. `AccessLost` is the Windows mapping (Phase 6.5).
* **Session:** `Interrupted` → host sends a `StreamPaused { reason }` control
  message and **no media**, the session stays `Active`; `Resumed` →
  `StreamResumed` + forced keyframe; `Stopped` → session closes with a close
  code defined in protocol.md during Phase 4.

| ID | Test | PASS if |
|---|---|---|
| T1 | Sans-IO, fake capture: every event in every session state | actions exactly as above; no media action while interrupted; mutation gate covers it |
| T2 | macOS, real: `pmset displaysleepnow`, then wake (`caffeinate -u -t 2`); 5 cycles in one session | `Interrupted` ≤ 1 s after sleep; `Resumed` ≤ 2 s after wake; first frame after resume is a keyframe; same session throughout; no memory growth across cycles (≤ 2 MB) |
| T3 | Lid close, captured display removed | Both **testable** (corrections 2026-10-20, §12), run in step 7. **Lid close / open** (owner closes the lid): `Interrupted` on close, `Resumed` ≤ 2 s after the display is back on open, same session. **Captured display removed** (a `CGVirtualDisplay` is captured, then destroyed — Phase 2's tooling; real hardware may differ): `Interrupted` ≤ 1 s, no crash, no CPU spin while absent; if it returns within 2 minutes the stream resumes in the same session with a keyframe, if not the session ends with `CaptureStopped` (never `Normal`, never another display; decision D-29, architecture D38). Only **physical** monitor unplug stays untested (roadmap D-16) |
| T4 | Policy rule: no `-3815`, `SCStream` or other OS names in remora-session / remora-net | scanner passes; plant fails |

## 8. Functional

* `remora-host serve` streams once a viewer is approved; `remora-viewer connect`
  opens a window showing the live screen; the stats (R3) appear in the title and
  on stderr; closing either side ends the session cleanly (Phase 3 close codes).
* **CI:** the first Phase 4 task is a probe of whether the GitHub macOS runner's
  VideoToolbox can encode and decode (never checked so far). If it can, M1, M3–M6,
  N1, N2 and P7 run in CI on a synthetic source. If it cannot, CI runs them with
  a **test-only pass-through codec** (bytes in = bytes out; it replaces the codec,
  **never the encryption**), and they also run on the M4 with VideoToolbox before
  acceptance. Either way the CI job states which codec it used, and a skipped
  media test fails the job (as the A04 guard does).

## 9. Mutation gate and fuzzing

* Scope additions (`.cargo/mutants.toml`, as files land): media send/receive
  and reassembly in remora-net, the media-session state in remora-session, the
  new remora-proto parsers, the capture-event handling, and the new
  policy-scanner rules. Same rule: **0 missed**, survivors justified one line each.
* New fuzz targets: reassembler (M6), NAL / parameter-set parsing (M7), new
  control messages. 10 min each, 0 crashes, plus the 9 existing targets.

## 10. Build order (as phase3-criteria §7b)

Each component's attack tests are committed **before or with** its
implementation; the commit order is the evidence and is not rewritten (merge
commit). Every "catch" test is first seen failing against its plant.

1. P0 clock check; CI VideoToolbox probe.
2. Capture trait change + T1, T4 (then the macOS backend + T2).
3. Media framing: datagram layout, reassembly + M6 + fuzz.
4. Sealed send path + M2, M1a, M3, M5, M8.
5. VideoToolbox decode + M7 + fuzz.
6. Viewer window (R1, R2) + P7.
7. End-to-end: M1b, M4, N1–N4, then P1–P6, P8 on the M4.

## 11. Exit items carried from the deferred list

Phase 4 must close: **D-1** (INV2, media), **D-2** (INV9), **D-8** (capture
restart), **D-9** (remove the dev signing identity and the RemoraDev
screen-recording grant, at the very end), **D-10** (benchmark drift: P8).
Before Phase 4 finishes, D-17 must have been examined (done 2026-10-19:
docs/d17-video-surface-options.md).
The phase report lists the whole deferred list row by row (CLAUDE.md).

## 11b. Progress notes

* **Step 1 (2026-10-20).** P0 passes on the M4: offset between two
  processes ≤ 0.42 µs at a 3.4–3.75 µs round trip (3 runs; limits 50 µs /
  200 µs); a planted 1 ms skew is measured as 0.9996–1.00002 ms and fails.
  **CI probe:** GitHub's macOS runner (macos-15) **hardware-encodes**:
  `VT_PROBE encode=ok frames=30/30 keyframes=1 dropped_or_failed=0`. So
  §8's first branch applies: the media tests run in CI with VideoToolbox
  (decode probed in step 5). The pass-through codec is not needed unless
  the decode probe says otherwise.

* **Step 2 (2026-10-20).** T1 (12 sans-IO tests) and T4 (policy rule,
  planted OS names caught) pass; mutation testing of the new session
  functions 22 mutants / 0 missed, policy.rs 61 / 0 missed. **T2 on the M4**
  (`remora-host watch-capture` via RemoraDev.app, `pmset displaysleepnow` then
  `caffeinate -u -t 2`, 5 cycles in one capture session):
  Interrupted 75–87 ms after sleep (≤ 1 s), Resumed 325–334 ms after wake
  (≤ 2 s), footprint 6.4 → 6.2 MB (no growth). A first run was disturbed by a
  browser "Video Wake Lock" that turned the display back on early in cycles
  1–3 (power log `pmset -g log`: off and on within 0–3 s); every Resumed still
  came ≤ ~1.3 s after the display really turned on — Resumed is emitted on the
  new stream's first callback, so it cannot precede real frames. **Still open
  from T2:** "the first frame after resume is a keyframe" needs the streaming
  host's encoder — checked in step 7.

* **Step 4 (2026-10-21).** Sealed send path (architecture D39). Tests:
  `remora-session/tests/m3_m5_m8_media.rs` (16, sans-IO),
  `remora-net/tests/m1a_m3_media.rs` (2, real QUIC), the M2 compile-fail
  doctests in `remora-crypto` (`SealedDatagram`) and `remora-session`
  (`HostAction::Media`), and the policy-scanner rule. Each "catch" test
  was seen failing against a planted fault, then the plant was removed:
  a `seal` that returns plaintext (M1a: "payload 0 carries plaintext of
  frame 0 at byte 0"); a public field and `From<Vec<u8>>` on
  `SealedDatagram` (both compile-fail doctests fail); a second
  `send_datagram` call in `remora-net/src/host.rs` (scanner names it); the
  host sealing for sessions awaiting approval (M3 names the state, and
  also caught the key announcements leaking). **M1a** used synthetic
  frames (random bytes with a 32-byte canary, 600 frames at 60 fps): the
  seal does not depend on the codec; the VideoToolbox pipeline repeats it
  in step 7 (M1b, N1). **M8**: 10⁶ packets, 20 rotations, no counter
  repeated (CI's test job; the mutation job runs it with `M8_PACKETS` =
  20 000, still 20 rotations, as it does A04 with 3 samples: 10⁶ per
  mutant would put the session shard over its 120-minute limit; the media
  mutants were re-run at 20 000 with the same result). *Slip:* the first
  version of that change read the variable as `M8_packets` (a scripted
  rename hit it), so CI ignored it, the session shard ran 2 minutes per
  mutant and timed out, and the local "re-run at 20 000" had in fact run
  10⁶. Fixed in the next commit, the local re-run repeated at a real
  20 000 (60 mutants: 55 caught, 4 unviable, 1 justified equivalent), and
  the Mutants workflow now fails if a test stops reading a variable it
  sets (planted rename caught). **Mutation:** the new session media code first left 17
  survivors (key lifetime not pinned, current/next key not shown to
  survive the grace window, unusable-but-authentic datagrams and three
  drop counters never checked); new tests kill 16, one is equivalent
  (justified in mutants.toml). Final: session media 57 mutants, 53
  caught, 3 unviable, 1 equivalent; send/approve/viewer paths 83 tested;
  crypto/proto/policy/net changes 54 mutants, 42 caught, 12 unviable,
  0 missed. No new fuzz target: the bytes a viewer receives are parsed by
  the existing targets `media_open` (header + AEAD), `video_reassembly`
  (fragment body) and `messages` (key announcements).

* **Step 5 (2026-10-21).** H.264 decode behind checks (architecture D40).
  Tests: `remora-codec/tests/m7_h264.rs` (26, every OS: frame and SPS
  rules, exact limits, the gate), `m7_hostile_decode.rs` (7, VideoToolbox),
  `m7_decode_memory.rs` (1, own process), `remora-session/tests/
  m7_keyframe_request.rs` (5), `remora-net/tests/m7_keyframe_request.rs`
  (1, real QUIC), the decode probe. **M7 on the M4:** a real 60-frame
  stream decodes; a 1080p keyframe to a 720p viewer and an 8K+ SPS create
  **no** decoder session; 600 random/random-slice frames and 507
  truncated ones: no crash, no decode call near the 5 s watchdog, a real
  keyframe decodes afterwards; memory over 3000 hostile frames (1100
  decoder sessions created and dropped): footprint 111 → 95 MB, IOSurfaces
  0.3 → 0.3 MB (limit +8 MB). **Probe:** `VT_PROBE decode=ok frames=30/30`
  locally; CI now requires both probe lines. **Fuzz** `h264_frame`: 10 min,
  40.4 M runs, 0 crashes; corpus minimised to 858 inputs (seeded from real
  encoder output). **Plants, each seen failing then removed:** no viewer
  size check (oversized test), no 8K check in `parse_sps`, coded size not
  checked, a decode call that sleeps 7 s (watchdog names call 1), every
  decoded picture leaked (first missed by `footprint`, §12; caught after),
  the gate not waiting after a decode error (two places), no frame-gap
  rule, a probe whose decoder refuses everything (prints `decode=BROKEN`
  and fails). **Mutation:** `h264.rs` 156 mutants, 152 caught, 4 unviable,
  0 missed, with only the tests that exist on Linux (where CI's shard
  runs); one equivalent `+ 256` was removed from the code instead of
  excluded. Session `request_keyframe`/`on_active`/`on_pending`: 19
  mutants, 13 caught, 5 unviable, 1 timeout (an existing `on_pending`
  mutant that hangs), 0 missed. **Not yet:** the viewer window (step 6)
  and decoding the real capture stream end to end (step 7); the decode
  thread in `remora-viewer` releases each picture.

* **Step 6 (2026-10-21).** Viewer window and P7 (architecture D41).
  Tests: `remora-codec/tests/p7_barcode.rs` (11, every OS: barcode round
  trips through luma and the renderer's RGB, ±60 noise, every one- and
  two-cell error reads as "no number" — all 780 pairs checked; `Nv12::new`
  bounds), `remora-viewer/tests/p7_frames.rs` (4, macOS, real encoder →
  `VtDecoder` → renderer offscreen → read back). **P7:** 90 of 90 frames
  drawn once, in order, each showing its own number; with frames 40–41
  lost, 0–39 then 60–89 (nothing until the keyframe); with 51 before 50
  and 70 twice, 0–49 then 60–70, never backwards, never twice. **Plants,
  each seen failing then removed:** a renderer that keeps the first
  picture ("drawn frame 1: number 0 after 0 (repeat)"), chroma bound as
  luma ("drawn frame 0: barcode unreadable"), the decoder's frame-gap rule
  removed ("drawn frame 40: barcode unreadable" — the step-5 finding seen
  in pixels: a frame decoded after a lost one is visibly wrong). **Window
  smoke run** (temporary harness, not committed; 1920 × 1248 synthetic
  stream): present mode `Immediate`, format `Bgra8Unorm`; the R3 line
  each second. Its CPU time for upload + acquire + draw + present was
  p50 ≈ 2 ms, p95 ≈ 2.5 ms — **not** a P1/P2 measurement (that is to GPU
  completion, step 7), but above the spike's 0.75–0.80 ms p95 for upload
  + draw alone and above the 1.5 ms stage budget, so step 7 must measure
  it properly before anything is concluded. When the window is hidden,
  macOS gives no drawable and frames are decoded but not drawn (the
  stats show 0 fps).

* **Step 7a (2026-10-22).** Streaming host (architecture D42). Tests:
  `remora-host` `stream.rs` (6, macOS, scripted capture backend and the
  synthetic source), `remora-viewer` `decode.rs` (1, error → counter),
  e2e `streaming_host_video_is_decoded_by_the_viewer` (host `--source
  synthetic`, viewer `--no-window`, real QUIC on loopback): **180 frames
  decoded in 3 s, 0 refused, 0 waiting, 0 failed, 0 dropped**, and the
  host stops streaming when the session ends. **T2's open item closed:**
  the first frame after capture resumes is a keyframe (scripted capture;
  the real `pmset` cycle repeats it in 7d). **Plants, each seen failing
  then removed:** no keyframe on resume, a keyframe request ignored,
  arrival time sent instead of display time (the first version of that
  test had bounds too loose to see 5 ms and missed it — tightened to a
  50 ms display-to-arrival gap), the stream never stopping after the last
  session, a "waiting" refusal counted as malformed. A forced first
  keyframe was **removed** instead: removing it changed nothing, because
  VideoToolbox's first frame is always an IDR. **Mutation** (`stream.rs`,
  not in the gated scope — app code): 29 mutants, 23 caught, 5 unviable,
  1 timeout, 0 missed; the first run missed 9, which led to the rate,
  stop and size checks of the synthetic source, and to removing a bitrate
  parameter no test could observe (the synthetic pattern is too easy to
  encode for bitrate to show; bitrate is tuned with P1 in 7d).

* **Step 7b, N3 and N4 (2026-10-22).** **N3:** policy-scanner rule "file
  write in a crate that handles screen content" (`File::create`,
  `File::create_new`, `File::options`, `fs::write`, `OpenOptions` in the
  `src/` of capture, codec, net, session, host, viewer; tests, the key
  store and the capture-to-file benchmark `remora-host/src/bench.rs`
  allowed). The real workspace passes; a planted `File::create("frame.bin")`
  in the viewer's decoder fails the workspace scan, and the unit test
  plants each call in each crate. **N4:** the `Debug` form of every type
  holding video content checked for any 16-byte window of it (new
  testkit `find_windows`: decimal `Debug` lists, hex, text). **It found
  two real leaks:** `Fragment` derived `Debug` over its plaintext body,
  and `Reassembler` (so also the viewer session's `MediaIn`) over the
  fragments of open frames — a `{:?}` of either would have logged screen
  content. Both now print counts and sizes only. `EncodedFrame`,
  `CapturedFrame`, `VideoFrame` and `DecodedFrame` were already clean
  (the first two were seen failing against a planted content field).
  **Mutation:** `check_rust` 26 mutants, 25 caught, 1 unviable; the two
  new `Debug` impls 2/2 caught (after the tests also required the
  sizes and ids to be printed: a `Debug` printing nothing leaks nothing
  too); `find_windows` 3, 2 caught, 1 unviable.

## 12. Changes to criteria

* **2026-10-19 — owner approval.** R1–R5 approved as proposed. R1 and R2 are
  recorded as a measured constraint in architecture **D34** (R2's reason:
  the CPU path's p95 is *steadier*, 0.75–0.80 vs 0.54–1.26 ms, and the budget
  is judged at p95). Two additions, neither changes a threshold:
  1. **D-17 examined before Phase 4 finishes** (≈ 30 min desk research):
     done the same day, docs/d17-video-surface-options.md — solvable; options
     A (one window, two layers; to spike before Phase 7), B (child window),
     C (two windows), D (another toolkit).
  2. **Roadmap guard:** CI `roadmap` job (architecture D35).
* Standing question for every "catch" test in this phase (owner): *what would
  this test still pass with, if the thing it checks were removed?* (The M1a /
  M1b split is the example: a wire capture alone passes even with the media
  seal removed, because QUIC encrypts too.) Each test's plant answers it.
* **2026-10-20 — T3 correction (found in the deferred-list phase re-check).**
  T3 said lid close was "not testable" on this machine; Phase 2 tested lid
  close/open on it (phase2-criteria Q4, `hotplug-lid.log`). Lid close/open is
  now a test (step 7, owner closes the lid); only display removal stays a gap.
  This adds a test; no threshold changes.
* **2026-10-20 — sweep of asserted limitations (owner).** Every "cannot /
  not testable / unavailable" claim in the phase criteria, quality,
  architecture, distribution and NAT docs was checked against earlier
  phases' evidence. One more was contradicted: T3's "display removal not
  testable" — Phase 2 removed the captured display with a virtual display
  (phase2-criteria §5.4). T3 now tests it (see above); a new design
  decision follows from it (roadmap D-29). All other claims stand.
* **2026-10-21 — M3 and M8 read precisely (step 4; no threshold changes,
  flagged to the owner).**
  1. *M3, viewer side* said "drops media datagrams received before
     `Established`". Phase 3's tests already **close** the session on a
     datagram during the handshake (stricter, kept: no host can have sent
     media then). The real gap was later: a viewer **waiting for
     approval** used to close too, but there the datagram can legitimately
     overtake `SessionAccept` (ordered stream vs datagrams) and a lost packet
     would end a real session. It now **drops unread and counts** in that
     state (test `m3_viewer_datagrams_while_pending_are_dropped_unread`;
     the old test `a20_viewer_datagrams_before_active_close_the_session` was
     split into that and `a20_viewer_datagrams_during_the_handshake_close_
     the_session`). Never fed to the decoder in either case.
  2. *M8* "host and viewer keys differ": the Phase 4 viewer sends **no**
     media (pointer motion comes with input, Phase 6, roadmap D-1b), so it
     has no media key. What Phase 4 can check, and does: every **session**
     has its own key (`m8_every_session_has_its_own_key`). The viewer-key
     half moves to D-1b.
* **2026-10-21 — step 5 plan, approved by the owner ("ok"); no threshold
  changes.**
  1. *Codec:* Phase 4 streams and decodes **H.264 only** (Phase 2: the
     faster low-latency hardware encoder on the M4). HEVC decode is roadmap
     D-32.
  2. *M7's "negotiated size":* no `Capabilities` message exists yet, so
     nothing is negotiated. The viewer enforces its **own** limit
     (`SizeLimit`, ≤ 7680 × 4320) on every SPS before the decoder is
     configured; sending it to the host is roadmap D-31. The limit applies
     to the **coded** size too (what the decoder allocates), not only the
     cropped one.
  3. *"Keyframe request":* new control message `RecoveryRequest`
     (protocol.md §5 tag 9, no fields yet), viewer → host, Active only. The
     viewer sends at most one per 500 ms; the host forces at most one
     keyframe per 500 ms for all viewers together, so a viewer cannot make
     the stream keyframes only.
  4. *Accepted subset:* the viewer accepts only what Remora's encoder
     produces: Annex B, NAL types 1, 5, 6, 7, 8, 9; SPS/PPS only (and
     always) in a keyframe; 8-bit 4:2:0 Baseline/Main/High. Everything
     else is refused before the decoder sees it.
  5. *M7 memory bound,* fixed before measuring: footprint growth ≤ 8 MB
     over 3000 hostile frames after a 300-frame warm-up, in its own test
     process.
* **2026-10-21 — M7 read precisely (step 5; no threshold changes, flagged
  to the owner).**
  1. *"Viewer memory bounded" counted the wrong memory.* The planned
     measure, process footprint, did not move when a planted bug leaked
     every decoded picture (~100 MB): decoded pictures are IOSurfaces,
     which `footprint` does not count. The test now counts footprint
     **plus** the IOSurface memory mapped into the process (`vmmap
     --summary`), same 8 MB threshold; the planted leak then fails it
     ("memory grew 91 317 862 bytes"). Counting more memory only makes the
     check stricter. **P5 (viewer memory, step 7) must count IOSurfaces
     the same way**, or it would miss a leak of pictures too.
  2. *A lost frame was a silent wrong picture.* VideoToolbox decoded a P
     frame whose reference had never been given to it and reported
     success. The decoder now treats a gap in frame ids like a decode error
     (wait for a keyframe, ask for one): test
     `m7_a_missing_frame_waits_for_a_keyframe`, seen failing first. This
     adds a check; P7 (no repeats, no reordering) is unaffected.
* **2026-10-21 — M7 memory FAILED on GitHub's macOS VM (open; reported
  to the owner, no threshold changed).** First CI run of step 5
  (`49e14e9`, macos-15 runner): footprint **51 → 65 MB (+14 MB, limit
  +8 MB)**, IOSurfaces 0 → 0 MB, over 3000 hostile frames (1100 decoder
  sessions). The runner logs `IOServiceMatching failed for:
  AppleM2ScalerParavirtDriver`, and no picture is an IOSurface: its
  VideoToolbox path is not the M4's. On the M4 the same test passes
  (111 → 95 MB), and locally with VideoToolbox's software decoder forced
  (temporary experiment) memory stays flat at 109 MB from 3000 to 15 000
  hostile frames (5100 sessions): no leak reproduced. The test now prints
  memory every 500 frames (measurement only, same check) so the next CI
  run shows whether the VM's growth levels off (warm-up) or keeps rising
  (a leak). Until then M7 "memory bounded" is **met on the M4, failing in
  CI**.
  *Update (`6ae4182`, same runner image):* the test **passed** on the VM
  (Test step, `m7_memory_stays_bounded_under_a_hostile_stream ... ok`),
  but a passing test's output is captured, so the curve was not printed.
  One fail at +14 MB and one pass with no code change in between: the
  VM's result varies from run to run. CI now runs the test three more times
  with `--nocapture` and writes every curve to the job summary (step "M7
  memory curve", measurement only, any failing run fails CI). Still
  **open**; the threshold is unchanged.
  *Update (`8a7256b`, three curves):* after 500 … 3000 frames the VM's
  footprint moves between **57 and 69 MB with no trend** (run 1: 63, 57,
  68, 65, 60, 68; run 2: 68, 62, 66, 63, 62, 65; run 3: 66, 57, 58, 69,
  59, 66), from 50 MB after the 300-frame warm-up. But all three runs
  reported the final footprint as **14 MB**, read a moment after the
  3000-frame reading of 65–68 MB: the only footprint read right after
  a `vmmap` call. The passes were therefore on a meaningless number —
  **a measurement bug that let the check pass**. Fixed: every footprint is
  now read right after decoding and never right after `vmmap`, the final
  one must agree with a second reading (≤ 4 MB apart, or the test fails),
  and a reading after `vmmap` is printed for diagnosis only. On the M4:
  125 → 114 MB, pass. Read the same way, the VM's growth is **+15 to
  +18 MB** against the +8 MB limit, so M7 is expected to **fail in CI**
  again: a fluctuation of about ±6 MB around a level reached after the
  warm-up, not growth over the run. Proposed design change (not applied, needs
  the owner): a longer warm-up (1000 frames, decoder sessions created
  and dropped as in the run) before the baseline, and the baseline and
  the final value each the median of three readings; the +8 MB limit
  unchanged.
  *Update (`7be80a8`, the fixed measurement on the VM):* **FAIL, by the
  new stability check**: footprint 70, 97, 99, 102, 109, then **61 MB**
  after 500 … 3000 frames, and two readings with nothing in between
  61.0 and 56.0 MB (`footprint unstable: 63963136 then 58720256 bytes`).
  On this VM the process footprint swings by tens of MB on its own, so
  it cannot measure an 8 MB growth there; a longer warm-up and medians
  (the earlier proposal) would not fix that. The streaming e2e test
  passed on the same run. Reported to the owner with a new proposal; no
  threshold changed.
* **2026-10-22 — M7 "memory bounded": how it is checked (owner: "ok" to
  the proposal of the same day).** Closes the open entry above.
  1. The **+8 MB limit** (footprint + IOSurfaces, unchanged) is checked
     on **real Macs**: the M4 before acceptance, and any hardware CI.
  2. On a **virtual machine** (`sysctl kern.hv_vmm_present` = 1) the
     footprint cannot measure 8 MB (swings of tens of MB, readings 5 MB
     apart with nothing in between), so the test prints the numbers and
     the line `M7 memory limit: NOT checked (virtual machine …)`. Never
     silent: the CI step fails unless the test printed either that line
     or `M7 memory limit: checked …`, and puts it in the job summary.
  3. **New, on every machine:** the decoder counts its live decoder
     sessions and decoded pictures (`DecodeStats::sessions_alive`,
     `pictures_alive`); after every 500 hostile frames at most 1 session
     and 0 pictures may exist. A leak of our own decoder objects fails
     anywhere, the CI VM included. A leak *inside* VideoToolbox can only
     be seen by the memory limit, which is why (1) stays.
  Implemented test-first (`a4581a0` RED): `m7_live_sessions_and_pictures_
  are_counted` and the per-500-frame count check in the memory test.
  **Plants, each seen failing then removed:** a failed decoder session
  leaked with `mem::forget` instead of dropped, and an extra live
  reference kept for every picture (both fail the count check at the
  first 500 frames). Mutation of the counting code: 4 mutants, 4 caught.
  On the M4: `M7 memory limit: checked (+0.0 MB, limit +8 MB)`.
* Standing rule (owner, 2026-10-20): **a UX change to a security-relevant
  flow needs its own attack test** — phase3-criteria §10.8, the F-UX1
  prompt-number confused-deputy case. Applies to the Phase 4 viewer window
  and stats output wherever they touch codes, approval or identity.
