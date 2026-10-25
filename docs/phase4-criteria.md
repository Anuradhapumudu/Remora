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
| P3 | Viewer keeps up | Of the frames the screen produced during the 60 s run, at least **98 %** are drawn by the viewer; **0** decode errors, **0** AEAD failures, **0** reassembly drops on clean loopback. A run counts only if the screen produced **≥ 55 fps** (3300 frames in 60 s). *(Was "drawn ≥ 3528 in 60 s", which assumed a 60 fps source; changed 2026-10-23, §12)* | Counters on both sides, inside the measured 60 s. "Produced" is counted where Remora first sees a frame: each frame ScreenCaptureKit delivers with new content (`serve --timing`: one `captured:` line; frames the encoder drops or fails: `not encoded:`). A frame the screen made but the capture never delivered cannot be counted; it shows only as a gap in P4's frame interval. Viewer: `connect --timing` prints the decoder counts and a `media:` line (AEAD failures, frames given up by reassembly) once a second |
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
| T3 | Lid close, captured display removed | Both **testable** (corrections 2026-10-20, §12), run in step 7. **Lid close / open** (owner closes the lid): `Interrupted` on close, `Resumed` ≤ 2 s after the display is back on open, same session. **Captured display removed** (a `CGVirtualDisplay` is captured, then destroyed — Phase 2's tooling; real hardware may differ): `Interrupted` ≤ 1 s, no crash, no CPU spin while absent; if it returns within 2 minutes the stream resumes in the same session with a keyframe, if not the session ends with `CaptureStopped` (never `Normal`, never another display; decision D-29, architecture D38). While it waits, both sides show "The host's display is unavailable (lid closed or disconnected). Waiting, N s left." (`StreamState` reason 4 + `remaining_ms`, done 2026-10-22, architecture D43; wording and names D44, 2026-10-23; the overlay is roadmap D-33). A closed lid with the Mac awake leaves the display list too and gets the same countdown (D44). Only **physical** monitor unplug stays untested (roadmap D-16) |
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

* **Step 7b, M1b, M4, N1, N2 (2026-10-22).** `remora-viewer/tests/
  m1b_m4_n1_wire.rs` (one test, its own process: it captures every
  `tracing` event of the process at TRACE, quinn and rustls included —
  new `LogCapture::global`): 600 real encoded frames (1280 × 720, a P7
  barcode, a 32-byte random pixel canary and a band of fresh random pixels
  in each) from `HostServer` through a recording UDP relay to `connect`.
  **M1b:** 10 912 UDP payloads, 10.7 MB, **entropy 7.9989 bits/byte**, no
  16-byte window of any encoded frame and no canary in any of them; the
  checker finds a frame window spliced into a recorded payload (kept in
  the test). **M4:** halfway, the relay re-sent the 100 oldest and 50
  newest host→viewer packets: 600 of 600 frames delivered once each,
  600 drawn, numbers strictly increasing. QUIC itself drops a re-sent UDP
  packet (packet numbers are never reused), so the replay never reached
  our media layer; our replay window is the second line and is tested
  directly in M5 (sans-IO). **N1:** 45 565 log lines at TRACE, no frame
  window (raw, hex, byte list; new testkit `Windows16`) and no canary.
  **N2** (`e2e_cli` `n2_…`, the real binaries, each with its own `HOME`,
  `TMPDIR`, `XDG_*` and working directory, 10 s of streaming, 599 frames
  decoded): the only files written are the two key files, and no file
  holds H.264 parameter sets or keyframe slices; no file under the macOS
  per-user temp and cache folders names our binaries (no window, so no
  Metal shader cache). N2 cannot look for the pixel canary or encoded
  frames *inside* the binaries' files (the test does not see the host's
  frames); it checks the file list and H.264 headers, while N1 does the
  window check in-process. **Plants, each seen failing then removed:** a
  `trace!` of each received frame's bytes in `remora-net` (N1), every
  frame delivered twice (M4), the viewer writing each frame to
  `frame.bin` in its working directory (N2).

* **Step 7c, D-29 and T3 "captured display removed" (2026-10-22).**
  `GoneTimer` in remora-capture (OS-neutral): only time the display is
  **missing from the display list** counts (removed); a listed display
  that is asleep never expires (its wait ends by liveness, D37). Tests:
  `d29_…` (2), both seen failing against plants (the wait not reset when
  the display returns; a listed display counted as missing); mutation 3/3
  caught. The macOS restart loop asks the timer on every retry and stops
  with `CaptureError::DisplayRemoved` ("the captured display was removed
  and did not come back") after `display_gone_limit` (120 s; settable for
  the test run); it still only ever restarts the same display ID. **T3 on
  the M4** (`scripts/macos/t3-display-removed.sh`, a private
  `CGVirtualDisplay` captured through RemoraDev.app, then destroyed):
  `Interrupted` within 1 s of removal (logged ~1 s before the script's own
  mark); with a 15 s limit `STOPPED … removed and did not come back` 16.9 s
  after `Interrupted`; memory 6.0–6.4 MB throughout. **No CPU spin while
  absent:** the first version asked for the display list every 0.5 s and
  used **2.7 % of a core** (270 ms in 10 s); while the display is missing
  it now asks every 2 s: **0.7 %** (70 ms in 10 s). A sleeping (listed)
  display keeps the 0.5 s retry, so T2's resume time is unchanged.
  **"Returns within 2 minutes" could not be produced with this tooling:**
  a re-created virtual display gets a **new display ID** (4 → 5), so
  capture did not resume — correctly, as it never captures another
  display (D38). The same-ID return is the restart path T2 measured on
  real hardware (display sleep → wake, `Resumed` ≤ 2 s); whether a real
  monitor keeps its ID when replugged is untested (roadmap D-16).
  **Not done then (owner to decide):** D-29's "both sides show the wait
  and the time left" — done the same day, next note. **Lid close** (T3's
  other half) needs the owner at the machine (step 7d).

* **Step 7c-2, D-29 shown on both sides (2026-10-22, owner: "split it";
  architecture D43). DONE: the protocol part.** `StreamState` gained
  `reason = 4` (display removed) and `remaining_ms` (field 3), a **minor
  addition** (protocol.md §5, §8 change log; owner chose it over a major
  bump, which would change every `remora/1/…` key label). The validator
  refuses a resumed message with time left and more than 1 h (§7). The
  capture reports `DisplayRemoved { remaining }` once per absence
  (`GoneTimer::observe`); the host session keeps a deadline, sends the
  time left once, again only for a new deadline, and tells a viewer
  approved during the wait the time actually left. **Minimal display:**
  host terminal `Display removed. Waiting, N s left.` at the pause and
  every 10 s; the viewer prints the same and its window title counts down
  every second (the overlay is Phase 4.5, roadmap D-33). Tests: wire
  shapes and exact bytes (also a fuzz seed), a viewer without the field
  still reads the pause, 4 session tests, `GoneTimer` transitions,
  rounding, QUIC loopback. **10 plants, each caught** (bound removed;
  resumed-with-time allowed; full wait sent to a late joiner; a repeated
  report deduplicated; deadline not cleared; `Back` not reported; time
  dropped on decode; seconds rounded down; ms→s in the mapping and in the
  net wrapper). Fuzz `messages`: 9.0 M runs / 121 s with 7 new seeds, 0
  crashes. Mutation of the changed functions: remora-proto `decode_envelope` 10/10 caught; remora-session 32 (27 caught, 5 unviable, 0 missed); remora-net wrapper 4/4 caught. **On the M4** (T3 script, 15 s
  limit): `INTERRUPTED DisplayUnavailable` then `DisplayRemoved {
  remaining: 15s }` 0.55 s later, `STOPPED` 16.3 s after that (the
  missing display is polled every 2 s, so the countdown reaches 0 up to
  2 s before the session ends, never after); CPU while absent 0.7 %.
  **Not checked automatically:** the host and viewer text on a real
  removal (`serve` always captures the main display, so the virtual
  display cannot be used with it); the shared text function is tested.

* **Step 7d tooling (2026-10-22).** `serve --timing` and `connect
  --timing` print one `timing:` line per frame (shared-clock µs: capture,
  encoder output, sent; received, decoded, **GPU draw done** via
  `Queue::on_submitted_work_done` + `poll(Wait)`, present returned) — times
  and sizes only (e2e check that every field is `key=number`; seen
  failing against a planted `head=[0, 0, 0, 1]`). `scripts/macos/
  p1-latency.py` (since replaced by `phase4-session.py p1`, below) runs
  host and viewer, accepts, streams, joins the logs by capture time and
  prints P1, P2, every stage and P3. **Tooling check**
  (synthetic source, 5 s, not a P1 run): P1 p50 10.7–11.1 ms, p95
  13.7–16.4 ms; capture → encoded 6.2–6.5 ms p50 (a synthetic frame's
  "display time" is when it was made). **Finding:** in all three checks
  the window stopped drawing after 2–4 s — `get_current_texture` said
  **occluded** (another window in front), so only 24–53 % of frames were
  drawn. The R3 stats line now says `no drawable N (occluded)`. The real
  P1 runs need the viewer window in front and visible (owner session).

* **Step 7d session runner (2026-10-22).** `scripts/macos/phase4-session.py
  check|p1|p5|p6|p8|m7|t2|t3-lid`: one command per step; the host runs
  through RemoraDev.app (Screen Recording) with input through a named
  pipe; each step writes `results/phase4/<step>.txt`, one line per
  verdict to `results/phase4/summary.md` and raw logs to `logs/` with
  one-time codes and passwords replaced by `[redacted]`; the Mac is kept
  awake with `caffeinate -dims`. A run is reported **INVALID (not
  counted)**, never PASS or FAIL, when the motion page was not on screen
  (< 55 fps captured) or the viewer window was covered (occluded).
  P1 measures 60 s after a 10 s warm-up (time to click the window to the
  front). Thresholds are copied from §4 and §7 into the script's
  constants. **Finding from the tooling check:** "present returned" comes
  *before* "GPU draw done" (−0.5 to −1.1 ms): `present()` only queues the
  frame. P4's "drawn → present returned" is therefore reported as
  measured (negative), information only.

* **Step 7d, the owner's measuring session (2026-10-23, M4, AC power,
  `results/phase4/`).** All steps PASS; numbers and the row-by-row
  comparison go in the phase report. **Finding from T3 (lid):** the
  runner keeps the Mac awake (`caffeinate -dims`), so closing the lid did
  **not** sleep the Mac ("Entering DarkWake state due to 'Clamshell
  Sleep'"): **our own test setup changed the behaviour being tested** —
  T3 as run tested a closed lid with the Mac awake, not the normal case
  where the Mac sleeps. In that state the built-in display leaves the
  display list, so both sides counted down from 120 s ("display
  removed"); the lid was opened at 10 s left. This contradicted D38 and
  the `GoneTimer` docs ("lid closed stays listed, never expires").
  Owner decision (option A, architecture D44): keep the 2-minute end,
  correct the docs, say "unavailable (lid closed or disconnected)", and
  rename the wire reasons (1 *display asleep*, 4 *display unavailable*;
  values unchanged). The run with the Mac really sleeping is roadmap
  gate **G-2** (before the phase report is final); its expected result
  is written in §11c before it is run.

* **Step 7d follow-up: the open questions from the session (2026-10-23).**
  1. **P5's 147 MB, and a leak found on the way.** Viewer memory by
     setup (synthetic source, `footprint`): no window **6.3 MB**; window
     covered **2427 MB after 15 s** — every picture's upload waited for a
     `queue.submit` that only a draw makes, and a covered window cannot
     draw. Fixed test-first (`ff35fcb` RED +897 MB over 300 undrawn
     pictures, `b996e04` GREEN +0 MB): the covered window now holds
     **89 MB**; a visible one **144 MB**, of which **94 MB** is GPU memory
     owned through Metal/wgpu. That 94 MB did not change between the
     window sizes tried, but resizing by script was refused for two of the
     three sizes (no Accessibility permission), so "independent of window
     size" is **not shown**. What inside wgpu/Metal holds it was not
     determined (needs Instruments); listed for the phase report. P5's
     owner run (visible window, flat 147–148 MB) stands; it could not
     have caught the covered-window case.
  2. **decoded → drawn vs its 1.5 ms budget.** Split with new timing
     stamps (synthetic, window in front, 30 s, p50): hand-off to the
     window thread 0.02 ms, upload 0.73 ms, getting a surface 0.03 ms,
     GPU draw 1.17 ms. **No wait for the display's refresh is inside
     it**: the time is copying each 3 MB picture (CPU into wgpu's
     staging, then GPU into the texture) and the GPU's draw. So the code,
     not the budget, is where the time goes; importing the decoder's
     IOSurface directly (roadmap D-17 options) would remove the copy.
     The fix in (1) does not slow it: decoded → drawn 1.95 ms with the
     extra submit vs 2.06 ms without (that comparison is only 24 frames:
     the window lost the front).
  3. **T2's resume, 0.70–0.72 s vs 0.33 s in step 2.** Step 2's
     capture-only test rerun the same night with the same sleep/wake
     timing: **0.75–0.79 s**. The streaming host adds nothing; the Mac
     took longer to bring the display back than on 2026-10-20. The power
     log's whole-second times cannot show why.
  4. **01:40 vs 02:16 P1 runs (≈ 3 ms apart at p50).** Every stage after
     the encoder was about 1.5× slower at 01:40, including sending over
     loopback (0.65 vs 0.33 ms), which no window setting affects: a
     machine-wide state (load or clock speed), not Remora's code (only
     log lines changed between them). Not determined further; both
     sessions pass P1/P2.

* **Step 7d, second session (2026-10-23 evening, `results/phase4/*-18*`).**
  Gate G-2 met (roadmap; matched §11c). P1/P2/P3 re-measured with the
  covered-window fix: PASS, no regression. P5 with the window in front:
  PASS at **149 MB of 150** (roadmap D-34). **P5 with the window covered:
  closed as not achievable by hand (3 × INVALID); the guard is the
  automated test `p5_pictures_that_are_never_drawn_do_not_pile_up`.** No
  more attempts (owner). What is and is not covered:
  * **Covered:** the automated test proves that uploads which are never
    drawn do not pile up: it fails with the fix planted out (+896 MB on
    the M4 and +896 MB on CI's VM, on its memory assertion) and passes with
    it (+0 MB; 6 passes on CI's VM after its GPU wait was added, `6f1d984`).
  * **Not covered:** no manual run reproduced a real window that cannot
    draw. Covering the viewer with a full-screen terminal (18:29),
    minimising it (18:41) and covering it with full-screen Safari (18:53)
    each left it **drawing 60 fps** for 10 minutes (the runner's covered
    check: 538 of 538 stats lines drew frames), so those runs were
    INVALID. That exact path — a real window that gets no surface — is
    guarded **only by the synthetic test, not by an end-to-end P5.** The
    one real window seen without a surface was in a diagnostic probe
    (window never brought to the front): 2427 MB after 15 s before the
    fix, 89 MB after it — a single 15-second observation, not a P5 run.
    When macOS withholds the surface is not known (step 6 saw it for a
    hidden window).
  * Finding from those runs: the viewer keeps drawing at 60 fps while
    covered or minimised (roadmap D-35).

## 11c. T3 with the Mac asleep: expected result, written before the run (gate G-2)

Written 2026-10-23, before the owner runs `scripts/macos/phase4-session.py
t3-lid --mac-sleeps` (roadmap G-2). The run is compared against this; any
difference is a finding, not something to explain away afterwards.

**Setup.** Host and viewer run on the **same Mac** over loopback. The
runner prevents only display and idle sleep (`caffeinate -di`, as Phase
2's lid test, where the Mac slept ≈ 29 s), so closing the lid sleeps the
Mac. The run counts only if the power log shows `Entering Sleep state due
to 'Clamshell Sleep'` (the awake run of 2026-10-23 showed `Entering
DarkWake state …` instead).

**What the clocks do while the Mac sleeps (read, not assumed).** Rust's
`Instant` on Apple systems is `CLOCK_UPTIME_RAW`, which "does not
increment while the system is asleep" (std 1.99.1,
`library/std/src/sys/time/unix.rs:55-67`). tokio's clock is
`std::time::Instant::now()` (tokio 1.53.2 `src/time/clock.rs:15-16`) and
quinn's runtime clock is tokio's (quinn 0.11.12 `src/runtime/tokio.rs:37-38`).
So the QUIC idle timeout (30 s), the keep-alive and the 2-minute display
wait all **stand still while the Mac sleeps**; only short maintenance
wakes advance them.

**Expected, step by step:**

1. **Lid closed:** within about 1 s the host prints `capture paused
   (DisplayAsleep)` and the viewer `stream paused (the host's display is
   asleep)`. If the built-in display leaves the display list before the
   Mac is fully asleep, an `unavailable … 120 s left` line may follow;
   whether it does is recorded, not predicted. Then the Mac sleeps.
2. **After 30–35 s:** **nothing.** The viewer is on the same sleeping Mac,
   so it is asleep too, and its idle clock is not running: no `failed:
   connection lost` line. D37's "the viewer reports connection lost after
   30–35 s" needs the viewer on **another machine**, which this run
   cannot show; that case is described below for Phase 5.
3. **Lid opened:** no reconnect happens and none is needed. The same QUIC
   connection simply continues, because no timeout ran during sleep.
   Remora has no automatic reconnect at all. Capture's restart loop finds
   the display listed: the host prints `capture resumed` **≤ 2 s after the
   power log's `Display is turned on`**, the first frame after it is a
   **keyframe**, and the viewer prints `stream resumed` in the **same
   session**. If a countdown had started in step 1, it continues from
   about where it stood, not 30 s lower.

**PASS if:** the Mac really slept (power log), the session is the same one
afterwards, `capture resumed` ≤ 2 s after the display came on (+1 s for
the power log's whole-second times), keyframe first, and no `connection
lost`. A session that ends on wake is a FAIL against this expectation and
is reported with its logs.

**For information: the two-machine case (Phase 5, not run here).** The
host Mac sleeps; the viewer on another machine hears nothing for 30 s and
prints `failed: connection lost - no reply from the host for 30 s
(network down, or the host stopped)` (D37; `remora-viewer` main.rs). When
the lid opens, the host's own connection has not timed out yet (its clock
stood still); its packets reach a viewer that has already closed the
connection, and the host's session ends — at once if the viewer's QUIC
stack answers with a stateless reset, otherwise by the host's own idle
timeout about 30 s later (**unverified** which; to be checked in Phase 5). The person at the viewer must connect again with a new code: there
is no automatic reconnect.

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
* **2026-10-22 — D-29 split (owner).** "Both sides show the wait and the
  time left" is split: the **protocol** (`StreamState` reason 4 +
  `remaining_ms`, sent once, counted down locally) and a **plain-text
  display** (host terminal line; viewer terminal line and window title)
  are Phase 4 and done (§11b step 7c-2); the **proper visual** (overlay,
  countdown) is the Phase 4.5 GUI, roadmap D-33. The owner asked for a
  protocol version bump; on the trade-off (the major version is part of
  every key-derivation label, and §8 already treats a new optional field
  as minor) the owner chose a **minor addition** recorded in protocol.md
  §8. Adds a test item; no threshold changes.
* **2026-10-23 — P3 reworded after a FAIL (owner).** In the owner's P1
  session, run 1 failed P3 as it was written ("drawn ≥ 3528 in 60 s"):
  3376 drawn. That run's viewer drew **100 %** of the 3376 frames the
  host sent; the screen itself changed only **56.3 times a second**
  (runs 2 and 3: 59.2 and 59.5 fps, 100 % drawn, PASS). The old wording
  assumed the source produced 60 fps (3528 = 98 % of 3600). Owner's
  decision: *"Of the frames the screen produced during the 60 s run, at
  least 98 % are drawn by the viewer"* (same tolerance), and a validity
  floor in the criteria rather than only in the runner: **a run counts
  only if the screen produced at least 55 fps (3300 frames in 60 s)**.
  "Produced" is measured as frames ScreenCaptureKit delivered with new
  content — the earliest point Remora can count a frame; the owner asked
  for losses anywhere in the chain including capture, and losses inside
  the capture itself are visible only as gaps in P4's frame interval
  (said so to the owner the same day). That count did not exist when runs
  1–3 were made: the host logged a frame only once encoded and sent, and
  an encoder drop left no trace. The host now logs `captured:` and `not
  encoded:` (`p3_every_captured_frame_is_accounted_for`, 3 plants caught),
  and the viewer logs its media counts so the AEAD and reassembly parts
  of P3 are checked inside the window (before, the runner did not read
  them). **Runs 1–3 stay in the results unchanged** (`results/phase4/
  p1-0140.txt`; run 1 recorded as FAIL under the old wording). Under the
  new wording run 1 passes on the frames it sent (100 %); whether it
  captured frames it never sent was not logged, so P1 is run again with
  the capture count. Not a threshold change for P1 or P2.

## 13. Results — the Phase 4 report (2026-10-23; accepted by the owner 2026-10-25)

**Status:** every Phase 4 criterion passes on the M4, with three caveats
listed in §13.5. **D-9 closed 2026-10-25** (dev signing identity and the
RemoraDev grant removed; evidence in roadmap.md). Still to do before Phase 4
is done: the owner's acceptance — **given 2026-10-25, after reading this section.** Evidence: `results/phase4/`
(raw output of every measured run), the commits named below, CI on
`6f1d984` (all five workflows green).

### 13.1 Criteria, row by row

| ID | Result | Numbers vs limit | Evidence |
|---|---|---|---|
| R1 | Done as decided | winit 0.30.13 + wgpu 30.0.1; present mode `Immediate` offered and used | architecture D41 |
| R2 | Done as decided | CPU upload of NV12 planes; zero-copy still D-18 | D41; upload 0.78 ms p50 (§13.2) |
| R3 | Done | stats in the title + one stderr line per second | D41 |
| R4 | Done | INV2 tested on media; input → D-1b (Phase 6) | §5 |
| R5 | Done | winit direct dependency | dependencies.md |
| **P0** | PASS | offset ≤ 0.42 µs (≤ 50), round trip 3.4–3.75 µs (≤ 200); planted 1 ms skew caught | §11b step 1 |
| **P1** | PASS | p95 worst run: **14.00 ms** (02:16 set), **14.53 ms** (18:12 set, with the fix); limit < 20 | `p1-0216.txt`, `p1-1812.txt` |
| **P2** | PASS | p95 worst run 4.65 / 4.54 ms; limit ≤ 11.9 | same |
| P3 | PASS (reworded 2026-10-23, §12) | 100 % of captured frames drawn in all 6 counted runs; sources 58.4–60.0 fps (floor 55); 0 decode/AEAD/reassembly failures | same; the 01:40 set (`p1-0140.txt`) is kept as recorded, run 1 FAIL under the old wording |
| P4 | Reported | frame interval p50 16.67 ms; "present returned" comes **1.0–1.4 ms before** the GPU finishes (present only queues); `Fifo` not measured (`Immediate` was offered); glass-to-glass not measured (no camera, D-19) | same |
| P5 | PASS, **1 MB margin** | window in front: peak **148 MB** (02:24) and **149 MB** (18:17), limit < 150; growth +0.00 MB, slope −0.008 / −0.022 MB/min. Covered window: not achievable by hand (§11b) | `p5-0224.txt`, `p5-1817.txt`; roadmap D-34 |
| P6 | PASS | **0.88 %** of one core incl. VTEncoderXPCService; limit < 2 % | `p6-0236.txt` |
| P7 | PASS | 90/90 frames drawn once, in order; loss and reorder cases never backwards, never twice | §11b step 6 |
| P8 | PASS | C12 p95 7.61–7.64 ms (≤ 11); p50 7.49–7.51 ms (Phase 2: 7.51); C2 p50 7.06 ms (the D-10 drift was 9.0) | `p8-0205.txt` |
| **M1a** | PASS | no frame window or canary in any datagram payload; plaintext-seal plant caught | §11b step 4 |
| **M1b** | PASS | 10.7 MB of UDP payloads, entropy 7.9989 (≥ 7.99), no frame window or canary | `m1b_m4_n1_wire.rs`, 3afe9a0 |
| **M2** | PASS | compile-fail doctests; one `send_datagram` call site (scanner) | §11b step 4 |
| M3 | PASS | no media before `Active`; viewer drops pending-state datagrams unread | §11b step 4, §12 |
| M4 | PASS | 150 replayed packets: 600/600 frames delivered once, drawn in increasing order | step 7b |
| M5 | PASS | tamper / unknown key / truncation dropped and counted | step 4 |
| M6 | PASS | every limit checked before storing or allocating, 32 MiB total budget; mutation 88 (82 caught, 5 unviable, 1 timeout, 0 missed); fuzz `video_reassembly` 13.6 M runs, 0 crashes | `remora-proto/tests/m6_video.rs`, d34952b RED / 54e4dc3 GREEN (step 3 has no §11b note — a gap in the record; its evidence is the commit) |
| M7 | PASS | oversize refused before configuration; hostile streams no crash/hang; memory **+0.0 MB on the real M4** (limit +8) | step 5; `m7-0237.txt` |
| M8 | PASS | 10⁶ packets, 20 rotations, no counter repeated | step 4 |
| **N1** | PASS | 45 565 trace lines, no window or canary | step 7b |
| **N2** | PASS | only the two key files on disk | step 7b |
| **N3** | PASS | policy rule; plants caught | step 7b |
| N4 | PASS | found and fixed three `Debug` leaks over plaintext | step 7b |
| T1 | PASS | 12 sans-IO tests + D-29 tests; mutation 0 missed | steps 2, 7c |
| T2 | PASS | 5/5: pause 0.08–0.10 s (≤ 1), resume 0.70–0.72 s (≤ 2), keyframe after every resume, same session, +0.00 MB | `t2-0240.txt` |
| T3 | PASS | lid, Mac awake: resume 0.7–1.7 s after display on; lid, Mac asleep (G-2): 0.1–1.1 s, matched §11c; display removed: `Interrupted` ≤ 1 s, stop after the limit, 0.7 % CPU | `t3-lid-0249.txt`, `t3-lid-mac-sleeps-1809.txt`, step 7c |
| T4 | PASS | no OS names in session/net; plant caught | step 2 |
| §8 functional | PASS | `serve` streams after approval; the viewer window shows it; closing ends the session; CI's macOS runner encodes and decodes with VideoToolbox | steps 1, 5, 7a |

### 13.2 Measured numbers vs the latency budget (§3)

The 18:12 set (with the fix), p95 of the worst run:

| Stage | Budget p95 | Measured p95 |
|---|---|---|
| Capture + encode | ≤ 11 | 9.37–10.01 |
| Seal + send | 1.0 | 0.07–0.09 |
| Loopback | — | 0.34–0.39 |
| Decode | 4.0 | 1.50–1.69 |
| Upload + draw to GPU completion | **1.5** | **2.08–2.42 — over** |
| Sum after encode (P2) | 7.0 | 3.95–4.54 |

**Over budget: decoded → drawn.** It does **not** include waiting for the
display's refresh (getting a surface: 0.03 ms). It is the work: the hand-off
to the window thread 0.02 ms, the CPU copy of each 3 MB picture 0.78 ms
(p50), and the GPU draw 1.17 ms. The budget came from a spike that measured
upload + draw on the CPU only (≤ 0.80 ms p95); the endpoint here is GPU
completion. The code, not the budget, is where time can be saved: D-18
(zero-copy import) removes the copy. The gates P1 and P2 pass with 5.5 and
7.4 ms to spare.

**Between sessions**, the same code measured P1 p50 ≈ 16.0 ms (01:40) and
13.0–13.4 ms (02:16, 18:12): at 01:40 every stage after the encoder was
about 1.5× slower, loopback included — a machine-wide state, not
determined further (§11b).

### 13.3 Manual test steps (exact)

From `~/Documents/github/Remora` on the M4, AC power, Low Power Mode off,
Do Not Disturb on, only Terminal (and Safari for the moving page) open:

1. `scripts/macos/phase4-session.py check` — preflight; must say PASS.
2. `open -a Safari scripts/macos/motion-pattern.html`, Option-click the
   green button (fills the screen; not full screen), then
   `scripts/macos/phase4-session.py p1`; drag each viewer window to the
   bottom-right corner and click it once.
3. `scripts/macos/phase4-session.py p8` (Safari as in 2, no viewer).
4. `scripts/macos/phase4-session.py p5` (as in 2; 10 minutes).
5. `osascript -e 'quit app "Safari"'`, then
   `scripts/macos/phase4-session.py p6` (hands off for 80 s).
6. `scripts/macos/phase4-session.py m7`.
7. `scripts/macos/phase4-session.py t2` (the display goes off 5 times;
   hands off).
8. `scripts/macos/phase4-session.py t3-lid --mac-sleeps` (close the lid
   when told, open it after ~30 s).

By hand, without the runner: `remora-host serve` prints a code and a
password; `remora-viewer connect <code> --password <password>` connects;
type `accept <n>` at the host; the viewer window shows the screen.

### 13.4 Findings this phase

* **Covered-window GPU leak** (found 2026-10-23 while explaining P5's
  147 MB): a window that cannot draw kept every picture's upload; 2.4 GB in
  15 s. Fixed test-first (ff35fcb RED, b996e04 GREEN).
* **A closed lid with the Mac awake leaves the display list** — D38 and the
  `GoneTimer` docs said the opposite, written from expectation. Found by
  T3, corrected (architecture D44), wire reasons renamed.
* **Three `Debug` implementations printed plaintext** (N4), fixed.
* **P3's wording assumed a 60 fps source**; reworded after run 1 failed
  while drawing 100 % (§12).
* **The P5 test was flaky on CI's VM** (read memory before the GPU had
  finished); fixed with a bounded wait (6f1d984), plant shown failing on
  the VM.
* **New tokio advisory during the report** (RUSTSEC-2026-0386, `AsyncFd`
  I/O safety): `cargo deny` failed CI on `1ceef72`; tokio 1.53.3 adopted as
  a security-fix exception (`406c23b`, dependencies.md; expires 2026-10-27).
* **The dev identity test passed on the M4 but not on CI's Mac**: `codesign`
  on macOS 15.7.9 / 26.6.2 needs the keychain on the search list, macOS
  27.0.1 does not (roadmap D-9 evidence). Fixed in the test (`5061384`).
* **Dependabot PRs #7–#12 (checked 2026-10-25): none fixes a published
  advisory.** `cargo audit` flags none of our locked versions and GitHub
  shows 0 Dependabot alerts. zeroize 1.9.0, objc2 0.6.4 and hkdf 0.12.4 have
  no advisories; curve25519-dalek 4.1.3, ed25519-dalek 2.2.0 and blake2
  0.10.6 are already at or past the fix of their one old advisory each
  (RUSTSEC-2024-0344, -2022-0093, -2019-0019). Actions: download-artifact's
  GHSA-cxww-7g56-2vh6 affects 4.0.0–4.1.2, we use 8.0.1; the other two have
  none. #9–#12 are major versions (a new RustCrypto generation: D3); #8
  (zeroize 1.9.1) must pass the 14-day check.

**Mistakes of mine this phase, for the record:** the session runner first
mis-judged occlusion and P3 from running totals (two false INVALID/FAIL
verdicts), and a tooling check wrote unmarked lines into the owner's
`summary.md` (removed, and synthetic runs are now tagged); protocol.md
said the viewer's countdown ends "never early" (wrong: up to ~2 s early;
corrected); I called the upload copy "D-17" twice when it is D-18.

**Mac permissions after D-9 (2026-10-25).** The owner turned off
Terminal's **Full Disk Access** and **Accessibility** on 2026-10-25 and
quit Terminal (new process 52707, started 02:45:43; the old one, 10618,
had run since 2026-10-20 and still held both — the first attempt did not
take effect, found from the privacy database before anything was
recorded). Evidence: Full Disk Access — the read-only read of the system
privacy database now fails with `authorization denied` (it succeeded
until then); Accessibility — the owner's check in System Settings (the
database can no longer be read). **`pmset -g log` works without Full Disk
Access** (exit 0; the 775 `Entering Sleep state` lines the T3-lid runner
looks for are all there), so no measuring session needs Full Disk Access;
Accessibility is used by no script (Phase 6 input injection goes through
RemoraDev.app, not Terminal). No Remora app holds any privacy grant.

### 13.5 Known limitations

* **P5 passes by 1 MB** (149 of 150 MB); what holds the 94 MB of GPU memory
  is unknown → D-34, a v0.1 blocker.
* **A real covered window that cannot draw was never reproduced by hand**;
  that path is guarded only by the synthetic test (§11b).
* **Everything ran on one Mac over loopback.** No network loss, no second
  machine: the two-machine lid case (the viewer reports `connection lost`
  after 30–35 s; whether the host's session then ends at once or after its
  own idle timeout is unverified) is Phase 5. No FEC (D-27).
* **The viewer keeps drawing while covered or minimised** (D-35).
* A display that **returns** after removal was not producible with a
  virtual display (new ID); physical monitors untested (D-16).
* Software timestamps end at "GPU finished", not at the glass (D-19).
* macOS only: Windows backends are Phase 6.5.

### 13.6 Deferred list, row by row (roadmap.md)

| # | Phase 4 outcome |
|---|---|
| D-1 | **Closed** 2026-10-22 — INV2 on the real media path (M1a, M1b, M2–M8) |
| D-1b | Unchanged — INV2 for input, Phase 6 |
| D-2 | **Closed** 2026-10-22 — INV9 (N1–N4) |
| D-3 | Unchanged — INV10, Phase 6 |
| D-4 | Unchanged — INV11 GUI test, Phase 4.5 |
| D-5 | Unchanged — keychain, v0.1 |
| D-6, D-7 | Unchanged — v1.0 |
| D-8 | **Closed** 2026-10-23 — capture restart: T2 twice, T3 lid awake and asleep, display removed |
| D-9 | **Closed** 2026-10-25 — identity and grant removed after the recreate path was proven on macOS 15.7.9, 26.6.2 and 27.0.1 (`test-dev-identity.sh`, CI green on `5061384`); evidence in roadmap.md |
| D-10 | **Closed** 2026-10-23 — shown gone (C2 p50 7.06 ms in 3 runs), **not explained**; reopen if it returns. This report's comparison (the interim rule until D-25): C2 p50 **7.06 ms** vs the 7.06 ms baseline — the drift is **not** back |
| D-11, D-12 | Unchanged — Phase 6.5 |
| D-13 | Unchanged — first public release |
| D-14, D-15 | Unchanged |
| D-16 | Unchanged — physical unplug/replug stays here, including a removed display coming back with its ID (not producible with a virtual display, D-28) |
| D-17 | Unchanged — Phase 4.5 design; cross-referenced from D-34 |
| D-18 | **Decided with D-34** (owner, 2026-10-24): its phase is set when D-34's Instruments investigation reports, no later than the v0.1 gate; the copy path tied to the 94 MB → the phase that fixes D-34, otherwise Phase 9 (decoded → drawn is over its stage budget, §13.2, but P1/P2 keep 5.5/7.4 ms spare) |
| D-19 | **Moved** to Phase 9 by its own rule (no camera at this report) |
| D-20, D-21 | Unchanged — Phase 4.5 |
| D-22 | Unchanged — Phase 6.5 |
| D-23 | Unchanged — Phase 7 |
| D-24 | Unchanged — Phase 5 |
| D-25 | **Not done in Phase 4** (its "close by"): runs are compared by eye in the session runner, but no check flags a > 1 ms disagreement. **Moved to Phase 7** (owner, 2026-10-24), linked to D-10: until it exists, each phase report compares C2 p50 with the 7.06 ms baseline |
| D-26 | Unchanged — Phase 4.5 planned work |
| D-27 | Unchanged — Phase 5 |
| D-28 | **Closed** 2026-10-23 — T3 lid and display removal run in step 7 |
| D-29 | **Closed** 2026-10-23 — implemented, shown, corrected (D43, D44) |
| D-30 | Unchanged — Phase 4.5 or later |
| D-31 | Unchanged — Phase 5 |
| D-32 | Unchanged — Phase 7 |
| D-33 | New this phase (2026-10-22) — the countdown overlay, Phase 4.5 |
| D-34 | **New** 2026-10-23 — the 94 MB of GPU memory, **v0.1 blocker** |
| D-35 | **New** 2026-10-23 — viewer draws while covered/minimised, Phase 4.5, nice-to-have |
| D-36 | **New** 2026-10-25 — recreate the dev identity at the start of the next phase that needs screen capture, remove it at that phase's end (owner) |

Gates: G-1 met (Phase 3), **G-2 met** 2026-10-23. Open gates: 0.
