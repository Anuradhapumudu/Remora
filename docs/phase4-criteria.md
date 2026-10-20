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
| T3 | Lid close, display removal | **not testable** on this machine (needs an external display) → known gap, added to roadmap D-16 |
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
* Standing rule (owner, 2026-10-20): **a UX change to a security-relevant
  flow needs its own attack test** — phase3-criteria §10.8, the F-UX1
  prompt-number confused-deputy case. Applies to the Phase 4 viewer window
  and stats output wherever they touch codes, approval or identity.
