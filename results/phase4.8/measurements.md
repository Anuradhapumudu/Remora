# Phase 4.8 measurements (owner's Fedora laptop host, Mac viewer, home Wi-Fi)

Times and counts only; no sound or screen content was recorded (INV9).
Viewer `--timing` logs (`~/remora-av.log`, `~/remora-av2.log` on the
owner's Mac, not committed). Bluetooth earbuds as the output device.

## Method

- Audio and video capture times both come from the host's monotonic
  clock; the viewer's times from its own. Each figure "viewer time minus
  capture time" is off by the same clock difference, so **audio minus
  video (lip sync, AU3) is exact**.
- For AU1 the clock difference is estimated as the least
  arrival-minus-capture of any audio packet, minus the 20 ms the host
  waits to fill a packet, minus half the ping round trip (4.4 ms / 2).
  This is an estimate.
- "Reaches the output" = cpal's playback time: callback + device buffer
  + kAudioDevicePropertyLatency + SafetyOffset (cpal 0.18.2
  `coreaudio/macos/device.rs`). For the earbuds CoreAudio reported
  **160.9 ms** throughout both runs; whether that is all of their real
  delay is **unverified** (it is what macOS declares).

## Run 1 (before the buffer fixes), 2026-11-03, 574 s, 12 664 frames

| | p50 | p95 | Target |
|---|---|---|---|
| Video: capture → presented | 34.8 ms | 60.9 ms | — |
| Audio: capture → output, without the earbuds' 160.9 ms (AU1) | 121.2 ms | 121.7 ms | ≤ 150 ms p95: met |
| Audio: capture → output, with the earbuds | 282.1 ms | 282.6 ms | (reported) |
| Lip sync: sound later than picture (AU3) | 247 ms | | ±80 ms: **not met** |
| Playout buffer held | 110.8 ms | 116.5 ms | meant ~40 ms |
| Sound packets concealed (AU2), earlier 80 s session | 1 of 4 020 (0.02 %) | | ≤ 1 %: met |

Cause of the large buffer: it filled while the earbuds started and,
with sound arriving exactly as fast as it played, never drained.

Video stutter in the same run: 230 presentation gaps > 100 ms; 206
waits for a keyframe after loss (recovery p50 85 / p95 693 / max 1 089
ms; 1 024 pictures discarded) and host capture gaps of 100–700 ms (once
2.4 s) while the laptop's CPU played the video and encoded in software.
Recorded in roadmap D-56. **Corrected after run 3:** the "host capture
gaps" were read from presented pictures only; discarded ones look the
same. See run 3.

## Run 2 (with the 1 % catch-up, 7a18177), 2026-11-03, 122 s

| | p50 | p95 | Target |
|---|---|---|---|
| Video: capture → presented | 38.5 ms | 61.3 ms | — |
| Audio: capture → output, without the earbuds (AU1) | 87.3 ms | 123.1 ms | ≤ 150 ms p95: met |
| Audio: capture → output, with the earbuds | 248.2 ms | 284.0 ms | (reported) |
| Lip sync, sound later (AU3) | 210 ms | | ±80 ms: **not met with the earbuds** |
| Playout buffer held | 71.1 ms | 111.0 ms | |

The buffer drained as designed (115 → 54 ms in ~8 s) but ran dry
several times and refilled to ~110 ms in one burst each time (host
CPU starvation, as for video). Fix after this run: a backlog right
after running dry is dropped at once (next commit); to be re-measured.

Without the earbuds' declared 160.9 ms, run 2 puts sound ~50 ms after
the picture: inside AU3's ±80 ms on a low-latency output (estimate;
the Mac's built-in speakers were not measured).

## Run 3 (with the backlog drop, b844c13), 2026-11-03, 110 s

Earbuds still the output (CoreAudio delay 160.9 ms).

| | p50 | p95 |
|---|---|---|
| Video: capture → presented | 22.6 ms | 43.2 ms |
| Audio: capture → output, with the earbuds | 216.2 ms | 222.3 ms |
| Audio: without the earbuds' 160.9 ms (AU1) | ~55 ms | ~61 ms |
| Lip sync, sound later (AU3) | 194 ms (≈ 33 ms without the earbuds' delay) | |
| Playout buffer held | 44.1 ms | 54.2 ms |

The buffer fixes work (held p50 111 → 71 → 44 ms). AU3 is not met with
Bluetooth earbuds: their declared 160.9 ms alone is twice the ±80 ms
budget; without it, sound trails the picture by ~33 ms (estimate).

**Freezes (owner: "freezing on frames like second and continue playing
and freeze again"):** 9 gaps of 0.35–1.0 s in 110 s. The per-second
`media:` counters show the network layer receiving a steady 28–37
pictures/s with **1–3 pictures/s given up** (`frames_dropped`, no bad or
late fragments), each followed by a keyframe wait (recovery p50 71 /
p95 625 / max 971 ms). Sound on the same connection lost 1 packet in
4 020 (earlier session), so this is probably not Wi-Fi loss. Causes to
check first in D-56 (unverified): quinn discarding oldest unsent
datagrams, or the reassembler abandoning frames whose last fragment is
only late.
