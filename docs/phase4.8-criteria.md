# Phase 4.8 (D-51): Sound — the host's audio plays on the viewer — criteria

**Status: APPROVED by the owner, 2026-11-02**, with the recommended answer
to every decision in §2: Q1 "Keep playing" (the host's speakers are not
muted), Q2 + Q3 "Yes to both" (sound on by default with a mute key in the
viewer; libopus bundled at a pinned version behind our size checks and
fuzzing). Building starts with spike S-A1.

## 0. What exists, and what is not verified yet

**Exists:**

- The encrypted media path. Video already travels as sealed QUIC
  datagrams: per-session media key, AEAD, a replay window, size limits,
  a fuzzed parser, and keys that rotate (phase4-criteria M1–M8). Audio
  can be a second kind of datagram on that same path, with no new
  crypto.
- On the Linux host, PipeWire is already in use. `pipewire` 0.10.1 has
  the key `stream.capture.sink` (`src/keys.rs:451`), which asks PipeWire
  for *what the computer is playing* (its output), not a microphone.

**Candidates, checked in the registry on 2026-11-02:**

- **`opus` 0.4.0** (2026-08-23, MIT/Apache-2.0, ~2.2 M recent downloads),
  built on `opusic-sys` (BSD-3-Clause; 0.7.6 is under 14 days old, so
  0.7.5).
- **`objc2-audio-toolbox` / `objc2-core-audio` 0.3.2.** These are the
  same objc2 generation as our capture code, so no second family.

**Not verified (spike S-A1, before any criteria item depends on it):**

- whether `opusic-sys` builds libopus from bundled source (it needs
  cmake?) or links the system's;
- whether capturing the laptop's output through PipeWire needs a portal
  permission or works for a user's own process;
- whether the laptop's speakers or TV keep playing while sound is
  captured (they should: capture only copies);
- real latency, including Bluetooth earbuds. AirPods-class earbuds add
  their own ~150–250 ms by themselves; this is a widely reported figure,
  **unverified**, to be measured.

## 1. Scope

**In:** a Linux host's sound plays on the Mac viewer during a session,
using Opus (48 kHz stereo, 20 ms packets), the existing encrypted
datagram path, a small jitter buffer on the viewer, and playback on the
Mac's current output device (including Bluetooth).

**Out:**

- a Mac host's sound (ScreenCaptureKit can capture audio; a later
  phase);
- the viewer's microphone to the host;
- Windows;
- per-app audio;
- volume control from the Mac (D-53).

## 2. Decisions for the owner (recommendation first)

| # | Question | Recommendation | Why |
|---|---|---|---|
| Q1 | While a session runs, should the laptop's own speakers / TV go quiet? | **No, keep them playing** (just copy the sound) | Muting the host is a change to the host computer that a remote person causes; the person at the host might be listening. A "mute host while connected" option can come later |
| Q2 | Sound on by default? | **On, with a mute toggle in the viewer** (and off with `--no-audio` on either side) | You asked for it as part of using the laptop; muting is one key |
| Q3 | libopus is C code parsing what the network sends. Accept it? | **Yes, as bundled source at a pinned version**, with our own size checks before it and a fuzz target around it | No mature pure-Rust Opus decoder is known (to verify in S-A1); libopus is continuously fuzzed by its project (unverified until read). Risk stated in §7 |

## 3. Security requirements (each gets a test seen failing)

| ID | Requirement | Test |
|---|---|---|
| A1 | Audio flows only in an Active session, from approval to end; capture starts at approval and stops with the session (no capture when nobody is connected) | integration; plant: capture started at host start |
| A2 | INV2: audio is sealed like video. No audio sample or Opus byte appears in what is handed to QUIC | loopback capture test extended to audio, canary in the samples |
| A3 | Audio packets are untrusted on the viewer: size-limited before decoding, malformed ones counted and dropped, never a crash | unit + fuzz target `audio_packet` |
| A4 | INV9: no audio content in logs, ever; counts and times only | grep lint + `Debug` tests |
| A5 | Replay/old packets refused (shared media replay window) | unit (reuse M-tests' style) |
| A6 | The viewer's mute is real: no audio is played when muted (the host may still send) | unit |

## 4. Targets

| ID | Target |
|---|---|
| AU1 | Host capture → Mac speaker output ≤ 150 ms p95 on the home Wi-Fi, **not counting** the earbuds' own Bluetooth delay (measured and reported separately) |
| AU2 | No more than 1 % of 20 ms packets concealed (lost or late) on the home Wi-Fi |
| AU3 | Picture and sound within ±80 ms of each other (lip sync) |

## 5. Dependencies

`opus` 0.4.0 / `opusic-sys` 0.7.5 (C libopus; how it is built to be read
in S-A1), `objc2-audio-toolbox` 0.3.2 (+ `-core-audio` if needed), all
under the 14-day check and `cargo deny`; dependencies.md in the same
commit.

## 6. Build order

1. Criteria approved; spike S-A1 on the laptop (PipeWire sink capture →
   Opus → Mac playback; latency, gaps; the open questions in §0).
2. Protocol: an audio datagram kind, limits, fuzz target (A3, A5).
3. Host: capture + encode during Active only (A1, A4).
4. Viewer: decode + jitter buffer + playback + mute (A6).
5. Sync with the picture (AU3); A2 test.
6. Live test Mac ↔ laptop with your earbuds; report; roadmap.

## 7. Known limitations (stated plainly)

- Bluetooth earbuds add their own delay, which Remora cannot remove.
- libopus is C: a decoding bug in it would be a memory-safety bug in the
  viewer. Mitigated by size checks before it, fuzzing, and pinned,
  current versions; not eliminated.
- There is no separate "sound is being captured" indicator on the
  laptop; GNOME's screen-sharing indicator shows a session is active, and
  sound only flows during one (A1).
