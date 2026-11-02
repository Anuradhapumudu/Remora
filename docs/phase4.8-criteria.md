# Phase 4.8 (D-51): Sound — the host's audio plays on the viewer — criteria

**Status: APPROVED by the owner, 2026-11-02**, with the recommended answer
to every decision in §2: Q1 "Keep playing" (the host's speakers are not
muted), Q2 + Q3 "Yes to both" (sound on by default with a mute key in the
viewer; libopus bundled at a pinned version behind our size checks and
fuzzing). Building starts with spike S-A1.

**Amended by the owner, 2026-11-03** (after hearing the laptop's sound on
the Mac: "can we implement a feature which is only me can hear the voice
instead of playing on that laptop too ?"): a **host setting** silences
the laptop's speakers while a session is active (chose "Host setting"
over a viewer request or always-on), built **now, inside 4.8** (chose
"Now, inside 4.8"). Q1's default stays: without the setting the speakers
keep playing. New requirement A7 (§3) and step 5b (§6).

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
| A7 | `serve --mute-speakers` (owner, 2026-11-03): the host's own speakers are silent exactly while sound is being sent (from approval to the end of the last session, A1's span) and restored afterwards to how they were; never un-muted if the person had muted them; if they cannot be muted the session goes on and the host says so. Only the person at the host can turn it on: no viewer message can mute a host | unit with a fake mixer; plants: mute engaged before approval, not restored at the end, an already-muted speaker un-muted at the end |

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
5b. `--mute-speakers` (A7). Spike, 2026-11-03 on the laptop (PipeWire
   1.x with WirePlumber): a 0.02-peak test tone captured through
   `stream.capture.sink` measured peak 0.0200 with the speakers normal,
   **muted**, and at **volume 0** - the copy Remora records is taken
   before the sink's mute and volume, so muting the speakers does not
   silence what the viewer hears.
6. Live test Mac ↔ laptop with your earbuds; report; roadmap.

## 7. Known limitations (stated plainly)

- Bluetooth earbuds add their own delay, which Remora cannot remove.
- libopus is C: a decoding bug in it would be a memory-safety bug in the
  viewer. Mitigated by size checks before it, fuzzing, and pinned,
  current versions; not eliminated.
- There is no separate "sound is being captured" indicator on the
  laptop; GNOME's screen-sharing indicator shows a session is active, and
  sound only flows during one (A1).

## 8. Report (2026-11-03)

**Result:** the Fedora laptop's sound plays on the Mac during a session,
sealed like video, through the Mac's current output (the owner used
Bluetooth earbuds: "yes I can hear sounds"). With `serve
--mute-speakers` (A7) only the viewer hears it. Commits bcf298b …
faac119 (spike dd80699). Plants: `results/phase4.8/plants.md`; numbers:
`results/phase4.8/measurements.md`; spike:
`spikes/sound/results/sa1-20261102.txt`.

### Security requirements

| ID | Status | Evidence |
|---|---|---|
| A1 | **Met** | `crates/remora-session/tests/a1_a5_audio.rs::a1_audio_reaches_only_active_sessions` (structural: only an Active session holds media keys, with a positive control); `crates/remora-host/src/serve.rs::a1_tests::a1_sound_runs_only_while_a_session_is_active` (plants: recording at the prompt, never stopping; caught). Live: `sound:` lines only between approval and the end |
| A2 | **Met** | `crates/remora-net/tests/a2_audio_sealed.rs::a2_audio_is_sealed_on_the_wire_and_arrives_intact` (canary samples never in what QUIC receives; plant caught by delivery failing, the scan method is M1a's) |
| A3 | **Met** | `crates/remora-proto/tests/a3_audio.rs` (size limits both sides of each boundary), `crates/remora-session/tests/a1_a5_audio.rs::a3_an_empty_audio_body_is_counted_not_played`, `crates/remora-codec/src/audio.rs` tests (decoder refuses empty and oversized input itself; garbage never panics); fuzz target `audio_packet` |
| A4 | **Met** | `crates/remora-proto/tests/a4_debug.rs::a4_audio_packets_print_no_sound`, `crates/remora-viewer/src/sound.rs::tests::a4_debug_shows_counts_never_samples` (both planted and caught); the lint half is the policy scanner's no-file-writes rule over every crate the sound code lives in; `--timing` lines are times and counts only |
| A5 | **Met** | `crates/remora-session/tests/a1_a5_audio.rs::a5_a_replayed_audio_datagram_is_not_played_again` (the shared media replay window) |
| A6 | **Met** | `crates/remora-viewer/src/sound.rs::tests::a6_muted_is_silent_and_still_consumes`, `crates/remora-viewer/src/window.rs::tests::a6_the_mute_key_toggles_and_is_never_sent` (three plants caught). Ctrl+Option+M in the video window; `--no-audio` |
| A7 | **Fix built, live check pending.** Found 2026-11-03 03:33: the laptop's speakers were left muted after a session although the owner never muted them (WirePlumber saved `"mute":true` at 01:43:48, during a session whose end printed "speakers: restored"); the exact event was not reconstructed. Read: gnome-shell 50.4's volume slider fights the mute (dragging it unmutes; below the first step it mutes and sets volume 0). Fixed (6287664): the restore is checked and retried; a note names the muted output (id + PipeWire name) before muting and is cleared only after a verified restore; every `serve` start repairs a left mute, by name only. Tests: `crates/remora-host/src/speakers.rs` (10, including four new plants) and `serve.rs::a1_tests::a7_*`; earlier live: `a7_live_wpctl_mutes_and_restores` and the owner's session (`Volume: 1.00 [MUTED]` during) |

### Targets

| ID | Result |
|---|---|
| AU1 | **Met**: capture → Mac output without the earbuds' own delay p95 ~123 ms (run 2), ~61 ms (run 3, after the buffer fixes); target ≤ 150 ms. Method and the clock estimate in measurements.md |
| AU2 | **Met**: 1 of 4 020 packets concealed (0.02 %; target ≤ 1 %) |
| AU3 | **Not met with Bluetooth earbuds**: sound 194 ms after the picture (run 3), of which the earbuds' declared delay is 160.9 ms. Without it ~33 ms (inside ±80 ms; estimate, the built-in speakers were not measured). The owner sees the difference on talking videos. Remora cannot remove the earbuds' delay; the only remedy is delaying the picture (see "Open question") |

### Mutation testing (focused runs)

See `results/phase4.8/plants.md` (viewer `sound.rs` + mute key: first
run 64 caught / 30 missed, after the new tests 80 / 6, the six
explained) and the table added with this report for the protocol, codec
and host speaker files.

### Found while building

- **The sound buffer never drained** (live, run 1: ~110 ms held where 40
  was meant): it filled while the earbuds started and sound then arrives
  exactly as fast as it plays. Fixed by playing 1 % faster after a whole
  second above 60 ms (7a18177) and by dropping a backlog at once right
  after running dry (b844c13). Held p50 111 → 71 → 44 ms.
- **Dragging a slider past the window edge ended the session** (phase
  4.6 code): position 1.0 became pixel `width`, which GNOME refused
  ("Invalid position"), and refused input ends the session. Clamped to
  the last pixel (9f14351, plant caught).
- **The host cannot share a login screen**: after a restart the laptop
  sat at GDM's greeter; the portal needs a logged-in desktop (laptop
  notes, 3d3672a).
- **Video freezes** of 0.4–1 s while watching videos: probably video
  fragments dropped on our side, not Wi-Fi loss (sound on the same path
  lost 1 in 4 020). Not sound work: moved to D-56 as its first step,
  with the candidates named. An earlier analysis that blamed host
  capture stalls was wrong and was corrected (82870a4).
- **Cmd+Q in the viewer sent no goodbye**: the host waited 30 s
  ("connection lost: no reply from the viewer"), recording sound and,
  with `--mute-speakers`, keeping its speakers muted that long. AppKit
  ends the process right after winit's `exiting`; both apps now say
  goodbye there and wait up to 1.5 s (332ad63, plant caught). Live check
  with the owner pending.
- **Dependencies**: RUSTSEC-2026-0433 (pulldown-cmark, not reachable)
  taken as a logged security-fix exception; a yanked async-executor went
  back to 1.13.3 (da89bc2).

### Manual steps (as the owner ran them)

1. Laptop: logged in to GNOME; host started with `serve
   --mute-speakers` (`scripts/dev/laptop-host.sh start --mute-speakers`).
2. Mac: `remora-viewer connect --device "7266 055 4675-2" --timing 2>
   ~/remora-av3.log`; accepted with `scripts/dev/laptop-accept.sh`.
3. Played a YouTube video on the laptop: sound in the earbuds, laptop
   speakers muted, restored when the session ended; Ctrl+Option+M muted
   the Mac side only; the volume slider dragged past the window edge no
   longer ended the session.

### Known limitations

- Bluetooth earbuds' delay (160.9 ms declared by macOS) puts sound
  visibly behind the picture (AU3).
- A host killed outright (kill -9, power loss) cannot restore the
  speakers at once; the next `remora-host serve` does (by the output's
  name), or the person unmutes them by hand.
- Moving GNOME's own volume slider during a `--mute-speakers` session
  unmutes the laptop (GNOME's rule, gnome-shell 50.4 `volume.js`): the
  person at the laptop, or the remote viewer, choosing to hear it.
- libopus is C code parsing network data on the viewer (size checks and
  fuzzing before it; not eliminated).
- Only a Linux host sends sound; only the Mac viewer plays it.
- No separate "sound is being captured" indicator on the laptop (sound
  flows only during a session GNOME already shows).

### Open question for the owner (not approved work)

**"Watch mode"**: delay the picture to match slow outputs such as
Bluetooth earbuds, for watching videos only (it would also delay the
mouse). Proposed 2026-11-03; the owner has not chosen yet. It becomes a
roadmap row only if approved.

### Deferred items, row by row

| Row | Before | Now |
|---|---|---|
| D-51 (sound) | Building | **Reported** here; awaiting the owner's acceptance |
| D-53 (Mac volume keys) | "With D-51" | **Not done in 4.8**, still open: sound plays, but the Mac's volume keys still do not reach the laptop (macOS keeps them). Workaround: the laptop's own volume slider through remote control, or `--mute-speakers`. Stays a row, now "after D-56" |
| D-54 (GNOME indicator hidden in full screen) | Before a Linux host release | Unchanged |
| D-55 (one Mac app) | After 4.8 | Unchanged; after D-56 by the owner's 60 fps request |
| D-56 (hardware encoders, 60 fps) | After 4.8 | **Next.** Owner decisions recorded (stable 60 fps; RPM Fusion for Intel only); now starts with the video-freeze diagnosis |
| New | — | None besides the D-56 additions above |
