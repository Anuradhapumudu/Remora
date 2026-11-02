# Phase 4.8 plants: the real failure, seen caught

Same rules as `results/phase4.7/plants.md` (CLAUDE.md "plant the real
failure").

| Row | Plant (the real failure) | Caught by | Date |
|---|---|---|---|
| A3 | The audio body parser keeps Opus data longer than MAX_OPUS_BYTES | `crates/remora-proto/tests/a3_audio.rs::a3_short_empty_and_oversized_bodies_are_refused` | 2026-11-02 |

The fuzz target `audio_packet` did **not** find that plant in 60 s: it
must grow an input past 1012 bytes from a tiny corpus. The unit test is
the guard; the fuzz target's job is "no panic, consistent round trip".
| A3 (session) | An audio body that fails its checks is played anyway | `crates/remora-session/tests/a1_a5_audio.rs::a3_an_empty_audio_body_is_counted_not_played` | 2026-11-02 |

**A1 in the session layer is structural:** only an Active session holds
media keys, so `seal_for_active` cannot seal for a session at the prompt
(`a1_audio_reaches_only_active_sessions` checks it with a positive
control). The A1 failure worth planting is the host app capturing before
approval; it is planted at that level.
| A2 | Audio datagrams also carry the plaintext body after the ciphertext | `crates/remora-net/tests/a2_audio_sealed.rs::a2_audio_is_sealed_on_the_wire_and_arrives_intact` — **caught at line 72 (delivery stopped: the appended bytes broke the AEAD tag), not by the canary scan**. A leak that keeps delivery working (a separate plaintext copy) is the scan's job; the scan method is M1a's, proven for video in Phase 4 | 2026-11-02 |

Process note: while speeding the A2 scan up (a set of windows instead of a
quadratic search) an edit left the test not compiling, and a first plant
run printed nothing - read for a moment as "no failure". Plant runs now
always show the test's own lines.
| A3 (codec) | The Opus decoder wrapper hands any size to libopus | `crates/remora-codec/src/audio.rs::tests::wrong_sizes_are_refused_and_loss_is_concealed` | 2026-11-02 |
| A1 | The host starts recording sound at the prompt (before approval) | `crates/remora-host/src/serve.rs::a1_tests::a1_sound_runs_only_while_a_session_is_active` | 2026-11-02 |
| A1 | The host never stops recording when the session ends | same test | 2026-11-02 |
| A6 | The player ignores the mute (plays sound while muted) | `crates/remora-viewer/src/sound.rs::tests::a6_muted_is_silent_and_still_consumes` ("sound while muted") | 2026-11-03 |
| A6 | Muted, the player stops consuming, so old sound piles up and plays on unmute | same test ("muted must not let sound pile up") | 2026-11-03 |
| A6 | The mute key's M release is sent to the host | `crates/remora-viewer/src/window.rs::tests::a6_the_mute_key_toggles_and_is_never_sent` (the release assertion) | 2026-11-03 |
| A4 (viewer) | The playout buffer derives `Debug`, printing held samples | `crates/remora-viewer/src/sound.rs::tests::a4_debug_shows_counts_never_samples` | 2026-11-03 |

## Mutation testing (focused, `--no-config -f <file>`), 2026-11-03

| Scope | Caught | Missed | Unviable / timeout |
|---|---|---|---|
| `crates/remora-viewer/src/sound.rs` + `MuteKey`, first run | 64 | **30** | 3 / 1 |
| same, after the tests in this commit | 80 | 6 | 4 / 2 |
| `MuteKey` alone, after the press-toggles check | all but 2 | 2 | — |

The first misses were real gaps: interpolation was only tested with
constant sound (now a rising left and falling right ramp at 96 kHz), the
START boundary (30 ms must stay silent), a packet exactly half the seq
space ahead, `toggle_mute`'s return value, the mute toggling on the first
press rather than a repeat (the `repeat` argument was removed: a press
while held is the repeat), and the sound thread itself (now run with an
output that has no device). Left, with reasons:

- `|` → `^` in `MuteKey::key` (×2): equivalent; the flags are distinct
  bits.
- `Output::start` → `Ok(Default)`: opens the real device; checked only by
  the live test on the Mac.
- `Drop for Sound` → `()`: dropping the sender already ends the thread;
  only the `sound:` line is lost.
- `window.rs:326` (`compatible_surface`): phase-4 window code, not this
  phase's.

## A7: `serve --mute-speakers` (owner, 2026-11-03)

| ID | Planted failure | Caught by | Date |
|---|---|---|---|
| A7 | The guard never restores the speakers | `crates/remora-host/src/speakers.rs::tests::a7_mutes_then_restores_the_same_output` and `crates/remora-host/src/serve.rs::a1_tests::a7_speakers_are_silent_only_while_a_session_is_active` | 2026-11-03 |
| A7 | An output the person had muted is muted "again" and un-muted at the end (the already-muted check removed) | `speakers.rs::tests::a7_an_output_muted_by_the_person_stays_muted` | 2026-11-03 |
| A7 | The speakers are muted before recording starts (so a host that cannot record still mutes, briefly) | `serve.rs::a1_tests::a7_a_host_that_cannot_record_never_mutes` — **first missed**: the test read only the end state, and the brief mute was already undone. The fake mixer now records every change and the test requires none | 2026-11-03 |
| A7 | Sound (and with it the mute) starts at the prompt, before approval | `serve.rs::a1_tests::a7_speakers_are_silent_only_while_a_session_is_active` ("speakers silenced before the person approved") | 2026-11-03 |

## Found in the 4.8 live test: pointer at the picture's edge (2026-11-03)

Phase 4.6 code, fixed here (the accepted 4.6 records are left as they
are). Dragging the laptop's volume slider past the viewer window's right
edge sent x = 1.0; the host turned it into pixel `width`, one past the
last column; GNOME refused it ("Invalid position") and the refused input
ended the session, as the input rules require.

| ID | Planted failure | Caught by | Date |
|---|---|---|---|
| (4.6 input) | The old conversion `v.clamp(0, 1) * side` (1.0 -> `side`) | `crates/remora-input/src/sys/linux.rs::tests::positions_stay_on_the_picture` (left 1920.0, right 1919.0; run on the laptop, Linux-only module) | 2026-11-03 |
| AU1/AU3 tool | The playout buffer stops counting consumed sound, so the measured age drifts (100, 110, 120 ms instead of 100) | `crates/remora-viewer/src/sound.rs::tests::the_age_follows_the_sound_through_the_buffer` | 2026-11-03 |
| AU1 | Catch-up switched off (`CATCH_UP = 1.0`): a buffer that filled while the earbuds started stays full (the live 110 ms) | `crates/remora-viewer/src/sound.rs::tests::a_full_buffer_drains_back_to_start` ("still holding 4800 frames") | 2026-11-03 |
| AU1 | A run-dry no longer reopens the resync window: the burst after a gap stays queued (the live jump to ~110 ms) | `crates/remora-viewer/src/sound.rs::tests::a_backlog_right_after_running_dry_is_dropped_at_once` ("kept a backlog of 4800 frames") | 2026-11-03 |
