# Phase 4.6 plants: the real failure, seen caught

Same rules as `results/phase4.5/plants.md` (CLAUDE.md "plant the real
failure"): each row is a real bug planted once, seen caught by the named
test, then removed.

| Row | Plant (the real failure) | Caught by | Date |
|---|---|---|---|
| L3 | `PointerMove`, `Scroll` and new buttons decoded with no checks | `crates/remora-proto/tests/l3_input.rs::pointer_move_outside_or_not_a_number_is_refused`, `::scroll_is_finite_and_bounded`, `::buttons_left_right_middle_back_forward_only` | 2026-11-02 |
| L2 (viewer half) | Losing focus releases nothing on the host | `crates/remora-viewer/src/input.rs::losing_focus_releases_everything_once` (and `::everything_sent_passes_the_protocol_checks`) | 2026-11-02 |
| L2 | `Guard`'s `Drop` releases nothing (INV10) | `crates/remora-input/tests/l2_l4_guard.rs::inv10_dropping_the_guard_releases_everything_held`, `::inv10_release_happens_even_when_the_backend_failed` | 2026-11-02 |
| L2 | Release stops at the first key the OS refuses, leaving the rest held. **First plant was NOT caught**; the test on the right was added and then caught it | `crates/remora-input/tests/l2_l4_guard.rs::inv10_one_failed_release_does_not_stop_the_others` | 2026-11-02 |
| L3 | Keys outside the table reach the OS | `crates/remora-input/tests/l2_l4_guard.rs::l3_unknown_keys_are_dropped_and_counted` | 2026-11-02 |
| L4 | No rate limit | `crates/remora-input/tests/l2_l4_guard.rs::l4_a_flood_is_refused` | 2026-11-02 |
| L4 | No cap on keys held | `crates/remora-input/tests/l2_l4_guard.rs::l4_too_many_keys_held_is_refused` | 2026-11-02 |

## Mutation testing (`.cargo/mutants.toml`), 2026-11-02

| Scope | Caught | Missed | Unviable | Timeout |
|---|---|---|---|---|
| `crates/remora-input/src/guard.rs` | 17 | **0** | 1 | 0 |
| `remora-proto` (all files in mutants.toml, incl. the new input checks in `messages.rs`) | 252 | **0** | 21 | 13 |

The 13 timeouts are all in code from earlier phases, not this step:
`frame.rs` `FrameDecoder::push` (5), `video.rs` `Reassembler` (7), and the
media key id check in `messages.rs` (1). In each, the mutant makes a test
hang past cargo-mutants' 65 s limit (e.g. a key every session refuses, so
a test waits for a session that never starts) rather than fail quickly.
A hang is not a pass, so none of these is a missed mutant; but a test that
hangs instead of failing is slower evidence, noted here, not fixed in 4.6.

## Fuzz target `input_event` (L3), 2026-11-02

| Plant (the real failure) | Result |
|---|---|
| Guard's key-table check removed (unknown keys reach the OS) | First version of the target (raw bytes → `decode_envelope`) **NOT caught** in 60 s / 4.6 M runs: random bytes almost never form a nested Envelope → Input → Key, so the guard was barely reached. Rewritten to build an `Input` from the bytes, encode it, then decode and guard it (the host's path); caught at once: `key 0x1 reached the OS` |
| Held-keys cap removed (`MAX_HELD`) | Not found by the fuzzer in 120 s (it needs 33 distinct table keys pressed in one input); caught by the unit test `l2_l4_guard.rs::l4_too_many_keys_held_is_refused` (row above). The fuzz target's job is L3, field validity |

Clean run after removing the plants: 1.45 M runs in 60 s, no finding.
Corpus minimised (`cargo fuzz cmin`, max length 512): 545 inputs, 69 KB.

## Host remote control (`crates/remora-host/src/control.rs`), 2026-11-02

| Row | Plant (the real failure) | Caught by |
|---|---|---|
| L1 | Input for a session that is not Active opens an injector on demand and is applied ("deliver in Pending") | `control.rs::l1_input_reaches_the_os_only_while_active` |
| L2 | `Lost` (viewer crash, network gone, idle timeout) drops nothing: held keys stay pressed | `control.rs::l2_every_end_path_releases_held_keys` (names the end path) |
| L4 | A refused flood ends the session but releases only when the close comes back | `control.rs::l4_a_flood_ends_the_session_and_releases` |

The first plants also showed a test flaw: the fake injector panicked again
on a poisoned lock while a failed assertion unwound (the guard's `Drop`
runs then), which aborts the whole test binary. Fixed before recording.

Mutation testing: 7 caught, 1 **missed** (`can_control` → `false`: no test
had an injector configured and checked it); test added; rerun 8 caught,
0 missed, 1 unviable.

## Linux capture, encoder, injector (step 5), 2026-11-02, on the owner's laptop

| Row | Plant (the real failure) | Caught by |
|---|---|---|
| L8 | Restore-token file created 0644 | `crates/remora-capture/src/sys/linux.rs::l8_the_restore_token_is_never_printed_and_saved_0600` ("token file mode 100644") |
| L8 | Restore token's `Debug` prints the token | same test (`left: "RestoreToken(secret-capability)"`) |
| L3 (buffer) | PipeWire picture copied without checking its length | `crates/remora-capture/src/sys/linux.rs::copy_picture_refuses_numbers_that_do_not_fit` (panicked: index out of range) |
| — (colour) | Not planted: **found**. The spike's chroma coefficients (-26, -87, 112) sum to -1, tinting every grey (U = 127) | `crates/remora-codec/src/yuv.rs::colours_match_bt709_video_range_within_one_step` failed on first run; fixed to -86 |
| — (portal) | Not planted: **seen for real** with the first version (one tokio runtime per portal session): the second session in one host process hung 120 s with no dialog (host log 2026-11-02 09:30-09:32 UTC) | `crates/remora-capture/tests/portal_sessions.rs::two_portal_sessions_in_one_process` (ignored in CI: needs a desktop; laptop: 3 sessions, 23-30 ms each, 1920x1080 pictures) |

## LP4: keyframe on a still screen (Linux), 2026-11-02

| Row | Plant (the real failure) | Caught by |
|---|---|---|
| LP4 | Repeat thread never acts (a keyframe asked for on a still screen waits for the next screen change, as before) | `crates/remora-host/src/stream.rs::linux_tests::lp4_a_keyframe_asked_for_on_a_still_screen_comes_from_the_last_picture` ("a keyframe within 300 ms on a still screen") |

The test's first version failed for a test reason: its fake screen changed
every pixel between pictures, which openh264's scene-change detection
answers with IDRs; the fake now changes one pixel, as a still desktop does.
