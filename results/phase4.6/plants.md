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
