# Phase 4.6 plants: the real failure, seen caught

Same rules as `results/phase4.5/plants.md` (CLAUDE.md "plant the real
failure"): each row is a real bug planted once, seen caught by the named
test, then removed.

| Row | Plant (the real failure) | Caught by | Date |
|---|---|---|---|
| L3 | `PointerMove`, `Scroll` and new buttons decoded with no checks | `crates/remora-proto/tests/l3_input.rs::pointer_move_outside_or_not_a_number_is_refused`, `::scroll_is_finite_and_bounded`, `::buttons_left_right_middle_back_forward_only` | 2026-11-02 |
| L2 (viewer half) | Losing focus releases nothing on the host | `crates/remora-viewer/src/input.rs::losing_focus_releases_everything_once` (and `::everything_sent_passes_the_protocol_checks`) | 2026-11-02 |
