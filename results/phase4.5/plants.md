# Phase 4.5 plants: the real failure, seen caught

CLAUDE.md: a test whose job is to catch something is shown catching the
real failure once, then the plant is removed. One row per plant; R7
(`scripts/ci/check-plants.py`, CI) checks that every row's criteria row
exists and that the test or self-test case that caught it is still there.
`--complete` lists the criteria rows that name a plant and have none here
yet (run for the phase report).

"(decision module)" means planted in `remora_app::decide`; the GUI-level
plant for the same row is still to come with the GUI (D-46).

| Row | Plant (the real failure) | Caught by | Date |
|---|---|---|---|
| H2 | Accept answers the newest dialog, not the one clicked (decision module) | `crates/remora-app/tests/phase45_decide.rs::h2_accept_on_the_older_dialog_accepts_the_older_session` | 2026-11-01 |
| H3 | Return bound to Accept (decision module) | `crates/remora-app/tests/phase45_decide.rs::h3_return_space_escape_deny_and_no_key_accepts` | 2026-11-01 |
| H4 | No arming delay (decision module) | `crates/remora-app/tests/phase45_decide.rs::h4_click_before_the_delay_does_nothing` | 2026-11-01 |
| H4 | Only the release checked against the delay (decision module) | `crates/remora-app/tests/phase45_decide.rs::h4_press_before_and_release_after_the_delay_does_nothing` | 2026-11-01 |
| H4 | A new dialog does not re-arm Accept (decision module) | `crates/remora-app/tests/phase45_decide.rs::h4_a_new_dialog_restarts_the_delay_and_cancels_a_press` | 2026-11-01 |
| H5 | The dialog ignores its session's end (decision module) | `crates/remora-app/tests/phase45_decide.rs::h5_the_dialog_shows_the_sessions_time_left_and_has_no_timer_of_its_own` | 2026-11-01 |
| H6 | The raw name shown (decision module) | `crates/remora-app/tests/phase45_decide.rs::h2_view_shows_this_dialogs_code_and_escaped_name` | 2026-11-01 |
| H9 | Busy check removed from admission | `crates/remora-session/tests/h9_host_busy.rs::h9_connection_while_active_is_refused_busy_before_any_crypto` | 2026-11-01 |
| H9 | Busy checked after the limiter (uses a slot and the per-IP budget) | `crates/remora-session/tests/h9_host_busy.rs::h9_after_the_session_ends_the_same_address_and_password_work` | 2026-11-01 |
| H9 | Pending sessions counted as busy | `crates/remora-session/tests/h9_host_busy.rs::h9_pending_sessions_do_not_make_the_host_busy` | 2026-11-01 |
| H9 | `one_active_session` ignored (admission and approve) | `crates/remora-session/tests/h9_host_busy.rs::h9_a_multi_viewer_host_still_admits_while_active` | 2026-11-01 |
| H9 | Approve check removed (a waiting viewer approved next to an active one) | `crates/remora-session/tests/h9_host_busy.rs::h9_a_viewer_already_waiting_cannot_be_approved_next_to_an_active_one` | 2026-11-01 |
| H9 | Closed as RateLimited instead of HostBusy | `crates/remora-net/tests/h9_host_busy.rs::h9_second_viewer_is_refused_busy_and_the_password_survives` | 2026-11-01 |
| H9 | No RefusedBusy event (attempt not logged) | `crates/remora-net/tests/h9_host_busy.rs::h9_second_viewer_is_refused_busy_and_the_password_survives` | 2026-11-01 |
| H9 | The host app builds its config with `one_active_session: false` | `crates/remora-host/src/serve.rs::h9_the_app_serves_one_viewer_at_a_time` | 2026-11-01 |
| H9 | Other dialogs left open when one becomes Active (decision module) | `crates/remora-app/tests/phase45_decide.rs::h9_other_dialogs_are_denied_when_a_session_becomes_active` | 2026-11-01 |
| H10 | Code and password shown while Active (decision module) | `crates/remora-app/tests/phase45_decide.rs::h10_code_hidden_while_active_until_show` | 2026-11-01 |
| I1 | Indicator hidden after 5 s (decision module) | `crates/remora-app/tests/phase45_decide.rs::i1_indicator_shown_exactly_while_active` | 2026-11-01 |
| I2 | End session not wired (decision module) | `crates/remora-app/tests/phase45_decide.rs::i2_end_session_disconnects_the_active_session` | 2026-11-01 |
| R4 | A fifth dialog opens | `crates/remora-app/tests/phase45_decide.rs::r4_at_most_four_dialogs_never_more` | 2026-11-01 |
| V4 | Verified set on connect (decision module) | `crates/remora-app/tests/phase45_decide.rs::v4_verified_only_by_the_codes_match` | 2026-11-01 |
| V5 | Declined message missing (decision module) | `crates/remora-app/tests/phase45_decide.rs::v5_denied_or_timed_out_says_ask_for_a_new_code` | 2026-11-01 |
| V6 | Countdown not shown (decision module) | `crates/remora-app/tests/phase45_decide.rs::v6_display_unavailable_counts_down_locally_then_resumes` | 2026-11-01 |
| O1 | Still drawing while covered | `crates/remora-viewer/src/window.rs::o1_covered_window_draws_nothing_then_draws_at_once` | 2026-11-01 |
| O1 | The window ignores Occluded events | `crates/remora-viewer/src/window.rs::o1_the_windows_occlusion_events_reach_it` | 2026-11-01 |
| R2 | The checker does not see tokio tests | `scripts/ci/check-tests.py: a removed async test is caught` | 2026-11-01 |
| R2 | The checker accepts a test moved to another crate | `scripts/ci/check-tests.py: a test moved to another crate is caught` | 2026-11-01 |
| R7 | A record names a test that does not exist | `scripts/ci/check-plants.py: test fn that does not exist` | 2026-11-01 |
| R7 | A record names a row that does not exist | `scripts/ci/check-plants.py: unknown row` | 2026-11-01 |
| R9 | Battery at the end not checked | `scripts/macos/measuring.py: battery at end` | 2026-11-01 |
| R9 | Another program's caffeinate accepted | `scripts/macos/measuring.py: a caffeinate for someone else does not count` | 2026-11-01 |
| R9 | Pausing instrument allowance ignored | `scripts/macos/measuring.py: pausing over allowance` | 2026-11-01 |
| R9 | A runner calls vmmap directly | `scripts/ci/check-measuring.py: python: vmmap directly` | 2026-11-01 |
| H9 | A refusal during connect returned as an error, not the host's close (the CI race of 2026-11-01) | `crates/remora-net/tests/h9_host_busy.rs::h9_a_refusal_during_connect_is_the_hosts_close_not_an_error` | 2026-11-01 |
| R8 | A newly locked crate missing from dependencies.md | `scripts/ci/check-dep-docs.py: a new undocumented crate is caught` | 2026-11-01 |
| R8 | A crate name only in prose counted as documented | `scripts/ci/check-dep-docs.py: a name only in prose does not count` | 2026-11-01 |
