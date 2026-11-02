# Phase 4.7 plants: the real failure, seen caught

Same rules as `results/phase4.6/plants.md` (CLAUDE.md "plant the real
failure"): each row is a real bug planted once, seen caught by the named
test, then removed.

| Row | Plant (the real failure) | Caught by | Date |
|---|---|---|---|
| C6 | Device list file saved 0644 | `crates/remora-app/src/devices.rs::c6_the_file_is_owner_only_and_refused_when_others_can_read_it` ("file mode 100644") | 2026-11-02 |
| C6 | Load ignores the file's permissions | same test (`Permissions(0o644)` not returned) | 2026-11-02 |
| C6 | Parser keeps names longer than MAX_NAME | fuzz target `device_list` (seeded with a real file): "assertion failed: list.iter().all(\|d\| d.name.len() <= MAX_NAME)" within 120 s | 2026-11-02 |
| C7 | `set_trusted` adds keys instead of replacing the list (forgetting does nothing) | `crates/remora-net/tests/c3_c7_known_viewers.rs::c7_a_forgotten_viewer_is_refused_in_trusted_mode_at_once` (`left: None, right: Some(AuthFailed)`) | 2026-11-02 |

**C3, plant not valid yet:** auto-approving every prompt inside
`remora-net`'s action loop deadlocked the host (it re-entered the host
lock), so the test hung instead of failing. A hang is not a catch. The
approval gate lives in `remora-session` (`Host::approve`, mutation-tested
since Phase 3); C3 is re-checked by the session crate's mutation run at
the end of this phase, and a plant inside the session layer is to do.
| C2 | The host remembers every viewer it accepts (auto-remember) | `crates/remora-host/src/serve.rs::c2_tests::c2_accepting_never_remembers_only_the_remember_command_does` ("accepting alone remembered the viewer") | 2026-11-02 |
