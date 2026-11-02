# Phase 4.7 plants: the real failure, seen caught

Same rules as `results/phase4.6/plants.md` (CLAUDE.md "plant the real
failure"): each row is a real bug planted once, seen caught by the named
test, then removed.

| Row | Plant (the real failure) | Caught by | Date |
|---|---|---|---|
| C6 | Device list file saved 0644 | `crates/remora-app/src/devices.rs::c6_the_file_is_owner_only_and_refused_when_others_can_read_it` ("file mode 100644") | 2026-11-02 |
| C6 | Load ignores the file's permissions | same test (`Permissions(0o644)` not returned) | 2026-11-02 |
| C6 | Parser keeps names longer than MAX_NAME | fuzz target `device_list` (seeded with a real file): "assertion failed: list.iter().all(\|d\| d.name.len() <= MAX_NAME)" within 120 s | 2026-11-02 |
