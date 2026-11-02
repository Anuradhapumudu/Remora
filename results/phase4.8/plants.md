# Phase 4.8 plants: the real failure, seen caught

Same rules as `results/phase4.7/plants.md` (CLAUDE.md "plant the real
failure").

| Row | Plant (the real failure) | Caught by | Date |
|---|---|---|---|
| A3 | The audio body parser keeps Opus data longer than MAX_OPUS_BYTES | `crates/remora-proto/tests/a3_audio.rs::a3_short_empty_and_oversized_bodies_are_refused` | 2026-11-02 |

The fuzz target `audio_packet` did **not** find that plant in 60 s: it
must grow an input past 1012 bytes from a tiny corpus. The unit test is
the guard; the fuzz target's job is "no panic, consistent round trip".
