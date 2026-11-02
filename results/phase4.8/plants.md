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
