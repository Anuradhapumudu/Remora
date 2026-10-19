# Roadmap

## v0.1 — first shippable release

**Definition (all must be true):**

- [ ] Encrypted (SPAKE2 + Noise) **peer-to-peer over the internet**, connected by
      copy-paste offer/answer codes *or* device ID via remora-signal
- [ ] Host accept/deny prompt, safety code, session indicator, one-click disconnect
- [ ] **Single monitor** streaming, hardware encode/decode with software fallback
- [ ] **Mouse + keyboard** control with host-local override and stuck-key release
- [ ] **Auto** quality mode (rate controller adapting bitrate → fps → resolution)
- [ ] Stats overlay
- [ ] **macOS + Windows**, both as host and viewer
- [x] Installable builds (.dmg, .msi/.zip) from the release pipeline — proven by `v0.0.1` (2026-10-17); must stay green as features land
- [ ] Every threat-model invariant (INV1–INV14) has its test; fuzz targets for all parsers
- [ ] Real-world test across two home networks in different countries passed

**Explicitly post-v0.1:** Linux X11 and Wayland backends (Linux builds still
produced), Sharp text / Smooth / Low bandwidth modes and the Advanced panel,
relay fallback, multi-viewer/SFU/simulcast, roles, unattended access,
clipboard, file transfer, audio, multi-monitor, mobile viewers, H.265/AV1,
trusted-device management UI beyond "remember this device".

> Note: Phase 7 builds all quality modes and the Advanced panel because they
> share the rate controller; only **Auto** is a v0.1 *requirement*. If Phase 7
> runs long, the other modes can ship in v0.2 without blocking v0.1.

## Phases

Each phase ends **runnable**, with tests and exact manual test steps.
"v0.1 distance" is a rough count of v0.1 checklist items still open.

| Phase | Content | Status |
|---|---|---|
| 1 | Plan, docs, threat model, workspace skeleton | ✅ done 2026-10-17 |
| 1.5 | Release pipeline (unsigned), CI | ✅ done 2026-10-17 — `v0.0.1` built all artifacts on GitHub; all verified |
| 2 | macOS ScreenCaptureKit capture + VideoToolbox encode → file; benchmark; verify 4:4:4 / LTR / intra-refresh support | ✅ gate passed 2026-10-17 (C12, C3, C4, C5; C2 failed as written → measurement redesigned, see phase2-criteria.md §6) |
| 2.5 | **Windows spike** (throwaway): capture one DXGI frame, inject one SendInput click; report trait changes | ✅ done 2026-10-17 on GitHub's Windows runner — capture and input both work; 4 trait changes proposed (docs/phase2.5-windows-spike.md). Real-PC confirmation open. |
| 3 | Noise + SPAKE2 handshake over QUIC on localhost; safety code; CLI accept prompt; security tests; fuzz targets | ✅ all criteria met 2026-10-19, awaiting owner acceptance — results in phase3-criteria.md §10 |
| 4 | Encrypted loopback streaming; wgpu viewer; stats overlay | |
| 5 | STUN + ICE (`is`) + hole punching with offer/answer codes; test across two home networks | |
| 6 | Remote mouse/keyboard + host-local override (macOS) | |
| 6.5 | **Full Windows backends** (capture, encode, input) | |
| 7 | Rate controller, quality modes, Advanced panel; network-simulation tests | |
| 8 | remora-signal (signaling + STUN) + Docker + Oracle Cloud guide; connect by device ID | |
| 9 | Linux X11 backends; cross-platform internet tests | post-v0.1 |

v0.1 is reached at the end of **Phase 8** (Linux X11 in Phase 9 is post-v0.1).

## v1.0 formal-modelling list (in priority order)

Design-level assurance that tests cannot give (tests check the implementation
against the design, not the design itself):

1. **Remora safety-code commitment scheme** (commit-then-reveal SAS over the
   Noise handshake hash, protocol.md §3.3) — Remora's own construction; no
   published analysis covers it because the SPAKE2 crate provides no key
   confirmation. Model in ProVerif/Tamarin: an active attacker who knows the
   password cannot make the two sessions' codes collide with probability above
   10⁻⁶ per attempt.
2. **Handshake composition:** SPAKE2 (python-spake2 variant) → PSK → Noise
   `XXpsk0` with exporter + hello binding, including implicit (instead of RFC
   9382) key confirmation.
2b. **Cross-implementation test vector for `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s`**
   (owner, 2026-10-18: critical path, not a nice-to-have). Two parts of the
   crypto core currently rest on a single implementation agreeing with
   itself: item 1 (our commitment scheme) and our exact Noise pattern, which
   snow's own vector suite does not contain (crypto-claims-audit C22).
   Realistic options, verified 2026-10-18:
   * **flynn/noise (Go, BSD-3)** — its committed `vectors.txt` already has
     3 vectors named exactly `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s` (fixed
     statics, ephemerals, PSK, per-message ciphertexts), produced by its own
     `vectorgen`. Replay them through snow using its
     `fixed_ephemeral_key_for_testing_only` builder option: one test file,
     the vector file pinned by commit SHA + sha256. **Cheapest, preferred.**
   * The same `vectorgen` (Go is installed on the dev machine) can produce
     vectors with **our** prologue layout and payload sizes.
   * **noiseprotocol (Python)** supports `psk` modifiers, 25519,
     ChaChaPoly and BLAKE2s (verified in its 0.3.1 source) — a third
     implementation, but last released 2020-11-25 and needs `cryptography`.
   * Asking the Noise community (mailing list) — slow; gives review rather
     than vectors. Useful for item 1, not for this.
   Limit: agreement between two implementations shows both compute the
   spec's function; it says nothing about the pattern's security.
   **Close by:** before v1.0 (target: alongside Phase 5, so it does not drift).
3. Trusted-device (password-less) mode and identity pinning.

## Deferred items (the one tracked list)

Everything we know is not done yet, in **one** place (owner, 2026-10-19).
Phase documents point here instead of keeping their own lists. **This list
is reported, row by row, at the end of every phase** (CLAUDE.md) so nothing
drifts quietly; a row leaves only when it is closed (with the evidence) or
the owner accepts it.

**Kind:** **BLOCKER** = must be closed before the named release/phase can
be called done; *nice-to-have* = wanted, but its absence does not block it.

| # | Item | Kind | Blocks / close by | Why it is deferred |
|---|---|---|---|---|
| D-1 | **INV2** — no media or input without encryption, tested on the **real media path** (loopback capture: UDP payload never plaintext) | **BLOCKER** | Phase 4 | No media path existed in Phase 3; only the media AEAD was tested (A11–A13) |
| D-1b | **INV2 for input** — the same loopback-capture test over input events (pointer, keys) | **BLOCKER** | Phase 6 | Split from D-1 (2026-10-19): Phase 4 has no input path |
| D-2 | **INV9** — no screen pixels logged or written to disk by the streaming path | **BLOCKER** | Phase 4 | No pixels flowed in Phase 3 |
| D-3 | **INV10** — keys and mouse buttons released when a session ends for any reason | **BLOCKER** | Phase 6 | No input injection until Phase 6 |
| D-4 | **INV11** — session indicator: automated **GUI** test (visible for the whole `Active` period; its button reaches `Closed` within 1 s). The CLI part is automated since Phase 3 | **BLOCKER** | Phase 7 | No GUI until Phase 7; a manual check decays |
| D-5 | **Keychain migration** — device keys out of the 0600 file into the OS keychain (keyring 4.x, re-verify its API); on Windows the file has no permission check today (D31) | **BLOCKER** | **v0.1** | Phase 3 needed persistent keys for trusted mode / A19 |
| D-6 | **Noise cross-implementation test vector** for `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s` (flynn/noise has three; C22, v1.0 list 2b) | **BLOCKER** | **v1.0** | snow's own suite does not contain our exact pattern |
| D-7 | **Formal model of the safety-code commit-reveal scheme** (ProVerif/Tamarin; v1.0 list 1) and of the handshake composition (list 2) | **BLOCKER** | **v1.0** | Tests check the implementation, not the design; no published analysis covers our construction |
| D-8 | Capture restart after −3815 (display sleep, lid close, display removed) — measured in Phase 2, not implemented | **BLOCKER** | Phase 4 (with the `Interrupted`/`Resumed` trait change, D17) | Phase 2 only measured it |
| D-9 | Remove the dev signing identity and the RemoraDev screen-recording grant (phase2-criteria §7) | **BLOCKER** | End of Phase 4 (owner decision to keep it until then) | Still needed while developing capture |
| D-10 | Unexplained ~2 ms capture+encode benchmark drift (C2 p50 9.0 vs 7.05 ms, 2026-10-17, M4) | **BLOCKER** (until explained or shown gone) | Phase 4 checks whether it reappears | Not reproduced yet; machine state is recorded with every run |
| D-11 | MSI install / uninstall / upgrade on real Windows | **BLOCKER** | Phase 6.5 | No Windows machine yet |
| D-12 | Windows on real hardware: NVENC/QuickSync/AMF, GPU-memory frames, multi-monitor, DPI/HDR, ACCESS_LOST, UIPI | **BLOCKER** | Phase 6.5 | The CI runner has only a software display driver |
| D-13 | macOS signing + notarization | **BLOCKER** | First public release | No Apple Developer ID yet |
| D-14 | Replace SPAKE2 (python-spake2 port) with CPace or an RFC 9382 implementation — review question (crypto-claims-audit §1) | *nice-to-have* (decision needed) | Decide before v1.0 | The `Pake` abstraction prepares the swap; A32 hardens the current one |
| D-15 | Per-chip encoder floors for Intel Mac, NVENC, QuickSync, AMF | *nice-to-have* | Phases 6.5 / 9 | Only measured on Apple M4 |
| D-16 | Physical display hotplug and the other untested Q4 cases (phase2-criteria §5.4), including capture restart after **lid close** and **display removal** (phase4-criteria T3) | *nice-to-have* | Phase 9 (earlier if a monitor is available) | No external display available |
| D-17 | How the Slint UI and our own video surface share a window (Slint always presents with vsync, D32): options include separate windows, a Slint overlay layer above our `CAMetalLayer`, or an upstream Slint present-mode setting | **BLOCKER** | Phase 7 | Found by the render spike (D32); Phase 4 needs no Slint (D33, if approved) |
| D-18 | Zero-copy IOSurface → wgpu import on the viewer (works, D32; saves ≈ 0.3 ms p50) | *nice-to-have* | Phase 9, or earlier if the budget needs it | Needs `unsafe` wgpu-hal calls outside the three FFI crates → an unsafe-policy decision by the owner |
| D-19 | Glass-to-glass effect of `Immediate` present in a composited macOS window (camera or photodiode measurement) | *nice-to-have* | Phase 4 report if equipment is available, else Phase 9 | Software timestamps cannot see the WindowServer compositor |

**Release view:** blocks **v0.1** — D-1, D-1b, D-2…D-5, D-8…D-13, D-17 (D-6/D-7 block
**v1.0**). Phase 3 closed nothing on this list except the CLI half of INV11.

## Process slips (recorded so the list above stays trustworthy)

| Date found | What slipped | How it happened | Fix |
|---|---|---|---|
| 2026-10-19 | **Slint + wgpu zero-copy render spike** — the owner approved it around 2026-10-17; it was never run | The approval was **never written into any tracked list**: no roadmap row, no criteria item, no decision-log entry. The only written trace was "zero-copy IOSurface → Metal import on the viewer is an optimization for later" (Phase 1 design, 2026-10-16). A search of docs/, git history and the session transcripts on this machine (2026-10-19) found no record of the approval itself, so the date is the owner's. With nothing pointing at it, the spike fell out as soon as the conversation moved on. First item to slip in this project. | Run the same day, before the Phase 4 criteria (architecture D32). Rule from now on (CLAUDE.md): **an approved item becomes a row in "Deferred items" (or a criteria item) in the same commit that records the approval** — anything not in a tracked list is assumed lost. |

## Progress log

| Date | Phase | v0.1 items open | Notes |
|---|---|---|---|
| 2026-10-19 | 3 | 9 / 10 | Encrypted, authenticated handshake over QUIC on loopback: SPAKE2 (python-spake2 port, hardened by our A32 validator) → Noise XXpsk0 / XX with the TLS exporter in the prologue, SAS commit-reveal as type-states, approval gate, attempt limiter, single-use codes and passwords; host/viewer CLI. 36 attacks + F1–F3 pass (§10). A04: AUTH_FAILED 200.4–202.2 ms (Linux CI, 1 800 samples); F2 handshake p50 0.95 ms / p95 2.64 ms; A17-stat 0 / 10 000; fuzz 9 × 10 min, 0 crashes. No v0.1 checklist item completes yet ("every invariant has its test" still waits for INV2/9/10). |
| 2026-10-17 | 2 | 9 / 10 | Capture + hardware encode on M4: screen change → encoded 8.1 ms p95 (≤ 11), 60 fps, < 1 % CPU static, no memory growth. 4:4:4 only outside low-latency mode; display sleep/lid/unplug stop the stream (−3815). No v0.1 checklist item completes until streaming exists (Phase 4). |
| 2026-10-17 | 1 + 1.5 | 9 / 10 | Docs, threat model, skeleton, CI and release workflows. `v0.0.1` pipeline release verified (MSI install on real Windows still to do). |
