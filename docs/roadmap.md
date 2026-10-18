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
| 3 | Noise + SPAKE2 handshake over QUIC on localhost; safety code; CLI accept prompt; security tests; fuzz targets | |
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

## Known gaps before v0.1

Things that could not be verified yet and must be closed (or explicitly
accepted by the owner) before v0.1:

| Gap | Why open | Close by |
|---|---|---|
| MSI install / uninstall / upgrade-in-place on real Windows | No Windows machine yet | Phase 6.5 |
| Windows spike on real hardware: hardware encoders (NVENC/QuickSync/AMF), GPU-memory frames, multi-monitor, DPI/HDR, ACCESS_LOST recovery, UIPI | GitHub runner has only Microsoft's software display driver | Phase 6.5 (needs a real Windows PC) |
| macOS signing + notarization path | No Apple Developer ID yet | Before first public release |
| Per-chip encoder floors for Intel Mac, NVENC, QuickSync, AMF | Only measured on Apple M4 | Phases 6.5 / 9 |
| **Open question: unexplained ~2 ms benchmark drift.** The same capture+encode configuration measured C2 p50 ≈ 9.0 ms at 02:56–02:59 and ≈ 7.05 ms from 03:05 on (2026-10-17, M4), no thermal/performance warning. ~2 ms is ~10 % of the 20 ms budget. | Not reproduced or explained yet; machine state is now recorded with every run and disagreements > 1 ms are flagged | Phase 4 checks whether it reappears |
| Physical display hotplug and the other untested Q4 cases (external monitor unplug/replug, clamshell, mirroring, arrangement, aspect/refresh/HDR changes, lock screen, fast user switching) — list in phase2-criteria.md §5.4 | No external display available; single-display subset tested | Phase 9 (or earlier if a monitor is available) |
| Threat-model invariants not testable in Phase 3: INV2 on the real media path, INV9 (no pixels logged/written), INV10 (keys/buttons released), INV11 (session indicator, partly manual) — phase3-criteria.md §5 | No media/input path yet | INV2/INV9/INV11 in Phase 4, INV10 in Phase 6 |
| No formal model of the handshake composition; `spake2` crate unaudited (python-spake2 compatible, not RFC 9382) | Out of scope for tests (phase3-criteria.md §6) | External review / ProVerif-Tamarin model before v1.0 |
| **v1.0 review question:** replace SPAKE2 (python-spake2 variant) with CPace (IRTF CFRG draft) or an RFC 9382 implementation — crypto-claims-audit.md §1 | Swap is prepared by the `Pake` abstraction | Before v1.0 |
| **Decay risk: INV11 is partly manual** (session indicator) — manual checks get skipped | No UI yet | Phase 4: automated CLI indicator check; Phase 7: automated GUI test (indicator visible for the whole `Active` period, button reaches `Closed` within 1 s) |
| **Device keys are in a file, not the OS keychain** (owner decision 2026-10-19, D31): 0600 on Unix and refused if others can read it; on Windows only the profile directory's default ACL protects it (no permission check) | Phase 3 needed persistent keys for trusted mode and A19 | Before v0.1: move to the OS keychain (keyring 4.x, re-verify its API) |
| Remove the dev signing identity + RemoraDev screen-recording grant (phase2-criteria.md §7) — kept by owner decision while developing | Still needed for development | End of Phase 4 |
| Host must restart capture after −3815 (display sleep, lid close, display removed) — measured in Phase 2, not implemented yet | Phase 2 only measured it | Phase 4 (streaming) / 6 |

## Progress log

| Date | Phase | v0.1 items open | Notes |
|---|---|---|---|
| 2026-10-17 | 2 | 9 / 10 | Capture + hardware encode on M4: screen change → encoded 8.1 ms p95 (≤ 11), 60 fps, < 1 % CPU static, no memory growth. 4:4:4 only outside low-latency mode; display sleep/lid/unplug stop the stream (−3815). No v0.1 checklist item completes until streaming exists (Phase 4). |
| 2026-10-17 | 1 + 1.5 | 9 / 10 | Docs, threat model, skeleton, CI and release workflows. `v0.0.1` pipeline release verified (MSI install on real Windows still to do). |
