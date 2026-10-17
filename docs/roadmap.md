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
| 2.5 | **Windows spike** (throwaway): capture one DXGI frame, inject one SendInput click; report trait changes | |
| 3 | Noise + SPAKE2 handshake over QUIC on localhost; safety code; CLI accept prompt; security tests; fuzz targets | |
| 4 | Encrypted loopback streaming; wgpu viewer; stats overlay | |
| 5 | STUN + ICE (`is`) + hole punching with offer/answer codes; test across two home networks | |
| 6 | Remote mouse/keyboard + host-local override (macOS) | |
| 6.5 | **Full Windows backends** (capture, encode, input) | |
| 7 | Rate controller, quality modes, Advanced panel; network-simulation tests | |
| 8 | remora-signal (signaling + STUN) + Docker + Oracle Cloud guide; connect by device ID | |
| 9 | Linux X11 backends; cross-platform internet tests | post-v0.1 |

v0.1 is reached at the end of **Phase 8** (Linux X11 in Phase 9 is post-v0.1).

## Known gaps before v0.1

Things that could not be verified yet and must be closed (or explicitly
accepted by the owner) before v0.1:

| Gap | Why open | Close by |
|---|---|---|
| MSI install / uninstall / upgrade-in-place on real Windows | No Windows machine yet | Phase 6.5 |
| macOS signing + notarization path | No Apple Developer ID yet | Before first public release |
| Per-chip encoder floors for Intel Mac, NVENC, QuickSync, AMF | Only measured on Apple M4 | Phases 6.5 / 9 |
| **Open question: unexplained ~2 ms benchmark drift.** The same capture+encode configuration measured C2 p50 ≈ 9.0 ms at 02:56–02:59 and ≈ 7.05 ms from 03:05 on (2026-10-17, M4), no thermal/performance warning. ~2 ms is ~10 % of the 20 ms budget. | Not reproduced or explained yet; machine state is now recorded with every run and disagreements > 1 ms are flagged | Phase 4 checks whether it reappears |
| Physical display hotplug and the other untested Q4 cases (external monitor unplug/replug, clamshell, mirroring, arrangement, aspect/refresh/HDR changes, lock screen, fast user switching) — list in phase2-criteria.md §5.4 | No external display available; single-display subset tested | Phase 9 (or earlier if a monitor is available) |
| Remove the dev signing identity + RemoraDev screen-recording grant (phase2-criteria.md §7) — kept by owner decision while developing | Still needed for development | End of Phase 4 |
| Host must restart capture after −3815 (display sleep, lid close, display removed) — measured in Phase 2, not implemented yet | Phase 2 only measured it | Phase 4 (streaming) / 6 |

## Progress log

| Date | Phase | v0.1 items open | Notes |
|---|---|---|---|
| 2026-10-17 | 2 | 9 / 10 | Capture + hardware encode on M4: screen change → encoded 8.1 ms p95 (≤ 11), 60 fps, < 1 % CPU static, no memory growth. 4:4:4 only outside low-latency mode; display sleep/lid/unplug stop the stream (−3815). No v0.1 checklist item completes until streaming exists (Phase 4). |
| 2026-10-17 | 1 + 1.5 | 9 / 10 | Docs, threat model, skeleton, CI and release workflows. `v0.0.1` pipeline release verified (MSI install on real Windows still to do). |
