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
| 2 | macOS ScreenCaptureKit capture + VideoToolbox encode → file; benchmark; verify 4:4:4 / LTR / intra-refresh support | next |
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

## Progress log

| Date | Phase | v0.1 items open | Notes |
|---|---|---|---|
| 2026-10-17 | 1 + 1.5 | 9 / 10 | Docs, threat model, skeleton, CI and release workflows. `v0.0.1` pipeline release verified (MSI install on real Windows still to do). |
