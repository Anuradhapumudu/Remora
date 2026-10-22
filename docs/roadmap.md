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
| 3 | Noise + SPAKE2 handshake over QUIC on localhost; safety code; CLI accept prompt; security tests; fuzz targets | ✅ accepted by the owner 2026-10-19 (walkthrough 2026-10-20, phase3-criteria §10.8) — results in phase3-criteria.md §10 |
| 4 | Encrypted loopback streaming; wgpu viewer; stats overlay | in progress (criteria approved 2026-10-19: phase4-criteria.md) |
| 4.5 | **Small GUI** pulled forward from Phase 7 (owner, 2026-10-20): host Accept/Deny dialog and viewer connect form, so testing no longer needs the terminal. Criteria written and approved before code | planned (roadmap D-26) |
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
| D-1b | **INV2 for input** — the same loopback-capture test over input events (pointer, keys); and M8's "host and viewer media keys differ" once the viewer sends pointer-motion datagrams (phase4-criteria §12, 2026-10-21) | **BLOCKER** | Phase 6 | Split from D-1 (2026-10-19): Phase 4 has no input path |
| D-2 | **INV9** — no screen pixels logged or written to disk by the streaming path | **BLOCKER** | Phase 4 | No pixels flowed in Phase 3 |
| D-3 | **INV10** — keys and mouse buttons released when a session ends for any reason | **BLOCKER** | Phase 6 | No input injection until Phase 6 |
| D-4 | **INV11** — session indicator: automated **GUI** test (visible for the whole `Active` period; its button reaches `Closed` within 1 s). The CLI part is automated since Phase 3 | **BLOCKER** | **Phase 4.5** (the small GUI shows sessions: INV11 applies to it; was Phase 7) | No GUI until Phase 7; a manual check decays Phase re-checked 2026-10-20 (owner: record the phase that NEEDS an item, not the furthest-away one). |
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
| D-16 | Physical display hotplug and the other untested Q4 cases (phase2-criteria §5.4), including **physical** monitor unplug / replug (removal of the captured display is testable with a virtual display: D-28) | *nice-to-have* | Phase 9 (earlier if a monitor is available) | No external display available |
| D-17 | How the Slint UI and our own video surface share a window (Slint never owns the video, D34). **Examined 2026-10-19: solvable** (docs/d17-video-surface-options.md): A one window / two layers (best UX, unverified, needs `unsafe`), B child window, C two windows (no integration risk), D another toolkit. Proposed first step: a ≤ 2 h spike of A on macOS before Phase 7 design | **BLOCKER** | **Phase 4.5 design** (its GUI is the first Slint UI next to our video window; was Phase 7) | Consequence of R1 (D34); Phase 4 needs no Slint Phase re-checked 2026-10-20 (owner: record the phase that NEEDS an item, not the furthest-away one). |
| D-18 | Zero-copy IOSurface → wgpu import on the viewer (works, D32; saves ≈ 0.3 ms p50) | *nice-to-have* | Phase 9, or earlier if the budget needs it | Needs `unsafe` wgpu-hal calls outside the three FFI crates → an unsafe-policy decision by the owner |
| D-19 | Glass-to-glass effect of `Immediate` present in a composited macOS window (camera or photodiode measurement) | *nice-to-have* | Phase 4 report if equipment is available, else Phase 9 | Software timestamps cannot see the WindowServer compositor |
| D-20 | UI (first GUI: Phase 4.5): on a first connection the viewer marks an **unpinned device "unverified"** until the safety code is confirmed (protocol.md "Device ID", owner 2026-10-18) | **BLOCKER** | **Phase 4.5** (the connect form shows the host and the safety code; was Phase 7) | Recorded only in protocol.md until the 2026-10-20 audit (Process slips) Phase re-checked 2026-10-20 (owner: record the phase that NEEDS an item, not the furthest-away one). |
| D-21 | UI (first GUI: Phase 4.5): after a **denied** prompt both sides make clear that a retry needs the **fresh code** (INV15; protocol.md §handshake outcomes, owner 2026-10-18) — plus the F-UX3 explanation of every new code/password pair | **BLOCKER** | **Phase 4.5** (host accept/deny dialog and viewer connect form; was Phase 7) | As D-20 Phase re-checked 2026-10-20 (owner: record the phase that NEEDS an item, not the furthest-away one). |
| D-22 | Capture/input trait changes #1 cursor event, #3 optional move rects, #4 optional `Idle` (architecture D17, owner 2026-10-17) | **BLOCKER** | Phase 6.5 | Recorded only in D17 until the 2026-10-20 audit |
| D-23 | Stats overlay shows which chroma mode is **actually** in use (4:4:4 vs the low-latency 4:2:0 fallback), and Phase 7 measures the latency cost of Sharp text's 4:4:4 (quality.md §4:4:4, owner 2026-10-16) | **BLOCKER** | Phase 7 | Recorded only in quality.md until the 2026-10-20 audit |
| D-24 | Phase 5 ICE: use str0m's ICE as the reference, or a sans-IO ICE crate, and document which behaviours we copied (nat-traversal.md, owner 2026-10-16) | **BLOCKER** | Phase 5 | Design input recorded in nat-traversal.md; listed so it cannot slip |
| D-25 | "A benchmark that disagrees with a previous one by > ~1 ms is flagged, never averaged away" (owner 2026-10-16) is a **process rule with no check**; machine state is recorded (sysmon) but nothing compares runs | *nice-to-have* | Phase 4 (benchmark work) | Found by the 2026-10-20 audit; a rule we rely on should have a check |
| D-26 | Phase 4.5 small GUI: host Accept/Deny dialog + viewer connect form (Slint for UI only, D34), carrying F-UX1–4 and D-20/D-21 into the GUI; criteria first | *nice-to-have* (planned work; the full GUI stays a Phase 7 item) | Phase 4.5, right after Phase 4 | Owner, 2026-10-20: "terminal makes testing hard" |
| D-27 | Forward error correction (Reed–Solomon `FecRepair` datagrams, `fec_group`; protocol.md §6) — Phase 4 sends none and the viewer rejects a non-zero `fec_group` | **BLOCKER** | **Phase 5** — the first real networks and real packet loss (was Phase 7). Phase 5's criteria decide whether FEC or keyframe recovery alone handles loss there; Phase 7 tunes the repair ratio with network simulation | Not in the Phase 4 criteria; loopback has no loss to recover from (step 3, 2026-10-20) Phase re-checked 2026-10-20 (owner: record the phase that NEEDS an item, not the furthest-away one). |
| D-28 | Capture restart after **lid close / open** and after the **captured display disappears** — phase4-criteria T3 wrongly said both were "not testable": Phase 2 tested lid close/open on this Mac (`hotplug-lid.log`) and removed the captured display with a `CGVirtualDisplay` (`scripts/macos/virtual-display.m`, `hotplug-virtual-unplug.log`; private API, so real hardware may differ). Lid close needs the owner at the Mac | **BLOCKER** | Phase 4 (step 7, owner present) | Found by the 2026-10-20 phase re-check; laptops are the common host Display removal added by the 2026-10-20 sweep of asserted limitations. |
| D-29 | **Decided 2026-10-21 (owner: "yes I'm always agree with you", to option B with N = 2 minutes; architecture D38):** when the captured display disappears, the host waits up to **2 minutes** for it; both sides show the wait and the time left; if it returns, the stream resumes in the same session with a keyframe; if not, the session ends with `CloseCode::CaptureStopped` and the reason "captured display was removed", never `Normal`. Never switches to another display by itself. **Implemented 2026-10-22** (phase4-criteria §11b step 7c: wait, stop with `DisplayRemoved`, never another display; T3 on the M4 with a virtual display). **Shown on both sides 2026-10-22** (owner: "split it"): `StreamState` reason 4 + `remaining_ms` (protocol.md §5, a minor addition §8), host terminal line, viewer terminal line and window title (architecture D43); the proper visual is D-33 | **BLOCKER** | Phase 4 step 7 | Found while correcting T3 (2026-10-20); behaviour must be chosen, not left to the restart loop |
| D-30 | The person at the host chooses another display to share (after the captured one disappears, or at any time); the viewer never chooses, and Remora never switches by itself (D38) | *nice-to-have* | Phase 4.5 GUI or later | Owner approved 2026-10-21 with D-29; the consent-preserving version of "switch to the main display" |
| D-31 | **`Capabilities` exchange** (protocol.md §5 tag 1): the viewer announces the codecs it decodes and its `max_width × max_height`, and the host encodes within them. Phase 4's viewer enforces its own limit (≤ 7680 × 4320, `remora_codec::h264::SizeLimit`) on every SPS before the decoder is configured, but never tells the host, so a host streaming above it gets only refusals | **BLOCKER** | Phase 5 (first host and viewer on different machines) | Owner approved 2026-10-21 (step 5 plan, "ok"): M7's "negotiated size" is the viewer's own limit until this exists (phase4-criteria §12) |
| D-32 | **HEVC decode** on the viewer (parameter-set checks for VPS/SPS/PPS as for H.264, a fuzz target, M7 again) | *nice-to-have* | Phase 7 (image quality) | Owner approved 2026-10-21 (step 5 plan): Phase 2 measured H.264 as the faster low-latency encoder on the M4, so Phase 4 streams and decodes H.264 only |
| D-33 | **"Display removed" overlay with a countdown** in the viewer (and the host's session panel): the proper visual for D-29's wait. Phase 4 shows it as plain text only — terminal lines on both sides and the viewer's window title (architecture D43); a viewer approved during the wait has no window yet and shows it in its terminal only | *nice-to-have* | Phase 4.5 GUI | Owner decision 2026-10-22 (D-29 "split it": protocol and minimal text in Phase 4, the visual in the Phase 4.5 GUI) |

**Release view:** blocks **v0.1** — D-1, D-1b, D-2…D-5, D-8…D-13, D-17, D-20…D-24, D-27…D-29, D-31 (D-6/D-7 block
**v1.0**). Phase 3 closed nothing on this list except the CLI half of INV11.

### Closed

A deferred item is never deleted: when it is closed its row moves here with
the evidence (CI `roadmap` job, `scripts/ci/check-roadmap.py`, fails if an ID
disappears).

| # | Item | Closed | Evidence |
|---|---|---|---|

## Open gates (owner "don't proceed until X")

Every gate the owner sets becomes a row here **in the same commit that
acknowledges it** (CLAUDE.md). Before starting each step, the open rows are
checked with `python3 scripts/ci/check-roadmap.py --open-gates` — not
remembered. A row is never deleted: its status moves from OPEN to
MET (with the evidence) or WAIVED (with the owner's words). CI's `roadmap`
job checks the table's shape and that no gate disappears.

| # | Gate (owner's words) | Set | Blocks | Status |
|---|---|---|---|---|
| G-1 | "I'll run the two-terminal walkthrough myself (including the wrong-password, deny, trusted-mode and wrong-device steps in §10.7) and confirm before you begin Phase 4 work" (2026-10-19); "Stop and hold at the end of step 3 … will send results before step 4 starts" (2026-10-20) | 2026-10-19 | Phase 4 step 4 onward | MET 2026-10-21 — owner ran every step in their own two terminals and sent screenshots: accept, wrong password, deny (2026-10-20); trusted mode across a restart and wrong device (2026-10-21), the latter `identity mismatch`, exit 3, no host prompt. Results row by row in phase3-criteria §10.8. Findings fixed on the way: F-L1 (30 s idle disconnect), F-UX5, F-UX6 |

## Process slips (recorded so the list above stays trustworthy)

| Date found | What slipped | How it happened | Fix |
|---|---|---|---|
| 2026-10-19 | **Slint + wgpu zero-copy render spike** — the owner approved it around 2026-10-17; it was never run | The approval was **never written into any tracked list**: no roadmap row, no criteria item, no decision-log entry. The only written trace was "zero-copy IOSurface → Metal import on the viewer is an optimization for later" (Phase 1 design, 2026-10-16). A search of docs/, git history and the session transcripts on this machine (2026-10-19) found no record of the approval itself, so the date is the owner's. With nothing pointing at it, the spike fell out as soon as the conversation moved on. First item to slip in this project. | Run the same day, before the Phase 4 criteria (architecture D32). Rule from now on (CLAUDE.md): **an approved item becomes a row in "Deferred items" (or a criteria item) in the same commit that records the approval** — anything not in a tracked list is assumed lost. |
|  2026-10-20 | **Dev key-storage warning on every run** (F-UX2) — the owner approved file-based key storage on the condition that the CLI warns on every run that the keys are unencrypted; the CLI printed only a first-run `note:` | **Correction (owner, 2026-10-20):** the condition **was written down** — point 1 of the owner's key-storage approval message ("Make it self-announcing, not just documented. The CLI prints a visible warning on every run…"). Approvals as written **are** the record; the broken step was the **transfer** of a condition in an approval into a tracked row in the repo (criteria item, roadmap row, decision entry, test). Where the transfer broke, as far as we can see: the development session received only the multiple-choice answer "File now, keychain later (Recommended)" (2026-10-18 18:06); the written message does not appear in the session transcripts on this machine (searched 2026-10-20), so the condition never reached the implementation. Found by the owner's walkthrough, not by us. | Fixed 2026-10-20 (warning on every run of both apps, e2e test, planted regressions caught). The CLAUDE.md rule (an approval of future work or a condition becomes a tracked row in the same commit) addresses the transfer step. **Audit** of the 18 owner approval messages that reached the sessions (2026-10-16…20): no other condition missing from the code; five approved future requirements lived only in design docs → D-20…D-24; one rule without a check → D-25. **Limit of the audit:** it can only see messages that reached a session; any other points of the key-storage approval message were not checked (owner asked to paste it). |
| 2026-10-20 | **Phase 3 walkthrough gate passed without being met** — Phase 4 steps 1–3 were built although walkthrough steps 6–7 (trusted mode across restart, wrong device) were never run by hand | The gate lived only in the conversation: no tracked row. The owner sent screenshots for 3 of 5 steps and wrote "working I think … lets build ui or continue"; Claude judged the two remaining steps covered by their e2e tests and asked "what should come next?" instead of "may the remaining walkthrough steps be waived?" — turning "continue" into a waiver the owner never gave. Owner (2026-10-20): "an instruction with nothing tracking it doesn't happen"; third slip of this kind (render spike, F-UX2 condition, this gate). | Hold at the end of step 3. New "Open gates" table (G-1) guarded by CI; CLAUDE.md: every owner gate becomes a row in the same commit that acknowledges it, and open gates are checked with `--open-gates` before each step; a gate is only ever MET (evidence) or WAIVED (owner's words), never inferred. |

## Progress log

| Date | Phase | v0.1 items open | Notes |
|---|---|---|---|
| 2026-10-19 | 3 | 9 / 10 | Encrypted, authenticated handshake over QUIC on loopback: SPAKE2 (python-spake2 port, hardened by our A32 validator) → Noise XXpsk0 / XX with the TLS exporter in the prologue, SAS commit-reveal as type-states, approval gate, attempt limiter, single-use codes and passwords; host/viewer CLI. 36 attacks + F1–F3 pass (§10). A04: AUTH_FAILED 200.4–202.2 ms (Linux CI, 1 800 samples); F2 handshake p50 0.95 ms / p95 2.64 ms; A17-stat 0 / 10 000; fuzz 9 × 10 min, 0 crashes. No v0.1 checklist item completes yet ("every invariant has its test" still waits for INV2/9/10). |
| 2026-10-17 | 2 | 9 / 10 | Capture + hardware encode on M4: screen change → encoded 8.1 ms p95 (≤ 11), 60 fps, < 1 % CPU static, no memory growth. 4:4:4 only outside low-latency mode; display sleep/lid/unplug stop the stream (−3815). No v0.1 checklist item completes until streaming exists (Phase 4). |
| 2026-10-17 | 1 + 1.5 | 9 / 10 | Docs, threat model, skeleton, CI and release workflows. `v0.0.1` pipeline release verified (MSI install on real Windows still to do). |
