# D-50: view and control a Linux (GNOME Wayland) host from the Mac — criteria

**Status: DRAFT, waiting for the owner's approval.** Nothing below is built
until the owner approves it (roadmap D-50: "spike, then criteria for the
owner's approval, then building"). When approved, this file is renamed to
`docs/phase4.6-criteria.md`, so `scripts/ci/check-criteria.py` checks its
tables like every other phase's.

## 0. What the spikes showed (evidence, not belief)

All numbers: `spikes/linux-capture/results/sl1a-20261102.txt`. The machine
is the owner's laptop: Fedora 43, GNOME 50 on Wayland, 1920×1080, no
hardware video encoder.

| Spike | Result |
|---|---|
| S-L1a capture | portal ScreenCast + PipeWire, 55.3 fps at 1080p (4K: 15–21 fps) |
| S-L1b encode | openh264 software, parallel BT.709 conversion + slices: 10.7 ms p50 / 13.6 ms p95, 54.6 fps |
| S-L1c stream | real Remora session laptop → Mac viewer over Wi-Fi: 30–33 fps drawn, decode 2–3 ms; 1.6 % frames lost, each loss stalls until the next keyframe (dips to 13 fps) |
| S-L2 input | RemoteDesktop portal v2: keyboard + pointer granted after **one** click at the laptop; restore token → next run **0.0 s, no dialog**; ~0.5 ms per injected event |

Spike code is throwaway (D-41) and used **no `unsafe`** (the `pipewire`
0.10.1 and `ashpd` 0.13.13 APIs we called are safe Rust).

**Not verified yet (must be checked, not assumed):**
- that GNOME shows its own "screen is being shared / remote controlled"
  indicator in the top bar during a portal session (the owner can look);
- how the person revokes the saved permission (GNOME Settings → Privacy /
  Apps is expected, not checked);
- that injected keys go to the focused window only, and that the GNOME
  lock screen refuses injected input when locked.

## 1. Scope

**In:** a Linux host (GNOME Wayland via portals) that shows its screen to
the Mac viewer and accepts mouse and keyboard from it. Same code, password,
safety code, Accept/Deny and encryption as the Mac host — no new security
path.

**Out (stays where it is):** input injection on a **Mac** host (Phase 6,
D-1b/D-3/D-38 unchanged); clipboard, file transfer, audio; Windows; KDE and
other desktops (portal-based, so likely to work, but **unverified** and not
claimed); the 4K panel case (D-50 note: capture at 1080p or scale later).

## 2. Decisions for the owner (recommendation first)

| # | Question | Recommendation | Why |
|---|---|---|---|
| Q1 | Where does the code live? | Real crates: `remora-capture/src/sys/linux.rs`, `remora-codec` (openh264 encoder), `remora-input/src/sys/linux.rs`, a Linux build of `remora-host` (CLI first) | Input is attack surface; it needs the real tests, fuzzing, and policy checks, which a spike doesn't get |
| Q2 | How does pointer **motion** travel? | Reliable stream, new `Input` kind `PointerMove {x, y}`; the viewer coalesces to at most one per drawn frame (≤ 120/s) | Simplest correct path; protocol.md's "motion as a datagram" stays the plan for Phase 6 (D-1b) |
| Q3 | Mac ⌘ key → Linux? | **Physical** mapping (⌘ → Super), as protocol.md already says (USB HID usage = physical key) | Predictable, layout-independent; a "⌘ → Ctrl" option can come later |
| Q4 | Host UI on Linux | CLI (`remora-host serve`), Accept/Deny in the terminal, as on the Mac before the GUI | The Slint GUI on Linux is extra work for no security gain now |
| Q5 | Laptop permission | Portal restore token saved 0600 in the user's config dir; `remora-host forget-permission` deletes it | One click ever (what the owner asked for), and a way back |

## 3. Security requirements (each gets a test that has been seen failing)

| ID | Requirement | Test |
|---|---|---|
| L1 | Input is processed only in `Active` (INV1). Already true in `remora-session` (`host.rs` delivers `Input` only from `Active`); add a host-binary test that input before Accept never reaches the injector | integration, plant: deliver in `Pending` |
| L2 | **INV10:** every key and button the viewer pressed is released on every end: Goodbye, End session, viewer crash, network loss/timeout, host error. The injector tracks the pressed set itself (it does not trust the viewer's `ReleaseAll`) | integration with a fake injector for each end path; plant: skip release on timeout |
| L3 | Every field validated before injection: x, y finite and clamped to 0..1; button in an allowlist (left/right/middle/back/forward); key = known HID usage in our table, else dropped and counted; scroll finite and clamped | unit + fuzz target `input_event` |
| L4 | Rate limit: > 2000 input events/s or > 32 keys held closes the session with a counted reason | unit; plant: 10 000 events burst |
| L5 | **D-38 on this host:** the Linux host's own controls are its terminal. With one active session (H9) a remote viewer cannot accept a second viewer; what remote keys **can** do in the host terminal (type `end`) only ends their own session. Recorded as a known limitation, test that `accept` typed while Active is refused (`AnotherSessionActive`) | unit (exists for H9) + manual |
| L6 | **INV11:** host shows "session active" and one action ends it (terminal line + GNOME's own indicator, **if** verified in §0) | manual checklist |
| L7 | No input path without encryption (INV2): input rides the existing Noise stream only; loopback-capture test extended to input | integration (closes part of D-1b) |
| L8 | Restore token is a secret-ish capability: file 0600, never logged, `Debug` redacted | unit + grep lint |

## 4. Performance targets

| ID | Target | Measured in spikes |
|---|---|---|
| LP1 | Host capture+convert+encode p95 ≤ 20 ms at 1080p | 13.6 ms |
| LP2 | ≥ 30 fps drawn on the Mac over the owner's Wi-Fi | 30–33 (dips 13) |
| LP3 | Injected event cost p95 ≤ 2 ms on the host | 0.64–0.68 ms |
| LP4 | Recovery after a lost frame ≤ 200 ms (today: waits for a keyframe request round trip) | not met yet: needs the keyframe-request path measured; intra refresh if not |

## 5. Dependencies (14-day rule, D3, dependencies.md in the same commit)

`ashpd` 0.13.13 (features `tokio`, `screencast`, `remote_desktop`),
`pipewire` 0.10.1, `openh264` 0.9.8 (builds Cisco's C source; BSD-2-Clause),
Linux-only (`[target.'cfg(target_os = "linux")'.dependencies]`). Versions
re-checked with `cargo info` and the crate-age check before adding; any
`cargo deny` licence/ban finding stops the step.

## 6. Build order (test first, as in phase 3)

1. Criteria approved → roadmap row(s), this file renamed.
2. Protocol: `PointerMove` + `Scroll` + `ReleaseAll` kinds, size limits, fuzz target.
3. Viewer: capture mouse/keys in the video window → HID → `send_input`.
4. Host injector trait + fake; attack tests L1–L4 committed **before** the Linux injector.
5. Linux capture + encoder in the real crates; Linux `remora-host serve`.
6. Laptop end to end: view + control, LP1–LP4 measured, manual L5/L6.
7. Roadmap: progress log, deferred items row by row.

## 7. Known limitations (stated plainly)

- Wi-Fi loss stalls the picture until a keyframe (LP4 open).
- 4K panels capture at 15–21 fps; the laptop runs 1080p.
- Only GNOME on Wayland has been tried.
- A remote user who controls the laptop can do anything the logged-in
  person can, including typing into the host's terminal; that is what
  "control" means. The protection is Accept/Deny + the safety code + one
  active session.
