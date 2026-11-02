# Phase 4.6 (D-50): view and control a Linux (GNOME Wayland) host from the Mac — criteria

**Status: APPROVED by the owner, 2026-11-02**, as drafted, with the
recommended answer to every decision in §2 ("Real crates", "⌘ → Super",
"Approve as drafted"). Roadmap D-50: "spike, then criteria for the owner's
approval, then building" — building may start. Phase 4.5's manual items
(M1–M7, O2, D-34 runs, final P5) are still open; the owner chose to run
this work alongside them (D-50, 2026-11-01: "laptop control next").

## 0. What the spikes showed (evidence, not belief)

All numbers: `spikes/linux-capture/results/sl1a-20261102.txt`. The machine
is the owner's laptop: Fedora 44, GNOME 50 on Wayland, 1920×1080, no
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
- ~~that GNOME shows its own indicator~~ — **observed by the owner**
  2026-11-02 during S-L2 ("Yes, I saw an icon" in the top bar). Still to
  be checked in the manual test (L6) for the real host, not only the spike;
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

## 8. Report (2026-11-02)

**Result:** the owner viewed and controlled the Fedora laptop from the Mac
(GNOME 50 Wayland, Wi-Fi LAN): Settings and Firefox opened, pages
scrolled and text typed remotely; one approval at the laptop ever (saved
portal permission). Code: commits 8430936 … bafce32 (protocol, viewer,
guard, host control, Linux capture/encoder/injector, fixes from the live
sessions). Plants: `results/phase4.6/plants.md`; numbers:
`results/phase4.6/measurements.md`.

### Security requirements

| ID | Status | Evidence |
|---|---|---|
| L1 | **Met** (unit level) | `remora-host/src/control.rs::l1_input_reaches_the_os_only_while_active` (plant: input before Active opens an injector, caught); the session layer's own refusal before Active is A20/A21. A host-binary network test was not written: the injector is reached only through `Control`, which this test covers |
| L2 | **Met** (event level) | `control.rs::l2_every_end_path_releases_held_keys` (Normal, ProtocolViolation, CaptureStopped, Timeout, Lost, Failed; plant on Lost caught), `l2_host_stopping_releases_held_keys`; guard: `remora-input/tests/l2_l4_guard.rs` (5 plants, one first NOT caught then fixed). Live: GNOME's Stop ended a session with keys released (`session ended 1 (CaptureStopped)`) |
| L3 | **Met** | decode checks `remora-proto/tests/l3_input.rs`; key table drop `l2_l4_guard.rs::l3_unknown_keys_are_dropped_and_counted`; fuzz target `input_event` (first version did NOT catch its plant; rewritten, caught) |
| L4 | **Met** | `l2_l4_guard.rs::l4_*`, `control.rs::l4_a_flood_ends_the_session_and_releases` |
| L5 | **Met** (as specified) | H9 unit test (one active session); manual: only `accept`/`deny`/`disconnect` typed in the host terminal act, and a second viewer is refused while one is Active |
| L6 | **Met, with a finding** | GNOME's indicator shows during every session; one click ends it at once since 0ae615c (seen live). **Finding D-54:** hidden while an app is full screen |
| L7 | **Met** | `remora-net/tests/l7_input_sealed.rs`: a real session over QUIC sends every input kind with a random canary; no 8-byte window of any input's plaintext appears in the frames handed to QUIC, and the host receives each input intact. The plant (input sent as plaintext) is kept as a test that must see the plaintext and no delivery |
| L8 | **Met** | file: `remora-app/src/token_file.rs::l8_the_token_file_is_owner_only_and_round_trips` (plant 0644 caught); `Debug`: `remora-capture/src/sys/linux.rs::l8_the_restore_token_is_never_printed` (plant caught). The file is written by remora-app, never by remora-capture (the policy test refused the first version that did) |

### Performance targets

| ID | Target | Measured | |
|---|---|---|---|
| LP1 | capture+encode p95 ≤ 20 ms | 34.2 ms (8 Mbit/s session); bench on video: 24–41 ms for every software setting | **Not met** — software H.264 while the laptop also plays video. Path: Intel GPU encoder (VA-API, needs RPM Fusion: owner's decision) |
| LP2 | ≥ 30 fps over Wi-Fi | 30–44 fps while the screen moves | **Met** (GNOME sends nothing for a still screen, so idle seconds show low fps) |
| LP3 | injected event p95 ≤ 2 ms | 0.64–0.97 ms (S-L2; dbus-monitor saw every kind arrive) | **Met** |
| LP4 | recovery ≤ 200 ms | before the fix: viewer waited 479 pictures in one session; after (4f98162): 5 recoveries in 2.5 min, **p50 68 ms, max 324 ms** | **Met at p50, not at max** |

**Wi-Fi:** ping Mac → laptop p50 53.9 / p95 128 / max 277 ms (best 4 ms),
laptop on 2.4 GHz with Wi-Fi power saving **on**. This, not Remora, is
most of the control lag the owner felt. Turning power saving off needs
administrator rights on the laptop; the owner runs that command.

### Changes found by using it (not in the criteria)

Trackpad scrolling did nothing (finish flag on every event), two
pointers were visible (the Mac's is now hidden over the video), text was
soft (openh264's 120 kbit/s default; now 4 Mbit/s QP 20–34 from a
measured bench), the second portal session in a host run hung (one
process-wide portal runtime now), GNOME's Stop ended the session only on
the next input (now at once), and the spike's colour conversion tinted
greys (fixed by its test).

### Manual test steps (as the owner ran them)

1. Laptop: `remora-host serve --bind <laptop-ip>:0` (prints code and password).
2. Mac: `remora-viewer gui`, paste the code, type the password.
3. Compare the six-digit safety code; at the host type `accept <n>` only if equal.
4. First time ever: GNOME asks to share the screen and allow control; tick
   "remember". Later sessions: no dialog.
5. Move, click, type, scroll in the video window; check one pointer.
6. Click GNOME's orange indicator: the session ends at once on both sides.
7. `remora-host forget-permission` removes the saved permission.

### Known limitations (updated)

- LP1 not met in software; LP4 worst case 324 ms.
- The first-ever GNOME dialog can outlast the host's 60 s accept window
  (the session is refused; the saved permission then makes the next one
  work). To fix with D-52's GUI work.
- No sound (D-51), Mac volume keys do not reach the host (D-53),
  indicator hidden in full screen (D-54).
- Only GNOME 50 on Wayland tried; 4K panels unmeasured.

### Deferred items, row by row

- **D-50** (laptop control): delivered as above; closes when the owner
  accepts this phase.
- **D-51** sound, **D-52** connect simply, **D-53** volume keys, **D-54**
  full-screen indicator: new today, open.
- No other row changed in this phase.
