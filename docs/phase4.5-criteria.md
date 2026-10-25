# Phase 4.5 acceptance criteria — small GUI (host Accept/Deny, viewer connect form)

Status: **APPROVED by the owner 2026-10-25 (gate G-3 MET), with the
answers and additions in §1.** Drafted the same day (`9277f8c`).

Same gate rule as Phases 2–4:

* Thresholds are fixed **before** any code and are not changed after measuring.
* If a threshold FAILS, work **stops** and the failure is reported with the
  numbers and a proposed design change. A threshold changes only through a
  new, dated, owner-approved entry in §14.
* The 20 ms end-to-end budget is never raised (quality.md §1). Numbers are
  per-chip (Apple M4, macOS 27.0.1, as phase4-criteria §2).

Why this phase exists: the owner pulled a small GUI forward from Phase 7
(2026-10-20, roadmap D-26) because testing in two terminals is hard. **It is
small on purpose.** Everything not in §0's "in scope" list is out.

Sources read for this draft (2026-10-25), so every claim below can be
checked: i-slint-backend-winit 1.18.1 `lib.rs`, `event_loop.rs`,
`winitwindowadapter.rs`; i-slint-core 1.18.1 `graphics/wgpu_30.rs`; winit
0.30.13 `src/event.rs`, `src/window.rs`, `src/platform/macos.rs`,
`src/platform_impl/macos/window_delegate.rs`; `cargo info
i-slint-backend-testing@1.18.1`; our `remora-session` and `remora-proto`
sources; threat-model.md; protocol.md; docs/d17-video-surface-options.md.
Anything not checked there is marked **unverified**.

## 0. Scope

**In scope (the whole phase):**

1. **Host Accept/Deny dialog** (§4) — one dialog per waiting viewer, showing
   who is asking and the safety code; Deny by default; a time limit.
2. **Host session indicator and "End session"** (§5) — INV11 in the GUI (D-4).
3. **Host main window** — the connection code and one-time password with the
   F-UX3 explanation of every new pair, the INV12 notice ("3 failed attempts
   … new password generated"), and the F-UX2 unencrypted-key warning
   (until D-5).
4. **Viewer connect form** (§6) — paste the connection code, type the
   password, see the host's device ID, the safety code and "unverified"
   (D-20); the denied/fresh-code message (D-21); the F-UX4 "the host decides"
   line.
5. **Viewer session window** (§6) — host device, verified/unverified,
   **Disconnect**, and the "display unavailable, N s left" countdown (D-33).
6. **Viewer stops drawing while its video window is covered** (§7, D-35).
7. **Launching without a terminal** — the host GUI from `RemoraDev.app`
   (signed with the dev identity, D-36), the viewer GUI from its own dev
   bundle (§1 Q9).
8. The CLI (`serve`, `connect`) **stays** and keeps every Phase 3/4 test; the
   GUI is a second front end over the same session code, not a rewrite.

**Out of scope (each stays where the roadmap puts it):**

| Not in 4.5 | Where it lives |
|---|---|
| Remote mouse/keyboard, host-local override | Phase 6 (D-1b, D-3; and the new D-38, §8) |
| UI drawn **over** the video (one window, two layers: D-17 option A) | Phase 7 design |
| Drawn stats overlay (stats stay in the title + stderr, R3) | Phase 7 |
| Quality modes, Advanced panel, settings screens | Phase 7 |
| Choosing another display at the host (D-30) | Phase 7 (§1 Q1) |
| Trusted-device management UI, "remember this device" button (pinning stays the CLI `--pin`) | Phase 8 / v0.1 |
| Device-ID connect, signaling | Phase 8 |
| One combined Remora app with a start screen | Phase 7 |
| OS notification on connect (threat-model §7.5) | Phase 7 (roadmap D-40) |
| Windows/Linux GUI | Phase 6.5 / 9 (the GUI code stays OS-neutral above the trait) |
| Zero-copy (D-18), what holds the 94 MB (D-34) | their own rows — unless §3 pulls D-34 in |
| Session log, themes, localisation, onboarding | later |

## 1. Decisions (answered by the owner 2026-10-25)

The table is the draft as sent; the owner's answers follow it and win
wherever they differ.

| # | Question | Recommendation | Why |
|---|---|---|---|
| **Q1** | Approve the scope and the out-of-scope list (§0)? D-30 moves from "Phase 4.5 GUI or later" to Phase 7 | Yes | Keeps "small" small; D-30 is a nice-to-have and needs a display picker |
| **Q2** | **D-17 for 4.5: option C′** — two top-level windows (Slint UI, our video window) driven by **one** event loop, **no `unsafe`** (§2). Option A's spike stays Phase 7 design | Yes | Slint 1.18.1 has the hooks for it (read, §2); nothing in 4.5 needs UI over the video |
| **Q3** | **P5 after 4.5: same limit, < 150 MB** for the viewer with its GUI as the user sees it in a session (§3). If spike S1 shows the GUI does not fit, **D-34's Instruments investigation moves into 4.5** before the GUI is built; the limit is not raised in 4.5 | Same limit, tied to D-34 | A raised limit with a 1 MB margin today would hide the problem D-34 exists for |
| **Q4** | Keyboard rule for the dialog: Return, Space and Escape all **Deny**; **Accept is not in the keyboard focus chain** (pointer click, or a deliberate accessibility action such as VoiceOver); Accept is **disabled for 1 s** after the dialog appears or changes | Yes | A keystroke typed into another app when the dialog takes focus can only deny (§4 H3, H4) |
| **Q5** | **One active session at a time:** a connection attempt while a session is `Active` gets **no prompt** and is refused as "host busy", without consuming the one-time password | Yes | v0.1 is single-viewer; removes the case "the connected viewer accepts a second viewer" before Phase 6 adds input (§4 H9) |
| **Q6** | D-20: the viewer's **"The codes match"** button marks the host verified **for this session only**; **"They don't match"** ends the session with a warning. Pinning stays the CLI `--pin` | Yes | protocol.md: a device becomes verified only by that confirmation; pinning UI is out of scope |
| **Q7** | **D-36 timing.** The row says recreate/remove **per phase**; your message says "at the start of any **session** that needs screen capture, remove it at the end". Per work session means a new key each time, so macOS asks for Screen Recording again every session | Per phase, as recorded — but this is your call | Fewer keychain changes and grants; the identity exists only while 4.5 runs. Per session is stricter and costs one System Settings click each time |
| **Q8** | D-33 in the viewer: the countdown is shown in the **viewer session window next to the video** (big text) and in the video window's title (as now), **not over the video** | Yes | Over the video needs D-17 option A (Phase 7) |
| **Q9** | How the GUI launches: `RemoraDev.app` becomes a normal app (Dock icon, can take focus) running the host GUI; the viewer GUI runs from a second unsigned dev bundle (it needs no capture permission). **PR #6 (Phase 4) is merged with a merge commit before 4.5 code starts**; the criteria live on branch `phase-4.5` | Yes | The host dialog must be able to come to the front, which `LSUIElement` forbids today (`dev-app.sh`). Merging first keeps 4.5's history separate |
| **Q10** | While a session is `Active`, the host window **hides the code and password** ("hidden while someone is connected — Show"). The OS notification on connect moves to Phase 7 as a new row | Yes | The host's screen is being streamed: a visible fresh code and password would reach the connected viewer (§4 H10) |

**Owner's answers (2026-10-25):**

| # | Answer |
|---|---|
| Q1 | Yes. D-30 moves to Phase 7 |
| Q2 | Yes. If S1 shows C′ does not work: stop and bring the options |
| Q3 | Yes, < 150 MB with the GUI open as it really is in a session. If it does not fit with 5 MB to spare: D-34's Instruments investigation comes into 4.5, **time-boxed like S1** (3 h). If it still does not fit: stop and bring the options, **including changing the limit with a reason — that decision stays with the owner** |
| Q4 | Yes, plus: **a click counts only if both the press and the release happen after the 1 s delay** (H4). Known limitation: keyboard-only users (Full Keyboard Access without VoiceOver) cannot accept (§11b) |
| Q5 | Yes, and: **refuse before the handshake**, so a refused attempt never gets a password guess; **log each refused attempt on the host** (H9) |
| Q6 | Yes |
| Q7 | **Per phase**, as the D-36 row says ("per session" was a wording mistake). Check: if straightforward on macOS 27, make `codesign` **ask for confirmation** when it uses the dev key instead of having silent access, so nothing can sign as RemoraDev unnoticed between sessions; if not straightforward, skip it and note why (§11, D-36) |
| Q8 | Yes |
| Q9 | Yes to all three; PR #6 merged with a **merge commit**, not squash, so the hashes cited in the Phase 4 evidence stay in main's history |
| Q10 | Yes to both (code and password hidden while active; OS notification → Phase 7, roadmap D-40) |

The limitations stated in the draft are recorded in §11b. **The `unsafe`
AppKit call for the indicator** (§5 I3), if S1 shows it is needed: the owner
gets the exact code, why it is needed and how it is isolated, and decides
then.

## 2. D-17 first: how Slint and our video window share the app

**What 4.5 needs:** Slint windows (dialog, forms, session window) **and** our
own winit + wgpu video window (R1, D34) in the **same viewer process**. winit
allows one event loop per process, and Slint's winit backend runs its own.
So the question is not "one window or two" but "can our window live on
Slint's event loop without `unsafe`?"

**What Slint 1.18.1 provides (read):**

* `i_slint_backend_winit::invoke_from_active_event_loop(func)` runs a closure
  on the event loop **with the `ActiveEventLoop`**, "to call winit APIs that
  need it, for example to create custom windows" (`lib.rs:794`, doc comment
  above it). Callable from any thread.
* `BackendBuilder::with_custom_application_handler` (`lib.rs:365`) installs a
  `CustomApplicationHandler` (`lib.rs:218`) that sees winit events **before**
  Slint; events for a window Slint does not know are passed to it
  (`event_loop.rs:121-122`). That is where our video window's events
  (resize, close, `Occluded`) arrive.
* Slint depends on winit `0.30.2` (semver range) with `rwh_06`
  (`Cargo.toml:214-216`), so it can share our winit 0.30.13; **confirm in the
  lock** when Slint is added.
* `WGPUConfiguration::Manual { instance, adapter, device, queue }`
  (`graphics/wgpu_30.rs:80`) lets Slint use **our** wgpu device instead of
  creating a second one — relevant to memory (§3).

**Options for 4.5:**

| | Option | `unsafe`? | Fits 4.5? |
|---|---|---|---|
| **C′** | **Two top-level windows, one event loop**: Slint owns the loop; our video window is created via `invoke_from_active_event_loop` and its events handled in our `CustomApplicationHandler`; decoded pictures reach it the same way (replacing today's `EventLoopProxy` user event, D41), still drawn **on arrival** | **None** (creating a wgpu surface from an `Arc<winit::Window>` is the safe path we already use) | **Yes — proposed** |
| C | Two windows in **two processes** (GUI process + video process) | none | No: IPC between processes is a threat-model review trigger (§10) and a new attack surface |
| B | Video as a **child window** (`with_parent_window`, `unsafe` in winit; on macOS a separate `NSWindow` above the parent, d17 doc) | yes | No need in 4.5 |
| A | One window, two layers | yes | Phase 7 design |

**Unsafe-policy decision:** with C′, **none is needed in 4.5**. If S1 shows
C′ does not work (for example the video window misses events, or drawing on
arrival is delayed by Slint's loop), work stops and the options come back to
the owner **before** any GUI code depends on them; B and A would each need
their own unsafe-policy decision (CLAUDE.md: not D19's precedent).

**Spike S1 checks C′** (§3): both windows open in one process, our window
gets its events, frames are drawn on arrival with the same frame interval as
Phase 4 (P4: 16.67 ms p50 at 60 Hz with a 60 fps source), and nothing needs
`unsafe`.

## 3. Memory: measure before building, and how P5 applies

**The risk.** P5 (viewer `phys_footprint` < 150 MB) passed at **149 MB**;
94 MB of it is GPU memory nobody has explained yet (D-34). Any GUI in the
viewer process adds memory. It must be measured **before** the GUI design is
fixed, not found at the end.

**P5 rule after 4.5 (fixed now, before measuring):** the limit stays
**< 150 MB**, growth min 1 → min 10 ≤ 2 MB, slope ≤ 0.1 MB/min (phase4 P5),
measured with the viewer GUI **as the user sees it during a session** (session
window open, video window in front). It is **not raised in 4.5** (§1 Q3).

**Spike S1 (throwaway, `spikes/gui-memory`, own workspace like
`spikes/slint-wgpu`; timebox 3 h; runs after approval, before any GUI code):**

A stand-in viewer: our winit + wgpu video window drawing 1920 × 1248 NV12
uploads at 60 fps (the Phase 4 path), plus a Slint window with the connect
form's widgets. `phys_footprint` sampled every 10 s for 3 min, and the
"graphics" part as in D-34. Configurations:

| # | Configuration |
|---|---|
| S1-0 | Video window only (the baseline of the stand-in) |
| S1-1 | + Slint, default renderer (femtovg on its **own** wgpu device) |
| S1-2 | + Slint sharing **our** wgpu device (`WGPUConfiguration::Manual`) |
| S1-3 | + Slint with its **software** renderer (no GPU device of its own) |
| S1-4 | The best of 1–3 with the Slint window **closed** after "connect" (does the memory come back?) |

The number that matters is **what each adds over S1-0**, applied to the real
viewer's 149 MB. S1 also answers, yes/no with evidence: C′ works (§2); our
window receives `Occluded` through the custom handler (D-35); Slint's testing
backend can drive a button from a Rust test (D-4, §5); an `always-on-top`
Slint window stays visible over a full-screen app on another Space (§5 I3).

**After S1 (report to the owner before building):**

* A configuration whose added memory keeps the real viewer **< 150 MB with
  ≥ 5 MB to spare** → build with it.
* None does → **stop**. Proposed next step (Q3): D-34's Instruments
  investigation inside 4.5 (it needs the dev identity anyway, D-36), then
  measure again. A new limit is only possible as a §14 entry with the
  owner's approval and a reason, and D-34 keeps blocking v0.1 either way.

The host gets the same treatment in the final runs: host memory with the GUI
is **reported** (no host memory gate exists today), and P6 (host CPU, static
screen, < 2 %) is **re-gated** with the host GUI open (§9).

## 4. Host Accept/Deny dialog — who sees the screen

The dialog is the control that decides who sees the owner's screen
(threat-model §4 item 6; ADV6: an attacker who knows the password is stopped
only by the safety code and this prompt). Each row has an automated test with
a planted failure unless marked manual.

| ID | Requirement | Test (plant) |
|---|---|---|
| **H1** | Shows the **safety code** (6 digits, large, the `123 456` format), the viewer's **device ID**, its **trust status** (pinned / new) and its **name**, labelled "name chosen by the other computer, not checked" | GUI test reads the dialog's text; plant: dialog bound to another session's code → caught |
| **H2** | Accept is **bound to this dialog's session ID and safety code** (A22 at the GUI level). With two dialogs open, Accept on B activates only B; a dialog whose session has ended (viewer left, timed out) closes and **can never accept** anything | Two pending sessions, click B; plant "accept the newest" → caught. Viewer disconnects while the dialog is open → dialog gone, session never `Active` |
| **H3** | **Deny is the default.** Return, Space and Escape deny; no key accepts (§1 Q4) | Send every key event to the dialog; plant: Return bound to Accept → caught |
| **H4** | **Accept is armed after 1 s**, again after any change (a second dialog appearing on top restarts it). **A click counts only if both the press and the release happen after the delay** (owner, Q4): a press that started before the delay ran out can never accept, even if released later | Click at 0.5 s → nothing; press at 0.9 s + release at 1.2 s → nothing; plants: no delay, and checking only the release → both caught |
| **H5** | **No answer in 60 s means deny.** The dialog shows the time left; at 0 it closes and the session ends `Rejected` (`PROMPT_TIMEOUT_MS` = 60 000, `remora-session/src/lib.rs:56`; A24) — the GUI adds no timer of its own that could disagree | Session-level clock test as A24 + GUI test that the dialog closes; plant: GUI ignores the timeout → caught |
| **H6** | **The viewer's name cannot fake the dialog:** control characters, bidi overrides (U+202A–U+202E, U+2066–U+2069) and zero-width characters are shown as visible escapes; length is already ≤ 64 bytes (`DEVICE_NAME_MAX`). The name never appears in the buttons or the title | Names with `\n`, RLO + "Accept", zero-width joiners; plant: raw name → caught |
| **H7** | The dialog **comes to the front** when a prompt arrives (the app activates), so it is not hidden behind other windows; it cannot be minimised while waiting | Manual (M2) |
| **H8** | After **Deny or timeout**, the host shows the new code and password with the F-UX3 note; the viewer says "The host declined. Ask for a new code to try again." (D-21, protocol.md §handshake outcomes) | e2e GUI test both sides; plant: old code still shown → caught |
| **H9** | **One active session** (§1 Q5): while a session is `Active`, a new connection is refused as "host busy" **before the handshake** (owner): it gets no dialog and never reaches the password check, so it is **not a password guess**, does not count toward INV12 and does not consume the one-time password (INV15 untouched). **Each refused attempt is logged on the host** (time, source address — no secrets) and shown in the host window, so repeated tries are visible. How the refusal travels on the wire is checked against protocol.md and the limiter before implementing (not yet read) | e2e: second viewer during a session → refused, no dialog, the password still works afterwards, one log line per attempt; plants: dialog shown, handshake run before refusing, no log line → each caught |
| **H10** | While a session is `Active`, the host window **hides the code and password** (the screen is streamed to the viewer); "Show" reveals them | GUI test; plant: shown while active → caught |
| **H11** | INV1 unchanged: nothing reaches the renderer before Accept (A20 stays; the GUI cannot call anything that skips the state machine — it sends the same `approve(session, sas)` command the CLI sends) | Existing A20–A24 + a check that the GUI module only uses the session API |
| **H12** | The dialog and every host window: **no screen content, password or key in logs** (INV8, INV9); the password is shown, never logged | N-style log scan over a GUI session (as phase4 N1) |

**Threat-model items checked for 4.5:** §7.5 S ("connection from a device
the user didn't expect": device name, ID, trust status, safety code — H1);
T ("input before approval" — H11); I ("session continues unnoticed" — §5);
D (≤ 4 pending handshakes, `MAX_PENDING`: at most 4 dialogs, never more);
residual risk 5 (people click Accept without comparing): the dialog puts the
code first and says "Accept only if the other person reads you the same
code". **Not mitigated in 4.5, stated plainly:** any local program with
Accessibility permission can press Accept through the accessibility API —
that program can already control the whole Mac (outside the threat model's
attacker list; noted in threat-model §9 by this phase).

## 5. Session indicator and "End session" (INV11, closes D-4)

| ID | Requirement | Test |
|---|---|---|
| **I1** | From `Active` until `Closed`, the host shows a **session window**: "<device> is viewing your screen", the time since it started, and **End session**. It has no close or minimise button while a session is active | **Automated GUI test (D-4):** for every session event the indicator is visible exactly while the state is `Active`; plant: hidden after 5 s → caught |
| **I2** | **End session** is one click and reaches `Closed` within **1 s**, the viewer is told (`Goodbye`), capture stops | Automated: click → `Closed` ≤ 1 s; plant: button not wired → caught |
| **I3** | The indicator is visible **whatever else is on screen**: `always-on-top` (Slint sets winit `WindowLevel::AlwaysOnTop`, `winitwindowadapter.rs:1898`), and the menu bar shows that a session is active. **Unverified:** whether an always-on-top window shows over a full-screen app on another Space — winit 0.30.13's macOS extensions have no "all Spaces" setting (`platform/macos.rs`), so if S1 shows it does not, the options come to the owner: accept and document the gap, or one AppKit call (`unsafe`, an unsafe-policy decision) | Manual M3 + S1 |

**How D-4 closes:** I1 and I2 run as Rust tests through Slint's testing
backend. `i-slint-backend-testing` 1.18.1 exists (crates.io; licence
`GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR
LicenseRef-Slint-Software-3.0`, as Slint); **its API for finding and pressing
an element is unverified** — S1 checks it. If it cannot, D-4 stays open and
the owner hears it at the S1 report, not at the end.

## 6. Viewer connect form and session window (D-20, D-21)

| ID | Requirement | Test (plant) |
|---|---|---|
| **V1** | Connection code field: pasted text is length-checked (`CODE_TEXT_MAX` = 1024) **before** parsing, then parsed by the existing parser (fuzz target `connection_code`, no new parser). The host's device ID from the code is shown before connecting | Oversize paste rejected with a message; existing fuzz target unchanged |
| **V2** | Password field: masked, never logged; copied into a zeroizing buffer at **Connect** and the field cleared. **Stated plainly:** Slint keeps its own copy of the text in its own string type, which does not zeroize, and the accessibility tree may hold it too — a residual risk recorded in threat-model §9 (as `spake2`/`snow`, C11) | Log scan (N-style) with a canary password; plant: password in a log line → caught |
| **V3** | After the handshake the form shows the **safety code** and **"Unverified — compare this code with the person at the host"** (D-20); the F-UX4 line "waiting for the person at the host to accept or deny (nothing to type here)" | GUI test reads both; plant: "verified" before confirmation → caught |
| **V4** | **"The codes match"** marks the host verified **for this session** (§1 Q6); **"They don't match"** ends the session and says why. Verified is never set by the short code matching (protocol.md "Device ID") | GUI test; plant: verified set on connect → caught |
| **V5** | Deny / timeout: "The host declined. Ask for a new code to try again." (D-21) | e2e with H8 |
| **V6** | Session window: host device, verified/unverified, **Disconnect** (one click, `Goodbye`), and the D-33 countdown "Display unavailable — N s left" from `StreamState` reason 4 + `remaining_ms` (protocol.md §5), counting down locally between updates and replaced by "resumed" or the end reason | GUI test feeding `StreamState`; plant: countdown not shown → caught |

## 7. D-35: stop drawing while the video window is not visible

| ID | Requirement | Test |
|---|---|---|
| **O1** | On `WindowEvent::Occluded(true)` (sent on macOS from the window's occlusion state, winit `window_delegate.rs:352`) the viewer **keeps decoding** (the H.264 reference chain must stay intact) but **skips upload and draw**; on `Occluded(false)` the next decoded picture is drawn at once | Unit/offscreen test: occluded → 0 draws while frames still decode; plant: still drawing → caught |
| **O2** | Same three cases as the D-35 find (full-screen terminal, minimised, full-screen Safari): drawn fps ≈ 0 while covered; after uncovering, the picture is current (P7 barcode increases, no stale frame) | Manual, `results/phase4.5/o2-*` |

## 8. Remote input must never reach Remora's own controls (note for Phase 6)

Phase 6 adds remote mouse and keyboard. From then on the viewer could click
**Accept** on a second viewer's dialog, **Show** on the hidden password, or
anything else in a Remora window that is visible in the stream. 4.5 removes
part of it now (one active session: no dialog appears during a session, H9;
password hidden, H10), but the rule belongs to Phase 6 and is recorded as
**roadmap D-38 (BLOCKER, Phase 6)**: injected events never reach a Remora
window, with an attack test that injects clicks on every Remora control's
coordinates and keys while a Remora window has focus, and expects no effect.
The mechanism is Phase 6's design (for example: drop injected events whose
target is a Remora window, which the host knows in-process); none is verified
yet.

## 9. Performance: P1, P2, P3 must not get worse

Same conditions as phase4-criteria §2 (AC power, Low Power Mode off, release
build, 3 × 60 s motion runs, worst run counts), with the GUI **in place**:
session accepted through the host dialog, host session window visible,
viewer session window open, video window in front.

| ID | PASS if | Phase 4 value (18:12 set) |
|---|---|---|
| **P1** | gate unchanged: p95 < 20 ms; **and** worst-run p95 ≤ Phase 4 + 1 ms | 14.53 → ≤ 15.53 ms |
| **P2** | gate unchanged: p95 ≤ 11.9 ms; **and** worst-run p95 ≤ Phase 4 + 1 ms | 4.54 → ≤ 5.54 ms |
| **P3** | unchanged: ≥ 98 % drawn, 0 decode/AEAD/reassembly failures, source ≥ 55 fps | 100 % |
| P5 | §3 | 149 MB |
| P6 | unchanged: host CPU < 2 % of one core, static screen, **host GUI open** | 0.88 % |
| C2 | reported against 7.06 ms (owner rule above the deferred table) | 7.06 ms |

The "+ 1 ms" is the owner's rule that a benchmark more than ~1 ms from the
previous one is flagged, never averaged away (D-25). **If P1 or P2 is over
it:** let the Mac cool and rerun (the D-10 rule); if the cooled rerun is
still over, stop and report — it is a regression to explain even though the
20 ms gate passes. Also reported: the "decoded → drawn" stage (Phase 4:
2.08–2.42 ms p95), since that is where C′ changes the path (§2).

## 10. Security tests, policy and dependencies

* Every H/I/V/O row with "plant" is seen failing once, then the plant is
  removed (CLAUDE.md).
* **Mutation gate:** the GUI's decision code (dialog state, key handling,
  arming delay, name escaping, indicator state) lives in a plain Rust module
  without Slint types, added to `.cargo/mutants.toml`; **0 missed**.
* **No new parser** except the name escaping (H6), which gets a fuzz target
  (it handles untrusted text).
* No `unsafe` (§2). `unwrap`/`expect` rules unchanged.
* **Dependencies:** `slint` 1.18.1 is in `[workspace.dependencies]` already
  but no crate uses it yet. Adding it: ≥ 14 days old (it is: verify the date
  with `cargo info` when adding), `cargo deny` licence exception for the GPL
  option, **per crate** (deny.toml's comment requires it), only for
  `remora-host` and `remora-viewer`; `docs/dependencies.md` updated with
  every new transitive crate; the Slint `GPL-3.0-only` option combined with
  our `GPL-3.0-or-later` apps is recorded in architecture.md (the existing
  note says "GPL-3.0").
* **Threat model** updated in the same commits: §7.5 rows for H1–H12, the
  residual risks in §4 and V2.

## 11. Deferred rows due in 4.5, and how each closes

| Row | Closes when | Evidence |
|---|---|---|
| **D-4** (BLOCKER) INV11 GUI test | I1 and I2 run automatically in CI | test names, plants caught |
| **D-17** (BLOCKER) Slint + video window | Option C′ works in S1 and in the real viewer, no `unsafe`; option A stays a Phase 7 design question (row text updated, not closed, if the owner prefers to keep A open) | S1 report, §2 |
| **D-20** (BLOCKER) unverified mark | V3, V4 | GUI tests |
| **D-21** (BLOCKER) denied → fresh code | H8, V5 + F-UX3 note in the GUI | e2e GUI test |
| **D-33** (GUI part of D-29) countdown | V6 (viewer) + host session window shows the same | GUI test + manual M5 |
| **D-35** (nice-to-have) covered window | O1, O2 | test + `o2-*` |
| **D-36** (BLOCKER) dev identity | recreated at the start of 4.5's first capture step, removed at the **end of the phase** (§1 Q7), with the D-9 checks. At the recreate, the Q7 check: can `codesign` be made to ask for confirmation instead of the silent access `dev-identity.sh` grants today (`security import … -T /usr/bin/codesign`)? Done if straightforward on macOS 27, otherwise skipped with the reason | as D-9 |
| **D-26** (the phase itself) | this document's rows pass | the phase report |
| D-30 | not in 4.5 → Phase 7 (§1 Q1) | row moved 2026-10-25 |

## 11b. Known limitations (recorded with the owner's approval, 2026-10-25)

* **The password stays in Slint's memory.** Slint keeps its own copy of the
  typed text in its own string type, which does not zeroize, and the
  accessibility tree may hold it too (V2). Our copy is zeroized; Slint's is
  not, until the process exits.
* **Apps with Accessibility permission can press Accept** through the
  accessibility API. Such an app can already control the whole Mac; it is
  outside the threat model's attacker list (§4).
* **The indicator over a full-screen app on another Space is unverified**
  (I3): winit 0.30.13 has no "all Spaces" setting. If S1 shows it is hidden
  there, the AppKit call needs `unsafe` and comes to the owner as exact code
  (§1); until then this is a limitation.
* **Keyboard-only users cannot accept** (Q4): Accept is not in the keyboard
  focus chain, so Full Keyboard Access without VoiceOver cannot reach it.
  Deny stays reachable by keyboard.

## 12. Housekeeping (owner, 2026-10-25)

* **On or after 2026-10-27, the first task is removing the tokio line** from
  `.cargo/crate-age-exceptions.txt` (tokio 1.53.3 is then 14 days old), before
  CI fails on it. Roadmap **D-37**.
* **D-13** (is v0.1 public?) and the **Dependabot PRs #7–#12** wait until
  before v0.1. Roadmap D-13 (decision due before the v0.1 gate) and **D-39**.

## 13. Build order

1. Owner approves this document (gate G-3: MET 2026-10-25). Merge PR #6
   with a merge commit once CI on its last commit is green (§1 Q9).
2. On/after 2026-10-27: D-37 (tokio line) first.
3. D-36 recreate (per phase) when the first step needs capture — S1 needs
   none, so it comes first. The recreate needs the owner at the Mac (the
   Screen Recording grant): the owner is told before.
4. **Spike S1** (§3) → report to the owner: memory per configuration, C′,
   testing backend, `Occluded`, always-on-top. **Stop for the owner's answer
   if anything fails** (P5 fit, C′, D-4 automation). If P5 does not fit:
   D-34's Instruments investigation, time-boxed (3 h), then measure again;
   still no fit → the owner decides (§1 Q3).
5. Decision module (no Slint) test-first: H2–H6, H9, H10, I1, I2, V4 logic,
   plants, mutants.
6. Host GUI (dialog, main window, session window), then viewer GUI (form,
   session window, C′ video window), then O1.
7. Final runs (§9), manual steps (M1–M6), D-36 remove, report (§13 of the
   final document), deferred list row by row.

Manual steps, written in full in the report: M1 accept through the GUI with
codes compared; M2 dialog comes to the front over another app; M3 indicator
over a full-screen app; M4 deny and retry with the fresh code; M5 display
unavailable countdown on both sides (virtual display, as T3); M6 launch both
sides from Finder, no terminal.

## 14. Changes to criteria

| Date | Change | Owner's words / reason |
|---|---|---|
| 2026-10-25 | Approved with the answers in §1: H4 press **and** release after the delay; H9 refuse before the handshake and log every refused attempt; Q3's time-boxed D-34 step, the limit decision staying with the owner; D-36 per phase plus the `codesign` confirmation check; §11b known limitations | "G-3: approved with these answers. Update the criteria and push." |
