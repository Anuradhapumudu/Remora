# Phase 4 — next Mac session (run-sheet)

Written 2026-10-23, after CI on `0cf31db` was green. About 35 minutes. Every
step writes `results/phase4/<step>-<HHMM>.txt`, adds its PASS / FAIL / INVALID
lines to `summary.md` and keeps logs in `logs/`. Run everything from
`~/Documents/github/Remora` (this checkout already has `p5 --covered`).

## 1. Setup (3 min)

- [ ] Charger in
- [ ] Low Power Mode **off** (System Settings → Battery)
- [ ] Do Not Disturb **on** (Control Center → Focus)
- [ ] Quit everything except Terminal (and Safari for steps 3–4); close every
      Safari tab except the moving page (video tabs keep the display awake)
- [ ] No external monitor plugged in
- [ ] `scripts/macos/phase4-session.py check` → `-> PASS`
- [ ] **G-2 is the opposite of last session:** the runner must **not** keep the
      Mac awake. `--mac-sleeps` does that itself (`caffeinate -di` instead of
      `-dims`); don't start any other keep-awake tool.

## 2. G-2: lid close with the Mac asleep (3 min) — first

- [ ] `scripts/macos/phase4-session.py t3-lid --mac-sleeps`
- [ ] At `>>> CLOSE THE LID NOW <<<`: close the lid, wait about 30 s, open it,
      log in if asked. Hands off until `T3 lid, Mac sleeps: … ->` appears.

**Expected result** (phase4-criteria §11c, verbatim):

> 1. **Lid closed:** within about 1 s the host prints `capture paused
>    (DisplayAsleep)` and the viewer `stream paused (the host's display is
>    asleep)`. If the built-in display leaves the display list before the
>    Mac is fully asleep, an `unavailable … 120 s left` line may follow;
>    whether it does is recorded, not predicted. Then the Mac sleeps.
> 2. **After 30–35 s:** **nothing.** The viewer is on the same sleeping Mac,
>    so it is asleep too, and its idle clock is not running: no `failed:
>    connection lost` line. D37's "the viewer reports connection lost after
>    30–35 s" needs the viewer on **another machine**, which this run
>    cannot show; that case is described below for Phase 5.
> 3. **Lid opened:** no reconnect happens and none is needed. The same QUIC
>    connection simply continues, because no timeout ran during sleep.
>    Remora has no automatic reconnect at all. Capture's restart loop finds
>    the display listed: the host prints `capture resumed` **≤ 2 s after the
>    power log's `Display is turned on`**, the first frame after it is a
>    **keyframe**, and the viewer prints `stream resumed` in the **same
>    session**. If a countdown had started in step 1, it continues from
>    about where it stood, not 30 s lower.
>
> **PASS if:** the Mac really slept (power log), the session is the same one
> afterwards, `capture resumed` ≤ 2 s after the display came on (+1 s for
> the power log's whole-second times), keyframe first, and no `connection
> lost`. A session that ends on wake is a FAIL against this expectation and
> is reported with its logs.

Record:
- [ ] Power log line printed by the runner: `Entering Sleep state …
      'Clamshell Sleep'` (if it says only DarkWake → INVALID, the Mac did not
      sleep; find what kept it awake and rerun)
- [ ] `viewer showed:` line — matches steps 1–3 above? Did an `unavailable …
      120 s left` line appear (step 1 records it either way)?
- [ ] Matched §11c: yes / no. If no: which step (1, 2 or 3), and the exact
      line that differed

## 3. P1 ×3 with the fix (5 min)

- [ ] `open -a Safari scripts/macos/motion-pattern.html`, Option-click the
      green button (fills the screen, not full screen)
- [ ] `scripts/macos/phase4-session.py p1`
- [ ] Each run: drag the viewer window to the **bottom-right corner**, click it
      once, hands off
- [ ] Compare with 02:16: P1 p95 ≤ 14.00 ms, P2 ≤ 4.65 ms, P3 100 %
      (limits: P1 < 20 ms, P2 ≤ 11.9 ms, P3 ≥ 98 % of captured, source ≥ 55 fps)

## 4. P5 window in front (11 min)

- [ ] Safari still showing the moving page
- [ ] `scripts/macos/phase4-session.py p5`
- [ ] Drag the viewer window to the bottom-right corner, click it, hands off
- [ ] Compare with last session's 147–148 MB (limit < 150 MB, growth ≤ 2 MB,
      slope ≤ 0.1 MB/min)

## 5. P5 window covered — the leak guard (11 min)

- [ ] `osascript -e 'quit app "Safari"'`
- [ ] `scripts/macos/phase4-session.py p5 --covered` (synthetic picture: with
      the window covered nothing on screen moves, so the real screen would
      send almost no frames)
- [ ] When the viewer window opens: click Terminal, Option-click Terminal's
      green button so it covers the whole screen, hands off
- [ ] Must stay **flat near 89 MB**, never climbing (before the fix: 2.4 GB in
      15 s). INVALID if the window was not really covered (`covered check`
      line: more than 5 % of stats lines drew frames)

## 6. Still open after this session

Before the report: nothing else measured — then the phase report (deferred
list row by row) and D-9. Later phases: the two-machine lid case (Phase 5);
what holds the viewer's 94 MB of GPU memory (needs Instruments); decoded →
drawn's copy (D-17 options, Phase 7).
