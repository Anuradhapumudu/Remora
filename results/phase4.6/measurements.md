# Phase 4.6 measurements (owner's Fedora 44 laptop host, Mac viewer, Wi-Fi LAN)

Times and sizes only; no screen content was recorded (INV9).

## Session 2026-11-02 ~15:30 (host `--timing`, 8 Mbit/s, QP 10-36)

Host (`timing.log`, 7273 encoded pictures; owner scrolling pages and
playing a video): capture to encoded p50 **26.1 ms**, p95 **34.2 ms**,
max 160.9 ms (LP1 target p95 <= 20 ms: **not met**). Picture size p50
7059 B, p95 36903 B, max 641075 B. 92 keyframes (p50 68660 B), almost all
requested by the viewer after a loss.

Viewer (stats lines pasted by the owner): 20-40 fps while the screen moves
(LP2 >= 30: met while busy; GNOME sends no pictures for a still screen);
decode p50 ~2 ms, upload+draw p50 ~2 ms; dropped 137, "waiting for a
keyframe" 479 pictures over the session (LP4: **not met**; this is the
stale/dark band the owner saw while scrolling).

## INV11 / L6 (GNOME's indicator), same day

- Clicking the orange top-bar indicator ends the session at once:
  `capture stopped - active sessions end`, `session ended 1
  (CaptureStopped)` (after commit 0ae615c; before it, the session ended
  only on the next input event).
- **Finding:** in a full-screen app (YouTube full screen) GNOME hides the
  top bar, so the indicator is not visible (owner, 2026-11-02). Same class
  as the macOS I3 finding. Recorded for the phase report.

## bench-encoder, 30 s, YouTube in theatre mode (CPU shared with playback)

| setting | pictures | encode p50 / p95 ms | bytes p50 / p95 / max | Mbit/s at 30 fps |
|---|---|---|---|---|
| 8M QP 10-36 (was the default) | 450 | 11.0 / 40.6 | 15492 / 32606 / 135529 | 4.0 |
| 120k QP 0-51 (spike) | 450 | 6.7 / 24.1 | 2532 / 18549 / 42863 | 1.1 |
| 4M QP 20-34 (**new default**) | 450 | 9.1 / 35.7 | 7530 / 23500 / 82887 | 2.2 |
| 8M QP 18-30 | 450 | 10.4 / 37.0 | 12991 / 37276 / 110655 | 3.7 |
| 2M QP 22-36 | 450 | 7.8 / 35.1 | 3366 / 18662 / 46986 | 1.3 |

No software setting meets LP1 on this content while the laptop also plays
the video. 4M QP 20-34 halves picture sizes (less Wi-Fi loss) and keeps
text at QP <= 34; whether it is sharp enough is the owner's judgement.
