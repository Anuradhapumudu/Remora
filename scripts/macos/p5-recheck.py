#!/usr/bin/env python3
"""P5 re-check (Phase 4.5, owner 2026-10-26): viewer memory with the decoded
pictures counted.

phase4-criteria (step 5, line 697) required P5 to count IOSurfaces as M7
does; the P5 runner (phase4-session.py) counted `footprint` only. This
script measures the same session as P5 (host + viewer on loopback, viewer
window 960 x 624 in front, 1920-wide picture, 60 fps, 10 min, every 10 s)
and records, side by side:

  footprint   phys_footprint (what P5 counted), every 10 s
  held        the viewer's own count of decoded pictures and their bytes,
              from its stats line ("pictures held N (X MB)", §3b)
  counted     C(t) = footprint(t) + held(t)
  IOSurface   vmmap --summary's IOSurface row, ONCE, at mid-run: vmmap
              pauses the viewer (W4), so it only checks that the viewer's
              own count agrees (virtual - dirty within one picture of held)

Why that sum (spikes/gui-memory/src/bin/iosurface-plant.rs, M4, 2026-10-26):
IOSurfaces this process creates are in its footprint AND in vmmap's row
with dirty = virtual (plant A: +95.1 MB in both), so adding them would count
them twice; pictures decoded by VideoToolbox are in vmmap's row with
dirty = 0 and NOT in the footprint (plant C: footprint +0.5 MB, IOSurface
+96.2 MB). The sum adds only the part the footprint misses.

Differences from P5: the host's synthetic picture instead of the screen
(no Screen Recording, so no dev identity: roadmap D-36), and the host runs
from this terminal instead of RemoraDev.app. Results go to
results/phase4.5/, never to the accepted results/phase4/.

Machine state, keeping the Mac awake, AC power, sleep and display checks and
the count of vmmap calls come from the shared helper (measuring.py, R9). Until
2026-11-01 this script ran vmmap every 10 s (p5-recheck-20261026-2144.txt);
the viewer's self-count replaced it the same day (phase4.5-criteria §3b,
owner: "do anything and build the app").

  scripts/macos/p5-recheck.py [--minutes 10]
"""
import argparse
import datetime
import importlib.util
import os
import re
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import measuring  # noqa: E402  (the shared measuring helper, R9)

spec = importlib.util.spec_from_file_location("p4", os.path.join(HERE, "phase4-session.py"))
p4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p4)

ROOT = p4.ROOT
OUT = os.path.join(ROOT, "results", "phase4.5")
HOST = os.path.join(ROOT, "target", "release", "remora-host")
HELD = re.compile(r"pictures held (\d+) \(([\d.]+) MB\)")
STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M")


class DirectHost(p4.Lines):
    """remora-host from this terminal (the synthetic source needs no permission)."""

    def __init__(self, args):
        super().__init__()
        self.p = subprocess.Popen([HOST, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.pid = self.p.pid
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            self.add(line)

    def send(self, text):
        self.p.stdin.write(text + "\n")
        self.p.stdin.flush()

    def quit(self):
        try:
            self.send("quit")
            self.p.stdin.close()
        except BrokenPipeError:
            pass
        self.p.wait(timeout=30)


def iosurface_mb(run, pid):
    """vmmap --summary's IOSurface row: (virtual, resident, dirty) MB; zeros if none."""
    out = run.instrument(["vmmap", "--summary", str(pid)])
    for line in out.splitlines():
        if line.startswith("IOSurface "):
            cols = line.split()[1:4]
            return tuple(to_mb(c) for c in cols)
    return (0.0, 0.0, 0.0)


def to_mb(v):
    unit = {"K": 1 / 1024, "M": 1.0, "G": 1024.0}.get(v[-1])
    return float(v[:-1]) * unit if unit else float(v) / 1048576


def held_at(timed, t):
    """The viewer's self-count, (pictures, MB), from its last stats line at
    or before `t`; None if it printed none yet."""
    seen = [m for s, l in timed if s <= t and (m := HELD.search(l))]
    return (int(seen[-1].group(1)), float(seen[-1].group(2))) if seen else None


def agree(u_mb, held, picture_mb):
    """vmmap's IOSurfaces not in the footprint (virtual - dirty) and the
    viewer's own count agree within one picture."""
    return abs(u_mb - held[1]) <= picture_mb


def dropped_after(stats, times, secs=3):
    """Increase of the viewer's running "dropped N" count within `secs` after
    each time in `times`: the frames lost while vmmap paused the viewer."""
    def dropped_at(t):
        seen = [int(m.group(1)) for s, l in stats if s <= t and (m := re.search(r"dropped (\d+)", l))]
        return seen[-1] if seen else 0
    return sum(dropped_at(t + secs) - dropped_at(t) for t in times)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=10)
    a = ap.parse_args()
    measuring.keep_awake()  # display, idle and system awake, as P5
    os.makedirs(os.path.join(OUT, "logs"), exist_ok=True)
    lines = []

    def say(t=""):
        print(t, flush=True)
        lines.append(t)

    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                            cwd=ROOT).stdout.strip()
    say(f"P5 re-check, {datetime.datetime.now().isoformat(timespec='seconds')}, commit {commit}")
    say("viewer memory, synthetic picture 1920 wide, window in front, footprint and the viewer's"
        " own picture count every 10 s, vmmap once")
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "remora-host", "-p", "remora-viewer"],
                   cwd=ROOT, check=True)
    run = measuring.Run(say, pauses_allowed=1)
    run.start()
    host = DirectHost(["serve", "--source", "synthetic", "--width", "1920"])
    code = host.expect("code:")[2].split(": ", 1)[1]
    password = host.expect("password:")[2].split(": ", 1)[1]
    viewer = p4.Viewer(["connect", code, "--password", password])
    n = host.expect("prompt ")[2].split(":")[0].split()[1]
    host.send(f"accept {n}")
    viewer.expect("SESSION ACTIVE")
    print("   the viewer window is open: leave the Mac alone, pointer in the middle of the screen",
          flush=True)
    say(f"  {'min':>5}  {'footprint':>9}  {'held':>4}  {'held MB':>7}  {'counted':>8}  (MB)")
    start, samples, n_sample, check = time.time(), [], 0, None
    mid = max(1, round(a.minutes * 6 / 2))  # the one vmmap, at mid-run
    while time.time() - start < a.minutes * 60:
        run.wait(10)
        n_sample += 1
        now = time.time()
        f = p4.footprint_mb(run, viewer.pid)
        held = held_at([(s, l) for s, l in viewer.snapshot() if l.startswith("stats: ")], now)
        if n_sample == mid:
            check = (time.time(), iosurface_mb(run, viewer.pid), held)
        if f is None or held is None:
            continue
        m = (now - start) / 60
        samples.append((m, f, held[0], held[1], f + held[1]))
        say(f"  {m:5.2f}  {f:9.1f}  {held[0]:4d}  {held[1]:7.1f}  {f + held[1]:8.1f}")
    host.send(f"disconnect {n}")
    counters = viewer.expect("video:", secs=30)[2]
    viewer.p.wait(timeout=30)
    host.quit()
    say(counters)
    timed = [(s, l) for s, l in viewer.snapshot() if l.startswith("stats: ")]
    stats = [l for _, l in timed]
    late = [l for l in stats[60:]]
    idle = [l for l in late if l.startswith("stats: 0 fps")]
    drew = bool(late) and len(idle) <= 0.05 * len(late)
    say(f"drawing check: {len(late) - len(idle)} of {len(late)} stats lines after minute 1 drew frames")
    checks = [("the window drew", drew, f"{len(late) - len(idle)} of {len(late)} stats lines")]
    if check is None or check[2] is None:
        checks.append(("self-count checked against vmmap", False, "no vmmap sample with a self-count"))
    else:
        at, (v, r, d), held = check
        per = max((s[3] / s[2] for s in samples if s[2]), default=0.0)
        ok = agree(v - d, held, per)
        say(f"self-count check (vmmap once, minute {(at - start) / 60:.1f}): IOSurface virtual {v:.1f}"
            f" resident {r:.1f} dirty {d:.1f} -> not in footprint {v - d:.1f} MB; viewer holds"
            f" {held[0]} pictures, {held[1]:.1f} MB; one picture {per:.1f} MB ->"
            f" {'agree' if ok else 'DISAGREE'}")
        say(f"frames dropped within 3 s after the vmmap call: {dropped_after(timed, [at])}")
        checks.append(("self-count agrees with vmmap", ok,
                       f"{v - d:.1f} MB (vmmap) vs {held[1]:.1f} MB (viewer), tolerance {per:.1f} MB"))
    valid = run.finish(checks)
    for name, col in (("footprint only (as P5 counted)", 1), ("footprint + pictures held (self-count)", 4)):
        after1 = [(s[0], s[col]) for s in samples if s[0] >= 1]
        peak = max(s[col] for s in samples)
        growth = after1[-1][1] - after1[0][1] if after1 else float("nan")
        say(f"==> {name}: peak {peak:.1f} MB (limit < {p4.P5_MAX_MB}), growth min 1 -> end {growth:+.2f} MB, "
            f"slope {p4.slope(after1):+.3f} MB/min -> {'under' if peak < p4.P5_MAX_MB else 'OVER'} the limit"
            + ("" if valid else " [run INVALID: not counted]"))
    path = os.path.join(OUT, f"p5-recheck-{STAMP}.txt")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    for name, proc in (("host", host), ("viewer", viewer)):
        with open(os.path.join(OUT, "logs", f"{STAMP}-p5-recheck-{name}.log"), "w") as fh:
            for _, l in proc.snapshot():
                fh.write("[redacted]\n" if p4.SECRET.match(l) else l + "\n")
    print(f"(written: {os.path.relpath(path, ROOT)})")


if __name__ == "__main__":
    main()
