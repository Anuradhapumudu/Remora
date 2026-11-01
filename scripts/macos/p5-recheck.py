#!/usr/bin/env python3
"""P5 re-check (Phase 4.5, owner 2026-10-26): viewer memory with the decoded
pictures counted.

phase4-criteria (step 5, line 697) required P5 to count IOSurfaces as M7
does; the P5 runner (phase4-session.py) counted `footprint` only. This
script measures the same session as P5 (host + viewer on loopback, viewer
window 960 x 624 in front, 1920-wide picture, 60 fps, 10 min, every 10 s)
and records, side by side:

  footprint   phys_footprint (what P5 counted), every 10 s
  IOSurface   vmmap --summary's IOSurface row: virtual, resident, dirty,
              once a minute (vmmap pauses the viewer: W4)
  counted     C(t) = footprint(t) + (IOSurface virtual - dirty) of the last
              vmmap at or before t (phase4-criteria §14, owner 2026-10-27)

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
2026-11-01 this script ran vmmap every 10 s (p5-recheck-20261026-2144.txt).

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
VMMAP_EVERY = 6  # samples (10 s each): vmmap once a minute
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
    say("viewer memory, synthetic picture 1920 wide, window in front, footprint every 10 s, vmmap every minute")
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "remora-host", "-p", "remora-viewer"],
                   cwd=ROOT, check=True)
    run = measuring.Run(say, pauses_allowed=int(a.minutes * 60 / 10 / VMMAP_EVERY) + 1)
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
    say(f"  {'min':>5}  {'footprint':>9}  {'IOS virt':>8}  {'IOS res':>7}  {'IOS dirty':>9}  {'counted':>8}  (MB)")
    start, samples, vmmap_times, ios, n_sample = time.time(), [], [], None, 0
    while time.time() - start < a.minutes * 60:
        run.wait(10)
        n_sample += 1
        f = p4.footprint_mb(run, viewer.pid)  # footprint first, then vmmap (M7 ordering)
        if n_sample % VMMAP_EVERY == 1:  # the first sample, then once a minute
            vmmap_times.append(time.time())
            ios = iosurface_mb(run, viewer.pid)
        if f is None or ios is None:
            continue
        v, r, d = ios
        m = (time.time() - start) / 60
        c = f + (v - d)
        samples.append((m, f, v, r, d, c))
        say(f"  {m:5.2f}  {f:9.1f}  {v:8.1f}  {r:7.1f}  {d:9.1f}  {c:8.1f}"
            + ("" if n_sample % VMMAP_EVERY == 1 else "  (IOSurface from the last vmmap)"))
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
    say(f"frames dropped within 3 s after the {len(vmmap_times)} vmmap calls: "
        f"{dropped_after(timed, vmmap_times)}")
    valid = run.finish([("the window drew", drew, f"{len(late) - len(idle)} of {len(late)} stats lines")])
    for name, col in (("footprint only (as P5 counted)", 1), ("footprint + IOSurfaces not in it", 5)):
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
