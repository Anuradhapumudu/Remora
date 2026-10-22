#!/usr/bin/env python3
"""Phase 4 step 7d: the owner's measuring session on the M4 (phase4-criteria §4, §7).

One command per step. Every run writes its numbers to results/phase4/<step>.txt,
appends one line per verdict to results/phase4/summary.md, and keeps the raw
logs in results/phase4/logs/ (one-time codes and passwords are removed before
anything is written). The Mac is kept awake (caffeinate) while a step runs.

  scripts/macos/phase4-session.py check      # preflight: power, build, permission
  scripts/macos/phase4-session.py p1         # P1-P4: 3 x (10 s warm-up + 60 s), motion page
  scripts/macos/phase4-session.py p5         # P5: viewer memory, 10 min, motion page
  scripts/macos/phase4-session.py p6         # P6: host CPU, still screen, 60 s
  scripts/macos/phase4-session.py p8         # P8: Phase 2 bench-capture, 3 x 60 s, motion page
  scripts/macos/phase4-session.py m7         # M7: decoder memory limit on this real Mac
  scripts/macos/phase4-session.py t2         # T2: display sleep / wake, 5 cycles (display goes off)
  scripts/macos/phase4-session.py t3-lid     # T3: YOU close the lid, wait ~30 s, open it
  scripts/macos/phase4-session.py p1 --source synthetic --seconds 5 --runs 1   # tooling check

The host runs through RemoraDev.app (scripts/macos/dev-app.sh), which holds
the Screen Recording permission; its input goes through a named pipe and its
output through a log file that is read as it grows. The viewer runs from this
terminal. Both talk over loopback, so P1 includes no network.
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RESULTS = os.path.join(ROOT, "results", "phase4")
LOGS = os.path.join(RESULTS, "logs")
APP = os.path.join(ROOT, "target", "dev", "RemoraDev.app")
VIEWER = os.path.join(ROOT, "target", "release", "remora-viewer")
DEV_APP = os.path.join(ROOT, "scripts", "macos", "dev-app.sh")
HOST_PROC = "RemoraDev.app/Contents/MacOS/remora-host"

# Thresholds: docs/phase4-criteria.md §4 and §7 (change them only there, by a §12 entry).
P1_P95_MS = 20.0
P2_P95_MS = 11.9
P3_MIN_DRAWN = 3528  # of 3600 in 60 s (98 %)
P5_MAX_MB, P5_GROWTH_MB, P5_SLOPE_MB_MIN = 150.0, 2.0, 0.1
P6_MAX_PCT = 2.0
P8_C12_P95_MS = 11.0
T2_PAUSE_S, T2_RESUME_S, T2_GROWTH_MB = 1.0, 2.0, 2.0
T3_RESUME_S = 2.0
MOTION_MIN_FPS = 55  # a motion run below this did not have the motion page on screen

SECRET = re.compile(r"^(code|password): ")


# ------------------------------------------------------------------ output --

class Report:
    """Collects one step's text; writes results/phase4/<step>.txt and summary.md."""

    def __init__(self, step):
        self.step, self.lines = step, []
        os.makedirs(LOGS, exist_ok=True)

    def say(self, text=""):
        print(text, flush=True)
        self.lines.append(text)

    def verdict(self, what, ok, detail, valid=True):
        word = "PASS" if ok else "FAIL"
        if not valid:
            word = "INVALID (not counted)"
        line = f"{what}: {detail} -> {word}"
        self.say(f"==> {line}")
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        with open(os.path.join(RESULTS, "summary.md"), "a") as fh:
            fh.write(f"- {stamp} {line}\n")
        return ok and valid

    def save(self):
        with open(os.path.join(RESULTS, f"{self.step}.txt"), "w") as fh:
            fh.write("\n".join(self.lines) + "\n")
        print(f"(written: results/phase4/{self.step}.txt, summary.md, logs/)")


def write_log(name, lines):
    """A process's output for the record, without one-time codes or passwords."""
    with open(os.path.join(LOGS, name), "w") as fh:
        for _, line in lines:
            fh.write("[redacted]\n" if SECRET.match(line) else line + "\n")


# --------------------------------------------------------------- processes --

class Lines:
    """Timestamped output lines of a child, with waiting for a prefix."""

    def __init__(self):
        self.lines, self.cond = [], threading.Condition()

    def add(self, line):
        with self.cond:
            self.lines.append((time.time(), line.rstrip("\n")))
            self.cond.notify_all()

    def expect(self, prefix, secs=30, after=0):
        """The first line starting with `prefix` at index >= after: (index, time, line)."""
        deadline = time.time() + secs
        with self.cond:
            while True:
                for i in range(after, len(self.lines)):
                    if self.lines[i][1].startswith(prefix):
                        return i, self.lines[i][0], self.lines[i][1]
                left = deadline - time.time()
                if left <= 0:
                    tail = "\n".join(l for _, l in self.lines[-15:] if not SECRET.match(l))
                    sys.exit(f"no line starting with {prefix!r} within {secs} s; last lines:\n{tail}")
                self.cond.wait(left)

    def snapshot(self):
        with self.cond:
            return list(self.lines)


class Host(Lines):
    """remora-host through RemoraDev.app: stdin from a pipe, output tailed from a file."""

    def __init__(self, args):
        super().__init__()
        self.dir = tempfile.mkdtemp(prefix="remora-p4-")
        fifo, self.log = os.path.join(self.dir, "in"), os.path.join(self.dir, "out")
        os.mkfifo(fifo, 0o600)
        open(self.log, "w").close()
        before = set(pids(HOST_PROC))
        self.opener = subprocess.Popen(
            ["open", "-W", "-n", "-g", "--stdin", fifo, "--stdout", self.log,
             "--stderr", self.log, APP, "--args", *args])
        self.stdin = open(fifo, "w")  # blocks until the app opens its end
        self.pid = None
        for _ in range(100):
            new = set(pids(HOST_PROC)) - before
            if new:
                self.pid = max(new)
                break
            time.sleep(0.05)
        self.done = False
        threading.Thread(target=self._tail, daemon=True).start()

    def _tail(self):
        with open(self.log) as fh:
            buf = ""
            while True:
                chunk = fh.read()
                if chunk:
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        self.add(line)
                elif self.done:
                    return
                else:
                    time.sleep(0.01)

    def send(self, text):
        self.stdin.write(text + "\n")
        self.stdin.flush()

    def quit(self):
        try:
            self.send("quit")
            self.stdin.close()
        except BrokenPipeError:
            pass
        self.opener.wait(timeout=30)
        time.sleep(0.3)
        self.done = True


class Viewer(Lines):
    """remora-viewer from this terminal."""

    def __init__(self, args):
        super().__init__()
        self.p = subprocess.Popen([VIEWER, *args], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, bufsize=1)
        self.pid = self.p.pid
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            self.add(line)


def pids(pattern):
    r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
    return [int(x) for x in r.stdout.split()]


def footprint_mb(pid):
    """phys_footprint (Activity Monitor's "Memory") of `pid`, in MB."""
    r = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True)
    m = re.search(r"Footprint: ([\d.]+) (KB|MB|GB)", r.stdout)
    if not m:
        return None
    scale = {"KB": 1 / 1024, "MB": 1, "GB": 1024}[m.group(2)]
    return float(m.group(1)) * scale


def cpu_seconds(pid_list):
    """Total CPU time (user + system) of these processes, in seconds."""
    total = 0.0
    for pid in pid_list:
        r = subprocess.run(["ps", "-o", "cputime=", "-p", str(pid)], capture_output=True, text=True)
        t = r.stdout.strip()
        if not t:
            continue
        parts = [float(x) for x in t.split(":")]
        while len(parts) < 3:
            parts.insert(0, 0.0)
        total += parts[0] * 3600 + parts[1] * 60 + parts[2]
    return total


def build():
    print("building (release) ...", flush=True)
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "remora-host",
                    "-p", "remora-viewer"], cwd=ROOT, check=True)
    subprocess.run([DEV_APP, "build"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def start_session(source, window=True, timing=False, width=1920):
    """Host + viewer, accepted. Returns (host, viewer)."""
    hargs = ["serve", "--source", source, "--width", str(width)]
    if timing:
        hargs.append("--timing")
    host = Host(hargs)
    code = host.expect("code:")[2].split(": ", 1)[1]
    password = host.expect("password:")[2].split(": ", 1)[1]
    vargs = ["connect", code, "--password", password]
    if timing:
        vargs.append("--timing")
    if not window:
        vargs.append("--no-window")
    viewer = Viewer(vargs)
    prompt = host.expect("prompt ")[2]
    n = prompt.split(":")[0].split()[1]
    host.send(f"accept {n}")
    viewer.active_t = viewer.expect("SESSION ACTIVE")[1]
    return host, viewer, n


def end_session(host, viewer, n):
    host.send(f"disconnect {n}")
    counters = viewer.expect("video:", secs=30)[2]
    viewer.p.wait(timeout=30)
    host.quit()
    return counters


def wait(secs, why=""):
    if why:
        print(f"   ... {why} ({secs:.0f} s)", flush=True)
    time.sleep(secs)


# ------------------------------------------------------------------- stats --

def pct(values, q):
    """Nearest-rank percentile of a sorted list."""
    if not values:
        return float("nan")
    k = max(0, min(len(values) - 1, int(round(q / 100 * len(values) + 0.5)) - 1))
    return values[k]


def row(name, values_ms):
    v = sorted(values_ms)
    return (f"{name:<22} n={len(v):5d}  p50 {pct(v, 50):6.2f}  p95 {pct(v, 95):6.2f}"
            f"  p99 {pct(v, 99):6.2f}  max {(v[-1] if v else float('nan')):6.2f} ms"), v


def fields(line):
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", line)}


def slope(points):
    """Least-squares slope of (x, y) points."""
    n = len(points)
    if n < 2:
        return 0.0
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    den = sum((x - mx) ** 2 for x, _ in points)
    return sum((x - mx) * (y - my) for x, y in points) / den if den else 0.0


# ------------------------------------------------------------------- steps --

def step_check(a, rep):
    ps = subprocess.run(["pmset", "-g", "ps"], capture_output=True, text=True).stdout
    on_ac = "AC Power" in ps
    rep.say(f"power: {'AC' if on_ac else 'BATTERY'}")
    low = re.search(r"lowpowermode\s+(\d)", subprocess.run(
        ["pmset", "-g"], capture_output=True, text=True).stdout)
    low_on = bool(low and low.group(1) == "1")
    rep.say(f"Low Power Mode: {'ON' if low_on else 'off'}")
    build()
    host, viewer, n = start_session("synthetic", window=False)
    wait(3, "3 s synthetic session through RemoraDev.app")
    counters = end_session(host, viewer, n)
    decoded = fields(counters.replace(" frames decoded", "=").replace("video: ", "decoded="))
    rep.say(counters)
    write_log("check-host.log", host.snapshot())
    write_log("check-viewer.log", viewer.snapshot())
    rep.say("Screen Recording: checked by the first P1 run (capture of the real screen)")
    rep.verdict("check", on_ac and not low_on and decoded.get("decoded", 0) > 0,
                f"AC {on_ac}, Low Power Mode {'on' if low_on else 'off'}, "
                f"session decoded {decoded.get('decoded', 0)} frames")


def step_p1(a, rep):
    build()
    worst = {}
    for run in range(1, a.runs + 1):
        rep.say(f"\n--- P1-P4 run {run}/{a.runs}: {a.warmup} s warm-up + {a.seconds} s measured ---")
        if a.source == "screen":
            print("   the viewer window opens now: CLICK IT so it is in front of the motion page,"
                  " then keep your hands off", flush=True)
        host, viewer, n = start_session(a.source, window=True, timing=True)
        wait(a.warmup + a.seconds + 1, "streaming")
        counters = end_session(host, viewer, n)
        hl, vl = host.snapshot(), viewer.snapshot()
        write_log(f"p1-run{run}-host.log", hl)
        write_log(f"p1-run{run}-viewer.log", vl)

        sent = {}
        for _, line in hl:
            if line.startswith("timing: "):
                f = fields(line)
                sent[f["capture_us"]] = f
        if not sent:
            rep.verdict(f"P1 run {run}", False, "the host sent no frames", valid=False)
            continue
        t0 = min(sent) + a.warmup * 1_000_000
        t1 = t0 + a.seconds * 1_000_000
        sent_in = {k: v for k, v in sent.items() if t0 <= k < t1}
        drawn = []
        for _, line in vl:
            if line.startswith("timing: "):
                f = fields(line)
                h = sent_in.get(f["capture_us"])
                if h:
                    drawn.append({**h, **f})
        occluded = sum(1 for _, l in vl if "occluded" in l)

        def col(x, y):
            return [(d[y] - d[x]) / 1000 for d in drawn if y in d and x in d]

        p1_text, p1 = row("P1 capture->drawn", col("capture_us", "drawn_us"))
        p2_text, p2 = row("P2 encoded->drawn", col("encoded_us", "drawn_us"))
        rep.say(p1_text)
        rep.say(p2_text)
        for name, x, y in [("  capture->encoded", "capture_us", "encoded_us"),
                           ("  encoded->sent", "encoded_us", "sent_us"),
                           ("  sent->received", "sent_us", "received_us"),
                           ("  received->decoded", "received_us", "decoded_us"),
                           ("  decoded->drawn", "decoded_us", "drawn_us")]:
            rep.say(row(name, col(x, y))[0])
        caps = sorted(sent_in)
        gaps = [(b - c) / 1000 for c, b in zip(caps, caps[1:])]
        rep.say(row("P4 frame interval", gaps)[0])
        rep.say(row("P4 drawn->presented", col("drawn_us", "presented_us"))[0])
        fps = len(sent_in) / a.seconds
        rep.say(f"P3 frames sent {len(sent_in)} ({fps:.1f} fps), drawn {len(drawn)}; "
                f"viewer {counters}; stats lines saying occluded: {occluded}")
        # P3 judges the measured window only: the viewer's running totals
        # from its once-a-second stats line at the start and at the end of
        # it (±1 s). Drops before the window is clicked to the front (the
        # picture cannot be shown yet) are warm-up, not P3.
        def stats_at(t):
            last = None
            for when, line in vl:
                if line.startswith("stats: ") and when <= t:
                    last = line
            return {k: int(v) for k, v in re.findall(r"(refused|failed|dropped) (\d+)", last or "")}
        begin = viewer.active_t + a.warmup
        s0, s1 = stats_at(begin), stats_at(begin + a.seconds)
        c = {k: s1.get(k, 0) - s0.get(k, 0) for k in ("refused", "failed", "dropped")}
        rep.say(f"   in the measured {a.seconds} s: refused {c['refused']}, failed {c['failed']},"
                f" dropped {c['dropped']} (whole session: {counters})")

        valid = a.source != "screen" or fps >= MOTION_MIN_FPS
        if not valid:
            rep.say(f"   only {fps:.1f} fps captured: the motion page was not on screen")
        # "no drawable N (occluded)" is a running total, so the word stays in
        # every later stats line once the window was covered for a moment
        # (e.g. before it was clicked). Covered DURING the measurement shows
        # as frames received but not drawn.
        not_drawn = len(sent_in) - len(drawn)
        if occluded and not_drawn > 0.02 * max(1, len(sent_in)):
            valid = False
            rep.say(f"   {not_drawn} frames not drawn while the viewer window was covered:"
                    " click it to the front and keep your hands off")
        p95_1, p95_2 = pct(p1, 95), pct(p2, 95)
        min_drawn = int(P3_MIN_DRAWN * a.seconds / 60)
        rep.verdict(f"P1 run {run}", p95_1 < P1_P95_MS, f"p95 {p95_1:.2f} ms (limit < {P1_P95_MS})", valid)
        rep.verdict(f"P2 run {run}", p95_2 <= P2_P95_MS, f"p95 {p95_2:.2f} ms (limit <= {P2_P95_MS})", valid)
        p3_ok = (len(drawn) >= min_drawn and c.get("failed", 0) == 0 and c.get("refused", 0) == 0
                 and c.get("dropped", 0) == 0)
        rep.verdict(f"P3 run {run}", p3_ok,
                    f"drawn {len(drawn)} (limit >= {min_drawn}), failed {c.get('failed', 0)}, "
                    f"refused {c.get('refused', 0)}, dropped {c.get('dropped', 0)}", valid)
        if valid:
            worst["P1"] = max(worst.get("P1", 0), p95_1)
            worst["P2"] = max(worst.get("P2", 0), p95_2)
        if run < a.runs:
            wait(10, "pause before the next run")
    if worst:
        rep.say("")
        rep.verdict("P1 worst run", worst["P1"] < P1_P95_MS, f"p95 {worst['P1']:.2f} ms")
        rep.verdict("P2 worst run", worst["P2"] <= P2_P95_MS, f"p95 {worst['P2']:.2f} ms")


def step_p5(a, rep):
    build()
    rep.say(f"P5: viewer memory over {a.minutes} min, sampled every 10 s")
    print("   CLICK the viewer window when it opens, then leave the Mac alone", flush=True)
    host, viewer, n = start_session("screen", window=True)
    start, samples = time.time(), []
    while time.time() - start < a.minutes * 60:
        time.sleep(10)
        mb = footprint_mb(viewer.pid)
        minute = (time.time() - start) / 60
        if mb is not None:
            samples.append((minute, mb))
            if len(samples) % 6 == 0:
                print(f"   minute {minute:4.1f}: {mb:.1f} MB", flush=True)
    counters = end_session(host, viewer, n)
    write_log("p5-host.log", host.snapshot())
    write_log("p5-viewer.log", viewer.snapshot())
    for m, mb in samples:
        rep.say(f"  {m:5.2f} min  {mb:7.2f} MB")
    rep.say(counters)
    after1 = [(m, mb) for m, mb in samples if m >= 1]
    peak = max(mb for _, mb in samples)
    first = next((mb for m, mb in samples if m >= 1), float("nan"))
    last = after1[-1][1] if after1 else float("nan")
    s = slope(after1)
    rep.verdict("P5", peak < P5_MAX_MB and last - first <= P5_GROWTH_MB and s <= P5_SLOPE_MB_MIN,
                f"peak {peak:.1f} MB (limit < {P5_MAX_MB}), growth min 1 -> end {last - first:+.2f} MB "
                f"(limit <= {P5_GROWTH_MB}), slope {s:+.3f} MB/min (limit <= {P5_SLOPE_MB_MIN})")


def step_p6(a, rep):
    build()
    rep.say("P6: host CPU while streaming a still screen, 60 s, viewer without a window")
    print("   do not touch the Mac until this step prints its result", flush=True)
    host, viewer, n = start_session("screen", window=False)
    wait(10, "settling")
    helpers = pids("VTEncoderXPCService")
    procs = [host.pid, *helpers]
    c0, t0 = cpu_seconds(procs), time.time()
    wait(60, "measuring")
    c1, t1 = cpu_seconds(procs), time.time()
    counters = end_session(host, viewer, n)
    write_log("p6-host.log", host.snapshot())
    write_log("p6-viewer.log", viewer.snapshot())
    used = 100 * (c1 - c0) / (t1 - t0)
    rep.say(f"processes: host {host.pid}, VTEncoderXPCService {helpers}")
    rep.say(f"CPU time {c1 - c0:.2f} s in {t1 - t0:.1f} s; viewer {counters}")
    rep.verdict("P6", used < P6_MAX_PCT, f"{used:.2f} % of one core (limit < {P6_MAX_PCT} %)")


def step_p8(a, rep):
    build()
    worst = 0.0
    for run in range(1, 4):
        rep.say(f"\n--- P8 run {run}/3: bench-capture, 60 s ---")
        r = subprocess.run([DEV_APP, "run", "bench-capture", "--seconds", "60"],
                           capture_output=True, text=True, cwd=ROOT)
        out = r.stdout + r.stderr
        with open(os.path.join(LOGS, f"p8-run{run}.log"), "w") as fh:
            fh.write(out)
        fps = re.search(r"complete frames: \d+ \(([\d.]+) fps\)", out)
        c12 = re.search(r"C12 screen → encoded\s+([\d.]+)\s+([\d.]+)", out)
        fps_v = float(fps.group(1)) if fps else 0.0
        if not c12:
            rep.verdict(f"P8 run {run}", False, "no C12 row in the bench output", valid=False)
            continue
        p50, p95 = float(c12.group(1)), float(c12.group(2))
        valid = fps_v >= MOTION_MIN_FPS
        rep.say(f"capture {fps_v:.1f} fps; C12 p50 {p50:.2f} ms (Phase 2: 7.05 and 9.0 ms), p95 {p95:.2f} ms")
        if not valid:
            rep.say("   the motion page was not on screen")
        rep.verdict(f"P8 run {run}", p95 <= P8_C12_P95_MS,
                    f"C12 p95 {p95:.2f} ms, p50 {p50:.2f} ms (limit p95 <= {P8_C12_P95_MS})", valid)
        if valid:
            worst = max(worst, p95)
    if worst:
        rep.verdict("P8 worst run", worst <= P8_C12_P95_MS, f"C12 p95 {worst:.2f} ms")


def step_m7(a, rep):
    r = subprocess.run(["cargo", "test", "--locked", "-p", "remora-codec", "--test",
                        "m7_decode_memory", "--", "--nocapture"],
                       capture_output=True, text=True, cwd=ROOT)
    out = r.stdout + r.stderr
    with open(os.path.join(LOGS, "m7.log"), "w") as fh:
        fh.write(out)
    line = next((l for l in out.splitlines() if l.startswith("M7 memory limit: ")), "")
    for l in out.splitlines():
        if l.startswith("M7 memory"):
            rep.say(l)
    checked = line.startswith("M7 memory limit: checked")
    rep.verdict("M7 memory limit", r.returncode == 0 and checked,
                (line or "no 'M7 memory limit' line") + f" (test exit {r.returncode})",
                valid=checked or r.returncode != 0)


def resume_facts(lines, after_index):
    """After `after_index`: time of 'capture resumed' and whether the next frame is a keyframe."""
    resumed_t, key = None, None
    for i in range(after_index, len(lines)):
        t, line = lines[i]
        if resumed_t is None and line.startswith("capture resumed"):
            resumed_t = t
        elif resumed_t is not None and line.startswith("timing: "):
            key = "keyframe=true" in line
            break
    return resumed_t, key


def step_t2(a, rep):
    build()
    rep.say("T2: 5 display sleep / wake cycles in one session (the display goes off 5 times)")
    host, viewer, n = start_session("screen", window=False, timing=True)
    wait(5, "streaming")
    mem0 = footprint_mb(host.pid)
    ok = True
    for cycle in range(1, 6):
        mark = len(host.snapshot())
        t_sleep = time.time()
        subprocess.run(["pmset", "displaysleepnow"], check=True)
        _, t_paused, _ = host.expect("capture paused", secs=15, after=mark)
        wait(8, f"cycle {cycle}: display off")
        mark2 = len(host.snapshot())
        t_wake = time.time()
        subprocess.run(["caffeinate", "-u", "-t", "2"], check=True)
        host.expect("capture resumed", secs=15, after=mark2)
        wait(3, "display on")
        t_resumed, key = resume_facts(host.snapshot(), mark2)
        pause_s, resume_s = t_paused - t_sleep, t_resumed - t_wake
        good = pause_s <= T2_PAUSE_S and resume_s <= T2_RESUME_S and key is True
        ok &= good
        rep.say(f"cycle {cycle}: paused {pause_s:.2f} s after sleep, resumed {resume_s:.2f} s after"
                f" wake, first frame after resume a keyframe: {key}")
        wait(5, "streaming")
    mem1 = footprint_mb(host.pid)
    alive = viewer.p.poll() is None
    counters = end_session(host, viewer, n)
    write_log("t2-host.log", host.snapshot())
    write_log("t2-viewer.log", viewer.snapshot())
    growth = (mem1 or 0) - (mem0 or 0)
    rep.say(f"host memory {mem0:.1f} -> {mem1:.1f} MB; viewer {counters}")
    rep.verdict("T2", ok and alive and growth <= T2_GROWTH_MB,
                f"pause <= {T2_PAUSE_S} s, resume <= {T2_RESUME_S} s, keyframe after every resume: "
                f"{'yes' if ok else 'NO'}; same session: {'yes' if alive else 'NO'}; "
                f"host memory {growth:+.2f} MB (limit <= {T2_GROWTH_MB})")


def display_on_times(since):
    """Wall times of 'Display is turned on' in the power log after `since` (1 s resolution)."""
    out = subprocess.run(["pmset", "-g", "log"], capture_output=True, text=True).stdout
    times = []
    for line in out.splitlines():
        if "Display is turned on" in line:
            m = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ([+-]\d{4})", line)
            if m:
                t = datetime.datetime.strptime(f"{m.group(1)} {m.group(2)}",
                                               "%Y-%m-%d %H:%M:%S %z").timestamp()
                if t >= since:
                    times.append(t)
    return times


def step_t3_lid(a, rep):
    build()
    rep.say("T3 lid: close the lid when asked, wait about 30 s, open it")
    host, viewer, n = start_session("screen", window=False, timing=True)
    wait(5, "streaming")
    start = time.time()
    mark = len(host.snapshot())
    print("\n   >>> CLOSE THE LID NOW. Wait about 30 s, then open it and log in if asked. <<<\n",
          flush=True)
    host.expect("capture paused", secs=300, after=mark)
    host.expect("capture resumed", secs=600, after=mark)
    wait(5, "lid open again")
    lines = host.snapshot()
    t_resumed, key = resume_facts(lines, mark)
    alive = viewer.p.poll() is None
    counters = end_session(host, viewer, n)
    write_log("t3-lid-host.log", host.snapshot())
    write_log("t3-lid-viewer.log", viewer.snapshot())
    on = [t for t in display_on_times(start) if t <= t_resumed + 1]
    delay = t_resumed - on[-1] if on else None
    rep.say(f"display on (power log, 1 s resolution): "
            f"{datetime.datetime.fromtimestamp(on[-1]).strftime('%H:%M:%S') if on else 'not found'}; "
            f"capture resumed {datetime.datetime.fromtimestamp(t_resumed).strftime('%H:%M:%S.%f')[:-3]}")
    rep.say(f"viewer {counters}")
    ok = alive and key is True and delay is not None and delay <= T3_RESUME_S + 1
    rep.verdict("T3 lid", ok,
                f"resumed {('%.1f s' % delay) if delay is not None else '?'} after the display came on "
                f"(limit {T3_RESUME_S} s, +1 s log resolution), keyframe first: {key}, "
                f"same session: {'yes' if alive else 'NO'}")


STEPS = {"check": step_check, "p1": step_p1, "p5": step_p5, "p6": step_p6, "p8": step_p8,
         "m7": step_m7, "t2": step_t2, "t3-lid": step_t3_lid}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=list(STEPS))
    ap.add_argument("--source", default="screen", choices=["screen", "synthetic"], help="p1 only")
    ap.add_argument("--seconds", type=int, default=60, help="p1: measured seconds per run")
    ap.add_argument("--warmup", type=int, default=10, help="p1: seconds before measuring")
    ap.add_argument("--runs", type=int, default=3, help="p1: number of runs")
    ap.add_argument("--minutes", type=int, default=10, help="p5: duration")
    a = ap.parse_args()
    # Keep the Mac awake (display, idle and system sleep) for the whole step;
    # T2's `pmset displaysleepnow` and closing the lid still work.
    if not os.environ.get("REMORA_CAFFEINATED"):
        os.environ["REMORA_CAFFEINATED"] = "1"
        os.execvp("caffeinate", ["caffeinate", "-dims", sys.executable, *sys.argv])
    rep = Report(a.step if a.source == "screen" else f"{a.step}-{a.source}")
    rep.say(f"Phase 4 {a.step}, {datetime.datetime.now().isoformat(timespec='seconds')}, "
            f"commit {subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True, cwd=ROOT).stdout.strip()}")
    try:
        STEPS[a.step](a, rep)
    finally:
        rep.save()


if __name__ == "__main__":
    main()
