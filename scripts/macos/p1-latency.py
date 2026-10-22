#!/usr/bin/env python3
"""Phase 4 P1/P2/P3 (phase4-criteria section 4): one latency run on this Mac.

Starts `remora-host serve --timing` and `remora-viewer connect --timing` on
loopback, accepts the viewer, streams for --seconds, ends the session, then
joins the two `timing:` logs by capture time (both processes read the same
mach clock; checked by P0) and prints, in ms:

  P1  capture (compositor display time) -> viewer GPU finished the draw
  P2  encoder output -> viewer GPU finished the draw
  stages: capture->encoded, encoded->sent, sent->received, received->decoded,
          decoded->drawn
  P3  frames drawn / frames sent, and the viewer's own counters

  scripts/macos/p1-latency.py --source screen --seconds 60   # the real P1 run
  scripts/macos/p1-latency.py --source synthetic --seconds 5 # tooling check

`--source screen` needs Screen Recording permission for the terminal running
this. Release builds; logs and the joined table go to target/phase4-results/.
"""
import argparse
import os
import re
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "target", "phase4-results")
BIN = os.path.join(ROOT, "target", "release")


def pct(values, q):
    """Nearest-rank percentile of a sorted list."""
    if not values:
        return float("nan")
    k = max(0, min(len(values) - 1, int(round(q / 100 * len(values) + 0.5)) - 1))
    return values[k]


def summary(name, values_us):
    v = sorted(x / 1000 for x in values_us)
    return (f"{name:<22} n={len(v):5d}  p50 {pct(v, 50):6.2f}  p95 {pct(v, 95):6.2f}"
            f"  p99 {pct(v, 99):6.2f}  max {v[-1] if v else float('nan'):6.2f} ms")


def fields(line):
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", line)}


class Proc:
    """A child whose stdout and stderr lines are collected."""

    def __init__(self, args, log):
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, bufsize=1)
        self.lines, self.log = [], open(log, "w")
        self.cond = threading.Condition()
        for stream in (self.p.stdout, self.p.stderr):
            threading.Thread(target=self._read, args=(stream,), daemon=True).start()

    def _read(self, stream):
        for line in stream:
            self.log.write(line)
            with self.cond:
                self.lines.append(line.rstrip("\n"))
                self.cond.notify_all()

    def expect(self, prefix, secs=20):
        deadline, seen = time.time() + secs, 0
        with self.cond:
            while True:
                for line in self.lines[seen:]:
                    if line.startswith(prefix):
                        return line
                seen = len(self.lines)
                left = deadline - time.time()
                if left <= 0:
                    sys.exit(f"no line starting with {prefix!r}; last lines:\n" +
                             "\n".join(self.lines[-20:]))
                self.cond.wait(left)

    def send(self, text):
        self.p.stdin.write(text + "\n")
        self.p.stdin.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="screen", choices=["screen", "synthetic"])
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--width", type=int, default=1920)
    ap.add_argument("--tag", default="run")
    a = ap.parse_args()

    subprocess.run(["cargo", "build", "--release", "-p", "remora-host", "-p", "remora-viewer"],
                   cwd=ROOT, check=True)
    os.makedirs(OUT, exist_ok=True)
    host = Proc([os.path.join(BIN, "remora-host"), "serve", "--source", a.source,
                 "--width", str(a.width), "--timing"], os.path.join(OUT, f"p1-{a.tag}-host.log"))
    code = host.expect("code:").split(": ", 1)[1]
    password = host.expect("password:").split(": ", 1)[1]
    viewer = Proc([os.path.join(BIN, "remora-viewer"), "connect", code, "--password", password,
                   "--timing"], os.path.join(OUT, f"p1-{a.tag}-viewer.log"))
    prompt = host.expect("prompt ")
    n = prompt.split(":")[0].split()[1]
    host.send(f"accept {n}")
    viewer.expect("SESSION ACTIVE")
    time.sleep(a.seconds)
    host.send(f"disconnect {n}")
    counters = viewer.expect("video:")
    viewer.p.wait(timeout=20)
    host.send("quit")
    host.p.wait(timeout=20)

    sent = {}
    for line in host.lines:
        if line.startswith("timing: "):
            f = fields(line)
            sent[f["capture_us"]] = f
    drawn = []
    for line in viewer.lines:
        if line.startswith("timing: "):
            f = fields(line)
            h = sent.get(f["capture_us"])
            if h:
                drawn.append({**h, **f})

    def col(a_key, b_key):
        return [d[b_key] - d[a_key] for d in drawn]

    report = [
        f"P1/P2 run '{a.tag}': source {a.source}, {a.seconds} s, width {a.width}",
        summary("P1 capture->drawn", col("capture_us", "drawn_us")),
        summary("P2 encoded->drawn", col("encoded_us", "drawn_us")),
        summary("  capture->encoded", col("capture_us", "encoded_us")),
        summary("  encoded->sent", col("encoded_us", "sent_us")),
        summary("  sent->received", col("sent_us", "received_us")),
        summary("  received->decoded", col("received_us", "decoded_us")),
        summary("  decoded->drawn", col("decoded_us", "drawn_us")),
        f"P3 frames sent {len(sent)}, drawn and matched {len(drawn)} "
        f"({100 * len(drawn) / max(1, len(sent)):.1f} %); viewer {counters}",
    ]
    text = "\n".join(report)
    print(text)
    with open(os.path.join(OUT, f"p1-{a.tag}.txt"), "w") as fh:
        fh.write(text + "\n")


if __name__ == "__main__":
    main()
