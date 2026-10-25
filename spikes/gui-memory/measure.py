#!/usr/bin/env python3
"""Spike S1 memory runs: start the stand-in viewer in one mode, sample
`footprint -p` every 10 s (as phase4 P5), print a summary line.

    python3 -I measure.py s0 [--seconds 180] [--close-ui-after 30]
"""
import re, subprocess, sys, time

BIN = "target/release/gui-memory-spike"


def to_mb(v, unit):
    return float(v) * {"B": 1 / 1048576, "KB": 1 / 1024, "MB": 1, "GB": 1024}[unit]


def sample(pid):
    out = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True).stdout
    m = re.search(r"Footprint: ([\d.]+) (B|KB|MB|GB)", out)
    total = to_mb(*m.groups()) if m else None
    gfx = 0.0
    for line in out.splitlines():
        if "graphics" in line.lower():
            g = re.match(r"\s*([\d.]+) (B|KB|MB|GB)", line)
            if g:
                gfx += to_mb(*g.groups())
    return total, gfx


def main():
    args = sys.argv[1:]
    mode = args[0]
    seconds = float(args[args.index("--seconds") + 1]) if "--seconds" in args else 180.0
    p = subprocess.Popen([BIN, *args], stderr=subprocess.PIPE, text=True)
    start = time.monotonic()
    rows = []
    while p.poll() is None:
        t = time.monotonic() - start
        if t > seconds - 2:
            break
        if t >= 10 * len(rows) + 5:
            total, gfx = sample(p.pid)
            if total is not None:
                rows.append((round(t), total, gfx))
                print(f"  t={round(t):4d}s footprint {total:7.1f} MB  graphics {gfx:6.1f} MB", flush=True)
        time.sleep(0.5)
    err = p.communicate()[1]
    for line in err.splitlines():
        if line.startswith(("RESULT", "video window:", "Slint window", "[")):
            print("  " + line)
    tot = [r[1] for r in rows]
    late = [r[1] for r in rows if r[0] >= 60] or tot
    print(f"SUMMARY {' '.join(args)}: peak {max(tot):.1f} MB, after 60 s min {min(late):.1f} "
          f"max {max(late):.1f} MB, graphics peak {max(r[2] for r in rows):.1f} MB, samples {len(rows)}")


if __name__ == "__main__":
    main()
