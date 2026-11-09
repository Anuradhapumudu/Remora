#!/usr/bin/env python3
"""Shared measuring helper: every runner that measures uses this (R9 = W2-W4,
phase4.5-criteria §15 and phase4-criteria §14; owner, 2026-10-27).

What a run gets from here, and the failure behind each item:

- Display, idle and system sleep prevented: keep_awake() re-runs the script
  under `caffeinate` and start() checks the assertion is held (W3: S1's first
  runs had none, the display slept for 2 min mid-run).
- Machine state at start and end, from `remora-host machine-state` in its own
  process (W2: the Phase 4 runner's P1, P5 and P6 recorded none).
- On AC power with Low Power Mode off: refused at start, checked at every
  wait() and at the end (S1's first attempts ran on battery).
- The Mac never slept: every wait() compares the wall clock with the monotonic
  clock, which on macOS (mach_absolute_time) stops while the Mac sleeps, and
  finish() reads Sleep entries from the power log. Seen 2026-10-30: the M7
  test's own timer said 14.78 s while 15 min passed; the Mac had slept.
- The display stayed on: "Display is turned off" in the power log (macOS
  reports no occlusion while the display is off, S1 2026-10-26).
- No instrument that pauses the measured process (W4: the P5 re-check's vmmap
  every 10 s cost ~20 dropped frames and a keyframe each time). instrument()
  runs a tool only if it is classified below; a run declares how many pausing
  calls it allows (default 0) and is INVALID above that.

    run = measuring.Run(say)            # say(text) prints and records a line
    run.start()                         # refuses battery / Low Power Mode
    ...  run.wait(10)                   # instead of time.sleep(10)
    out = run.instrument(["footprint", "-p", str(pid)])
    valid = run.finish([("window drew", ok, "534 of 539 stats lines")])

    python3 -I scripts/macos/measuring.py --self-test
"""
import datetime
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HOST = os.path.join(ROOT, "target", "release", "remora-host")

# Tools that stop the target process while they read it. vmmap measured
# (P5 re-check, 2026-10-26); the others attach or suspend the same way and are
# treated as pausing until a run shows otherwise (the safe direction).
PAUSING = {"vmmap", "sample", "leaks", "heap", "malloc_history", "spindump", "lldb", "xctrace"}
# Tools seen not to pause it. footprint: S1 sampled it every 10 s and drew
# 10 790-10 795 of 10 800 frames per 180 s run (spikes/gui-memory/results/
# s1-runs-3.txt). ps: reads CPU time only.
NOT_PAUSING = {"footprint", "ps"}
# Wall clock running ahead of the monotonic clock by more than this = a sleep.
SLEEP_GAP_S = 2.0
# Power-log events that make a run invalid unless the run expects them.
DISPLAY_OFF, SLEPT = "display_off", "sleep"


# ---------------------------------------------------------------- parsing --

def parse_power_source(ps_text):
    """'AC' or 'Battery' from `pmset -g ps` (first line), else None."""
    first = ps_text.splitlines()[0] if ps_text else ""
    if "'AC Power'" in first:
        return "AC"
    if "'Battery Power'" in first:
        return "Battery"
    return None


def parse_low_power(pmset_text):
    """True / False from `pmset -g`'s lowpowermode line, None if absent."""
    m = re.search(r"^\s*lowpowermode\s+(\d)", pmset_text, re.M)
    return None if m is None else m.group(1) == "1"


def parse_thermal(machine_text):
    """Thermal state word from `remora-host machine-state`, else None."""
    m = re.match(r"machine state \([^)]*\): thermal state (\w+)", machine_text)
    return m.group(1) if m else None


def power_events(log_text, since, until):
    """(kind, line) for display-off and sleep entries of `pmset -g log` with
    since <= time <= until ("YYYY-MM-DD HH:MM:SS" strings, local time)."""
    events = []
    for line in log_text.splitlines():
        stamp = line[:19]
        if not re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$", stamp) or not since <= stamp <= until:
            continue
        head, _, msg = line.partition("\t")
        kind = head[26:].strip()  # after "YYYY-MM-DD HH:MM:SS +zzzz "
        if kind == "Notification" and msg.strip().startswith("Display is turned off"):
            events.append((DISPLAY_OFF, " ".join(line.split())))
        elif kind == "Sleep":
            events.append((SLEPT, " ".join(line.split())))
    return events


def holds_display_awake(assertions_text, pid):
    """True if a caffeinate holds PreventUserIdleDisplaySleep on behalf of
    `pid` in `pmset -g assertions`. `caffeinate -dims <script>` keeps the
    script's pid and asserts from a child, whose next line reads "caffeinate
    asserting on behalf of 'python3' (pid N)" (seen 2026-11-01). Only our own
    pid counts: another program's caffeinate (one was running) can end any time."""
    lines = assertions_text.splitlines()
    return any("(caffeinate):" in a and "PreventUserIdleDisplaySleep" in a
               and "on behalf of" in b and b.rstrip().endswith(f"(pid {pid})")
               for a, b in zip(lines, lines[1:]))


def slept_seconds(mark, now):
    """How far the wall clock ran ahead of the monotonic clock between two
    (time.time(), time.monotonic()) pairs: the time the Mac slept."""
    return (now[0] - mark[0]) - (now[1] - mark[1])


def verdict(f):
    """(valid, reasons, warnings) for the facts `f` (a dict) of one run."""
    reasons, warnings = [], []
    if not f["caffeinated"]:
        reasons.append("display sleep was not prevented (no caffeinate assertion)")
    for when in ("start", "end"):
        if f[f"power_{when}"] != "AC":
            reasons.append(f"not on AC power at the {when} ({f[f'power_{when}']})")
        if f[f"low_power_{when}"] is not False:
            reasons.append(f"Low Power Mode at the {when}: {f[f'low_power_{when}']}")
        if f[f"thermal_{when}"] not in ("nominal", None):
            warnings.append(f"thermal state {f[f'thermal_{when}']} at the {when}")
        if f[f"thermal_{when}"] is None:
            warnings.append(f"thermal state unknown at the {when}")
    for note in f["live"]:
        reasons.append(note)
    expected = f.get("expect", set())
    for kind, line in f["events"]:
        if kind not in expected:
            reasons.append(("display turned off: " if kind == DISPLAY_OFF else "the Mac slept: ") + line)
    if f["pauses"] > f["pauses_allowed"]:
        reasons.append(f"{f['pauses']} calls of an instrument that pauses the process "
                       f"(allowed {f['pauses_allowed']})")
    for name, ok, detail in f.get("extra", []):
        if not ok:
            reasons.append(f"{name}: {detail}")
    return not reasons, reasons, warnings


# ------------------------------------------------------------------ the run --

def _out(argv):
    return subprocess.run(argv, capture_output=True, text=True).stdout


def keep_awake(flags="-dims"):
    """Re-run this script under caffeinate (display, idle, disk and system
    sleep prevented; pass "-di" to let the system sleep, as T3 --mac-sleeps)."""
    if not os.environ.get("REMORA_CAFFEINATED"):
        os.environ["REMORA_CAFFEINATED"] = "1"
        os.execvp("caffeinate", ["caffeinate", flags, sys.executable, *sys.argv])


class Run:
    """One measuring run: start(), wait()/instrument() while it runs, finish()."""

    def __init__(self, say, pauses_allowed=0, expect=(), host=HOST):
        self.say, self.pauses_allowed, self.expect, self.host = say, pauses_allowed, set(expect), host
        self.pauses, self.live, self.f = 0, [], {}

    def _state(self, when):
        text = _out([self.host, "machine-state", "--when", when]) if os.path.exists(self.host) else ""
        for line in text.splitlines() or [f"machine state ({when}): unavailable ({self.host} not built)"]:
            self.say(line)
        self.f[f"thermal_{when}"] = parse_thermal(text)
        self.f[f"power_{when}"] = parse_power_source(_out(["pmset", "-g", "ps"]))
        self.f[f"low_power_{when}"] = parse_low_power(_out(["pmset", "-g"]))

    def start(self):
        """Record the start state; exit before measuring if the run cannot count."""
        self.f["caffeinated"] = holds_display_awake(_out(["pmset", "-g", "assertions"]), os.getpid()) \
            or DISPLAY_OFF in self.expect
        self._state("start")
        early = [r for r in verdict({**self._blank(), **self.f, "power_end": "AC", "low_power_end": False,
                                     "thermal_end": "nominal"})[1]]
        if early:
            for r in early:
                self.say(f"REFUSED: {r}")
            sys.exit("this run would not count; fix the above and start again")
        self.since = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._mark = (time.time(), time.monotonic())

    def _blank(self):
        return {"caffeinated": True, "live": [], "events": [], "pauses": 0, "pauses_allowed": 0}

    def check(self):
        """Live checks, cheap enough for every sample (~30 ms): power source,
        Low Power Mode, and a sleep since the last check."""
        now = (time.time(), time.monotonic())
        gap = slept_seconds(self._mark, now)
        self._mark = now
        if gap > SLEEP_GAP_S and SLEPT not in self.expect:
            self._note(f"the Mac slept about {gap:.0f} s (wall clock ran ahead of the monotonic clock)")
        power = parse_power_source(_out(["pmset", "-g", "ps"]))
        if power != "AC":
            self._note(f"power source changed to {power}")
        if parse_low_power(_out(["pmset", "-g"])) is not False:
            self._note("Low Power Mode turned on")

    def _note(self, text):
        if text not in self.live:
            self.live.append(text)
            self.say(f"   !! {text}: this run will not count")

    def wait(self, secs):
        """time.sleep(secs) with the live checks every second."""
        end = time.monotonic() + secs
        while (left := end - time.monotonic()) > 0:
            time.sleep(min(1.0, left))
            self.check()

    def instrument(self, argv):
        """Run a measuring tool; pausing ones are counted against the allowance."""
        tool = os.path.basename(argv[0])
        if tool in PAUSING:
            self.pauses += 1
        elif tool not in NOT_PAUSING:
            raise ValueError(f"{tool}: not classified in measuring.PAUSING / NOT_PAUSING")
        return _out(argv)

    def finish(self, extra=()):
        """Record the end state, print VALID / INVALID with every reason; True if valid."""
        self.check()
        self._state("end")
        until = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        events = power_events(_out(["pmset", "-g", "log"]), self.since, until)
        for _, line in events:
            self.say("power log: " + line)
        valid, reasons, warnings = verdict({**self.f, "live": self.live, "events": events,
                                            "expect": self.expect, "pauses": self.pauses,
                                            "pauses_allowed": self.pauses_allowed, "extra": list(extra)})
        self.say(f"instruments that pause the process: {self.pauses} call(s), allowed {self.pauses_allowed}")
        for w in warnings:
            self.say(f"warning: {w}")
        self.say("VALIDITY: VALID" if valid else "VALIDITY: INVALID (not counted): " + "; ".join(reasons))
        return valid


# ---------------------------------------------------------------- self-test --

# Real lines from this M4's `pmset -g log` (2026-10-25 .. 2026-11-01).
LOG = """\
2026-10-25 20:58:47 +0530 Notification        \tDisplay is turned off                                                      \t
2026-10-25 21:03:54 +0530 Notification        \tDisplay is turned on                                                       \t
2026-10-30 12:34:02 +0530 Sleep               \tEntering Sleep state due to 'Maintenance Sleep':TCPKeepAlive=active Using Batt (Charge:43%) 2 secs
2026-10-30 12:34:04 +0530 DarkWake            \tDarkWake from Deep Idle [CDNP] : due to smc.sysState.Wake(0x70070000) wifibt SMC.OutboxNotEmpty/ Using BATT (Charge:43%) 5 secs
2026-11-01 16:19:51 +0530 Wake Requests       \t[process=mDNSResponder request=Maintenance deltaSecs=7198 wakeAt=2026-11-01 18:19:49 info="upkeep wake"]
2026-11-01 16:20:10 +0530 Wake                \tWake from Deep Idle [CDNVA] : due to smc.sysState.Wake(0x70070000) lid SMC.OutboxNotEmpty RTP.multi-touch/UserActivity Assertion Using AC (Charge:47%)
"""
PS_AC = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=23724131)\t78%; charging; 1:23 remaining present: true\n"
PS_BATT = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=23724131)\t43%; discharging; (no estimate) present: true\n"
ASSERTIONS = """\
   pid 81520(caffeinate): [0x0002ba9e00019ed7] 00:00:00 PreventUserIdleSystemSleep named: "caffeinate command-line tool"  
\tDetails: caffeinate asserting on behalf of 'python3' (pid 81519)
   pid 81520(caffeinate): [0x0002ba9e00059ed8] 00:00:00 PreventUserIdleDisplaySleep named: "caffeinate command-line tool"  
\tDetails: caffeinate asserting on behalf of 'python3' (pid 81519)
   pid 81180(caffeinate): [0x0002b9e000019d8c] 00:03:10 PreventUserIdleSystemSleep named: "caffeinate command-line tool"  
\tDetails: caffeinate asserting for 300 secs
   pid 90001(caffeinate): [0x0002ba9e00059ed9] 00:00:00 PreventUserIdleDisplaySleep named: "caffeinate command-line tool"  
\tDetails: caffeinate asserting on behalf of 'python3' (pid 815190)
"""
MACHINE = ("machine state (start): thermal state nominal\n  power: Now drawing from 'AC Power' | x | low power mode: 0\n")


def good():
    return {"caffeinated": True, "power_start": "AC", "power_end": "AC", "low_power_start": False,
            "low_power_end": False, "thermal_start": "nominal", "thermal_end": "nominal", "live": [],
            "events": [], "pauses": 0, "pauses_allowed": 0, "extra": []}


def self_test():
    fails = []

    def expect(name, cond):
        if not cond:
            fails.append(name)

    expect("AC parsed", parse_power_source(PS_AC) == "AC")
    expect("battery parsed", parse_power_source(PS_BATT) == "Battery")
    expect("unknown power is None", parse_power_source("") is None)
    expect("low power off", parse_low_power(" lowpowermode         0\n") is False)
    expect("low power on", parse_low_power(" lowpowermode         1\n") is True)
    expect("low power absent", parse_low_power("") is None)
    expect("thermal parsed", parse_thermal(MACHINE) == "nominal")
    expect("thermal format change is None", parse_thermal("machine state (start): thermal nominal") is None)
    ev = power_events(LOG, "2026-10-25 00:00:00", "2026-11-01 23:59:59")
    expect("display off and sleep found, nothing else", [k for k, _ in ev] == [DISPLAY_OFF, SLEPT])
    expect("window excludes earlier events",
           power_events(LOG, "2026-10-26 00:00:00", "2026-10-29 00:00:00") == [])
    expect("caffeinate on behalf of us holds the display awake", holds_display_awake(ASSERTIONS, 81519))
    expect("a caffeinate for someone else does not count", not holds_display_awake(ASSERTIONS, 81518))
    expect("system sleep alone does not count", not holds_display_awake(ASSERTIONS.split("\n   pid 81520")[0], 81519))
    expect("pid prefix does not match", not holds_display_awake(ASSERTIONS, 81519 // 10))
    expect("no assertions, not awake", not holds_display_awake("", 81519))
    expect("the 2026-10-30 sleep is seen", slept_seconds((0.0, 0.0), (912.0, 14.78)) > 800)
    expect("no sleep, no gap", abs(slept_seconds((100.0, 5.0), (110.0, 15.0))) < 1e-9)
    expect("a gap above the limit only when slept",
           slept_seconds((0.0, 0.0), (10.0, 10.0)) <= SLEEP_GAP_S < slept_seconds((0.0, 0.0), (13.0, 10.0)))
    expect("a good run is valid", verdict(good()) == (True, [], []))
    for name, change in (
        ("no caffeinate", {"caffeinated": False}),
        ("battery at start", {"power_start": "Battery"}),
        ("battery at end", {"power_end": "Battery"}),
        ("power unknown", {"power_end": None}),
        ("low power mode", {"low_power_end": True}),
        ("low power unknown", {"low_power_start": None}),
        ("live note", {"live": ["the Mac slept about 900 s"]}),
        ("display off", {"events": ev[:1]}),
        ("slept", {"events": ev[1:]}),
        ("pausing over allowance", {"pauses": 1}),
        ("runner's own check", {"extra": [("window drew", False, "3 of 539")]}),
    ):
        valid, reasons, _ = verdict({**good(), **change})
        expect(f"{name} -> INVALID with a reason", not valid and reasons)
    expect("expected events allowed", verdict({**good(), "events": ev, "expect": {DISPLAY_OFF, SLEPT}})[0])
    expect("pauses within allowance", verdict({**good(), "pauses": 6, "pauses_allowed": 6})[0])
    w = verdict({**good(), "thermal_end": "serious"})
    expect("thermal is a warning, not a reason", w[0] and w[2])
    global _out
    real, ran = _out, []
    _out = lambda argv: ran.append(argv) or ""  # no tool really runs in the self-test
    try:
        r = Run(lambda t: None)
        try:
            r.instrument(["mystery-tool"])
            expect("unclassified tool refused", False)
        except ValueError:
            pass
        r.instrument(["/usr/bin/vmmap", "--summary", "1"])
        r.instrument(["footprint", "-p", "1"])
        expect("pausing tool counted, other not", r.pauses == 1 and len(ran) == 2)
    finally:
        _out = real
    expect("PAUSING and NOT_PAUSING are disjoint", not PAUSING & NOT_PAUSING)
    for f in fails:
        print(f"SELF-TEST FAIL: {f}")
    print(f"measuring self-test: {'FAILED' if fails else 'ok'} ({len(fails)} failure(s))")
    return 1 if fails else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(__doc__)
