#!/usr/bin/env bash
# Phase 2 Q4 on a single-display Mac: what display changes do to a running capture.
# Each test runs bench-capture (through RemoraDev.app) while the change happens and
# saves the log; the bench prints status transitions, frame-size changes and OS
# stop events with timestamps.
#
#   scripts/macos/phase2-hotplug.sh resolution     # automatic; restores the mode afterwards
#   scripts/macos/phase2-hotplug.sh virtual        # automatic; private CGVirtualDisplay, nothing installed
#   scripts/macos/phase2-hotplug.sh display-sleep  # YOU wake the display with a key ~20 s later
#   scripts/macos/phase2-hotplug.sh lid            # YOU close the lid ~10 s in, open it ~30 s later
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/target/phase2-results"
APP="$ROOT/scripts/macos/dev-app.sh"
BIN="$ROOT/target"
mkdir -p "$OUT"
stamp() { date +%H:%M:%S; }
say_step() { echo "[$(stamp)] $*"; }

# Runs the bench in the background; prints its PID. Args: <log> <bench args…>
bench_bg() { local log="$1"; shift; "$APP" run bench-capture "$@" > "$log" 2>&1 & echo $!; }
events() { sed -n '/^events:/,/^$/p' "$1"; }

case "${1:-}" in
  resolution)
    swiftc -O "$ROOT/scripts/macos/display-mode.swift" -o "$BIN/display-mode" 2>/dev/null
    orig="$("$BIN/display-mode" list | awk -F'\t' '/\(current\)/ {print $1}')"
    # Pick the panel's native mode (2560×1664 px) if it isn't current, else any other usable mode.
    alt="$("$BIN/display-mode" list | awk -F'\t' -v o="$orig" '$1 != o && /2560×1664 px/ {print $1; exit}')"
    [[ -n "$alt" ]] || alt="$("$BIN/display-mode" list | awk -F'\t' -v o="$orig" '$1 != o {print $1; exit}')"
    say_step "current mode $orig, switching to $alt and back during a 40 s capture"
    pid="$(bench_bg "$OUT/hotplug-resolution.log" --seconds 40)"
    sleep 10; "$BIN/display-mode" set "$alt"
    sleep 15; "$BIN/display-mode" set "$orig"
    wait "$pid" || true
    events "$OUT/hotplug-resolution.log"
    ;;
  virtual)
    clang -fobjc-arc -framework Foundation -framework CoreGraphics \
      "$ROOT/scripts/macos/virtual-display.m" -o "$BIN/virtual-display"
    say_step "A) capturing the MAIN display while a virtual display is added (10 s) and removed (25 s)"
    pid="$(bench_bg "$OUT/hotplug-virtual-main.log" --seconds 40)"
    sleep 10; "$BIN/virtual-display" 15
    wait "$pid" || true
    events "$OUT/hotplug-virtual-main.log"
    say_step "B) capturing the VIRTUAL display itself, which is removed ~20 s into the capture (≈ unplug)"
    "$BIN/virtual-display" 25 > "$OUT/virtual-display.out" &
    vpid=$!
    sleep 3
    vid="$(sed -n 's/^created virtual display \([0-9]*\).*/\1/p' "$OUT/virtual-display.out")"
    if [[ -z "$vid" ]]; then echo "virtual display not created:"; cat "$OUT/virtual-display.out"; exit 1; fi
    "$APP" run bench-capture --seconds 40 --display-id "$vid" > "$OUT/hotplug-virtual-unplug.log" 2>&1 || true
    wait "$vpid" || true
    events "$OUT/hotplug-virtual-unplug.log"
    ;;
  display-sleep)
    say_step "60 s capture; display sleeps at 10 s — press a key to wake it after ~20 s"
    pid="$(bench_bg "$OUT/hotplug-display-sleep.log" --seconds 60)"
    sleep 10; pmset displaysleepnow
    wait "$pid" || true
    events "$OUT/hotplug-display-sleep.log"
    ;;
  lid)
    say_step "120 s capture started: close the lid now-ish (~10 s), open it ~30 s later"
    pid="$(bench_bg "$OUT/hotplug-lid.log" --seconds 120)"
    wait "$pid" || true
    events "$OUT/hotplug-lid.log"
    ;;
  *) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
