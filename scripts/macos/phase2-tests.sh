#!/usr/bin/env bash
# Runs the Phase 2 measurement blocks (docs/phase2-criteria.md §3) through
# RemoraDev.app and saves every raw log under target/phase2-results/.
#
#   scripts/macos/phase2-tests.sh motion   # C1, C2, C5: 3 × 60 s  (motion pattern full screen)
#   scripts/macos/phase2-tests.sh soak     # C4: 3 × 10 min        (motion pattern full screen)
#   scripts/macos/phase2-tests.sh static   # C3 + Q3: 3 × (60 s baseline + 60 s capture), hands off
#
# Every test is run 3 times; the WORST run is the one judged.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/target/phase2-results"
APP="$ROOT/scripts/macos/dev-app.sh"
mkdir -p "$OUT"
stamp() { date +%H:%M:%S; }

# Bring the motion pattern (Safari, already full screen) to the front.
front_safari() { open -a Safari; sleep 2; }

# A motion run is only valid if the screen really changed every frame.
check_valid() { # <log>
  local fps
  fps="$(sed -n 's/^complete frames: [0-9]* (\([0-9.]*\) fps).*/\1/p' "$1")"
  if awk -v f="${fps:-0}" 'BEGIN { exit !(f < 55) }'; then
    echo "    INVALID RUN: capture saw only ${fps:-0} fps — the motion pattern was not on screen. Not counted; stopping."
    exit 2
  fi
}

case "${1:-}" in
  motion)
    for i in 1 2 3; do
      echo "[$(stamp)] motion run $i/3 (60 s)"
      front_safari
      "$APP" run bench-capture --seconds 60 --out "$OUT/motion-$i.h264" > "$OUT/motion-$i.log" 2>&1
      grep -E "C1 capture|C2 encode|C5 keeps|complete frames:" "$OUT/motion-$i.log" | sed 's/^/    /'
      check_valid "$OUT/motion-$i.log"
    done
    ;;
  soak)
    for i in 1 2 3; do
      echo "[$(stamp)] soak run $i/3 (10 min, memory every 10 s)"
      front_safari
      "$APP" run bench-capture --seconds 600 --sample-memory 10 > "$OUT/soak-$i.log" 2>&1
      grep -E "C4 growth|complete frames:" "$OUT/soak-$i.log" | sed 's/^/    /'
      check_valid "$OUT/soak-$i.log"
    done
    ;;
  static)
    for i in 1 2 3; do
      echo "[$(stamp)] static run $i/3: 60 s baseline (no capture) …"
      "$APP" run bench-capture --seconds 60 --no-capture --measure-cpu > "$OUT/static-baseline-$i.log" 2>&1
      echo "[$(stamp)] static run $i/3: 60 s capture …"
      "$APP" run bench-capture --seconds 60 --measure-cpu > "$OUT/static-$i.log" 2>&1
      grep -E "C3 static|this process|helpers|per-second|callbacks by status" "$OUT/static-$i.log" | sed 's/^/    /'
    done
    ;;
  *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
echo "[$(stamp)] done — logs in $OUT"
