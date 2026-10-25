#!/usr/bin/env bash
# Phase 4 T3, "captured display removed" (roadmap D-29, architecture D38), on a
# single-display Mac: a private CGVirtualDisplay (scripts/macos/virtual-display.m)
# is captured, then destroyed. Real monitors may behave differently (roadmap D-16).
#
#   scripts/macos/t3-display-removed.sh returns   # gone for 20 s, then back: RESUMED
#   scripts/macos/t3-display-removed.sh gone      # never back (limit 15 s): STOPPED
#
# Runs `remora-host watch-capture` through RemoraDev.app (Screen Recording grant).
# Prints the capture events with millisecond times next to the times this script
# removed and re-created the display.
set -euo pipefail

if [[ -z "${REMORA_CAFFEINATED:-}" ]]; then
  exec env REMORA_CAFFEINATED=1 caffeinate -di "$0" "$@"
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/target/phase4-results"
APP="$ROOT/scripts/macos/dev-app.sh"
VD="$ROOT/target/virtual-display"
mkdir -p "$OUT"
ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
display_id() { sed -n 's/^created virtual display \([0-9]*\).*/\1/p' "$1"; }

clang -fobjc-arc -framework Foundation -framework CoreGraphics \
  "$ROOT/scripts/macos/virtual-display.m" -o "$VD"
"$APP" build > /dev/null

case "${1:-}" in
  returns)
    log="$OUT/t3-returns.log"; marks="$OUT/t3-returns.marks"; : > "$marks"
    "$VD" 15 > "$OUT/vd1.out" & vd=$!
    sleep 3; id="$(display_id "$OUT/vd1.out")"
    [[ -n "$id" ]] || { echo "virtual display not created"; exit 1; }
    "$APP" run watch-capture --seconds 50 --display-id "$id" > "$log" 2>&1 & w=$!
    wait "$vd"; echo "$(ms) REMOVED display $id" >> "$marks"
    sleep 20
    "$VD" 40 > "$OUT/vd2.out" & vd=$!
    sleep 1; echo "$(ms) BACK as display $(display_id "$OUT/vd2.out")" >> "$marks"
    wait "$w" || true
    kill "$vd" 2>/dev/null || true
    ;;
  gone)
    log="$OUT/t3-gone.log"; marks="$OUT/t3-gone.marks"; : > "$marks"
    "$VD" 12 > "$OUT/vd1.out" & vd=$!
    sleep 3; id="$(display_id "$OUT/vd1.out")"
    [[ -n "$id" ]] || { echo "virtual display not created"; exit 1; }
    "$APP" run watch-capture --seconds 40 --display-id "$id" --gone-limit 15 > "$log" 2>&1 & w=$!
    wait "$vd"; echo "$(ms) REMOVED display $id" >> "$marks"
    # No CPU spin while the display is absent: CPU time used in 10 s.
    pid="$(pgrep -n -f 'RemoraDev.app/Contents/MacOS/remora-host')"
    cpu() { ps -o time= -p "$pid" | awk -F'[:.]' '{print ($1*60+$2)*100+$3}'; }
    sleep 1; c1="$(cpu)"; sleep 10; c2="$(cpu)"
    echo "$(ms) CPU while absent: $(( (c2 - c1) * 10 )) ms in 10 s" >> "$marks"
    wait "$w" || true
    ;;
  *) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
cat "$marks"
grep -E "START|INTERRUPTED|RESUMED|STOPPED|END" "$log"
