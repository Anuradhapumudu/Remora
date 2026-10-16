#!/usr/bin/env bash
# Build RemoraDev.app (wrapping remora-host), sign it with the local dev identity,
# and run it through Launch Services so macOS attributes Screen Recording
# permission to RemoraDev — not to Terminal.
#
# Usage:
#   scripts/macos/dev-app.sh build
#   scripts/macos/dev-app.sh run <remora-host args…>     # e.g. bench-capture --seconds 60
#
# Output of `run` is printed when the app exits (it is captured via `open --stdout`).
# Paths given to the app (e.g. --out) must be absolute: its working directory is /.
#
# The dev app has its own bundle ID (io.github.anuradhapumudu.Remora.dev), so its
# permission grant is separate from the real Remora app's.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/target/dev/RemoraDev.app"
BUNDLE_ID="io.github.anuradhapumudu.Remora.dev"
IDENTITY="Remora Local Dev Signing"

build() {
  security find-identity -p codesigning | grep -q "$IDENTITY" || {
    echo "dev identity missing — run: scripts/macos/dev-identity.sh create" >&2; exit 1; }
  (cd "$ROOT" && cargo build --release --locked -p remora-host)
  rm -rf "$APP"
  mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
  cp "$ROOT/target/release/remora-host" "$APP/Contents/MacOS/remora-host"
  cp "$ROOT/packaging/macos/Remora.icns" "$APP/Contents/Resources/RemoraDev.icns"
  VERSION="$(cd "$ROOT" && cargo metadata --no-deps --format-version 1 \
    | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"
  sed -e "s/@BUNDLE_ID@/$BUNDLE_ID/" -e "s/@SHORT_VERSION@/$VERSION/" -e "s/@BUILD_VERSION@/$VERSION.0/" \
      -e "s|<string>remora-viewer</string>|<string>remora-host</string>|" \
      -e "s|<string>Remora</string>|<string>RemoraDev</string>|g" \
      "$ROOT/packaging/macos/Info.plist.in" > "$APP/Contents/Info.plist"
  # Background-only agent app: no Dock icon, never takes focus.
  plutil -insert LSUIElement -bool true "$APP/Contents/Info.plist"
  plutil -lint "$APP/Contents/Info.plist" >/dev/null
  codesign --force --sign "$IDENTITY" --identifier "$BUNDLE_ID" "$APP/Contents/MacOS/remora-host"
  codesign --force --sign "$IDENTITY" --identifier "$BUNDLE_ID" "$APP"
  codesign --verify --strict "$APP"
  echo "built and signed: $APP"
}

run() {
  [[ -d "$APP" ]] || build
  LOG="$(mktemp -t remora-dev)"
  # -W wait for exit, -n new instance, -g don't bring to the foreground (activating
  # an app would switch away from a full-screen Space, e.g. the motion pattern).
  open -W -n -g --stdout "$LOG" --stderr "$LOG" "$APP" --args "$@" || true
  cat "$LOG"; rm -f "$LOG"
}

case "${1:-}" in
  build) build ;;
  run) shift; run "$@" ;;
  *) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
