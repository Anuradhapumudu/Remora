#!/usr/bin/env bash
# Build RemoraViewerDev.app (wrapping remora-viewer) so the viewer GUI starts
# without a terminal (phase4.5-criteria §0 item 7, Q9). Unsigned on purpose:
# the viewer needs no capture permission, so no dev identity is involved
# (the arm64 linker's ad-hoc signature is all it carries).
#
# Usage:
#   scripts/macos/viewer-dev-app.sh build    # target/dev/RemoraViewerDev.app
#   scripts/macos/viewer-dev-app.sh open     # build if needed, then open it
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/target/dev/RemoraViewerDev.app"
BUNDLE_ID="io.github.anuradhapumudu.Remora.viewer.dev"

build() {
  (cd "$ROOT" && cargo build --release --locked -p remora-viewer)
  rm -rf "$APP"
  mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
  cp "$ROOT/target/release/remora-viewer" "$APP/Contents/MacOS/remora-viewer"
  cp "$ROOT/packaging/macos/Remora.icns" "$APP/Contents/Resources/RemoraViewerDev.icns"
  VERSION="$(cd "$ROOT" && cargo metadata --no-deps --format-version 1 \
    | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"
  sed -e "s/@BUNDLE_ID@/$BUNDLE_ID/" -e "s/@SHORT_VERSION@/$VERSION/" -e "s/@BUILD_VERSION@/$VERSION.0/" \
      -e "s|<string>Remora</string>|<string>RemoraViewerDev</string>|g" \
      "$ROOT/packaging/macos/Info.plist.in" > "$APP/Contents/Info.plist"
  # Opened with no arguments: the viewer GUI (remora_app::cli::args_or_gui).
  plutil -insert LSEnvironment -json '{"REMORA_GUI":"1"}' "$APP/Contents/Info.plist"
  plutil -lint "$APP/Contents/Info.plist" >/dev/null
  echo "built: $APP"
}

case "${1:-}" in
  build) build ;;
  open) [[ -d "$APP" ]] || build; open "$APP" ;;
  *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
