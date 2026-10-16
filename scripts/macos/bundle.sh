#!/usr/bin/env bash
# Build Remora.app (universal arm64 + x86_64) and a .dmg from already-built binaries.
#
# Usage:
#   scripts/macos/bundle.sh --arm64-dir DIR --x86_64-dir DIR --version X.Y.Z[-suffix] \
#                           [--build-number N] [--out dist]
#
#   DIR is a cargo output directory containing remora-host and remora-viewer,
#   e.g. target/aarch64-apple-darwin/release.
#
# Signing (all optional, from the environment):
#   MACOS_SIGNING_IDENTITY  codesign identity (e.g. "Developer ID Application: Name (TEAMID)"
#                           or a local self-signed dev identity). Unset → ad-hoc signature
#                           ("-"), which Apple Silicon requires at minimum.
#   REMORA_BUNDLE_ID        defaults to io.github.anuradhapumudu.Remora
#
# Notarization is a separate step: scripts/macos/notarize.sh <dmg>.
set -euo pipefail

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

ARM_DIR="" X86_DIR="" VERSION="" BUILD_NUMBER="0" OUT="dist"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --arm64-dir) ARM_DIR="$2"; shift 2 ;;
    --x86_64-dir) X86_DIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --build-number) BUILD_NUMBER="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done
[[ -n "$ARM_DIR" && -n "$X86_DIR" && -n "$VERSION" ]] || usage 1
[[ "$BUILD_NUMBER" =~ ^[0-9]+$ ]] || { echo "--build-number must be numeric" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUNDLE_ID="${REMORA_BUNDLE_ID:-io.github.anuradhapumudu.Remora}"
IDENTITY="${MACOS_SIGNING_IDENTITY:-}"
SHORT_VERSION="${VERSION%%-*}"            # CFBundleShortVersionString must be X.Y.Z
[[ "$SHORT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bad version: $VERSION" >&2; exit 1; }
BINS=(remora-host remora-viewer)

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
APP="$STAGE/Remora.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$OUT"

# 1. Universal binaries: lipo glues the arm64 and x86_64 builds into one file.
for b in "${BINS[@]}"; do
  lipo -create -output "$APP/Contents/MacOS/$b" "$ARM_DIR/$b" "$X86_DIR/$b"
  archs="$(lipo -archs "$APP/Contents/MacOS/$b")"
  [[ "$archs" == *arm64* && "$archs" == *x86_64* ]] || { echo "$b is not universal: $archs" >&2; exit 1; }
done

# 2. Info.plist and resources.
sed -e "s/@BUNDLE_ID@/$BUNDLE_ID/" \
    -e "s/@SHORT_VERSION@/$SHORT_VERSION/" \
    -e "s/@BUILD_VERSION@/$SHORT_VERSION.$BUILD_NUMBER/" \
    "$ROOT/packaging/macos/Info.plist.in" > "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null
cp "$ROOT/packaging/macos/Remora.icns" "$APP/Contents/Resources/Remora.icns"
cp "$ROOT/LICENSE-GPL" "$APP/Contents/Resources/LICENSE"

# 3. Sign. Nested executables first, then the bundle (codesign --deep is discouraged).
#    Hardened runtime (--options runtime) + secure timestamp are required for notarization;
#    a timestamp needs Apple's server, so only use it with a real identity.
if [[ -n "$IDENTITY" ]]; then
  SIGN=(codesign --force --options runtime --timestamp --sign "$IDENTITY" --identifier "$BUNDLE_ID")
  echo "Signing with identity: $IDENTITY"
else
  SIGN=(codesign --force --sign - --identifier "$BUNDLE_ID")
  echo "::warning::MACOS_SIGNING_IDENTITY not set — ad-hoc signing. Users will see Gatekeeper warnings and Screen Recording permission will re-prompt after every update."
fi
for b in "${BINS[@]}"; do
  "${SIGN[@]}" "$APP/Contents/MacOS/$b"
done
"${SIGN[@]}" "$APP"
codesign --verify --strict --verbose=2 "$APP"

# 4. DMG with an /Applications shortcut for drag-to-install.
DMG_NAME="Remora-$VERSION-macos-universal.dmg"
mkdir "$STAGE/dmg"
cp -R "$APP" "$STAGE/dmg/"
ln -s /Applications "$STAGE/dmg/Applications"
rm -f "$OUT/$DMG_NAME"
hdiutil create -volname "Remora $VERSION" -srcfolder "$STAGE/dmg" -fs HFS+ \
  -format UDZO -imagekey zlib-level=9 -ov "$OUT/$DMG_NAME" >/dev/null
if [[ -n "$IDENTITY" ]]; then
  codesign --force --timestamp --sign "$IDENTITY" "$OUT/$DMG_NAME"
fi

echo "Built: $OUT/$DMG_NAME"
