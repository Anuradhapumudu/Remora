#!/usr/bin/env bash
# Build Linux packages (.deb, .rpm, AppImage, .tar.gz) from an existing
# `cargo build --release` of remora-host and remora-viewer (native x86_64, glibc).
#
# Usage: scripts/linux/package.sh --version X.Y.Z[-suffix] [--out dist]
#
# Requires: cargo-deb, cargo-generate-rpm (CI installs them), curl, sha256sum.
set -euo pipefail

VERSION="" OUT="dist"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ -n "$VERSION" ]] || { echo "--version is required" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
mkdir -p "$OUT"
BIN_DIR="target/release"
for b in remora-host remora-viewer; do
  [[ -x "$BIN_DIR/$b" ]] || { echo "missing $BIN_DIR/$b — run cargo build --release first" >&2; exit 1; }
done

# The maintainer string has exactly one source: `authors` in the workspace Cargo.toml.
MAINTAINER="$(cargo metadata --no-deps --format-version 1 \
  | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["authors"][0])')"
[[ "$MAINTAINER" == *"<"*"@"*">" ]] || { echo "bad maintainer string: $MAINTAINER" >&2; exit 1; }

# Package managers order "0.1.0-nightly.x" *after* 0.1.0; "~" sorts before, which is what we want.
BASE="${VERSION%%-*}"
if [[ "$VERSION" == *-* ]]; then
  SUFFIX="${VERSION#*-}"
  DEB_VERSION="$BASE~$SUFFIX"
  RPM_RELEASE="0.${SUFFIX//-/.}"
else
  DEB_VERSION="$BASE"
  RPM_RELEASE="1"
fi

# 1. .deb (cargo-deb) — $auto computes shared-library dependencies via dpkg-shlibdeps.
cargo deb -p remora-viewer --no-build --deb-version "$DEB_VERSION" -o "$OUT/"

# 2. .rpm (cargo-generate-rpm). RPM versions cannot contain '-', so the suffix goes in Release.
cargo generate-rpm -p crates/remora-viewer -o "$OUT/" \
  -s "release = \"$RPM_RELEASE\"" -s "vendor = \"$MAINTAINER\""

# 3. AppImage — tools pinned by version AND sha256 (supply chain, threat model §7.8).
APPIMAGETOOL_URL="https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage"
APPIMAGETOOL_SHA256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
RUNTIME_URL="https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64"
RUNTIME_SHA256="2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"

TOOLS="$(mktemp -d)"
trap 'rm -rf "$TOOLS"' EXIT
curl -sSfL -o "$TOOLS/appimagetool" "$APPIMAGETOOL_URL"
curl -sSfL -o "$TOOLS/runtime" "$RUNTIME_URL"
echo "$APPIMAGETOOL_SHA256  $TOOLS/appimagetool" | sha256sum -c -
echo "$RUNTIME_SHA256  $TOOLS/runtime" | sha256sum -c -
chmod +x "$TOOLS/appimagetool"

APPDIR="$TOOLS/Remora.AppDir"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"
install -m 755 "$BIN_DIR/remora-host" "$BIN_DIR/remora-viewer" "$APPDIR/usr/bin/"
install -m 644 packaging/linux/remora.desktop "$APPDIR/usr/share/applications/"
install -m 644 packaging/linux/remora.desktop "$APPDIR/remora.desktop"
install -m 644 packaging/icons/remora-256.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/remora.png"
install -m 644 packaging/icons/remora-256.png "$APPDIR/remora.png"
ln -s usr/bin/remora-viewer "$APPDIR/AppRun"

# APPIMAGE_EXTRACT_AND_RUN avoids needing FUSE on the build machine.
APPIMAGE_EXTRACT_AND_RUN=1 ARCH=x86_64 "$TOOLS/appimagetool" --no-appstream \
  --runtime-file "$TOOLS/runtime" "$APPDIR" "$OUT/Remora-$VERSION-linux-x86_64.AppImage"

# 4. Plain tarball for people who want to unpack and run.
TARDIR="$TOOLS/remora-$VERSION-linux-x86_64"
mkdir -p "$TARDIR"
install -m 755 "$BIN_DIR/remora-host" "$BIN_DIR/remora-viewer" "$TARDIR/"
cp LICENSE-GPL "$TARDIR/LICENSE"
tar -C "$TOOLS" -czf "$OUT/remora-$VERSION-linux-x86_64.tar.gz" "remora-$VERSION-linux-x86_64"

ls -1 "$OUT"
