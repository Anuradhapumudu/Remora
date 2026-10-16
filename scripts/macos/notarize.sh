#!/usr/bin/env bash
# Notarize and staple a signed .dmg using an App Store Connect API key.
#
# Usage: scripts/macos/notarize.sh path/to/Remora.dmg
#
# Environment (all required):
#   APPLE_API_KEY_PATH   path to the AuthKey_XXXXXX.p8 file
#   APPLE_API_KEY_ID     the key ID (10 characters)
#   APPLE_API_ISSUER_ID  the issuer UUID from App Store Connect → Users and Access → Integrations
#
# notarytool uploads the DMG to Apple, waits for the automated malware scan, and
# stapler attaches the resulting ticket so Gatekeeper can verify it offline.
set -euo pipefail

DMG="${1:?usage: notarize.sh <dmg>}"
: "${APPLE_API_KEY_PATH:?}" "${APPLE_API_KEY_ID:?}" "${APPLE_API_ISSUER_ID:?}"

xcrun notarytool submit "$DMG" \
  --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID" \
  --wait --timeout 30m --output-format json | tee "$DMG.notary.json"

status="$(plutil -extract status raw -o - "$DMG.notary.json" 2>/dev/null || true)"
if [[ "$status" != "Accepted" ]]; then
  echo "Notarization failed (status: ${status:-unknown}). Fetch the log with:" >&2
  echo "  xcrun notarytool log <submission-id> --key ... --key-id ... --issuer ..." >&2
  exit 1
fi
rm -f "$DMG.notary.json"

xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
