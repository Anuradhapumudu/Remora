#!/usr/bin/env bash
# CI only: import a Developer ID certificate (.p12) into a temporary keychain.
#
# Environment:
#   MACOS_CERTIFICATE_P12_BASE64  base64 of the exported .p12 (certificate + private key)
#   MACOS_CERTIFICATE_PASSWORD    password chosen when exporting the .p12
#   RUNNER_TEMP                   provided by GitHub Actions
#
# The keychain lives in $RUNNER_TEMP and is deleted with the runner.
set -euo pipefail
: "${MACOS_CERTIFICATE_P12_BASE64:?}" "${MACOS_CERTIFICATE_PASSWORD:?}" "${RUNNER_TEMP:?}"

KEYCHAIN="$RUNNER_TEMP/remora-signing.keychain-db"
KEYCHAIN_PASSWORD="$(openssl rand -base64 32)"
P12="$RUNNER_TEMP/remora-cert.p12"

umask 077
printf '%s' "$MACOS_CERTIFICATE_P12_BASE64" | base64 --decode > "$P12"

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$P12" -k "$KEYCHAIN" -P "$MACOS_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
# Let codesign use the key without a GUI prompt.
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" >/dev/null
# Put it first in the search list (keep the existing ones).
existing=()
while IFS= read -r kc; do
  kc="${kc#"${kc%%[![:space:]]*}"}"   # trim leading whitespace
  existing+=("${kc//\"/}")            # strip quotes
done < <(security list-keychains -d user)
security list-keychains -d user -s "$KEYCHAIN" "${existing[@]}"
rm -f "$P12"

security find-identity -v -p codesigning "$KEYCHAIN"
