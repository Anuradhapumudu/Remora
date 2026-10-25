#!/usr/bin/env bash
# Local, self-signed code-signing identity for development builds of Remora.
#
# Why: macOS ties Screen Recording / Accessibility permission to an app's code
# signature. Ad-hoc signatures change on every rebuild (so macOS re-asks); a
# stable local identity keeps the permission across rebuilds. This identity is
# trusted ONLY on this Mac, ONLY for code signing, and is useless for
# distribution (that needs an Apple Developer ID — docs/distribution.md).
#
# Usage:
#   scripts/macos/dev-identity.sh status   # show whether it exists (changes nothing)
#   scripts/macos/dev-identity.sh create   # add it to your login keychain
#   scripts/macos/dev-identity.sh remove   # delete everything `create` added
#
# Tested by scripts/macos/test-dev-identity.sh (CI, macOS) on a throwaway keychain.
#
# What `create` adds to ~/Library/Keychains/login.keychain-db — exactly two items:
#   1. a private key   (RSA 2048, label "Remora Local Dev Signing")
#   2. a certificate   (CN "Remora Local Dev Signing", self-signed, valid 3 years,
#                       extendedKeyUsage = codeSigning only)
# No trust settings, no system keychain, no admin rights, no password prompt.
# (No trust is needed: macOS permissions check the app's designated requirement —
# "identifier … and certificate leaf = H<fingerprint>" — not a trusted root.)
set -euo pipefail

NAME="Remora Local Dev Signing"
# macOS's own LibreSSL: Homebrew OpenSSL 3+/4 writes .p12 files with algorithms the
# macOS keychain can't import ("MAC verification failed").
OPENSSL=/usr/bin/openssl
# REMORA_DEV_KEYCHAIN is for the script's own test (test-dev-identity.sh), which
# runs create/remove against a throwaway keychain; normal use leaves it unset.
KEYCHAIN="${REMORA_DEV_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}"

exists() { security find-certificate -c "$NAME" "$KEYCHAIN" >/dev/null 2>&1; }

case "${1:-status}" in
  status)
    if exists; then
      echo "present:"
      security find-certificate -c "$NAME" -p "$KEYCHAIN" | "$OPENSSL" x509 -noout -subject -enddate -fingerprint -sha256
      security find-identity -p codesigning "$KEYCHAIN" | grep "$NAME" || echo "(certificate present but no matching private key)"
    else
      echo "not present"
    fi
    ;;

  create)
    if exists; then echo "already exists — nothing to do"; exit 0; fi
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    umask 077
    cat > "$TMP/openssl.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $NAME
[ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
EOF
    "$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 1095 -config "$TMP/openssl.cnf" \
      -keyout "$TMP/key.pem" -out "$TMP/cert.pem" 2>/dev/null
    P12_PASS="$("$OPENSSL" rand -hex 16)"
    "$OPENSSL" pkcs12 -export -inkey "$TMP/key.pem" -in "$TMP/cert.pem" -name "$NAME" \
      -passout "pass:$P12_PASS" -out "$TMP/id.p12"
    # -T: let /usr/bin/codesign use the key without asking each time.
    security import "$TMP/id.p12" -k "$KEYCHAIN" -P "$P12_PASS" -T /usr/bin/codesign
    echo "created:"; "$0" status
    ;;

  remove)
    if ! exists; then echo "not present — nothing to do"; exit 0; fi
    security delete-identity -c "$NAME" "$KEYCHAIN"   # deletes the certificate AND its private key
    echo "removed. Also revoke the app's permission if you granted it:"
    echo "  tccutil reset ScreenCapture io.github.anuradhapumudu.Remora.dev"
    ;;

  *) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
