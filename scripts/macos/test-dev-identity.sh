#!/usr/bin/env bash
# Test of dev-identity.sh (roadmap D-9). Deleting the dev identity cannot be
# undone, so before it is deleted this proves `create` can make a working one
# again and `remove` deletes all of it. Runs against a THROWAWAY keychain in a
# temp folder (REMORA_DEV_KEYCHAIN); never touches the login keychain.
#
# Checks:
#   1. create -> status shows a code-signing identity (certificate + private key)
#   2. a binary signed with it as the dev app has the designated requirement
#      `identifier "<bundle id>" and certificate leaf = H"<cert SHA-1>"` — the
#      shape macOS's privacy database (TCC) matches a grant against
#   3. remove -> status "not present", and no private key with its label is left
#   4. the user's keychain search list is the same before and after
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NAME="Remora Local Dev Signing"
BUNDLE_ID="io.github.anuradhapumudu.Remora.dev"

fail() { echo "FAIL: $*" >&2; exit 1; }
# Private keys show up in dump-keychain as class 0x00000010; count those labelled NAME.
keys_named() {
  security dump-keychain "$KC" | awk -v n="\"$NAME\"" '
    /^class: / { k = ($2 == "0x00000010") }
    k && index($0, n) { c++; k = 0 }
    END { print c + 0 }'
}

TMP="$(mktemp -d)"
KC="$TMP/remora-dev-test.keychain-db"
SEARCH_BEFORE="$(security list-keychains -d user)"
cleanup() { security delete-keychain "$KC" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

security create-keychain -p "$(/usr/bin/openssl rand -hex 16)" "$KC"
security set-keychain-settings "$KC"   # no auto-lock while the test runs
export REMORA_DEV_KEYCHAIN="$KC"

# 1. create
out="$("$HERE/dev-identity.sh" create)"
echo "$out"
grep -q "\"$NAME\"" <<<"$out" || fail "create: status shows no code-signing identity"
grep -q "no matching private key" <<<"$out" && fail "create: certificate without its private key"
[ "$(keys_named)" = 1 ] || fail "create: expected 1 private key labelled \"$NAME\", found $(keys_named)"

# 2. sign as the dev app; the requirement must name the identifier and this certificate
cp /bin/echo "$TMP/probe"
codesign --force --sign "$NAME" --keychain "$KC" --identifier "$BUNDLE_ID" "$TMP/probe"
codesign --verify --strict "$TMP/probe"
sha1="$(security find-certificate -c "$NAME" -Z "$KC" | awk '/^SHA-1 hash:/ { print tolower($3) }')"
[ -n "$sha1" ] || fail "no SHA-1 for the certificate"
got="$(codesign -d -r- "$TMP/probe" 2>&1 | grep '^designated => ' || true)"
want="designated => identifier \"$BUNDLE_ID\" and certificate leaf = H\"$sha1\""
echo "$got"
[ "$got" = "$want" ] || fail "designated requirement: want <$want>, got <$got>"

# 3. remove deletes the certificate and the private key
"$HERE/dev-identity.sh" remove
[ "$("$HERE/dev-identity.sh" status)" = "not present" ] || fail "remove: certificate still present"
[ "$(keys_named)" = 0 ] || fail "remove: private key labelled \"$NAME\" still in the keychain"

# 4. the search list is unchanged (the throwaway keychain is deleted by the trap;
#    check here with it deleted, so the check itself sees the final state)
security delete-keychain "$KC"
[ "$(security list-keychains -d user)" = "$SEARCH_BEFORE" ] || fail "keychain search list changed"
echo "keychain search list unchanged:"
echo "$SEARCH_BEFORE"
echo "PASS: dev-identity.sh create/sign/remove"
