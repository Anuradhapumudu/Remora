#!/usr/bin/env bash
# Test of dev-identity.sh (roadmap D-9). Deleting the dev identity cannot be
# undone, so before it is deleted this proves `create` can make a working one
# again and `remove` deletes all of it. Runs against a THROWAWAY keychain in a
# temp folder (REMORA_DEV_KEYCHAIN); never adds to or deletes from the login
# keychain.
#
# Checks:
#   1. create -> status shows a code-signing identity (certificate + private key)
#   2. a binary signed with it as the dev app has the designated requirement
#      `identifier "<bundle id>" and certificate leaf = H"<cert SHA-1>"` — the
#      shape macOS's privacy database (TCC) matches a grant against
#   3. remove -> status "not present", and no private key with its label is left
#   4. the user's keychain search list is the same afterwards
#
# The search list. On macOS 15.7 and 26.6 (GitHub's runners) codesign finds an
# identity only in a keychain ON the search list, even with --keychain; macOS
# 27.0 on the M4 finds it either way (throwaway-branch diagnostic, 2026-10-25).
# So step 2 puts the throwaway keychain on the list for the signing only. The
# list is saved first and restored by a trap on every exit — pass, failure,
# Ctrl-C — and the trap checks it came back exactly as it was.
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

# Save the search list as paths; refuse to go on unless every entry is a real
# keychain file, so a parsing mistake can never make the restore drop one.
SEARCH_BEFORE="$(security list-keychains -d user)"
SAVED=()
while IFS= read -r l; do
  l="${l#"${l%%[![:space:]]*}"}"; l="${l#\"}"; l="${l%\"}"
  [ -n "$l" ] && SAVED+=("$l")
done <<<"$SEARCH_BEFORE"
[ "${#SAVED[@]}" -ge 1 ] || fail "could not read the keychain search list"
for k in "${SAVED[@]}"; do [ -f "$k" ] || fail "search list entry is not a file: $k"; done

TMP="$(mktemp -d)"
KC="$TMP/remora-dev-test.keychain-db"
ON_LIST=0
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ "$ON_LIST" = 1 ]; then
    security list-keychains -d user -s "${SAVED[@]}" || true
  fi
  if [ "$(security list-keychains -d user)" = "$SEARCH_BEFORE" ]; then
    echo "keychain search list as before:"; echo "$SEARCH_BEFORE"
  else
    echo "FAIL: keychain search list NOT restored. It was:" >&2; echo "$SEARCH_BEFORE" >&2
    echo "now:" >&2; security list-keychains -d user >&2; rc=1
  fi
  security delete-keychain "$KC" 2>/dev/null || true
  rm -rf "$TMP"
  [ "$rc" = 0 ] && echo "PASS: dev-identity.sh create/sign/remove, search list unchanged"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

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
ON_LIST=1
security list-keychains -d user -s "$KC" "${SAVED[@]}"
codesign --force --sign "$NAME" --keychain "$KC" --identifier "$BUNDLE_ID" "$TMP/probe"
security list-keychains -d user -s "${SAVED[@]}"
ON_LIST=0
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

# 4. is checked by the exit trap, which prints PASS only if the list is as before
