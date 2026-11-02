#!/bin/sh
# DEVELOPER TOOL (Phase 4.6 testing only): accept the viewer waiting at
# the laptop's host, from the Mac - ONLY if the safety code you read in
# YOUR viewer window equals the one the laptop shows. Matching codes prove
# no one sits between the two machines; a mismatch is refused and nothing
# is accepted. Owner, 2026-11-02: "can we approve that in terminal using
# command ... only for now". The proper answer for an unattended host is a
# decision in the "Connect simply" criteria (roadmap D-52).
#
#   scripts/dev/laptop-accept.sh 855732      (or "855 732")
#
# Uses the owner's shared SSH connection (see laptop-host.sh).
# REMORA_RUN_DIR (on the laptop, default ~/remora-run) exists for the
# script's own test with a fake log.
set -eu

LAPTOP="${REMORA_LAPTOP:-192.168.8.100}"
SOCK="$HOME/.ssh/remora-laptop"

want=$(printf '%s' "${*:-}" | tr -d ' ')
case "$want" in
[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
*)
    echo "usage: $0 <the six-digit safety code shown in YOUR viewer>" >&2
    exit 2
    ;;
esac

if ! ssh -S "$SOCK" -O check "pumudu@$LAPTOP" >/dev/null 2>&1; then
    echo "no shared SSH connection to $LAPTOP - see scripts/dev/laptop-host.sh" >&2
    exit 2
fi

# On the laptop: the newest prompt, its number and code; accept only when
# the codes match AND that prompt is still waiting (not withdrawn/ended).
ssh -S "$SOCK" -o BatchMode=yes "pumudu@$LAPTOP" sh -s "$want" "${REMORA_RUN_DIR:-}" <<'EOF'
want="$1"
cd "${2:-$HOME/remora-run}" || exit 1
line=$(grep '^prompt [0-9]*:' host.log | tail -1)
if [ -z "$line" ]; then
    echo "no viewer is waiting at the laptop"
    exit 1
fi
n=$(printf '%s\n' "$line" | sed -E 's/^prompt ([0-9]+):.*/\1/')
have=$(printf '%s\n' "$line" | sed -E 's/.*safety code ([0-9]{3}) ([0-9]{3}) .*/\1\2/')
if grep -Eq "^(prompt withdrawn $n|session ended $n|failed $n|SESSION ACTIVE $n)" host.log; then
    echo "prompt $n is no longer waiting (accepted, timed out or gone) - nothing done"
    exit 1
fi
if [ "$have" != "$want" ]; then
    echo "CODES DIFFER: laptop shows $have, you typed $want - NOT accepted."
    echo "Do not continue: someone may be between the two computers. Type 'deny' or let it time out."
    exit 1
fi
echo "accept $n" > in
sleep 4
echo "codes match ($have): accepted $n"
grep -E "^(SESSION ACTIVE $n|streaming|cannot|failed $n)" host.log | tail -3
EOF
