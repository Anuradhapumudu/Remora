#!/bin/sh
# DEVELOPER TOOL (Phase 4.6 testing only): run the Remora host on the
# owner's Fedora laptop from the Mac, over the owner's shared SSH
# connection. Not part of the product; see docs/laptop-host-notes.md.
#
#   scripts/dev/laptop-host.sh start [--flag ...]
#                                        start the host (prints code + password);
#                                        plain --flags go to `serve`, e.g. --mute-speakers
#   scripts/dev/laptop-host.sh code      print the newest code + password
#   scripts/dev/laptop-host.sh status    the host's recent lines (no secrets)
#   scripts/dev/laptop-host.sh stop      stop the host
#
# Needs the shared connection, opened by the owner (password typed by them):
#   ssh -M -S ~/.ssh/remora-laptop -o ControlPersist=12h -fN pumudu@<laptop-ip>
# REMORA_LAPTOP overrides the address (default 192.168.8.100).
set -eu

LAPTOP="${REMORA_LAPTOP:-192.168.8.100}"
SOCK="$HOME/.ssh/remora-laptop"

lap() {
    ssh -S "$SOCK" -o BatchMode=yes "pumudu@$LAPTOP" "$@"
}

if ! ssh -S "$SOCK" -O check "pumudu@$LAPTOP" >/dev/null 2>&1; then
    echo "no shared SSH connection to $LAPTOP - open it first (you type the password):" >&2
    echo "  ssh -M -S ~/.ssh/remora-laptop -o ControlPersist=12h -fN pumudu@$LAPTOP" >&2
    exit 2
fi

case "${1:-}" in
start)
    # start.sh starts the host inside the GNOME session, reading typed
    # commands from the pipe ~/remora-run/in (see the notes). Extra
    # arguments must be plain flags (they pass through a remote shell).
    shift
    for a in "$@"; do
        case "$a" in
        --*[!a-z-]*|-|--) echo "not a plain --flag: $a" >&2; exit 2 ;;
        --*) ;;
        *) echo "not a plain --flag: $a" >&2; exit 2 ;;
        esac
    done
    lap "pkill -x remora-host; pkill -x tail; sleep 1; ~/remora-run/start.sh $*; sleep 3; grep -E '^(listening|control|code|password|speakers):' ~/remora-run/host.log"
    ;;
code)
    lap 'grep -E "^(code|password):" ~/remora-run/host.log | tail -2'
    ;;
status)
    # Session lines only: no codes or passwords.
    lap 'grep -E "^(prompt|SESSION|session ended|connection lost|failed|input|streaming|capture|refused|cannot)" ~/remora-run/host.log | tail -8'
    ;;
stop)
    lap 'pkill -x remora-host && echo "host stopped" || echo "host was not running"; pkill -x tail || true'
    ;;
*)
    sed -n '2,15p' "$0"
    exit 2
    ;;
esac
