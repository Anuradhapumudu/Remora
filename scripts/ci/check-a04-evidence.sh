#!/usr/bin/env bash
# The A04 timing claim (phase3-criteria §3.1a) rests on ONE job: workflow
# "A04 timing" (.github/workflows/timing.yml), job "a04" - 200 samples per
# failure type, release build. Every other A04 run checks only that the
# floor exists. If that one job is disabled, stops running, or skips a
# merge to main, the board stays green with no timing guarantee behind it.
# This check makes that loud. Fails on:
#   1. the workflow is not "active" (disabled manually or by GitHub);
#   2. its last successful run is >= MAX_AGE_H hours old (or there is none);
#   3. the latest commit on main, older than GRACE_H hours (time for the run
#      to finish), has no successful run of its own.
# Needs: gh CLI, GH_TOKEN with actions:read, REPO=owner/name.
set -euo pipefail
WF=timing.yml
MAX_AGE_H=${MAX_AGE_H:-48}
GRACE_H=${GRACE_H:-6}
REPO=${REPO:?set REPO=owner/name}

epoch() { date -u -d "$1" +%s 2>/dev/null || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$1" +%s; }
now=$(date -u +%s)
fail=0

state=$(gh api "repos/$REPO/actions/workflows/$WF" --jq .state)
echo "A04 timing workflow state: $state"
if [ "$state" != "active" ]; then
  echo "::error::the A04 timing workflow is '$state' - the A04 timing claim has no evidence behind it"
  fail=1
fi

last=$(gh run list --repo "$REPO" --workflow "$WF" --status success --limit 1 --json createdAt --jq '.[0].createdAt // empty')
if [ -z "$last" ]; then
  echo "::error::no successful A04 timing run at all"
  fail=1
else
  age_h=$(( (now - $(epoch "$last")) / 3600 ))
  echo "last successful A04 timing run: $last ($age_h h ago)"
  if [ "$age_h" -ge "$MAX_AGE_H" ]; then
    echo "::error::A04 timing evidence is $age_h h old (>= $MAX_AGE_H h)"
    fail=1
  fi
fi

main_sha=$(gh api "repos/$REPO/commits/main" --jq .sha)
main_at=$(gh api "repos/$REPO/commits/main" --jq .commit.committer.date)
main_age_h=$(( (now - $(epoch "$main_at")) / 3600 ))
ok_on_main=$(gh run list --repo "$REPO" --workflow "$WF" --commit "$main_sha" --status success --limit 1 --json databaseId --jq 'length')
echo "main is ${main_sha:0:7} ($main_age_h h old); successful A04 runs for it: $ok_on_main"
if [ "$ok_on_main" -eq 0 ] && [ "$main_age_h" -ge "$GRACE_H" ]; then
  echo "::error::the latest merge to main (${main_sha:0:7}, $main_age_h h old) has no successful A04 timing run"
  fail=1
fi
exit "$fail"
