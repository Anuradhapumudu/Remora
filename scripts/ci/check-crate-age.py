#!/usr/bin/env python3
"""Fail if a newly locked crates.io package is less than 14 days old.

Enforces docs/dependencies.md policy rule 1 mechanically (architecture.md
D9). cargo-deny 0.20.2 has no release-age check, and cargo's
`-Z min-publish-age` is nightly-only and filters resolution rather than
checking a lockfile, so this script does it.

Usage:
    check-crate-age.py [--base REF] [--all] LOCKFILE...
    check-crate-age.py --self-test

* With --base, only (name, version) pairs that are new in LOCKFILE compared
  with the same path at REF are checked: an entry that passed once only gets
  older. Without --base (or with --all) every registry entry is checked.
* The release time comes from the crates.io API (`created_at` of that exact
  version). Requests are spaced 1 s apart (crates.io crawler policy).
* Fails CLOSED: if a version cannot be looked up, that is a failure, not a pass.

Stdlib only (runs on the runners' system Python 3.10, so no tomllib).
"""

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

MIN_AGE = dt.timedelta(days=14)
USER_AGENT = "Remora-CI crate-age check (https://github.com/Anuradhapumudu/Remora)"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
ENTRY = re.compile(
    r'^\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"\nsource = "([^"]+)"', re.M
)


def registry_entries(lock_text):
    """(name, version) of every crates.io package in a Cargo.lock."""
    return {(n, v) for n, v, src in ENTRY.findall(lock_text) if src == REGISTRY}


def lock_at(ref, path):
    """The lockfile at a git ref, or "" if it did not exist there."""
    r = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def fetch_created_at(name, version):
    """Release time of name@version from crates.io (UTC datetime)."""
    url = f"https://crates.io/api/v1/crates/{name}/{version}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.load(resp)
            return dt.datetime.fromisoformat(data["version"]["created_at"].replace("Z", "+00:00"))
        except (urllib.error.URLError, KeyError, ValueError) as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"could not look up {name} {version}: {last}")


def check(entries, fetch, now, pause=1.0):
    """Return a list of failure messages for entries younger than MIN_AGE."""
    failures = []
    for i, (name, version) in enumerate(sorted(entries)):
        if i and pause:
            time.sleep(pause)
        try:
            created = fetch(name, version)
        except RuntimeError as e:
            failures.append(f"UNVERIFIED {name} {version}: {e}")
            continue
        age = now - created
        if age < MIN_AGE:
            failures.append(
                f"TOO NEW   {name} {version}: released {created:%Y-%m-%d}, "
                f"{age.days} days ago (< {MIN_AGE.days}); lock the previous release with "
                f"`cargo update -p {name} --precise <older version>`"
            )
        else:
            print(f"ok        {name} {version} ({age.days} days)")
    return failures


def self_test():
    """Plants too-new and unverifiable entries with a fake registry: the
    check must report exactly those (it is a security control, so it has to
    be seen failing)."""
    now = dt.datetime(2026, 10, 18, tzinfo=dt.timezone.utc)
    dates = {
        ("old", "1.0.0"): now - dt.timedelta(days=400),
        ("edge-ok", "1.0.0"): now - dt.timedelta(days=14),
        ("edge-new", "1.0.0"): now - dt.timedelta(days=13, hours=23),
        ("fresh", "2.0.0"): now - dt.timedelta(days=1),
    }

    def fake(name, version):
        if (name, version) not in dates:
            raise RuntimeError("404")
        return dates[(name, version)]

    lock = "\n".join(
        f'[[package]]\nname = "{n}"\nversion = "{v}"\nsource = "{REGISTRY}"\n'
        for n, v in list(dates) + [("missing", "0.1.0")]
    ) + '[[package]]\nname = "local"\nversion = "0.0.1"\n'
    entries = registry_entries(lock)
    assert ("local", "0.0.1") not in entries, "path crates must be skipped"
    assert len(entries) == 5, entries
    failures = check(entries, fake, now, pause=0)
    flagged = sorted(re.match(r"(?:TOO NEW|UNVERIFIED) +(\S+)", f).group(1) for f in failures)
    assert flagged == ["edge-new", "fresh", "missing"], failures
    assert all(f.startswith(("TOO NEW", "UNVERIFIED")) for f in failures)
    # Diffing: an entry present at the base is not re-checked.
    base = lock.split("[[package]]\nname = \"fresh\"")[0]
    assert ("fresh", "2.0.0") in registry_entries(lock) - registry_entries(base)
    print("self-test: ok (planted too-new, edge and unverifiable entries all caught)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", help="git ref to diff against (only new entries are checked)")
    ap.add_argument("--all", action="store_true", help="check every entry")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("lockfiles", nargs="*")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.lockfiles:
        ap.error("no lockfiles given")
    entries = set()
    for path in args.lockfiles:
        with open(path, encoding="utf-8") as f:
            head = registry_entries(f.read())
        if args.base and not args.all:
            head -= registry_entries(lock_at(args.base, path))
        entries |= head
    print(f"checking {len(entries)} newly locked registry package(s)")
    failures = check(entries, fetch_created_at, dt.datetime.now(dt.timezone.utc))
    for f in failures:
        print(f, file=sys.stderr)
    if failures:
        print(f"{len(failures)} package(s) violate the 14-day rule", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
