#!/usr/bin/env python3
"""Fail if a newly locked crates.io package is less than 14 days old.

Enforces docs/dependencies.md policy rule 1 mechanically (architecture.md
D9). cargo-deny 0.20.2 has no release-age check, and cargo's
`-Z min-publish-age` is nightly-only and filters resolution rather than
checking a lockfile, so this script does it.

Usage:
    check-crate-age.py [--base REF] [--all] LOCKFILE...
    check-crate-age.py --exceptions-only      # only the exceptions (fast; pre-push)
    check-crate-age.py --self-test

* With --base, only (name, version) pairs that are new in LOCKFILE compared
  with the same path at REF are checked: an entry that passed once only gets
  older. Without --base (or with --all) every registry entry is checked.
* The release time comes from the crates.io API (`created_at` of that exact
  version). Requests are spaced 1 s apart (crates.io crawler policy).
* Fails CLOSED: if a version cannot be looked up, that is a failure, not a pass.
* **Security-fix exceptions** (`.cargo/crate-age-exceptions.txt`, one line per
  exception: `name version RUSTSEC-ID...`): a too-new release may be adopted
  only if it is the first patched release for RustSec advisories that affect
  the previous one. Each exception is VERIFIED, not trusted: every listed
  advisory is fetched from the RustSec advisory database and must name the
  same package with `">= <version>"` among its patched bounds. An exception
  whose version is already >= 14 days old is reported as stale (remove it).
* Every exception's exact expiry (release time + 14 days, UTC) is printed,
  and one that expires in under 48 hours is a WARNING (a GitHub annotation
  in CI), so its removal is scheduled from the check, not from a date
  counted by hand: D-37 was written as "2026-10-27" for a release that
  turned 14 days old at 20:51 UTC that day (owner, 2026-10-27).

Stdlib only (runs on the runners' system Python 3.10, so no tomllib).
"""

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

MIN_AGE = dt.timedelta(days=14)
WARN_BEFORE = dt.timedelta(hours=48)
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
        # OSError covers URLError and timeouts raised while reading the body.
        except (OSError, KeyError, ValueError) as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"could not look up {name} {version}: {last}")


ADVISORY_URL = "https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/{name}/{id}.md"


def load_exceptions(path):
    """{(name, version): [advisory ids]} from the exceptions file."""
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return out
    for n, line in enumerate(lines, 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3 or not all(re.fullmatch(r"RUSTSEC-\d{4}-\d{4}", p) for p in parts[2:]):
            sys.exit(f"{path}:{n}: expected `name version RUSTSEC-YYYY-NNNN...`")
        out[(parts[0], parts[1])] = parts[2:]
    return out


def fetch_advisory(name, advisory_id):
    url = ADVISORY_URL.format(name=name, id=advisory_id)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except OSError as e:
        raise RuntimeError(f"could not fetch {advisory_id}: {e}") from e


def exception_holds(name, version, ids, fetch_adv):
    """None if every advisory names this package and patches exactly at
    `version`; otherwise the reason it does not."""
    for advisory_id in ids:
        try:
            text = fetch_adv(name, advisory_id)
        except RuntimeError as e:
            return str(e)
        if f'package = "{name}"' not in text:
            return f"{advisory_id} is not an advisory for {name}"
        patched = re.search(r"^patched\s*=\s*\[(.*?)\]", text, re.M | re.S)
        # A bound may be a range: ">= 0.103.16, < 0.104.0-alpha.1"
        # (RUSTSEC-2026-0382). Only the ">=" part is the first patched version.
        bounds = re.findall(r'">=\s*([^",]+)', patched.group(1)) if patched else []
        if version not in [b.strip() for b in bounds]:
            return f"{advisory_id} does not name {version} as a first patched release ({bounds})"
    return None


def check_exceptions(exceptions, fetch, now, fetch_adv=None, pause=1.0, warnings=None, annotate=True):
    """Validate EVERY exception line, whether or not its crate changed in
    this diff (owner condition, D28): each one applies to exactly one crate,
    one version and its listed advisories, and EXPIRES once that release is
    14 days old - then the line must be deleted, so none can linger.
    Prints each exception's expiry; one expiring within WARN_BEFORE is
    appended to `warnings` (if given) and printed as a warning; with
    `annotate` (never in the self-test) it is also a GitHub annotation."""
    failures = []
    for i, ((name, version), ids) in enumerate(sorted(exceptions.items())):
        if i and pause:
            time.sleep(pause)
        try:
            created = fetch(name, version)
        except RuntimeError as e:
            failures.append(f"UNVERIFIED exception {name} {version}: {e}")
            continue
        age = now - created
        if age >= MIN_AGE:
            failures.append(
                f"EXPIRED   exception {name} {version} ({age.days} days old): delete its line "
                "from .cargo/crate-age-exceptions.txt (the 14-day rule now covers it)"
            )
            continue
        why_not = exception_holds(name, version, ids, fetch_adv or fetch_advisory)
        if why_not is not None:
            failures.append(f"BAD EXCEPTION {name} {version}: {why_not}")
            continue
        expires = created + MIN_AGE
        left = expires - now
        mins = int(left.total_seconds() // 60)
        span = f"{mins // 60} h {mins % 60:02d} min"
        print(f"EXCEPTION {name} {version}: released {created:%Y-%m-%d %H:%M} UTC, "
              f"expires {expires:%Y-%m-%d %H:%M} UTC (in {span})")
        if left < WARN_BEFORE:
            msg = (f"exception {name} {version} expires {expires:%Y-%m-%d %H:%M} UTC "
                   f"(in {span}): delete its line from .cargo/crate-age-exceptions.txt "
                   f"AFTER that time, not before (until then {name} {version} is under 14 days old)")
            if warnings is not None:
                warnings.append(msg)
            print(f"WARNING   {msg}")
            if annotate and os.environ.get("GITHUB_ACTIONS") == "true":
                print(f"::warning title=crate-age exception expiring::{msg}")
    return failures


def check(entries, fetch, now, pause=1.0, exceptions=None, fetch_adv=None):
    """Return a list of failure messages for entries younger than MIN_AGE."""
    exceptions = exceptions or {}
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
        ids = exceptions.get((name, version))
        if ids and age < MIN_AGE:
            # Validity of the exception itself is checked by
            # check_exceptions(), which runs on every exception every time.
            print(f"EXCEPTED  {name} {version} ({age.days} days): security fix for {', '.join(ids)}")
            continue
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
    # Exceptions: verified against (fake) advisories, never trusted blindly.
    advisories = {
        ("fresh", "RUSTSEC-2026-0001"): 'package = "fresh"\npatched = [">= 2.0.0"]\n',
        ("fresh", "RUSTSEC-2026-0002"): 'package = "other"\npatched = [">= 2.0.0"]\n',
        ("fresh", "RUSTSEC-2026-0003"): 'package = "fresh"\npatched = [">= 1.9.0"]\n',
        # Compound ranges, shaped like the real RUSTSEC-2026-0382.
        ("fresh", "RUSTSEC-2026-0004"): 'package = "fresh"\npatched = [">= 2.0.0, < 3.0.0-alpha.1", ">= 3.0.0-alpha.8"]\n',
        ("fresh", "RUSTSEC-2026-0005"): 'package = "fresh"\npatched = [">= 1.0.0, < 2.0.0", ">= 3.0.0"]\n',
    }

    def fake_adv(name, advisory_id):
        if (name, advisory_id) not in advisories:
            raise RuntimeError("404")
        return advisories[(name, advisory_id)]

    def run(ids):
        exc = {("fresh", "2.0.0"): ids}
        return check_exceptions(exc, fake, now, fetch_adv=fake_adv, pause=0, annotate=False) + check(
            entries, fake, now, pause=0, exceptions=exc, fetch_adv=fake_adv
        )

    ok = sorted(re.match(r"(?:TOO NEW|UNVERIFIED) +(\S+)", f).group(1) for f in run(["RUSTSEC-2026-0001"]))
    assert ok == ["edge-new", "missing"], ok
    ok = sorted(re.match(r"(?:TOO NEW|UNVERIFIED) +(\S+)", f).group(1) for f in run(["RUSTSEC-2026-0004"]))
    assert ok == ["edge-new", "missing"], ("compound range rejected", ok)
    for bad_ids in (["RUSTSEC-2026-0002"], ["RUSTSEC-2026-0003"], ["RUSTSEC-2026-0009"],
                    ["RUSTSEC-2026-0001", "RUSTSEC-2026-0002"],
                    # 2.0.0 is only the excluded upper end of a range here
                    ["RUSTSEC-2026-0005"]):
        assert any(f.startswith("BAD EXCEPTION fresh") for f in run(bad_ids)), bad_ids
    # An exception expires once its release is 14 days old: it must fail
    # (forcing the line's removal), even if that crate is not in the diff.
    expired = check_exceptions({("old", "1.0.0"): ["RUSTSEC-2026-0001"]}, fake, now, fetch_adv=fake_adv, pause=0,
                               annotate=False)
    assert len(expired) == 1 and expired[0].startswith("EXPIRED"), expired
    # Expiry warning: under 48 h left warns; 13 days left (fresh) and exactly
    # 48 h left (edge) do not.
    for left, warns in ((dt.timedelta(hours=23), True), (dt.timedelta(hours=47, minutes=59), True),
                        (dt.timedelta(hours=48), False), (dt.timedelta(days=13), False)):
        created = now - MIN_AGE + left
        w = []
        f = check_exceptions({("soon", "1.0.0"): ["RUSTSEC-2026-0001"]}, lambda n, v: created, now,
                             fetch_adv=lambda n, i: 'package = "soon"\npatched = [">= 1.0.0"]\n', pause=0,
                             warnings=w, annotate=False)
        assert f == [], f
        assert bool(w) == warns, (left, w)
        assert not w or "expires 2026-10-" in w[0], w
    # The self-test never writes GitHub annotations, even in CI: its fake
    # exceptions must not show up next to the real ones (seen in CI 2026-10-27).
    import contextlib, io
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        os.environ["GITHUB_ACTIONS"] = "true"
        try:
            check_exceptions({("soon", "1.0.0"): ["RUSTSEC-2026-0001"]}, lambda n, v: now - MIN_AGE + dt.timedelta(hours=1),
                             now, fetch_adv=lambda n, i: 'package = "soon"\npatched = [">= 1.0.0"]\n', pause=0,
                             annotate=False)
        finally:
            os.environ.pop("GITHUB_ACTIONS")
    assert "WARNING" in out.getvalue() and "::warning" not in out.getvalue(), out.getvalue()
    # An exception only covers its own version: the same crate at another
    # version is still TOO NEW.
    other = check({("fresh", "2.0.1")}, lambda n, v: now - dt.timedelta(days=1), now, pause=0,
                  exceptions={("fresh", "2.0.0"): ["RUSTSEC-2026-0001"]}, fetch_adv=fake_adv)
    assert len(other) == 1 and other[0].startswith("TOO NEW"), other
    # Diffing: an entry present at the base is not re-checked.
    base = lock.split("[[package]]\nname = \"fresh\"")[0]
    assert ("fresh", "2.0.0") in registry_entries(lock) - registry_entries(base)
    print("self-test: ok (planted too-new, edge, unverifiable entries, bad, expired and wrong-version exceptions all caught; "
          "expiry warnings under 48 h, none at 48 h or 13 days)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", help="git ref to diff against (only new entries are checked)")
    ap.add_argument("--all", action="store_true", help="check every entry")
    ap.add_argument("--exceptions-only", action="store_true",
                    help="check only the exceptions file (validity, expiry, 48 h warning)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("lockfiles", nargs="*")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.exceptions_only:
        exceptions = load_exceptions(".cargo/crate-age-exceptions.txt")
        failures = check_exceptions(exceptions, fetch_created_at, dt.datetime.now(dt.timezone.utc))
        for f in failures:
            print(f, file=sys.stderr)
        print(f"{len(exceptions)} exception(s) checked, {len(failures)} failure(s)")
        return 1 if failures else 0
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
    exceptions = load_exceptions(".cargo/crate-age-exceptions.txt")
    now = dt.datetime.now(dt.timezone.utc)
    failures = check_exceptions(exceptions, fetch_created_at, now)
    failures += check(entries, fetch_created_at, now, exceptions=exceptions)
    for f in failures:
        print(f, file=sys.stderr)
    if failures:
        print(f"{len(failures)} package(s) violate the 14-day rule", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
