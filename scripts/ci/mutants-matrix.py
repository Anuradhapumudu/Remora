#!/usr/bin/env python3
"""Derive the per-crate mutation-gate matrix from .cargo/mutants.toml.

The mutation gate (phase3-criteria §7) runs one CI job per crate so the jobs
run in parallel and a failure names its crate. `.cargo/mutants.toml`
`examine_globs` stays the single source of truth: every glob must name a
file under `crates/<crate>/`, and each such crate becomes one job. A crate
added to the config gets a job automatically; nothing has to be kept in
sync by hand.

Usage:
    mutants-matrix.py                 print the JSON list of crates
    mutants-matrix.py --verify-lists  also check, with `cargo mutants --list`,
                                      that the per-crate lists add up to the
                                      whole-workspace list (no mutant falls
                                      between jobs) and that no crate is empty

Stdlib only (runner Python 3.10: no tomllib), so the array is parsed with a
regex; the script fails loudly if the file does not look as expected.
"""

import json
import re
import subprocess
import sys

CONFIG = ".cargo/mutants.toml"


def crates_in_scope(text):
    m = re.search(r"^examine_globs\s*=\s*\[(.*?)^\]", text, re.S | re.M)
    if not m:
        sys.exit(f"{CONFIG}: no examine_globs array found")
    globs = re.findall(r'^\s*"([^"]+)"', m.group(1), re.M)
    if not globs:
        sys.exit(f"{CONFIG}: examine_globs is empty")
    crates = []
    for g in globs:
        cm = re.match(r"crates/([a-z0-9-]+)/", g)
        if not cm:
            sys.exit(f"{CONFIG}: glob {g!r} is not under crates/<crate>/")
        if cm.group(1) not in crates:
            crates.append(cm.group(1))
    return crates


def mutant_list(*args):
    out = subprocess.run(
        ["cargo", "mutants", "--list", "--no-shuffle", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [line for line in out.splitlines() if line.strip()]


def verify_lists(crates):
    total = mutant_list()
    union = []
    for c in crates:
        mine = mutant_list("-p", c)
        print(f"{c}: {len(mine)} mutants", file=sys.stderr)
        if not mine:
            sys.exit(f"{c}: 0 mutants in scope - a glob matches nothing (crate silently skipped)")
        union += mine
    if sorted(union) != sorted(total):
        missing = sorted(set(total) - set(union))
        extra = sorted(set(union) - set(total))
        sys.exit(f"per-crate lists != workspace list; missing {missing[:5]}, extra {extra[:5]}")
    print(f"per-crate lists cover all {len(total)} mutants", file=sys.stderr)


def main():
    with open(CONFIG, encoding="utf-8") as f:
        crates = crates_in_scope(f.read())
    if "--verify-lists" in sys.argv[1:]:
        verify_lists(crates)
    print(json.dumps(crates))


if __name__ == "__main__":
    main()
