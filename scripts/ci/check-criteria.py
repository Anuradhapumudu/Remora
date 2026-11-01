#!/usr/bin/env python3
"""Check (c) of the P5 correction (phase4-criteria §14, phase4.5-criteria
§15; owner 2026-10-27): requirements must live in rows that name real checks.

Line 697 of phase4-criteria was a requirement written as one sentence in
the prose; no row carried it and nothing checked it, and P5 was accepted on
the wrong measure. Two parts:

1. FAIL: a table row of the current criteria document names a check that
   does not exist. In table cells, every backticked file path
   (`scripts/ci/x.py`, `crates/.../y.rs`, `results/...`), bare script name
   (`p5-recheck.py`) and test (`path::fn`) must exist. Older accepted
   documents are reported as warnings (they are not edited).
2. WARN: sentences in prose (not tables, not code blocks) with must, shall,
   never, always, required or "to be checked" that cite no row ID (H1, R3,
   D-34, G-2, P5, M7, INV12, A22, ...): a requirement that may have no row.
   Printed with file and line; a warning until we see how noisy it is.

    check-criteria.py                 current = docs/phase4.5-criteria.md
    check-criteria.py --self-test

Stdlib only.
"""

import glob
import importlib.util
import os
import re
import sys

CURRENT = "docs/phase4.5-criteria.md"
spec = importlib.util.spec_from_file_location(
    "check_tests", os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-tests.py"))
check_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_tests)

TICK = re.compile(r"`([^`]+)`")
PATHLIKE = re.compile(r"^(?:\.?[\w.-]+/)+[\w.-]+\.(?:py|sh|rs|md|toml|yml|yaml|txt|swift|m)$")
SCRIPT = re.compile(r"^[\w.-]+\.(?:py|sh)$")
TESTREF = re.compile(r"^((?:[\w.-]+/)+[\w.-]+\.rs)::(\w+)$")
WORDS = re.compile(r"\b(must|shall|never|always|required)\b|to be checked", re.I)
ROW_ID = re.compile(r"\b(?:[HIVORPMNTFAC]\d+[a-z]?|D-\d+[a-z]?|G-\d+|INV\d+|W\d+|S1-\d|Q\d+)\b")


# Top-level folders of this repository; a path starting elsewhere (winit's
# `platform/macos.rs`, Slint's `lib.rs`) points into another project.
OURS = ("crates/", "scripts/", "docs/", "results/", "spikes/", "fuzz/", "packaging/", ".github/", "remora-")


def ours(path):
    return path.startswith(OURS)


def refs_in_tables(text):
    """(line number, backticked token) for every token in a table row."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("|"):
            out += [(n, t.strip()) for t in TICK.findall(line)]
    return out


def missing_checks(text, exists, script_exists, test_exists):
    """Problems: table tokens naming a file, script or test that is not there."""
    out = []
    for n, tok in refs_in_tables(text):
        tok = tok.split(" ")[0]
        m = TESTREF.match(tok)
        if m:
            if not test_exists(m.group(1), m.group(2)):
                out.append((n, f"test {tok} does not exist"))
        elif PATHLIKE.match(tok) and ours(tok):
            if not (exists(tok) or exists(f"crates/{tok}")):
                out.append((n, f"file {tok} does not exist"))
        elif SCRIPT.match(tok) and not script_exists(tok):
            out.append((n, f"script {tok} does not exist under scripts/ or spikes/"))
    return out


def prose_requirements(text):
    """(line, sentence) for requirement words in prose without a row ID."""
    out, in_code = [], False
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("```"):
            in_code = not in_code
            continue
        if in_code or s.startswith("|") or not s or s.startswith("#"):
            continue
        for sentence in re.split(r"(?<=[.!?])\s+", s):
            if WORDS.search(sentence) and not ROW_ID.search(sentence):
                out.append((n, sentence[:120]))
    return out


def real_exists(path):
    return os.path.exists(path)


def real_script(name):
    return any(glob.glob(f"{root}/**/{name}", recursive=True) for root in ("scripts", "spikes"))


def real_test(path, name):
    try:
        with open(path, encoding="utf-8") as fh:
            return name in check_tests.tests_in(fh.read())[0]
    except OSError:
        return False


def self_test():
    files = {"scripts/ci/a.py", "crates/x/tests/t.rs", "crates/remora-x/tests/t.rs"}
    exists = files.__contains__
    script = {"a.py"}.__contains__
    test = lambda p, n: (p, n) == ("crates/x/tests/t.rs", "real")  # noqa: E731
    fails = []

    def expect(name, got, want_some):
        if bool(got) != want_some:
            fails.append(f"{name}: {got}")

    good = ("| R1 | thing | `scripts/ci/a.py` and `a.py` and `crates/x/tests/t.rs::real` | built |\n"
            "Prose `scripts/ci/gone.py` is not a row.\n")
    expect("real checks pass", missing_checks(good, exists, script, test), False)
    expect("a missing file in a row fails",
           missing_checks("| R2 | x | `scripts/ci/gone.py` | built |\n", exists, script, test), True)
    expect("a missing bare script fails", missing_checks("| R3 | x | `gone.py` | y |\n", exists, script, test), True)
    expect("a missing test fails",
           missing_checks("| R4 | x | `crates/x/tests/t.rs::gone` | y |\n", exists, script, test), True)
    expect("a crate-relative path resolves under crates/",
           missing_checks("| R6 | x | `remora-x/tests/t.rs` | y |\n", exists, script, test), False)
    expect("a crate-relative path that is not there fails",
           missing_checks("| R6 | x | `remora-x/tests/gone.rs` | y |\n", exists, script, test), True)
    expect("another project's file is not judged",
           missing_checks("| I3 | x | winit's `platform/macos.rs` | y |\n", exists, script, test), False)
    expect("an ordinary code token is ignored",
           missing_checks("| R5 | x | `one_active_session` and `0x17` | y |\n", exists, script, test), False)
    expect("a requirement sentence without an ID warns",
           prose_requirements("The viewer must never log the password.\n"), True)
    expect("a requirement sentence with an ID does not warn",
           prose_requirements("The viewer must never log the password (V2).\n"), False)
    expect("tables and code blocks are not prose",
           prose_requirements("| x | must |\n```\nmust\n```\n# Must heading\n"), False)
    expect("a deferred ID counts", prose_requirements("This must be done before D-34 reports.\n"), False)
    for f in fails:
        print(f"SELF-TEST FAIL: {f}")
    print(f"check-criteria self-test: {'FAILED' if fails else 'ok'} ({len(fails)} failure(s))")
    return 1 if fails else 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    failures = 0
    for doc in sorted(glob.glob("docs/phase*-criteria.md")):
        with open(doc, encoding="utf-8") as fh:
            text = fh.read()
        current = doc == CURRENT
        for n, why in missing_checks(text, real_exists, real_script, real_test):
            print(f"{'FAIL' if current else 'warning'}: {doc}:{n}: a row names a check that is not there: {why}")
            failures += current
        if current:
            for n, s in prose_requirements(text):
                print(f"warning: {doc}:{n}: requirement in prose with no row ID: {s}")
    print(f"check-criteria: {failures} row(s) in {CURRENT} name a check that does not exist")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
