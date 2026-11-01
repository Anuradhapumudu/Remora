#!/usr/bin/env python3
"""No test disappears unnoticed (R2, phase4.5-criteria §15; owner 2026-10-27).

phase4.5-criteria §0 item 8: "the CLI stays and keeps every Phase 3/4
test". Nothing checked it: a deleted test passes CI. This compares the
tests in a BASE commit with HEAD, as check-roadmap.py does for deferred IDs:

  * test functions: every `#[test]` / `#[tokio::test(...)]` fn under crates/,
    keyed by file and name. One that is gone from HEAD fails the check,
    unless a fn of the same name still exists in the same crate (it moved)
    or docs/removed-tests.md has a row for it (`| path::name | date | why |`);
  * compile-fail doctests (M2's structural tests) have no names: per file,
    their number may not go down without a row `| path#compile_fail | ...`.

Read from source (git show for BASE), so nothing needs building.

    check-tests.py [BASE_REF]      compare HEAD's working tree with BASE_REF
                                   (default HEAD~1)
    check-tests.py --self-test     planted removals must be caught

Stdlib only.
"""

import os
import re
import subprocess
import sys

ROOTS = ("crates",)
ALLOW = "docs/removed-tests.md"
ATTR = re.compile(r"^\s*#\[(?:tokio::)?test(?:\(.*\))?\]\s*$")
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")
COMPILE_FAIL = re.compile(r"^\s*//[/!]\s*```\s*compile_fail")


def tests_in(text):
    """(test fn names, number of compile_fail doctests) in one file."""
    names, lines = [], text.splitlines()
    for i, line in enumerate(lines):
        if not ATTR.match(line):
            continue
        for nxt in lines[i + 1:i + 12]:
            m = FN.match(nxt)
            if m:
                names.append(m.group(1))
                break
    return names, sum(1 for l in lines if COMPILE_FAIL.match(l))


def crate_of(path):
    parts = path.split("/")
    return "/".join(parts[:2]) if len(parts) > 1 else path


def index(files):
    """{path: text} -> ({(path, name)}, {path: compile_fail count})."""
    tests, doc = set(), {}
    for path, text in files.items():
        names, n = tests_in(text)
        tests.update((path, name) for name in names)
        if n:
            doc[path] = n
    return tests, doc


def compare(base_files, head_files, allowed):
    """Problems: tests in BASE missing from HEAD without a reason."""
    base_tests, base_doc = index(base_files)
    head_tests, head_doc = index(head_files)
    head_by_crate = {(crate_of(p), n) for p, n in head_tests}
    problems = []
    for path, name in sorted(base_tests - head_tests):
        if (crate_of(path), name) in head_by_crate:
            continue  # moved within its crate
        if f"{path}::{name}" in allowed:
            continue
        problems.append(f"test removed: {path}::{name} (add a row to {ALLOW} with the reason)")
    for path, n in sorted(base_doc.items()):
        if head_doc.get(path, 0) < n and f"{path}#compile_fail" not in allowed:
            problems.append(f"compile_fail doctests in {path}: {n} -> {head_doc.get(path, 0)} "
                            f"(add a row `{path}#compile_fail` to {ALLOW})")
    return problems


def allowed_rows(text):
    """First cells of the table rows in docs/removed-tests.md."""
    out = set()
    for line in text.splitlines():
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and cells and cells[0] and not set(cells[0]) <= set("-: "):
            out.add(cells[0])
    return out


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def files_at(ref):
    out = {}
    for path in git("ls-tree", "-r", "--name-only", ref, "--", *ROOTS).splitlines():
        if path.endswith(".rs"):
            out[path] = git("show", f"{ref}:{path}")
    return out


def files_now():
    out = {}
    for root in ROOTS:
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d != "target"]
            for f in files:
                if f.endswith(".rs"):
                    path = os.path.join(base, f)
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        out[path] = fh.read()
    return out


def self_test():
    a = "#[test]\nfn keeps() {}\n\n#[tokio::test(flavor = \"multi_thread\")]\nasync fn async_one() {}\n"
    b = "/// ```compile_fail\n/// x\n/// ```\npub fn f() {}\n#[test]\n#[allow(dead_code)]\nfn second() {}\n"
    base = {"crates/x/tests/a.rs": a, "crates/x/src/lib.rs": b}
    fails = []

    def expect(name, problems, want):
        if bool(problems) != want:
            fails.append(f"{name}: {problems}")

    expect("unchanged passes", compare(base, dict(base), set()), False)
    expect("a removed test is caught",
           compare(base, {**base, "crates/x/tests/a.rs": a.replace("fn keeps() {}", "")}, set()), True)
    expect("a removed async test is caught",
           compare(base, {**base, "crates/x/tests/a.rs": a.replace("async fn async_one() {}", "")}, set()), True)
    expect("a test after another attribute is seen, and its removal caught",
           compare(base, {**base, "crates/x/src/lib.rs": b.replace("fn second() {}", "")}, set()), True)
    expect("a whole deleted file is caught",
           compare(base, {"crates/x/src/lib.rs": b}, set()), True)
    expect("a test moved within its crate passes",
           compare(base, {"crates/x/tests/b.rs": a, "crates/x/src/lib.rs": b}, set()), False)
    expect("a test moved to another crate is caught",
           compare(base, {"crates/y/tests/a.rs": a, "crates/x/src/lib.rs": b}, set()), True)
    expect("a removal with a reason passes",
           compare(base, {**base, "crates/x/tests/a.rs": a.replace("fn keeps() {}", "")},
                   {"crates/x/tests/a.rs::keeps"}), False)
    expect("a removed compile_fail doctest is caught",
           compare(base, {**base, "crates/x/src/lib.rs": b.replace("compile_fail", "ignore")}, set()), True)
    expect("allowed rows are read from the table",
           ["crates/x/tests/a.rs::keeps"] if "crates/x/tests/a.rs::keeps" in allowed_rows(
               "| Test | Removed | Why |\n|---|---|---|\n| `crates/x/tests/a.rs::keeps` | 2026-11-01 | merged |\n")
           else [], True)
    expect("the header row is not an allowed test", [r for r in allowed_rows("| Test | x |\n|---|---|\n") if r != "Test"], False)
    for f in fails:
        print(f"SELF-TEST FAIL: {f}")
    print(f"check-tests self-test: {'FAILED' if fails else 'ok'} ({len(fails)} failure(s))")
    return 1 if fails else 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    base = sys.argv[1] if len(sys.argv) > 1 else "HEAD~1"
    allowed = set()
    if os.path.exists(ALLOW):
        with open(ALLOW, encoding="utf-8") as fh:
            allowed = allowed_rows(fh.read())
    head = files_now()
    problems = compare(files_at(base), head, allowed)
    for p in problems:
        print(p)
    tests, doc = index(head)
    print(f"check-tests: {len(tests)} tests and {sum(doc.values())} compile_fail doctests "
          f"against {base}: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
