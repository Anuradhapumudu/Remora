#!/usr/bin/env python3
"""Every plant is on record, and every record points at something real
(R7, phase4.5-criteria §15; owner 2026-10-27).

CLAUDE.md: a test whose job is to catch something must be seen catching the
real failure once. Until now that lived only in commit messages. The record
is results/phase4.5/plants.md, one table row per plant:

    | Row | Plant (the real failure) | Caught by | Date |

* Row: a criteria row ID (H1, I2, V4, O1, R2, ...) that exists in
  docs/phase4.5-criteria.md.
* Caught by: `path::test_fn` (a Rust test that must still exist in that
  file), or `scripts/....py: case text` (a self-test case whose text must
  still be in that script).

    check-plants.py               every record is well-formed and real (CI)
    check-plants.py --complete    also: every criteria row whose test cell
                                  mentions "plant" has a record (the phase
                                  report runs this; it fails until the GUI
                                  rows are built)
    check-plants.py --self-test   planted bad records must be caught

Stdlib only.
"""

import importlib.util
import os
import re
import sys

CRITERIA = "docs/phase4.5-criteria.md"
RECORD = "results/phase4.5/plants.md"
ROW_ID = re.compile(r"^\*{0,2}([HIVOR]\d+)\*{0,2}$")

spec = importlib.util.spec_from_file_location(
    "check_tests", os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-tests.py"))
check_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_tests)


def cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def criteria_rows(text):
    """{row id: test cell text} from the criteria tables (first cell an ID)."""
    out = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        c = cells(line)
        m = ROW_ID.match(c[0]) if c else None
        if m and len(c) >= 3:
            out[m.group(1)] = c[-1] if len(c) == 3 else " ".join(c[2:])
    return out


def records(text):
    """The record's data rows: [(row, plant, caught_by, date)]."""
    out = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        c = cells(line)
        if len(c) != 4 or c[0] in ("Row",) or set(c[0]) <= set("-: "):
            continue
        out.append(tuple(c))
    return out


def problems_with(recs, rows, read):
    """Problems in the records; `read(path)` returns a file's text or None."""
    out = []
    for row, plant, caught, date in recs:
        where = f"{row} / {plant[:50]!r}"
        if row not in rows:
            out.append(f"{where}: no row {row} in {CRITERIA}")
        if not re.match(r"^\d{4}-\d\d-\d\d$", date):
            out.append(f"{where}: date {date!r} is not YYYY-MM-DD")
        if not plant:
            out.append(f"{where}: no plant described")
        ref = caught.strip("`")
        if "::" in ref:
            path, name = ref.split("::", 1)
            text = read(path)
            if text is None:
                out.append(f"{where}: {path} does not exist")
            elif name not in check_tests.tests_in(text)[0]:
                out.append(f"{where}: no test fn {name} in {path}")
        elif ref.startswith("scripts/") and ":" in ref:
            path, case = (s.strip() for s in ref.split(":", 1))
            text = read(path)
            if text is None:
                out.append(f"{where}: {path} does not exist")
            elif case not in text:
                out.append(f"{where}: no self-test case {case!r} in {path}")
        else:
            out.append(f"{where}: 'Caught by' must be `path::test_fn` or `scripts/x.py: case`")
    return out


def missing(recs, rows):
    """Criteria rows that name a plant but have no record."""
    have = {r[0] for r in recs}
    return sorted((r for r, test in rows.items() if "plant" in test.lower() and r not in have),
                  key=lambda r: (r[0], int(r[1:])))


def read_file(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def self_test():
    rows = {"H4": "Click at 0.5 s; plants: no delay", "I1": "GUI test; plant: hidden", "V5": "e2e with H8"}
    files = {"crates/a/tests/t.rs": "#[test]\nfn h4_delay() {}\n", "scripts/ci/x.py": 'expect("a removed test is caught", 1)'}
    read = files.get
    good = [("H4", "no delay", "`crates/a/tests/t.rs::h4_delay`", "2026-11-01"),
            ("I1", "hidden", "`scripts/ci/x.py: a removed test is caught`", "2026-11-01")]
    fails = []

    def expect(name, got, want_problem):
        if bool(got) != want_problem:
            fails.append(f"{name}: {got}")

    expect("good records pass", problems_with(good, rows, read), False)
    for name, bad in [
        ("unknown row", ("H99", "x", good[0][2], "2026-11-01")),
        ("test fn that does not exist", ("H4", "x", "`crates/a/tests/t.rs::gone`", "2026-11-01")),
        ("file that does not exist", ("H4", "x", "`crates/a/tests/nope.rs::h4_delay`", "2026-11-01")),
        ("self-test case that does not exist", ("I1", "x", "`scripts/ci/x.py: never written`", "2026-11-01")),
        ("no reference at all", ("H4", "x", "by eye", "2026-11-01")),
        ("bad date", ("H4", "x", good[0][2], "yesterday")),
        ("empty plant", ("H4", "", good[0][2], "2026-11-01")),
    ]:
        expect(name, problems_with([bad], rows, read), True)
    expect("rows naming a plant without a record are listed", missing(good[:1], rows), True)
    expect("all rows with plants recorded: none missing", missing(good, rows), False)
    expect("criteria table rows are read",
           [] if criteria_rows("| **H4** | Accept armed | Click; plants: no delay |\n") == {"H4": "Click; plants: no delay"} else ["x"],
           False)
    expect("record rows are read, header skipped",
           [] if records("| Row | Plant | Caught by | Date |\n|---|---|---|---|\n| H4 | p | `a::b` | 2026-11-01 |\n")
           == [("H4", "p", "`a::b`", "2026-11-01")] else ["x"], False)
    for f in fails:
        print(f"SELF-TEST FAIL: {f}")
    print(f"check-plants self-test: {'FAILED' if fails else 'ok'} ({len(fails)} failure(s))")
    return 1 if fails else 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    rows = criteria_rows(read_file(CRITERIA) or "")
    recs = records(read_file(RECORD) or "")
    problems = problems_with(recs, rows, read_file)
    for p in problems:
        print(p)
    gaps = missing(recs, rows)
    print(f"check-plants: {len(recs)} plants recorded for {len({r[0] for r in recs})} rows; "
          f"{len(problems)} problem(s); rows naming a plant with none recorded yet: {', '.join(gaps) or 'none'}")
    if "--complete" in sys.argv[1:] and gaps:
        return 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
