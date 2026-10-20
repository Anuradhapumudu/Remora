#!/usr/bin/env python3
"""Guard the load-bearing tables of docs/roadmap.md (owner, 2026-10-19).

The progress log and the deferred-items list are what every phase report is
judged against, and they are edited by hand. On 2026-10-19 a scripted edit
silently cut off everything after one table row, progress log included; it
was caught by eye. This check makes that a CI failure instead.

Rules (HEAD compared with a BASE version of the file):
  * The sections "Deferred items", "Process slips" and "Progress log" exist.
  * Deferred items: every open row has 5 cells, an ID like D-12 or D-1b, and
    a Kind starting with **BLOCKER** or *nice-to-have*. Closed rows (table
    under "### Closed") have 4 cells and non-empty evidence. IDs are unique.
  * No deferred ID ever disappears: every ID in BASE (open or closed) is still
    in HEAD (open or closed). Closing an item = moving its row to "Closed"
    with the evidence; it is never deleted.
  * Progress log and process slips are append-only: every BASE row's key
    (first two cells) is still present in HEAD.
  * Open gates (owner "don't proceed until X"): 5 cells, ID like G-1, status
    starting OPEN, MET or WAIVED (MET/WAIVED with the evidence or the owner's
    words); no gate ID ever disappears.

Usage:
    check-roadmap.py [BASE_REF]     compare HEAD's file with BASE_REF's
                                    (default HEAD~1; no base = structure only)
    check-roadmap.py --self-test    run planted failures; each must be caught
    check-roadmap.py --open-gates   list OPEN gates (run before every step)

Stdlib only.
"""

import re
import subprocess
import sys

PATH = "docs/roadmap.md"
ID_RE = re.compile(r"^D-\d+[a-z]?$")
GATE_RE = re.compile(r"^G-\d+$")
GATE_STATES = ("OPEN", "MET", "WAIVED")


class RoadmapError(Exception):
    pass


def section(text, title, required=True):
    """Body of the '## <title>...' section, up to the next '## ' heading.
    A BASE version older than this guard may lack a section: it is then
    treated as empty (nothing to compare), never as a pass for HEAD."""
    m = re.search(rf"^## {re.escape(title)}[^\n]*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        if required:
            raise RoadmapError(f"section '## {title}' is missing")
        return None
    return m.group(1)


def rows(body):
    """Data rows of the first markdown table in body (header and rule skipped)."""
    out, seen_rule = [], False
    for line in body.splitlines():
        if not line.startswith("|"):
            if seen_rule:
                break
            continue
        if re.match(r"^\|[\s|:-]+\|$", line):
            seen_rule = True
            continue
        if seen_rule:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            out.append(cells)
    return out


def parse_base(text):
    """Keys of an older version; sections it does not have yet count as empty."""
    out = {"ids": set(), "slips": set(), "log": set(), "gates": set()}
    gates = section(text, "Open gates", required=False)
    if gates is not None:
        out["gates"] = {r[0] for r in rows(gates) if r and GATE_RE.match(r[0])}
    deferred = section(text, "Deferred items", required=False)
    if deferred is not None:
        open_part, _, closed_part = deferred.partition("### Closed")
        out["ids"] = {r[0] for r in rows(open_part) + rows(closed_part) if r and ID_RE.match(r[0])}
    for key, title in (("slips", "Process slips"), ("log", "Progress log")):
        body = section(text, title, required=False)
        if body is not None:
            out[key] = {tuple(r[:2]) for r in rows(body)}
    return out


def parse(text):
    deferred = section(text, "Deferred items")
    open_part, _, closed_part = deferred.partition("### Closed")
    open_rows = rows(open_part)
    closed_rows = rows(closed_part) if closed_part else []
    if not open_rows:
        raise RoadmapError("deferred-items table has no rows")
    ids = []
    for r in open_rows:
        if len(r) != 5:
            raise RoadmapError(f"open deferred row has {len(r)} cells, want 5: {r[:1]}")
        if not ID_RE.match(r[0]):
            raise RoadmapError(f"bad deferred ID {r[0]!r}")
        if not (r[2].startswith("**BLOCKER**") or r[2].startswith("*nice-to-have*")):
            raise RoadmapError(f"{r[0]}: Kind must start with **BLOCKER** or *nice-to-have*")
        ids.append(r[0])
    for r in closed_rows:
        if len(r) != 4:
            raise RoadmapError(f"closed deferred row has {len(r)} cells, want 4: {r[:1]}")
        if not ID_RE.match(r[0]):
            raise RoadmapError(f"bad closed ID {r[0]!r}")
        if not r[3]:
            raise RoadmapError(f"{r[0]}: closed without evidence")
        ids.append(r[0])
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise RoadmapError(f"deferred IDs listed twice: {dup}")
    gates = {}
    for r in rows(section(text, "Open gates")):
        if len(r) != 5:
            raise RoadmapError(f"gate row has {len(r)} cells, want 5: {r[:1]}")
        if not GATE_RE.match(r[0]):
            raise RoadmapError(f"bad gate ID {r[0]!r}")
        state = r[4].split(" ", 1)[0].strip("*")
        if state not in GATE_STATES:
            raise RoadmapError(f"{r[0]}: status must start with OPEN, MET or WAIVED")
        if state != "OPEN" and len(r[4]) < len(state) + 10:
            raise RoadmapError(f"{r[0]}: {state} needs the evidence or the owner's words")
        if r[0] in gates:
            raise RoadmapError(f"gate listed twice: {r[0]}")
        gates[r[0]] = r
    slips = rows(section(text, "Process slips"))
    log = rows(section(text, "Progress log"))
    if not log:
        raise RoadmapError("progress log has no rows")
    for name, table in (("process slips", slips), ("progress log", log)):
        for r in table:
            if len(r) != 4 or not r[3]:
                raise RoadmapError(f"{name} row malformed: {r[:2]}")
    return {
        "ids": set(ids),
        "slips": {tuple(r[:2]) for r in slips},
        "log": {tuple(r[:2]) for r in log},
        "gates": gates,
    }


def compare(base_text, head_text):
    head = parse(head_text)
    if base_text is None:
        return head
    base = parse_base(base_text)
    lost = sorted(base["ids"] - head["ids"])
    if lost:
        raise RoadmapError(f"deferred items disappeared (close them, don't delete): {lost}")
    lost_gates = sorted(base["gates"] - set(head["gates"]))
    if lost_gates:
        raise RoadmapError(f"gates disappeared (mark them MET or WAIVED, don't delete): {lost_gates}")
    for key, name in (("log", "progress log"), ("slips", "process slips")):
        gone = sorted(base[key] - head[key])
        if gone:
            raise RoadmapError(f"{name} rows removed (append-only): {gone}")
    return head


def git_show(ref):
    r = subprocess.run(["git", "show", f"{ref}:{PATH}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def self_test():
    """Each plant is a real way the file has broken or could break."""
    with open(PATH, encoding="utf-8") as f:
        good = f.read()
    compare(good, good)  # the real file must pass against itself
    first_open = next(l for l in good.splitlines() if l.startswith("| D-"))
    log_head = good.index("## Progress log")
    plants = {
        # the 2026-10-19 incident: everything after a deferred row cut off
        "truncated after a deferred row": good[: good.index(first_open) + len(first_open) + 1],
        "progress log row deleted": re.sub(r"^\| 2026-10-17 \| 2 \|.*\n", "", good, count=1, flags=re.M),
        "deferred row deleted": good.replace(first_open + "\n", "", 1),
        "deferred row lost a cell": good.replace(first_open, first_open.rsplit("|", 2)[0] + "|", 1),
        "bad Kind": good.replace(first_open, first_open.replace("**BLOCKER**", "blocker", 1), 1),
        "section heading renamed": good[:log_head] + "## Log" + good[log_head + len("## Progress log"):],
        "duplicate ID": good.replace(first_open, first_open + "\n" + first_open, 1),
    }
    first_gate = next(l for l in good.splitlines() if l.startswith("| G-"))
    gate_cells = first_gate.strip().strip("|").split("|")
    def gate_status(status):
        return "|" + "|".join(gate_cells[:4]) + f"| {status} |"
    try:
        compare(good, good.replace(first_gate, gate_status("MET 2026-10-21: owner reported every step"), 1))
        print("allowed marking a gate MET with evidence")
    except RoadmapError as e:
        sys.exit(f"self-test FAILED: marking a gate MET properly was rejected: {e}")
    plants["gate row deleted"] = good.replace(first_gate + "\n", "", 1)
    plants["gate status invented"] = good.replace(first_gate, gate_status("DONE"), 1)
    plants["gate met without evidence"] = good.replace(first_gate, gate_status("MET"), 1)
    failed = []
    # The legitimate way out must keep working: move a row to "Closed".
    rid = first_open.split("|")[1].strip()
    closed_hdr = "|---|---|---|---|\n"
    def close(evidence):
        t = good.replace(first_open + "\n", "", 1)
        i = t.index(closed_hdr, t.index("### Closed")) + len(closed_hdr)
        return t[:i] + f"| {rid} | item | 2026-10-20 | {evidence} |\n" + t[i:]
    try:
        compare(good, close("test X passed, commit abc"))
        print(f"allowed closing {rid} with evidence")
    except RoadmapError as e:
        failed.append(f"closing {rid} properly was rejected: {e}")
    plants["closed without evidence"] = close("")
    for name, text in plants.items():
        if text == good:
            failed.append(f"plant '{name}' did not change the file")
            continue
        try:
            compare(good, text)
            failed.append(f"plant '{name}' was NOT caught")
        except RoadmapError as e:
            print(f"caught  {name}: {e}")
    if failed:
        sys.exit("self-test FAILED:\n  " + "\n  ".join(failed))
    print(f"self-test: all {len(plants)} plants caught")


def main():
    args = sys.argv[1:]
    if args == ["--self-test"]:
        self_test()
        return
    if args == ["--open-gates"]:
        # Run before starting every step (CLAUDE.md): gates are checked,
        # not remembered.
        with open(PATH, encoding="utf-8") as f:
            gates = parse(f.read())["gates"]
        open_rows = [r for r in gates.values() if r[4].startswith("OPEN")]
        for r in open_rows:
            print(f"OPEN {r[0]}: blocks {r[3]} - {r[1][:160]}")
        print(f"{len(open_rows)} open gate(s)")
        return
    base_ref = args[0] if args else "HEAD~1"
    with open(PATH, encoding="utf-8") as f:
        head_text = f.read()
    base_text = git_show(base_ref)
    try:
        head = compare(base_text, head_text)
    except RoadmapError as e:
        sys.exit(f"{PATH}: {e}")
    against = base_ref if base_text is not None else "nothing (no base version; structure only)"
    print(f"{PATH} OK against {against}: {len(head['ids'])} deferred IDs, "
          f"{len(head['log'])} progress-log rows, {len(head['slips'])} process slips")


if __name__ == "__main__":
    main()
