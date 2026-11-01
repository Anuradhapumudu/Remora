#!/usr/bin/env python3
"""Every newly locked crate is written down in docs/dependencies.md
(R8, phase4.5-criteria §15 and §10; owner 2026-10-27).

phase4.5-criteria §10: "docs/dependencies.md updated with every new
transitive crate". Nothing checked it. This compares the registry crates in
Cargo.lock (and fuzz/Cargo.lock) at BASE with HEAD: every crate NAME that is
new must appear in docs/dependencies.md in backticks (`name`), so a word
like "der" in a sentence does not count. Crates locked before BASE are not
judged (the older gap is printed for information).

    check-dep-docs.py [BASE_REF]     default HEAD~1
    check-dep-docs.py --self-test

Stdlib only (tomllib, Python 3.11+).
"""

import re
import subprocess
import sys
import tomllib

LOCKS = ("Cargo.lock", "fuzz/Cargo.lock")
DOC = "docs/dependencies.md"


def registry_names(lock_text):
    """Names of the crates.io packages in a lockfile's text."""
    if not lock_text:
        return set()
    lock = tomllib.loads(lock_text)
    return {p["name"] for p in lock.get("package", []) if p.get("source", "").startswith("registry+")}


def documented(doc_text, name):
    return re.search(r"`" + re.escape(name) + r"(?:[ @][^`]*)?`", doc_text) is not None


def undocumented(base_locks, head_locks, doc_text):
    """New names (in HEAD, not in BASE) missing from the document."""
    base = set().union(*(registry_names(t) for t in base_locks))
    head = set().union(*(registry_names(t) for t in head_locks))
    return sorted(n for n in head - base if not documented(doc_text, n))


def git_show(ref, path):
    r = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def self_test():
    def lock(*names):
        return "version = 4\n" + "".join(
            f'[[package]]\nname = "{n}"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
            for n in names) + '[[package]]\nname = "remora-app"\nversion = "0.0.1"\n'
    fails = []

    def expect(name, got, want):
        if got != want:
            fails.append(f"{name}: {got}")

    doc = "Uses `serde` and `der 0.7` (DER parsing).\nThe word der in prose and ctr.\n"
    expect("nothing new passes", undocumented([lock("a")], [lock("a")], doc), [])
    expect("a new documented crate passes", undocumented([lock("a")], [lock("a", "serde")], doc), [])
    expect("a new crate with a version in backticks passes", undocumented([lock()], [lock("der")], doc), [])
    expect("a new undocumented crate is caught", undocumented([lock("a")], [lock("a", "ring")], doc), ["ring"])
    expect("a name only in prose does not count", undocumented([lock()], [lock("ctr")], doc), ["ctr"])
    expect("older crates are not judged", undocumented([lock("old")], [lock("old")], ""), [])
    expect("workspace crates are not judged", undocumented([lock()], [lock()], ""), [])
    expect("the fuzz lock counts too", undocumented([lock(), lock()], [lock(), lock("arbitrary")], doc),
           ["arbitrary"])
    expect("a prefix does not count", undocumented([lock()], [lock("serde_json")], doc), ["serde_json"])
    for f in fails:
        print(f"SELF-TEST FAIL: {f}")
    print(f"check-dep-docs self-test: {'FAILED' if fails else 'ok'} ({len(fails)} failure(s))")
    return 1 if fails else 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    base = sys.argv[1] if len(sys.argv) > 1 else "HEAD~1"
    with open(DOC, encoding="utf-8") as fh:
        doc = fh.read()
    head_locks = []
    for p in LOCKS:
        try:
            with open(p, encoding="utf-8") as fh:
                head_locks.append(fh.read())
        except OSError:
            head_locks.append("")
    missing = undocumented([git_show(base, p) for p in LOCKS], head_locks, doc)
    for n in missing:
        print(f"UNDOCUMENTED new crate {n}: add it to {DOC} (in backticks, with why it is there)")
    all_names = set().union(*(registry_names(t) for t in head_locks))
    older = sum(1 for n in all_names if not documented(doc, n))
    print(f"check-dep-docs: {len(missing)} new crate(s) undocumented against {base}; "
          f"{older} of {len(all_names)} locked names are not in {DOC} at all (older gap, not judged)")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
