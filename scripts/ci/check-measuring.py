#!/usr/bin/env python3
"""Every measuring runner goes through the shared helper (R9, phase4.5-criteria
§15; owner 2026-10-27: "one shared measuring helper for every runner").

A rule we rely on gets a check (CLAUDE.md). This one fails when a script under
scripts/:

1. runs a measuring tool (vmmap, sample, leaks, ..., footprint) directly
   instead of through `run.instrument([...])`, which counts the tools that
   pause the measured process (W4);
2. measures (calls such a tool, or keeps the Mac awake) in Python without
   `measuring.Run(...)`, `.start()` and `.finish()` (machine state, AC power,
   sleep and display checks, VALIDITY: W2, W3);
3. keeps the Mac awake with `caffeinate` outside the helper. `caffeinate -u`
   (user activity, wakes the display: T2) is not keeping it awake and is fine.
   Shell runners from Phase 2 are listed in SHELL_RUNNERS with the reason.

Python is read with `ast`, so comments and docstrings that mention a tool do
not count. Shell lines are matched as commands, comments skipped. The spikes
are not scanned: they are deleted at the end of the phase (D-41).

    python3 -I scripts/ci/check-measuring.py [ROOT]
    python3 -I scripts/ci/check-measuring.py --self-test
"""
import ast
import os
import re
import sys
import tempfile

HELPER = os.path.join("scripts", "macos", "measuring.py")
PAUSING = {"vmmap", "sample", "leaks", "heap", "malloc_history", "spindump", "lldb", "xctrace"}
TOOLS = PAUSING | {"footprint"}
# Shell runners that keep the Mac awake themselves: accepted Phase 2/4 tools
# whose numbers come from bench-capture or watch-capture, which print machine
# state in the process itself. A new shell runner is not listed and fails.
SHELL_RUNNERS = {
    "scripts/macos/phase2-tests.sh": "Phase 2 runner; bench-capture prints machine state",
    "scripts/macos/phase2-hotplug.sh": "Phase 2 hot-plug runner (accepted record)",
    "scripts/macos/t3-display-removed.sh": "Phase 4 T3 runner (accepted record)",
}


def _name(node):
    """'a.b.c' for a Name/Attribute chain, else ''."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _name(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    return ""


def _first_word(node):
    """The tool name a command starts with: a list literal's first string, or
    the first word of a string command; '' otherwise."""
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        node = node.elts[0]
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return os.path.basename(node.value)
        return ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip():
        return os.path.basename(node.value.split()[0])
    return ""


def check_python(path, text):
    """Problems in one Python file."""
    problems, measures = [], False
    try:
        tree = ast.parse(text, path)
    except SyntaxError as e:
        return [f"{path}: does not parse: {e}"]
    allowed = set()  # ids of command nodes passed to .instrument()
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    for c in calls:
        if _name(c.func).endswith("instrument") and c.args:
            allowed.add(id(c.args[0]))
            measures = True
    for c in calls:
        func = _name(c.func)
        args = list(c.args)
        if func in ("os.execvp", "os.execv", "os.execlp", "os.execl") and args:
            tool = _first_word(args[0])
            if tool == "caffeinate":
                problems.append(f"{path}:{c.lineno}: keeps the Mac awake with caffeinate itself; "
                                "use measuring.keep_awake()")
                continue
        for a in args:
            tool = _first_word(a)
            if not tool or id(a) in allowed:
                continue
            if tool in TOOLS:
                problems.append(f"{path}:{c.lineno}: runs {tool} directly; use run.instrument([...]) "
                                "so the helper counts it")
                measures = True
            elif tool == "caffeinate":
                words = [e.value for e in getattr(a, "elts", []) if isinstance(e, ast.Constant)]
                if isinstance(a, ast.Constant):
                    words = a.value.split()
                if "-u" not in words[1:]:
                    problems.append(f"{path}:{c.lineno}: keeps the Mac awake with caffeinate itself; "
                                    "use measuring.keep_awake()")
    if measures:
        names = {_name(c.func) for c in calls}
        for need, why in (("measuring.Run", "measuring.Run(...)"), (".start", "run.start()"),
                          (".finish", "run.finish()")):
            if not any(n == need or (need.startswith(".") and n.endswith(need)) for n in names):
                problems.append(f"{path}: measures but never calls {why} (machine state and VALIDITY)")
    return problems


SHELL_TOOL = re.compile(r"(?:^|[;&|(`]|\$\(|\bexec\s+|\benv\s+(?:\S+=\S+\s+)*)\s*("
                        + "|".join(sorted(TOOLS | {"caffeinate"})) + r")\b(.*)")


def check_shell(path, text):
    """Problems in one shell script."""
    problems = []
    for n, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        for m in SHELL_TOOL.finditer(code):
            tool, rest = m.group(1), m.group(2)
            if tool == "caffeinate":
                if re.match(r"\s+-u\b", rest) or path in SHELL_RUNNERS:
                    continue
                problems.append(f"{path}:{n}: a new shell runner keeps the Mac awake itself; "
                                "write it in Python with measuring.Run (or list it in SHELL_RUNNERS with the reason)")
            else:
                problems.append(f"{path}:{n}: runs {tool} directly; measuring tools go through "
                                "measuring.Run.instrument (Python)")
    return problems


def scan(root):
    problems = []
    for base, dirs, files in os.walk(os.path.join(root, "scripts")):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in sorted(files):
            full = os.path.join(base, f)
            rel = os.path.relpath(full, root)
            if rel == HELPER or rel == os.path.join("scripts", "ci", "check-measuring.py"):
                continue
            with open(full, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            if f.endswith(".py"):
                problems += check_python(rel, text)
            elif f.endswith(".sh") or text.startswith("#!/usr/bin/env bash") or text.startswith("#!/bin/sh"):
                problems += check_shell(rel, text)
    return problems


GOOD_PY = '''
import measuring
"""Docstring naming vmmap and footprint is fine."""
def main():
    measuring.keep_awake()
    run = measuring.Run(print, pauses_allowed=10)
    run.start()
    run.instrument(["vmmap", "--summary", "1"])  # vmmap via the helper
    run.instrument(["footprint", "-p", "1"])
    subprocess.run(["caffeinate", "-u", "-t", "2"])
    run.finish()
'''
GOOD_SH = '''#!/usr/bin/env bash
# vmmap is mentioned in a comment only
caffeinate -u -t 2
echo footprint-free
echo done  # notes; vmmap was dropped here
'''
PLANTS = [
    ("python: vmmap directly", "x.py", GOOD_PY.replace('run.instrument(["vmmap"', 'subprocess.run(["vmmap"'), "runs vmmap directly"),
    ("python: /usr/bin/sample directly", "x.py", GOOD_PY + '\nsubprocess.run(["/usr/bin/sample", "1", "3"])\n', "runs sample directly"),
    ("python: footprint directly", "x.py", GOOD_PY.replace('run.instrument(["footprint"', 'subprocess.run(["footprint"'), "runs footprint directly"),
    ("python: shell string", "x.py", GOOD_PY + '\nsubprocess.run("leaks 1", shell=True)\n', "runs leaks directly"),
    ("python: own caffeinate exec", "x.py", GOOD_PY + '\nos.execvp("caffeinate", ["caffeinate", "-dims"])\n', "caffeinate itself"),
    ("python: caffeinate -d subprocess", "x.py", GOOD_PY + '\nsubprocess.Popen(["caffeinate", "-d"])\n', "caffeinate itself"),
    ("python: measures without Run", "x.py", GOOD_PY.replace("    run = measuring.Run(print, pauses_allowed=10)\n", ""), "never calls measuring.Run"),
    ("python: measures without finish", "x.py", GOOD_PY.replace("    run.finish()\n", ""), "never calls run.finish()"),
    ("python: measures without start", "x.py", GOOD_PY.replace("    run.start()\n", ""), "never calls run.start()"),
    ("shell: vmmap command", "x.sh", GOOD_SH + 'vmmap --summary "$pid"\n', "runs vmmap directly"),
    ("shell: footprint in $()", "x.sh", GOOD_SH + 'm=$(footprint -p "$pid")\n', "runs footprint directly"),
    ("shell: new runner with caffeinate", "x.sh", GOOD_SH + 'exec env REMORA_CAFFEINATED=1 caffeinate -di "$0"\n', "new shell runner"),
]


def self_test():
    fails = []
    with tempfile.TemporaryDirectory() as root:
        d = os.path.join(root, "scripts", "macos")
        os.makedirs(d)

        def run_with(name, text):
            for f in os.listdir(d):
                os.remove(os.path.join(d, f))
            with open(os.path.join(d, name), "w") as fh:
                fh.write(text)
            return scan(root)

        for name, text in (("good.py", GOOD_PY), ("good.sh", GOOD_SH)):
            got = run_with(name, text)
            if got:
                fails.append(f"clean {name} flagged: {got}")
        for what, name, text, needle in PLANTS:
            got = run_with(name, text)
            if not any(needle in p for p in got):
                fails.append(f"plant not caught: {what} (got {got})")
        listed = "scripts/macos/phase2-tests.sh"
        os.remove(os.path.join(d, name))
        with open(os.path.join(root, listed), "w") as fh:
            fh.write('#!/usr/bin/env bash\nexec env REMORA_CAFFEINATED=1 caffeinate -di "$0" "$@"\n')
        if scan(root):
            fails.append("a listed Phase 2 shell runner was flagged")
    for f in fails:
        print(f"SELF-TEST FAIL: {f}")
    print(f"check-measuring self-test: {'FAILED' if fails else 'ok'} "
          f"({len(PLANTS)} plants, {len(fails)} failure(s))")
    return 1 if fails else 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    problems = scan(root)
    for p in problems:
        print(p)
    print(f"check-measuring: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
