# Removed tests

A test that disappears fails CI (`scripts/ci/check-tests.py`, R2 in
phase4.5-criteria §15): phase4.5-criteria §0 item 8 says every Phase 3/4
test stays. A test may still go when it is wrong or replaced; then it gets a
row here, in the same commit, with the reason. A test moved to another file
of the same crate needs no row.

First cell: `path::test_name`, or `path#compile_fail` when compile-fail
doctests in that file are removed.

| Test | Removed | Why |
|---|---|---|
