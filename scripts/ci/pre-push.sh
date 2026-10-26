#!/usr/bin/env bash
# Main-workspace checks to run before every push (owner, 2026-10-26).
# The same commands as CI's `check` job (.github/workflows/ci.yml), minus the
# macOS-only probes. Why: `fac428a` pushed a spike after only the spike's own
# build had run; the main workspace's `cargo fmt` then failed on all three CI
# runners ("multiple workspace roots"). A rule we rely on gets a check, not a
# memory (CLAUDE.md), so scripts/githooks/pre-push runs this on `git push`.
#
#     scripts/ci/pre-push.sh                        # run by hand
#     git config core.hooksPath scripts/githooks    # once per clone: run on push
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

step() { printf '\n== pre-push: %s\n' "$*"; }

step "cargo fmt --all --check"
cargo fmt --all --check
step "cargo clippy --workspace --all-targets --locked -- -D warnings"
cargo clippy --workspace --all-targets --locked -- -D warnings
step "cargo test --workspace --locked"
cargo test --workspace --locked
step "cargo deny --locked check"
cargo deny --locked check
step "cargo audit"
cargo audit
step "roadmap tables"
python3 -I scripts/ci/check-roadmap.py

printf '\npre-push: all main-workspace checks passed\n'
