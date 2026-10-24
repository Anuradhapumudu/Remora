# Remora — developer guide

Remora: open-source, E2E-encrypted, P2P remote desktop in Rust.
Priorities: **SECURITY > CORRECTNESS > LOW LATENCY > IMAGE CLARITY > RESOURCE EFFICIENCY > FEATURES.**
The owner is a CS undergrad new to Rust: explain non-obvious decisions in
commit messages, docs and reports.

## Read before changing things

- `docs/threat-model.md` — normative. Security invariants INV1–INV14 must keep their tests.
- `docs/protocol.md` — byte layouts, key schedule, limits.
- `docs/architecture.md` — crate layering, unsafe policy, decision log (append, don't rewrite).
- `docs/dependencies.md` — dependency policy and the verified version table.
- `docs/roadmap.md` — phases, v0.1 definition, progress log (update after every phase).

## Commands

```sh
cargo build --workspace                                  # build everything
cargo test --workspace                                   # all tests
cargo fmt --all --check                                  # formatting (CI)
cargo clippy --workspace --all-targets -- -D warnings    # lints (CI)
cargo deny check                                         # licenses, bans, sources, advisories
cargo audit                                              # RustSec advisories
actionlint && zizmor .github/workflows                   # lint GitHub workflows
scripts/macos/bundle.sh --help                           # build Remora.app + .dmg locally
```

Toolchain is pinned in `rust-toolchain.toml` (rustup installs it automatically).
Local tools: `brew install cargo-deny cargo-audit actionlint zizmor`;
`cargo install --locked cargo-deb cargo-generate-rpm` for Linux packaging.

## Rules (non-negotiable)

- **No plaintext mode**, flag, feature or debug path that skips encryption.
- **No `unsafe`** outside `src/sys/` FFI modules of remora-capture/-codec/-input.
  Pure crates keep `#![forbid(unsafe_code)]`. Every unsafe block gets `// SAFETY:`.
- **No `unwrap()`/`expect()`** on anything that can come from the network or the OS
  (clippy denies them; tests are exempt).
- **Never log secrets or screen content.** Secret types implement `Debug` as `[redacted]`
  and derive `Zeroize`/`ZeroizeOnDrop`.
- Every parser: check size limits **before** allocating; add a cargo-fuzz target.
- Treat STUN, signaling server, network and connection codes as untrusted.
- Write security tests for every new attack surface (wrong password, replay, tamper, MITM).
- If something can't work reliably (e.g. P2P through symmetric NAT), say so plainly
  in docs and reports; never fake or silently skip it.

## Verified vs asserted (every security claim cites what was read)

Every security or cryptographic claim in our docs must cite the source that
was **actually read** — crate source at the locked version (file), RFC section,
or README — or be explicitly marked **unverified**. Never write a claim from
memory. Why (docs/crypto-claims-audit.md):
- **C14:** an audit of the dalek crates ("Quarkslab, 2019") was written from
  memory and turned out not to be stated anywhere we could check — removed.
- **C11:** "all secrets are zeroized" was asserted; `spake2` and `snow` don't use
  `zeroize` at all.
- **C12:** "VideoToolbox decodes out of process" was asserted, never checked.
- The SPAKE2 crate was called "RFC 9382-style"; it is a python-spake2 port.

**Rules we rely on for security are enforced by a check, not by memory.**
The 14-day dependency rule was violated **three times** while we believed it
was holding (zeroize 1.9.1, five transitive crates, rustls 0.23.46 — two of
them written into dependencies.md as if compliant); only the mechanical
`crate-age` CI check found them. Same class of failure as C14: a belief
recorded as a fact. If a rule protects security, add the check that fails
when it is broken.

## Plant the real failure (test standard)

When a test's job is to **catch** something, prove it can: plant the real
failure (a real violation, a real bad input, a real bug), confirm the test
fails and names it, then remove the plant. A test that has never been seen
failing proves nothing — e.g. the first policy scanner "passed" while a
mutation that made it scan nothing also passed. Back it with mutation testing
for security controls (`.cargo/mutants.toml`).

## Unsafe policy exceptions

Only `src/sys/` FFI modules may use `unsafe`. The single exception is
architecture.md **D19** (the test-only counting allocator). It is **not a
precedent**: any other request makes its own case and needs its own approval.

## Process evidence: don't rewrite phase-3 history

Phase 3 is built test-first: each component's attack tests are committed
before or with its implementation (phase3-criteria.md §7b). That commit order
**is the evidence**. When the phase-3 PR merges, use a **merge commit** — never
squash, rebase or reorder phase-3 commits into a tidier shape.

## Dependencies

- Verify versions against the registry (`cargo info <crate>`), never from memory.
- Releases must be ≥ 14 days old; otherwise lock the previous one with
  `cargo update -p <crate> --precise <ver>`.
- Stay on one RustCrypto generation (D3); `cargo deny check` enforces it.
- Add to `[workspace.dependencies]` in the root `Cargo.toml`, use `{ workspace = true }`
  in crates, and update `docs/dependencies.md` in the same commit.
- GitHub Actions: pin third-party actions by full commit SHA with a `# vX.Y.Z` comment.

## Conventions

- Edition 2024, MSRV 1.92. Libraries: `thiserror` errors; binaries: `anyhow`.
- Doc comments on every public item (`missing_docs` lint).
- OS-specific code lives in `src/sys/<os>.rs` behind a trait; nothing above the
  trait knows which OS it runs on.
- `remora-session` has no I/O: events in, actions out.
- Library crates: MIT OR Apache-2.0. Apps (host/viewer/signal): GPL-3.0-or-later.
  Each crate directory carries its license file(s).
- Small, focused commits; imperative subject ≤ 72 chars; body explains *why*.
- After each phase: update `docs/roadmap.md` (status + progress log), give exact
  manual test steps, measured numbers vs targets, and known limitations — and
  **report the "Deferred items" list in roadmap.md row by row** (what closed,
  what moved, what is new). Deferred work lives only in that list.
- **An owner approval of future work becomes a row in that list (or a
  criteria item) in the same commit that records it.** Approved-but-unwritten
  work is how the render spike slipped (roadmap "Process slips").
- **Every owner gate ("don't proceed until X") becomes a row in roadmap.md
  "Open gates" in the same commit that acknowledges it.** Before starting
  each step, run `python3 scripts/ci/check-roadmap.py --open-gates` and stop
  if a gate blocks it — gates are checked, not remembered. A gate is only
  MET (with evidence) or WAIVED (with the owner's own words); "continue" is
  not a waiver of a gate it does not name.

## macOS development notes

- When a binary runs from Terminal, macOS attributes Screen Recording /
  Accessibility permission to **Terminal** (the "responsible process"), so
  `cargo run` doesn't re-prompt after every rebuild.
- The bundled `Remora.app` is attributed to its own code signature: unsigned or
  ad-hoc-signed rebuilds re-prompt. Phase 2 adds a stable self-signed dev identity
  script for this (see docs/distribution.md).
