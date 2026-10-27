# Dependencies

Every external crate Remora uses, why, and the exact version chosen. Versions
were **checked against crates.io on 2026-10-17** (`cargo info` / `cargo search`,
plus a scratch build to detect duplicate crates), not taken from memory.

## Policy

1. **≥ 14 days old.** A release younger than 14 days is not adopted; we pin the
   previous one (`cargo update -p <crate> --precise <version>`). Gives the
   community time to notice a malicious or broken release.
   **Enforced mechanically** since 2026-10-18 by the `crate-age` CI job
   (`scripts/ci/check-crate-age.py`): every crates.io package newly locked in
   `Cargo.lock` or `fuzz/Cargo.lock` (compared with the merge-base on `main`)
   is looked up on the crates.io API and the build fails if it is < 14 days
   old, or if it cannot be looked up (fails closed). The job first runs a
   self-test with planted too-new entries. Why a script: cargo-deny 0.20.2 has
   no release-age check, and cargo's `-Z min-publish-age` is nightly-only and
   filters resolution instead of checking a lockfile — revisit when it is
   stable. Run locally: `python3 scripts/ci/check-crate-age.py --base
   $(git merge-base HEAD origin/main) Cargo.lock fuzz/Cargo.lock`.
2. **No pre-releases** (`-alpha`, `-pre`, `-dev`) for anything security-relevant.
3. **One RustCrypto generation.** All our crypto shares `curve25519-dalek 4`,
   `digest 0.10`, `rand_core 0.6` (decision D3 in architecture.md). cargo-deny
   fails CI if a second copy of a crypto crate appears.
4. **crates.io only** — no git dependencies (cargo-deny `sources`).
5. **Licenses** from the allow-list in `deny.toml` only.
6. New dependencies are added to `[workspace.dependencies]` in the root
   `Cargo.toml` and to this table in the same commit.

Versions below are the *requirement* written in `Cargo.toml`; `Cargo.lock`
holds the exact resolved version. A crate is only resolved into `Cargo.lock`
once a workspace member actually uses it.

## Table

| Crate | Requirement | Lock to | Used by | Why |
|---|---|---|---|---|
| tokio | 1.53 | 1.53.3 — **security-fix exception** (released 2026-10-13; RUSTSEC-2026-0386 affects 1.53.2) | net, signal, apps | Async runtime; quinn requires it |
| quinn | 0.11.12 | 0.11.12 (quinn-proto 0.11.19) | net | QUIC: datagrams, streams, migration, pluggable socket + congestion control |
| rustls | 0.23.46 (`ring`) | 0.23.46 — **security-fix exception** (released 2026-10-14; RUSTSEC-2026-0346/0347/0348/0349 affect ≤ 0.23.45). This table listed it on 2026-10-17 without noticing it was < 14 days old (third slip, found by the crate-age job) | net | quinn's TLS. Newest is 0.24.0-dev (pre-release) — not used |
| snow | 0.10.0 (`risky-raw-split` only if needed) | 0.10.0 | crypto | Noise Protocol Framework |
| spake2 | 0.4.0 | 0.4.0 | crypto | PAKE. **Not independently audited** (threat model §9). 0.5.0-pre exists — not used |
| ed25519-dalek | 2.2 | 2.2.0 | crypto | Identity keys. 3.0.0 exists but is on the next RustCrypto generation (D3) |
| chacha20poly1305 | 0.10 | 0.10.1 | crypto | Media AEAD (same version snow uses) |
| curve25519-dalek | 4.1.3 | 4.1.3 | crypto | **Only** for validating received SPAKE2 elements (A32: decompress, canonical re-encoding, `is_small_order`, `is_torsion_free`) and X25519 public keys (`MontgomeryPoint::mul_base_clamped`). Already in the graph via spake2/ed25519-dalek/snow; same single version (D3). 5.0.0 is the next generation |
| unicode-normalization | 0.1.25 | 0.1.25 (0.1.26 of 2026-10-16 < 14 days) | crypto | NFKC + `is_combining_mark` for the unattended-password policy (A30). License `(MIT OR Apache-2.0) AND Unicode-3.0` — both allowed |
| hkdf / sha2 / blake2 | 0.12 / 0.10 / 0.10 | — | crypto | Key derivation, hashes |
| rand_core | 0.6 (`getrandom`) | 0.6.4 | crypto | OS CSPRNG (`OsRng`) |
| zeroize | 1.8 | **1.9.0** (1.9.1 of 2026-10-06 was < 14 days old when first locked on 2026-10-18; this table previously said 1.9.1 — corrected) | crypto | Wipe secrets on drop |
| subtle | 2.6 | 2.6.1 | crypto | Constant-time comparison |
| keyring | 4.2 | 4.2.0 | crypto (key storage) | OS keychain. **v4 API differs from v3** (split into `keyring-core` + per-OS stores) — re-verify in Phase 3 |
| is | 0.11.1 | 0.11.1 | net | Sans-IO ICE agent from str0m (nat-traversal.md §3). Pin exact minor; frequent breaking releases |
| prost | 0.14.4 | 0.14.4 | proto | Protobuf runtime; messages written as Rust structs with `#[derive(prost::Message)]` (no code generator — decision D20) |
| base64 | 0.23.1 | 0.23.1 | proto | Connection codes: `URL_SAFE_NO_PAD` requires no padding and rejects non-canonical trailing bits (verified: base64-0.23.1/src/engine/general_purpose/mod.rs:472, 499) |
| prost-build | 0.14.4 | 0.14.4 | proto (build) | Code generation |
| protox | 0.9.1 | 0.9.1 (0.10.0 < 14 days) | proto (build) | Pure-Rust `.proto` compiler, so contributors don't need `protoc` |
| reed-solomon-simd | 3.1.0 | 3.1.0 | net | FEC for video datagrams |
| bytes | 1 | — | proto, net | Zero-copy buffers (quinn's buffer type) |
| rcgen | 0.14.10, default features **off**, `crypto` + `ring` | 0.14.10 (2026-08-28) | net | Throw-away self-signed certificate per QUIC endpoint. TLS is untrusted plumbing (D1): authentication is Noise + the exporter binding, so the certificate only has to exist. From the rustls organisation; no PEM, no aws-lc-rs (D8). Pulls in `time` → `deranged` locked to **0.5.8** and `powerfmt` to **0.2.0** (newer ones < 14 days) |
| objc2 | 0.6.4 | 0.6.4 (0.6.5 < 14 days) | capture, codec, input (macOS) | Objective-C runtime bindings; `define_class!` implements `SCStreamOutput` |
| objc2-foundation, -core-foundation, -core-graphics, -screen-capture-kit, -video-toolbox, -core-media, -core-video | 0.3.2, default features **off** | 0.3.2 | capture, codec (macOS); app (macOS: `-core-video` host clock, P0) | Generated Apple framework bindings; only the features we call (defaults pull in AVFoundation, Metal, OpenGL) |
| block2 / dispatch2 | 0.6.2 / 0.3.1 | — | capture (macOS) | Objective-C completion blocks; ScreenCaptureKit's dispatch queue |
| windows | 0.62.2 | — | capture, codec, input (Windows) | Official Microsoft bindings |
| x11rb | 0.14.0 | — | capture, input (Linux) | Pure-Rust X11 protocol |
| openh264 | 0.9.8 | 0.9.8 (0.9.9 < 14 days) | codec | Software H.264 fallback |
| wgpu | 30.0.1, default features **off**, `std` + `wgsl` + `metal` | 30.0.1 (2026-08-22) | viewer (macOS) | The Phase 4 video window and offscreen P7 rendering (phase4-criteria R1/R2). Metal backend only: the window is macOS-only until Phase 6.5, and every other backend would add code we do not run. Pulls naga 30.0.1 (shader compiler) and objc2-metal / objc2-quartz-core 0.3.2 |
| winit | 0.30.13, default features **off**, `rwh_06` | 0.30.13 (2026-03-02) | viewer (macOS) | The window and its event loop (R1, R5). No X11/Wayland features. 0.31 is beta only. Uses the older objc2 0.5 / objc2-app-kit 0.2 family itself, so both objc2 generations are in the lock (cargo deny reports the duplicate; it is not a RustCrypto crate, D3 is unaffected) |
| pollster | 1.0.1 | 1.0.1 (2026-07-10) | viewer (macOS) | Blocks on wgpu's adapter/device futures once at start-up (no async runtime on the window thread) |
| slint | 1.18.1 (`unstable-wgpu-30`) | — | viewer, host | UI; shares our wgpu 30 device. MSRV 1.92 → workspace MSRV |
| axum | 0.8.9 | — | signal | WebSocket signaling server |
| tracing / tracing-subscriber | 0.1.44 / 0.3.23 | — | all | Structured logging (with secret redaction) |
| thiserror | 2.0 | — | libraries | Error types |
| anyhow | 1.0 | — | binaries only | Error plumbing in `main` |
| clap | 4.6 | — | binaries | CLI flags (`--test-pattern`, …) |
| criterion | 0.8.2 | — | benches | Benchmarks |

## Transitive locks (2026-10-18, remora-crypto landing)

Adding remora-crypto resolved 70 new packages; each was checked against its
crates.io release date. Three were < 14 days old and were locked to the
previous release, in both `Cargo.lock` and `fuzz/Cargo.lock`:
`cc` 1.8.0 → **1.6.0** (1.7.0 was also < 14 days), `libc` 0.2.191 →
**0.2.190**, `zeroize` 1.9.1 → **1.9.0**.

**2026-10-21, Phase 4 step 6 (wgpu + winit + pollster):** 123 new
packages, each checked by `check-crate-age.py`. Nine were < 14 days old and
were locked to the newest release that is not: `combine` 4.6.9 → **4.6.8**,
`equivalent` 1.0.3 → **1.0.2**, `litrs` 1.0.1 → **1.0.0**, `redox_syscall`
0.9.5 → **0.9.4**, `toml_datetime` 1.1.2 → **1.1.1**, `toml_edit` 0.25.17 →
**0.25.15**, `toml_parser` 1.1.5 → **1.1.3**, `zerocopy` / `zerocopy-derive`
0.8.63 → **0.8.60**. No version already in the lock changed.

**Security-fix exceptions.** A release younger than 14 days may be adopted
only when it is the **first patched release** for RustSec advisories that
affect the version we would otherwise use — staying on a known-vulnerable
version to satisfy a supply-chain delay is the worse risk (priorities:
security first). Each exception is one line in
`.cargo/crate-age-exceptions.txt` (`crate version RUSTSEC-ID…`) and is
**verified by the CI check against the RustSec advisory database** (same
package, version listed as a `>=` patched bound), never trusted. Exceptions
**expire** once the release is 14 days old: the check then fails until the
line is deleted, and it validates every exception on every run, not only
crates in the current diff. Owner-approved 2026-10-18 (D30) on exactly these
terms: per crate, per version, per advisory ID; never a standing "security
fixes bypass the rule" flag.
The check prints every exception's **exact expiry** (release time + 14
days, UTC) and a **warning when one is under 48 hours away**, in CI (a
GitHub annotation) and in `scripts/ci/pre-push.sh`: a removal date counted
by hand was wrong once (roadmap D-37, 2026-10-27).

**Exception log** (every use, auditable):

| Date | Crate | Version | Advisories fixed | Released | Expires (14 days) | Removed |
|---|---|---|---|---|---|---|
| 2026-10-18 | rustls | 0.23.46 | RUSTSEC-2026-0346, -0347, -0348, -0349 | 2026-10-14 | 2026-10-28 | — |
| 2026-10-21 | rustls-webpki | 0.103.16 (transitive, via rustls/quinn) | RUSTSEC-2026-0382 (distrusted emSign intermediates accepted in certificate paths). **Not reachable here:** our QUIC client accepts any certificate and never builds a path (`remora-net/src/tls.rs` `AnyCertificate`, D1); adopted anyway — the CI advisory check fails on it and staying on a flagged version is the worse habit | 2026-10-20 | 2026-11-03 | — |
| 2026-10-25 | tokio | 1.53.3 | RUSTSEC-2026-0386 (`AsyncFd`'s safe constructors accept a file descriptor the caller does not own: an I/O-safety violation that can lead to a use-after-free). Our code never calls `AsyncFd`; whether our dependencies do was not checked — adopted either way (owner, 2026-10-25). Found when `cargo deny` failed CI on `1ceef72`. Only tokio's lock entry changed: `cargo update -p tokio` also moved four crates' `windows-sys` 0.61.2 → 0.52.0, which was not part of the fix, so the lock was edited to tokio alone and checked with `--locked` | 2026-10-13 | 2026-10-27 | — |

**Remembering the rule was not enough.** When the check first ran over the
phase-3 branch it found five more violations that earlier steps had locked
by hand without noticing: `arbitrary` 1.5.0 → **1.4.2** (fuzz only),
`either` 1.19.0 → **1.18.0**, `smallvec` 1.16.3 → **1.16.2**, `syn` 3.0.9 →
**3.0.6**, `unicode-ident` 1.0.27 → **1.0.26** (the latter three are
build-time / proc-macro crates). All locked to the newest release that was
≥ 14 days old on 2026-10-18.

## Spike lockfiles (outside the checks above)

Throwaway spikes keep their own workspace and lockfile (root `Cargo.toml`
`exclude`). `cargo deny`, `cargo audit` and the crate-age check read only the
main workspace, so nothing of ours checks these lockfiles; Dependabot does.

| Date | Spike | Change | Why |
|---|---|---|---|
| 2026-10-26 | `spikes/slint-wgpu` | tokio 1.54.0 → **1.53.3** (`cargo update -p tokio --precise 1.53.3`; only tokio's entry changed; `cargo build --locked --release` passes) | Dependabot alert #1, GHSA-5wjr-9356-4wc8 / CVE-2026-115567 (race condition in `tokio::time::Interval`), affects 1.54.0 only, patched in 1.54.1. 1.53.3 is the version the main workspace already locks and checks, so the 14-day rule is not touched. `cargo tree -i tokio --target all` shows tokio comes only through `wasm-bindgen-futures` (wgpu's WebAssembly path) and is not built for macOS (`cargo tree -i tokio` without `--target all`: nothing). Removed rather than dismissed (owner, 2026-10-26). The spike itself goes at the end of Phase 4.5 (roadmap D-41) |

## Known duplicate versions (accepted)

From a scratch resolve of the network + crypto set:

| Crate | Versions | Pulled by | Why accepted |
|---|---|---|---|
| getrandom | 0.2 / 0.3 / 0.4 | rand_core 0.6 & ring / snow / quinn's rand 0.10 | All are thin wrappers over the OS CSPRNG |
| rand_core, chacha20 (as RNG) | 0.6 + 0.10, 0.9 + 0.10 | quinn-proto's `rand 0.10` | Used by quinn for connection IDs, not for our keys |
| syn | 2 / 3 | proc macros (compile time only) | Not in the binary |

## Rejected / replaced

| Crate | Why not |
|---|---|
| stun-rs | Not updated since 2025-03; `is` ships a STUN parser we can fuzz |
| webrtc-ice | Async (not sans-IO), pulls in the webrtc-rs stack |
| aws-lc-rs (rustls default backend) | Build complexity on Windows (cmake + NASM) |
| screencapturekit (high-level crate) | Fast-moving (v11); objc2 generated bindings give us direct control |
