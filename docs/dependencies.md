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
| `openh264` | 0.9.8 | 0.9.8 (2026-08-08; 0.9.9 exists and is now ≥ 14 days old, but 0.9.8 is the version spike S-L1 measured, phase4.6-criteria §5) | codec (Linux) | Phase 4.6: the Linux host's H.264 encoder, in software (S-L1b: convert + encode p50 10.7 ms at 1080p on the owner's laptop). BSD-2-Clause. Its `openh264-sys2` 0.9.9 (BSD-2-Clause) compiles Cisco's C source shipped in the crate (`upstream/`, `build.rs` with `cc`; read 2026-11-02) — no system library, no download at build time; NASM assembly only if `nasm` is installed (`try_compile_nasm`, via `nasm-rs` 0.3.2). `wide` 1.7.1 and `safe_arch` 1.2.0 (Zlib OR Apache-2.0 OR MIT) are its SIMD helpers |
| `ashpd` | 0.13.13, default features **off**, `tokio` + `screencast` + `remote_desktop` | 0.13.13 (2026-07-17) | capture (Linux) | Phase 4.6 (architecture D48): the desktop portal over D-Bus (zbus) — ScreenCast to pick the monitor, RemoteDesktop for keyboard and pointer, restore tokens so the person allows it once. MIT. Measured on the owner's GNOME 50 in spikes S-L1/S-L2 |
| `pipewire` | 0.10.1 | 0.10.1 (2026-08-19) | capture (Linux) | Phase 4.6: receives the portal's screen stream. MIT. With `pipewire-sys`, `libspa`, `libspa-sys` 0.10.1 (MIT; FFI bindings generated by bindgen at build time, so the build needs **libclang** and **libpipewire-0.3** headers via pkg-config — `pipewire-sys` Cargo.toml `[package.metadata.system-deps]`, read 2026-11-02). Build-time helpers: `system-deps` 7.0.8, `cfg-expr` 0.20.10, `target-lexicon` 0.13.5 (Apache-2.0 WITH LLVM-exception), `version-compare` 0.2.1; `cookie-factory` 0.3.3 (MIT) serialises SPA pods. The `unsafe` lives in these crates, not in ours: `remora-capture/src/sys/linux.rs` uses only their safe API |
| futures-util | 0.3.34, default features **off** | 0.3.34 (already locked) | capture (Linux) | `StreamExt::next` for the portal session's `Closed` signal (the person pressed GNOME's "Stop") |
| `rustix` | 1.1.5, default features **off**, `std` + `time` | 1.1.5 (already locked through other crates) | app (Linux) | `clock_gettime(CLOCK_MONOTONIC)` for the shared latency clock (`remora-app/src/sys/linux.rs`) with no `unsafe` of our own: rustix-1.1.5 `src/time/clock.rs:60` is a safe function. Test P0 runs on Linux too (two processes agree; a planted 1 ms skew fails) |
| `mdns-sd` | 0.21.6, default features **off** | 0.21.6 (2026-10-19; 0.21.7 < 14 days) | net | Phase 4.7 home-network discovery (spike S-C1: Mac finds the laptop in 0.07–1.1 s across the owner's Wi-Fi). Apache-2.0 OR MIT. The crate itself is `#![forbid(unsafe_code)]` (src/lib.rs:157, read 2026-11-02). New with it: `flume` 0.12.0 (channels, Apache-2.0/MIT, no `unsafe`), `spin` 0.9.9 (flume's spin lock, MIT, uses `unsafe` internally), `if-addrs` 0.15.0 (lists network interfaces through the OS, MIT OR BSD-3-Clause, `unsafe` FFI), `socket-pktinfo` 0.4.1 (receives the arrival interface of each UDP packet, MIT, `unsafe` FFI). Counts of `unsafe` lines read from their sources: 0 / 117 / 50 / 31. What it hears is untrusted: parsed by `remora_net::discovery` with limits and a fuzz target (C4) |
| `opus` | 0.4.0 | 0.4.0 (2026-08-23) | codec | Phase 4.8 sound: Opus encode (host) and decode (viewer); MIT/Apache-2.0. Built on `opusic-sys` 0.7.5 (BSD-3-Clause; 0.7.6 < 14 days), whose default feature `bundled` compiles **libopus 1.6.1** from the C source shipped in the crate with cmake (opusic-sys build.rs, opus/package_version, read 2026-11-02; its opus.patch only changes MSVC runtime flags and OSCE defines). Needs `cmake` on build machines (installed on the Mac and the laptop; GitHub runner images: to be confirmed by CI) via the `cmake` crate 0.1.58. libopus is C code that parses network data on the viewer: packets are size-checked by `remora_proto::audio` and `remora_codec::audio` first (A3) |
| `cpal` | 0.18.2, default features **off** | 0.18.2 | viewer (macOS) | Phase 4.8 sound playback on the Mac: opens the current output device (speakers, Bluetooth earbuds) and pulls samples from our callback. Apache-2.0. On macOS it drives CoreAudio through `coreaudio-rs` 0.14.2 (MIT/Apache-2.0), `objc2-audio-toolbox` and `objc2-avf-audio` 0.3.2 (Zlib OR Apache-2.0 OR MIT, the same objc2 generation as our capture code), `mach2` 0.6.0 (BSD-2-Clause OR MIT OR Apache-2.0, Mach kernel calls), `dasp_sample` 0.11.0 and `num-derive` 0.4.2 (MIT OR Apache-2.0). `alsa` 0.11.0 (Apache-2.0/MIT) and `alsa-sys` 0.4.0 (MIT) are cpal's Linux backend: in the lockfile, **not built** (the viewer takes cpal on macOS only). The `unsafe` is in these crates, not ours (`remora-viewer/src/sound.rs` has none): lines containing `unsafe` in their `src/`, counted 2026-11-03: cpal 203, coreaudio-rs 52, mach2 66, dasp_sample 2, num-derive 0, objc2-audio-toolbox 1165 / objc2-avf-audio 3208 (generated bindings). Only decoded, size-checked samples reach it (A3) |
| wgpu | 30.0.1, default features **off**, `std` + `wgsl` + `metal` | 30.0.1 (2026-08-22) | viewer (macOS) | The Phase 4 video window and offscreen P7 rendering (phase4-criteria R1/R2). Metal backend only: the window is macOS-only until Phase 6.5, and every other backend would add code we do not run. Pulls naga 30.0.1 (shader compiler) and objc2-metal / objc2-quartz-core 0.3.2 |
| winit | 0.30.13, default features **off**, `rwh_06` | 0.30.13 (2026-03-02) | viewer (macOS) | The window and its event loop (R1, R5). No X11/Wayland features. 0.31 is beta only. Uses the older objc2 0.5 / objc2-app-kit 0.2 family itself, so both objc2 generations are in the lock (cargo deny reports the duplicate; it is not a RustCrypto crate, D3 is unaffected) |
| pollster | 1.0.1 | 1.0.1 (2026-07-10) | viewer (macOS) | Blocks on wgpu's adapter/device futures once at start-up (no async runtime on the window thread) |
| slint | 1.18.1, default features **off**: `std`, `compat-1-2`, `accessibility`, `backend-winit`, `renderer-software`, `unstable-winit-030` | 1.18.1 (2026-09-21) | ui, host, viewer (macOS) | The Phase 4.5 GUI. Winit backend so our video window shares Slint's event loop (C′, phase4.5-criteria §2); software renderer (S1: +17 MB, against +35–39 MB for femtovg on wgpu). Licence: GPL-3.0-only option, per-crate `deny.toml` exceptions. Its generated code holds `unsafe`, so the markup lives in `remora-ui` (architecture D45). MSRV 1.92 → workspace MSRV |
| objc2-app-kit | 0.3.2, default features **off**: `std`, `NSWindow`, `NSView`, `NSResponder` | 0.3.2 (already locked through Slint) | input (macOS) | I3: `NSWindow.setCollectionBehavior` for the session indicator (architecture D46) |
| raw-window-handle | 0.6.2 | 0.6.2 (already locked through winit) | input, host | The window handle winit gives for I3 |
| i-slint-backend-testing | 1.18.1 | 1.18.1 (2026-09-21) | host, viewer (macOS, tests only) | Drives the GUI from Rust tests (D-4): finds elements by accessible label, presses them. Needs `SLINT_EMIT_DEBUG_INFO=1` (`.cargo/config.toml`) |
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
| 2026-10-18 | rustls | 0.23.46 | RUSTSEC-2026-0346, -0347, -0348, -0349 | 2026-10-14 | 2026-10-28 | 2026-10-30 (roadmap D-42) |
| 2026-10-21 | rustls-webpki | 0.103.16 (transitive, via rustls/quinn) | RUSTSEC-2026-0382 (distrusted emSign intermediates accepted in certificate paths). **Not reachable here:** our QUIC client accepts any certificate and never builds a path (`remora-net/src/tls.rs` `AnyCertificate`, D1); adopted anyway — the CI advisory check fails on it and staying on a flagged version is the worse habit | 2026-10-20 | 2026-11-03 | — |
| 2026-10-25 | tokio | 1.53.3 | RUSTSEC-2026-0386 (`AsyncFd`'s safe constructors accept a file descriptor the caller does not own: an I/O-safety violation that can lead to a use-after-free). Our code never calls `AsyncFd`; whether our dependencies do was not checked — adopted either way (owner, 2026-10-25). Found when `cargo deny` failed CI on `1ceef72`. Only tokio's lock entry changed: `cargo update -p tokio` also moved four crates' `windows-sys` 0.61.2 → 0.52.0, which was not part of the fix, so the lock was edited to tokio alone and checked with `--locked` | 2026-10-13 | 2026-10-27 | 2026-10-30 (roadmap D-37) |

**Remembering the rule was not enough.** When the check first ran over the
phase-3 branch it found five more violations that earlier steps had locked
by hand without noticing: `arbitrary` 1.5.0 → **1.4.2** (fuzz only),
`either` 1.19.0 → **1.18.0**, `smallvec` 1.16.3 → **1.16.2**, `syn` 3.0.9 →
**3.0.6**, `unicode-ident` 1.0.27 → **1.0.26** (the latter three are
build-time / proc-macro crates). All locked to the newest release that was
≥ 14 days old on 2026-10-18.

## Phase 4.5 GUI: Slint's transitive crates (2026-11-01)

Adding `slint` 1.18.1 (macOS target only, through `remora-ui`, `remora-host`
and `remora-viewer`) resolved **299 new registry crates**. Cargo's lockfile
covers every platform, so the list also holds Linux crates (Wayland, X11,
`zbus`, AT-SPI) and Windows crates that are never built for macOS; the
14-day rule and `cargo deny` check them all the same.

* **14-day rule** (`check-crate-age.py`): 36 were newer than 14 days on
  2026-11-01 and are locked to the newest older release: `annotate-snippets` 0.12.17 → **0.12.16**, `crc32fast` 1.5.3 → **1.5.2**, `lyon_algorithms` 1.0.22 → **1.0.21**, `lyon_geom` 1.0.20 → **1.0.19**, `memmap2` 0.9.12 → **0.9.11**, `ordered-float` 5.5.1 → **5.5.0**, `pulldown-cmark` 0.13.6 → **0.13.5** (0.13.4 first, which `cargo deny` refused: RUSTSEC-2026-0414, see below), `roxmltree` 0.21.2 → **0.21.1**, `smol_str` 0.3.7 → **0.3.6**, `utf8_iter` 1.1.0 → **1.0.4**, `uuid` 1.29.0 → **1.28.0**, `webbrowser` 1.2.6 → **1.2.4**, `wl-clipboard-rs` 0.9.5 → **0.9.4**, `yazi` 0.2.2 → **0.2.1**, `zcheapstr` 1.2.0 → **1.1.0**. The
  `icu` family (all released 2026-10-22, each requiring the others at the
  same version) moved as one set: `icu_collections` → **2.3.0**, `icu_decimal` → **2.3.0**, `icu_decimal_data` → **2.3.0**, `icu_locale_core` → **2.3.0**, `icu_locale_fallback` → **2.3.0**, `icu_locale_fallback_data` → **2.3.0**, `icu_normalizer` → **2.3.0**, `icu_normalizer_data` → **2.3.0**, `icu_plurals` → **2.3.0**, `icu_plurals_data` → **2.3.0**, `icu_properties` → **2.3.0**, `icu_properties_data` → **2.3.0**, `icu_provider` → **2.3.1**, `icu_segmenter` → **2.3.0**, `icu_segmenter_data` → **2.3.0**, `fixed_decimal` → **0.7.2**, `tinystr` → **0.8.4**, `yoke` → **0.8.3**, `zerovec` → **0.11.8**, `zerovec-derive` → **0.11.6**.
* **`clipboard-win` has no compliant release yet.** 5.2.0–5.4.1 are all
  yanked, 5.1.0 is below `arboard` 3.6/3.7's `^5.3.1`, and 5.4.2 / 5.4.3 were
  released 2026-10-23. Locked to **5.4.2** (05:26:39 UTC), which is 14 days
  old at **2026-11-06 05:26 UTC (10:56 local)**. It is Windows-only (`arboard`
  uses Apple's clipboard on macOS), but it is in the lock, so the commits
  that add Slint are pushed after that time (roadmap D-47). No exception:
  the exception file is for security fixes only.
* **An older release can carry a fixed vulnerability.** Locking
  `pulldown-cmark` to 0.13.4 for the 14-day rule brought back
  RUSTSEC-2026-0414 (exponential event growth with `ENABLE_WIKILINKS`,
  fixed in 0.13.5); `cargo deny` refused it before anything was pushed.
  0.13.5 (2026-10-21 19:45 UTC) is 14 days old before these commits can be
  pushed (D-47), so it needs no exception. It is used only by Slint's markup
  compiler, at build time. **Rule:** after locking an older release, run
  `cargo deny check advisories` before committing.
* **Unmaintained (RustSec warnings, not vulnerabilities):** `bincode` 2.0.1
  (RUSTSEC-2025-0141), `ttf-parser` 0.25.1 (RUSTSEC-2026-0192), `zbus_names`
  4.3.5, `zvariant` / `zvariant_derive` 5.15.1 (RUSTSEC-2026-0370..0372).
  All come through Slint; `zbus*` / `zvariant*` only on Linux (AT-SPI). The
  policy reports unmaintained crates for our direct dependencies only
  (`deny.toml`), so these are recorded here, not failed.
* **Licences** (`cargo deny`): Slint's own crates are "GPL-3.0-only OR
  LicenseRef-Slint-…"; Remora takes GPL-3.0-only for the GPL apps, with one
  `[[licenses.exceptions]]` entry per Slint crate. `BSL-1.0` (Boost, permissive)
  joined the allow list for `clipboard-win` and `error-code`. Everything
  else is MIT, Apache-2.0, BSD, ISC, Zlib or Unicode-3.0.

Every new crate, its locked version, its licence and the crate that pulls
it in (one shortest path from our crates; R8 checks that each is here):

| Crate | Locked | Licence | Pulled in by |
|---|---|---|---|
| `ab_glyph` | 0.2.32 | Apache-2.0 | `sctk-adwaita` |
| `ab_glyph_rasterizer` | 0.1.10 | Apache-2.0 | `ab_glyph` |
| `accesskit` | 0.24.1 | MIT OR Apache-2.0 | `i-slint-core` |
| `accesskit_atspi_common` | 0.19.1 | MIT OR Apache-2.0 | `accesskit_unix` |
| `accesskit_consumer` | 0.38.0 | MIT OR Apache-2.0 | `accesskit_ios` |
| `accesskit_ios` | 0.1.2 | MIT OR Apache-2.0 | `accesskit_winit` |
| `accesskit_macos` | 0.26.3 | MIT OR Apache-2.0 | `accesskit_winit` |
| `accesskit_unix` | 0.22.1 | MIT OR Apache-2.0 | `accesskit_winit` |
| `accesskit_windows` | 0.34.0 | MIT OR Apache-2.0 | `accesskit_winit` |
| `accesskit_winit` | 0.33.2 | Apache-2.0 | `i-slint-backend-winit` |
| `adler2` | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | `miniz_oxide` |
| `ahash` | 0.8.12 | MIT OR Apache-2.0 | `winit` |
| `allocator-api2` | 0.2.21 | MIT OR Apache-2.0 | `hashbrown` |
| `android_system_properties` | 0.1.6 | MIT OR Apache-2.0 | `wgpu-hal` |
| `annotate-snippets` | 0.12.16 | MIT OR Apache-2.0 | `i-slint-compiler` |
| `arboard` | 3.7.0 | MIT OR Apache-2.0 | `i-slint-backend-winit` |
| `arrayref` | 0.3.9 | BSD-2-Clause | `tiny-skia` |
| `as-raw-xcb-connection` | 1.0.1 | MIT OR Apache-2.0 | `x11rb` |
| `ash` | 0.38.0+1.3.281 | MIT OR Apache-2.0 | `wgpu-hal` |
| `async-broadcast` | 0.7.2 | MIT OR Apache-2.0 | `zbus` |
| `async-channel` | 2.5.0 | Apache-2.0 OR MIT | `accesskit_unix` |
| `async-executor` | 1.14.0 | Apache-2.0 OR MIT | `zbus` |
| `async-io` | 2.6.0 | Apache-2.0 OR MIT | `zbus` |
| `async-lock` | 3.4.2 | Apache-2.0 OR MIT | `zbus` |
| `async-process` | 2.5.0 | Apache-2.0 OR MIT | `zbus` |
| `async-recursion` | 1.2.0 | MIT OR Apache-2.0 | `zbus` |
| `async-signal` | 0.2.14 | Apache-2.0 OR MIT | `async-process` |
| `async-task` | 4.7.1 | Apache-2.0 OR MIT | `zbus` |
| `async-trait` | 0.1.92 | MIT OR Apache-2.0 | `zbus` |
| `atspi` | 0.29.0 | Apache-2.0 OR MIT | `accesskit_unix` |
| `atspi-common` | 0.13.0 | Apache-2.0 OR MIT | `accesskit_atspi_common` |
| `atspi-proxies` | 0.13.0 | Apache-2.0 OR MIT | `atspi` |
| `bincode` | 2.0.1 | MIT | `typed-index-collections` |
| `bindgen` | 0.72.1 | BSD-3-Clause | `skia-bindings` |
| `blocking` | 1.7.0 | Apache-2.0 OR MIT | `zbus` |
| `borsh` | 1.8.1 | MIT OR Apache-2.0 | `smol_str` |
| `by_address` | 1.2.1 | MIT OR Apache-2.0 | `i-slint-compiler` |
| `byteorder-lite` | 0.1.0 | Unlicense OR MIT | `image` |
| `calloop-wayland-source` | 0.3.0 | MIT | `smithay-client-toolkit` |
| `cexpr` | 0.6.0 | Apache-2.0/MIT | `bindgen` |
| `cgl` | 0.3.2 | MIT / Apache-2.0 | `glutin` |
| `chrono` | 0.4.45 | MIT OR Apache-2.0 | `i-slint-core` |
| `clang-sys` | 1.9.1 | Apache-2.0 | `bindgen` |
| `clipboard-win` | 5.4.2 | BSL-1.0 | `arboard` |
| `clru` | 0.6.3 | MIT | `i-slint-core` |
| `color_quant` | 1.1.0 | MIT | `gif` |
| `const-field-offset` | 0.2.1 | MIT OR Apache-2.0 | `slint` |
| `const-field-offset-macro` | 0.2.1 | MIT OR Apache-2.0 | `const-field-offset` |
| `convert_case` | 0.10.0 | MIT | `derive_more-impl` |
| `countme` | 3.0.1 | MIT OR Apache-2.0 | `rowan` |
| `crc32fast` | 1.5.2 | MIT OR Apache-2.0 | `png` |
| `critical-section` | 1.2.0 | MIT OR Apache-2.0 | `once_cell` |
| `crossbeam-channel` | 0.5.17 | MIT OR Apache-2.0 | `muda` |
| `ctor` | 0.10.1 | Apache-2.0 OR MIT | `tiny-xlib` |
| `data-url` | 0.3.2 | MIT OR Apache-2.0 | `i-slint-compiler` |
| `derive_more` | 2.1.1 | MIT | `i-slint-common` |
| `derive_more-impl` | 2.1.1 | MIT | `derive_more` |
| `downcast-rs` | 1.2.1 | MIT/Apache-2.0 | `wayland-backend` |
| `drm` | 0.14.1 | MIT | `i-slint-backend-linuxkms` |
| `drm-ffi` | 0.9.1 | MIT | `drm` |
| `drm-fourcc` | 2.2.0 | MIT | `drm` |
| `drm-sys` | 0.8.1 | MIT | `drm-ffi` |
| `dtor` | 0.8.1 | Apache-2.0 OR MIT | `ctor` |
| `endi` | 1.1.1 | MIT | `zvariant` |
| `enumflags2` | 0.7.12 | MIT OR Apache-2.0 | `zbus` |
| `enumflags2_derive` | 0.7.12 | MIT OR Apache-2.0 | `enumflags2` |
| `error-code` | 3.4.0 | BSL-1.0 | `clipboard-win` |
| `euclid` | 0.22.14 | MIT OR Apache-2.0 | `i-slint-core` |
| `event-listener` | 5.4.2 | Apache-2.0 OR MIT | `zbus` |
| `event-listener-strategy` | 0.5.4 | Apache-2.0 OR MIT | `async-broadcast` |
| `fastrand` | 2.5.0 | Apache-2.0 OR MIT | `softbuffer` |
| `fdeflate` | 0.3.7 | MIT OR Apache-2.0 | `png` |
| `field-offset` | 0.3.6 | MIT OR Apache-2.0 | `const-field-offset` |
| `filetime` | 0.2.29 | MIT/Apache-2.0 | `tar` |
| `fixed_decimal` | 0.7.2 | Unicode-3.0 | `icu_decimal` |
| `fixedbitset` | 0.5.7 | MIT OR Apache-2.0 | `petgraph` |
| `flate2` | 1.1.10 | MIT OR Apache-2.0 | `usvg` |
| `float-cmp` | 0.9.0 | MIT | `strict-num` |
| `font-types` | 0.12.7 | MIT OR Apache-2.0 | `read-fonts` |
| `fontdb` | 0.24.0 | MIT | `usvg` |
| `fontique` | 0.11.1 | Apache-2.0 OR MIT | `i-slint-common` |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | `url` |
| `futures` | 0.3.34 | MIT OR Apache-2.0 | `i-slint-backend-winit` |
| `futures-channel` | 0.3.34 | MIT OR Apache-2.0 | `futures` |
| `futures-executor` | 0.3.34 | MIT OR Apache-2.0 | `futures` |
| `futures-io` | 0.3.34 | MIT OR Apache-2.0 | `futures` |
| `futures-lite` | 2.6.1 | Apache-2.0 OR MIT | `zbus` |
| `futures-macro` | 0.3.34 | MIT OR Apache-2.0 | `futures-util` |
| `futures-sink` | 0.3.34 | MIT OR Apache-2.0 | `futures` |
| `gethostname` | 1.1.0 | Apache-2.0 | `x11rb` |
| `gif` | 0.14.2 | MIT OR Apache-2.0 | `resvg` |
| `gl_generator` | 0.14.0 | Apache-2.0 | `glutin_egl_sys` |
| `glob` | 0.3.4 | MIT OR Apache-2.0 | `clang-sys` |
| `glow` | 0.18.0 | MIT OR Apache-2.0 OR Zlib | `i-slint-renderer-skia` |
| `glutin` | 0.32.3 | Apache-2.0 | `i-slint-backend-winit` |
| `glutin-winit` | 0.5.0 | MIT | `i-slint-backend-winit` |
| `glutin_egl_sys` | 0.7.1 | Apache-2.0 | `glutin` |
| `glutin_glx_sys` | 0.6.1 | Apache-2.0 | `glutin` |
| `glutin_wgl_sys` | 0.6.1 | Apache-2.0 | `glutin` |
| `gpu-allocator` | 0.28.0 | MIT OR Apache-2.0 | `wgpu-hal` |
| `grid` | 1.0.1 | MIT | `taffy` |
| `harfrust` | 0.12.0 | MIT | `parley` |
| `hex` | 0.4.3 | MIT OR Apache-2.0 | `zbus` |
| `htmlparser` | 0.2.1 | MIT OR Apache-2.0 | `i-slint-common` |
| `i-slint-backend-linuxkms` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `slint` |
| `i-slint-backend-selector` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `slint` |
| `i-slint-backend-testing` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `remora-host` |
| `i-slint-backend-winit` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `slint` |
| `i-slint-common` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `i-slint-backend-testing` |
| `i-slint-compiler` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `slint-macros` |
| `i-slint-core` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `i-slint-backend-testing` |
| `i-slint-core-macros` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `slint` |
| `i-slint-renderer-skia` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `i-slint-backend-winit` |
| `i-slint-renderer-software` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `i-slint-backend-testing` |
| `iana-time-zone` | 0.1.65 | MIT OR Apache-2.0 | `chrono` |
| `iana-time-zone-haiku` | 0.1.2 | MIT OR Apache-2.0 | `iana-time-zone` |
| `icu_collections` | 2.3.0 | Unicode-3.0 | `icu_normalizer` |
| `icu_decimal` | 2.3.0 | Unicode-3.0 | `i-slint-common` |
| `icu_decimal_data` | 2.3.0 | Unicode-3.0 | `icu_decimal` |
| `icu_locale_core` | 2.3.0 | Unicode-3.0 | `i-slint-common` |
| `icu_locale_fallback` | 2.3.0 | Unicode-3.0 | `icu_decimal` |
| `icu_locale_fallback_data` | 2.3.0 | Unicode-3.0 | `icu_locale_fallback` |
| `icu_normalizer` | 2.3.0 | Unicode-3.0 | `i-slint-core` |
| `icu_normalizer_data` | 2.3.0 | Unicode-3.0 | `icu_normalizer` |
| `icu_plurals` | 2.3.0 | Unicode-3.0 | `icu_decimal` |
| `icu_plurals_data` | 2.3.0 | Unicode-3.0 | `icu_plurals` |
| `icu_properties` | 2.3.0 | Unicode-3.0 | `icu_normalizer` |
| `icu_properties_data` | 2.3.0 | Unicode-3.0 | `icu_properties` |
| `icu_provider` | 2.3.1 | Unicode-3.0 | `i-slint-common` |
| `icu_segmenter` | 2.3.0 | Unicode-3.0 | `parley` |
| `icu_segmenter_data` | 2.3.0 | Unicode-3.0 | `icu_segmenter` |
| `idna` | 1.1.0 | MIT OR Apache-2.0 | `url` |
| `idna_adapter` | 1.2.2 | Apache-2.0 OR MIT | `idna` |
| `image` | 0.25.10 | MIT OR Apache-2.0 | `i-slint-core` |
| `image-webp` | 0.2.4 | MIT OR Apache-2.0 | `resvg` |
| `imagesize` | 0.15.0 | MIT | `usvg` |
| `imgref` | 1.12.3 | CC0-1.0 OR Apache-2.0 | `i-slint-backend-winit` |
| `input` | 0.10.0 | MIT | `i-slint-backend-linuxkms` |
| `input-sys` | 1.19.0 | MIT | `input` |
| `io-lifetimes` | 1.0.11 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | `udev` |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 | `serde_json` |
| `keyboard-types` | 0.7.0 | MIT OR Apache-2.0 | `muda` |
| `khronos_api` | 3.1.0 | Apache-2.0 | `gl_generator` |
| `kurbo` | 0.13.1 | Apache-2.0 OR MIT | `svgtypes` |
| `libseat` | 0.2.4 | MIT | `i-slint-backend-linuxkms` |
| `libseat-sys` | 0.2.0 | MIT | `libseat` |
| `libudev-sys` | 0.1.4 | MIT | `udev` |
| `linebender_resource_handle` | 0.1.1 | Apache-2.0 OR MIT | `fontique` |
| `litemap` | 0.8.3 | Unicode-3.0 | `icu_locale_core` |
| `lyon_algorithms` | 1.0.21 | MIT OR Apache-2.0 | `i-slint-core` |
| `lyon_extra` | 1.1.0 | MIT OR Apache-2.0 | `i-slint-core` |
| `lyon_geom` | 1.0.19 | MIT OR Apache-2.0 | `i-slint-core` |
| `lyon_path` | 1.0.19 | MIT OR Apache-2.0 | `i-slint-core` |
| `memmap2` | 0.9.11 | MIT OR Apache-2.0 | `winit` |
| `memoffset` | 0.9.1 | MIT | `field-offset` |
| `miniz_oxide` | 0.8.9 | MIT OR Zlib OR Apache-2.0 | `png` |
| `miniz_oxide` | 0.9.1 | MIT OR Zlib OR Apache-2.0 | `flate2` |
| `moxcms` | 0.8.1 | BSD-3-Clause OR Apache-2.0 | `image` |
| `muda` | 0.19.3 | Apache-2.0 OR MIT | `i-slint-backend-winit` |
| `nix` | 0.31.3 | MIT | `i-slint-backend-linuxkms` |
| `objc2-core-text` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | `fontique` |
| `ordered-float` | 5.5.0 | MIT | `wgpu-hal` |
| `ordered-stream` | 0.2.0 | MIT OR Apache-2.0 | `zbus` |
| `os_pipe` | 1.2.3 | MIT | `wl-clipboard-rs` |
| `owned_ttf_parser` | 0.25.1 | Apache-2.0 | `ab_glyph` |
| `parking` | 2.2.1 | Apache-2.0 OR MIT | `async-io` |
| `parlance` | 0.1.1 | Apache-2.0 OR MIT | `fontique` |
| `parley` | 0.11.1 | Apache-2.0 OR MIT | `i-slint-core` |
| `parley_data` | 0.11.1 | Apache-2.0 OR MIT | `parley` |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 | `winit` |
| `petgraph` | 0.8.3 | MIT OR Apache-2.0 | `tree_magic_mini` |
| `phf` | 0.13.1 | MIT | `accesskit_atspi_common` |
| `phf_generator` | 0.13.1 | MIT | `phf_macros` |
| `phf_macros` | 0.13.1 | MIT | `phf` |
| `phf_shared` | 0.13.1 | MIT | `phf` |
| `pico-args` | 0.5.0 | MIT | `resvg` |
| `pin-utils` | 0.1.1 | MIT OR Apache-2.0 | `spin_on` |
| `pin-weak` | 1.1.0 | MIT | `slint` |
| `piper` | 0.2.5 | MIT OR Apache-2.0 | `blocking` |
| `pkg-config` | 0.3.34 | MIT OR Apache-2.0 | `x11-dl` |
| `png` | 0.18.1 | MIT OR Apache-2.0 | `image` |
| `polycool` | 0.4.0 | MIT OR Apache-2.0 | `kurbo` |
| `potential_utf` | 0.1.6 | Unicode-3.0 | `icu_locale_fallback` |
| `presser` | 0.3.1 | MIT OR Apache-2.0 | `gpu-allocator` |
| `prettyplease` | 0.2.37 | MIT OR Apache-2.0 | `bindgen` |
| `pulldown-cmark` | 0.13.5 | MIT | `i-slint-common` |
| `pxfm` | 0.1.30 | BSD-3-Clause OR Apache-2.0 | `moxcms` |
| `quick-error` | 2.0.1 | MIT/Apache-2.0 | `image-webp` |
| `quick-xml` | 0.41.0 | MIT | `wayland-scanner` |
| `range-alloc` | 0.1.5 | MIT OR Apache-2.0 | `wgpu-hal` |
| `read-fonts` | 0.41.0 | MIT OR Apache-2.0 | `fontique` |
| `regex` | 1.13.1 | MIT OR Apache-2.0 | `skia-bindings` |
| `resvg` | 0.48.1 | Apache-2.0 OR MIT | `i-slint-common` |
| `rgb` | 0.8.53 | MIT | `i-slint-core` |
| `rowan` | 0.17.0 | MIT OR Apache-2.0 | `i-slint-compiler` |
| `roxmltree` | 0.21.1 | MIT OR Apache-2.0 | `fontique` |
| `scoped-tls` | 1.0.1 | MIT/Apache-2.0 | `wayland-backend` |
| `scoped-tls-hkt` | 0.1.5 | MIT/Apache-2.0 | `i-slint-backend-winit` |
| `sctk-adwaita` | 0.10.1 | MIT | `winit` |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | `i-slint-core-macros` |
| `serde_repr` | 0.1.21 | MIT OR Apache-2.0 | `zbus` |
| `serde_spanned` | 1.1.2 | MIT OR Apache-2.0 | `toml` |
| `signal-hook-registry` | 1.4.8 | MIT OR Apache-2.0 | `async-signal` |
| `simd-adler32` | 0.3.10 | MIT | `fdeflate` |
| `simplecss` | 0.2.2 | Apache-2.0 OR MIT | `usvg` |
| `siphasher` | 1.0.4 | MIT OR Apache-2.0 | `svgtypes` |
| `skia-bindings` | 0.153.3 | MIT | `skia-safe` |
| `skia-safe` | 0.153.3 | MIT | `i-slint-renderer-skia` |
| `skrifa` | 0.44.0 | MIT OR Apache-2.0 | `i-slint-common` |
| `slint` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `remora-host` |
| `slint-macros` | 1.18.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | `slint` |
| `slotmap` | 1.1.1 | Zlib | `taffy` |
| `smithay-client-toolkit` | 0.19.2 | MIT | `winit` |
| `softbuffer` | 0.4.8 | MIT OR Apache-2.0 | `i-slint-backend-winit` |
| `spin_on` | 0.1.1 | Apache-2.0 OR MIT | `slint-macros` |
| `spirv` | 0.4.0+sdk-1.4.341.0 | Apache-2.0 | `naga` |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 | `vtable` |
| `strict-num` | 0.1.1 | MIT | `usvg` |
| `strum` | 0.28.0 | MIT | `i-slint-core` |
| `strum_macros` | 0.28.0 | MIT | `strum` |
| `svgtypes` | 0.16.1 | Apache-2.0 OR MIT | `resvg` |
| `swash` | 0.2.10 | Apache-2.0 OR MIT | `i-slint-core` |
| `sys-locale` | 0.3.2 | MIT OR Apache-2.0 | `i-slint-core` |
| `taffy` | 0.10.1 | MIT | `i-slint-core` |
| `tar` | 0.4.46 | MIT OR Apache-2.0 | `skia-bindings` |
| `tempfile` | 3.27.0 | MIT OR Apache-2.0 | `uds_windows` |
| `text-size` | 1.1.1 | MIT OR Apache-2.0 | `rowan` |
| `tiny-skia` | 0.11.4 | BSD-3-Clause | `sctk-adwaita` |
| `tiny-skia` | 0.12.0 | BSD-3-Clause | `resvg` |
| `tiny-skia-path` | 0.11.4 | BSD-3-Clause | `tiny-skia` |
| `tiny-skia-path` | 0.12.0 | BSD-3-Clause | `tiny-skia` |
| `tiny-xlib` | 0.2.5 | MIT OR Apache-2.0 OR Zlib | `softbuffer` |
| `tinystr` | 0.8.4 | Unicode-3.0 | `icu_locale_core` |
| `toml` | 1.1.8+spec-1.1.0 | MIT OR Apache-2.0 | `skia-bindings` |
| `toml_writer` | 1.1.3+spec-1.1.0 | MIT OR Apache-2.0 | `toml` |
| `tree_magic_mini` | 3.2.2 | MIT | `wl-clipboard-rs` |
| `ttf-parser` | 0.25.1 | MIT OR Apache-2.0 | `owned_ttf_parser` |
| `typed-index-collections` | 3.5.0 | MIT OR Apache-2.0 | `i-slint-compiler` |
| `udev` | 0.9.3 | MIT | `input` |
| `uds_windows` | 1.2.1 | MIT | `zbus` |
| `unicase` | 2.10.0 | MIT OR Apache-2.0 | `pulldown-cmark` |
| `unicode-bidi` | 0.3.18 | MIT OR Apache-2.0 | `usvg` |
| `unicode-linebreak` | 0.1.5 | Apache-2.0 | `i-slint-core` |
| `unicode-script` | 0.5.8 | MIT OR Apache-2.0 | `i-slint-core` |
| `unicode-vo` | 0.1.0 | MIT/Apache-2.0 | `usvg` |
| `unicode-xid` | 0.2.6 | MIT OR Apache-2.0 | `derive_more-impl` |
| `unty` | 0.0.4 | MIT OR Apache-2.0 | `bincode` |
| `url` | 2.5.8 | MIT OR Apache-2.0 | `webbrowser` |
| `usvg` | 0.48.1 | Apache-2.0 OR MIT | `resvg` |
| `utf8_iter` | 1.0.4 | Apache-2.0 OR MIT | `icu_collections` |
| `uuid` | 1.28.0 | Apache-2.0 OR MIT | `accesskit` |
| `vtable` | 0.5.0 | MIT OR Apache-2.0 | `i-slint-backend-testing` |
| `vtable-macro` | 0.5.0 | MIT OR Apache-2.0 | `vtable` |
| `wayland-backend` | 0.3.17 | MIT | `winit` |
| `wayland-client` | 0.31.15 | MIT | `winit` |
| `wayland-csd-frame` | 0.3.0 | MIT | `smithay-client-toolkit` |
| `wayland-cursor` | 0.31.14 | MIT | `smithay-client-toolkit` |
| `wayland-protocols` | 0.32.13 | MIT | `winit` |
| `wayland-protocols-plasma` | 0.3.12 | MIT | `winit` |
| `wayland-protocols-wlr` | 0.3.12 | MIT | `smithay-client-toolkit` |
| `wayland-scanner` | 0.31.11 | MIT | `smithay-client-toolkit` |
| `wayland-sys` | 0.31.11 | MIT | `wayland-backend` |
| `webbrowser` | 1.2.4 | MIT OR Apache-2.0 | `i-slint-backend-winit` |
| `weezl` | 0.1.12 | MIT OR Apache-2.0 | `gif` |
| `wl-clipboard-rs` | 0.9.4 | MIT OR Apache-2.0 | `arboard` |
| `write-fonts` | 0.50.0 | MIT OR Apache-2.0 | `i-slint-renderer-skia` |
| `writeable` | 0.6.4 | Unicode-3.0 | `icu_decimal` |
| `x11-dl` | 2.21.0 | MIT | `winit` |
| `x11rb` | 0.13.2 | MIT OR Apache-2.0 | `winit` |
| `x11rb-protocol` | 0.13.2 | MIT OR Apache-2.0 | `x11rb` |
| `xattr` | 1.6.1 | MIT OR Apache-2.0 | `tar` |
| `xcursor` | 0.3.11 | MIT | `wayland-cursor` |
| `xkbcommon` | 0.9.0 | MIT | `i-slint-backend-linuxkms` |
| `xml-rs` | 0.8.29 | MIT | `gl_generator` |
| `xmlwriter` | 0.1.0 | MIT | `usvg` |
| `yazi` | 0.2.1 | Apache-2.0 OR MIT | `swash` |
| `yeslogic-fontconfig-sys` | 6.0.1 | MIT | `fontique` |
| `yoke` | 0.8.3 | Unicode-3.0 | `icu_provider` |
| `yoke-derive` | 0.8.4 | Unicode-3.0 | `yoke` |
| `zbus` | 5.19.0 | MIT | `i-slint-backend-winit` |
| `zbus-lockstep` | 0.5.2 | MIT | `atspi-common` |
| `zbus-lockstep-macros` | 0.5.2 | MIT | `atspi-common` |
| `zbus_macros` | 5.19.0 | MIT | `zbus` |
| `zbus_names` | 4.3.5 | MIT | `zbus` |
| `zbus_xml` | 5.2.1 | MIT | `zbus-lockstep` |
| `zcheapstr` | 1.1.0 | MIT | `zvariant` |
| `zeno` | 0.3.3 | Apache-2.0 OR MIT | `i-slint-renderer-software` |
| `zerofrom` | 0.1.8 | Unicode-3.0 | `icu_provider` |
| `zerofrom-derive` | 0.1.8 | Unicode-3.0 | `zerofrom` |
| `zerotrie` | 0.2.5 | Unicode-3.0 | `icu_provider` |
| `zerovec` | 0.11.8 | Unicode-3.0 | `icu_decimal` |
| `zerovec-derive` | 0.11.6 | Unicode-3.0 | `zerovec` |
| `zlib-rs` | 0.6.8 | Zlib | `flate2` |
| `zmij` | 1.0.23 | MIT | `serde_json` |
| `zune-core` | 0.5.3 | MIT OR Apache-2.0 OR Zlib | `image` |
| `zune-jpeg` | 0.5.15 | MIT OR Apache-2.0 OR Zlib | `resvg` |
| `zvariant` | 5.15.1 | MIT | `zbus` |
| `zvariant_derive` | 5.15.1 | MIT | `zvariant` |
| `zvariant_utils` | 4.2.0 | MIT | `zbus_macros` |

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
