# Dependencies

Every external crate Remora uses, why, and the exact version chosen. Versions
were **checked against crates.io on 2026-10-17** (`cargo info` / `cargo search`,
plus a scratch build to detect duplicate crates), not taken from memory.

## Policy

1. **≥ 14 days old.** A release younger than 14 days is not adopted; we pin the
   previous one (`cargo update -p <crate> --precise <version>`). Gives the
   community time to notice a malicious or broken release.
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
| tokio | 1.53 | 1.53.2 (1.53.3 < 14 days) | net, signal, apps | Async runtime; quinn requires it |
| quinn | 0.11.12 | 0.11.12 (quinn-proto 0.11.19) | net | QUIC: datagrams, streams, migration, pluggable socket + congestion control |
| rustls | 0.23.46 (`ring`) | 0.23.46 | net | quinn's TLS. Newest is 0.24.0-dev (pre-release) — not used |
| snow | 0.10.0 (`risky-raw-split` only if needed) | 0.10.0 | crypto | Noise Protocol Framework |
| spake2 | 0.4.0 | 0.4.0 | crypto | PAKE. **Not independently audited** (threat model §9). 0.5.0-pre exists — not used |
| ed25519-dalek | 2.2 | 2.2.0 | crypto | Identity keys. 3.0.0 exists but is on the next RustCrypto generation (D3) |
| chacha20poly1305 | 0.10 | 0.10.1 | crypto | Media AEAD (same version snow uses) |
| hkdf / sha2 / blake2 | 0.12 / 0.10 / 0.10 | — | crypto | Key derivation, hashes |
| rand_core | 0.6 (`getrandom`) | 0.6.4 | crypto | OS CSPRNG (`OsRng`) |
| zeroize | 1.8 | 1.9.1 | crypto | Wipe secrets on drop |
| subtle | 2.6 | 2.6.1 | crypto | Constant-time comparison |
| keyring | 4.2 | 4.2.0 | crypto (key storage) | OS keychain. **v4 API differs from v3** (split into `keyring-core` + per-OS stores) — re-verify in Phase 3 |
| is | 0.11.1 | 0.11.1 | net | Sans-IO ICE agent from str0m (nat-traversal.md §3). Pin exact minor; frequent breaking releases |
| prost | 0.14.4 | 0.14.4 | proto | Protobuf runtime |
| prost-build | 0.14.4 | 0.14.4 | proto (build) | Code generation |
| protox | 0.9.1 | 0.9.1 (0.10.0 < 14 days) | proto (build) | Pure-Rust `.proto` compiler, so contributors don't need `protoc` |
| reed-solomon-simd | 3.1.0 | 3.1.0 | net | FEC for video datagrams |
| bytes | 1 | — | proto, net | Zero-copy buffers (quinn's buffer type) |
| objc2 | 0.6.5 | — | capture, codec, input (macOS) | Safe-ish Objective-C runtime bindings |
| objc2-foundation, -screen-capture-kit, -video-toolbox, -core-media, -core-video | 0.3.2 | — | capture, codec (macOS) | Generated Apple framework bindings |
| windows | 0.62.2 | — | capture, codec, input (Windows) | Official Microsoft bindings |
| x11rb | 0.14.0 | — | capture, input (Linux) | Pure-Rust X11 protocol |
| openh264 | 0.9.8 | 0.9.8 (0.9.9 < 14 days) | codec | Software H.264 fallback |
| wgpu | 30.0.1 | — | viewer | GPU rendering (Metal / D3D12 / Vulkan) |
| slint | 1.18.1 (`unstable-wgpu-30`) | — | viewer, host | UI; shares our wgpu 30 device. MSRV 1.92 → workspace MSRV |
| axum | 0.8.9 | — | signal | WebSocket signaling server |
| tracing / tracing-subscriber | 0.1.44 / 0.3.23 | — | all | Structured logging (with secret redaction) |
| thiserror | 2.0 | — | libraries | Error types |
| anyhow | 1.0 | — | binaries only | Error plumbing in `main` |
| clap | 4.6 | — | binaries | CLI flags (`--test-pattern`, …) |
| criterion | 0.8.2 | — | benches | Benchmarks |

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
