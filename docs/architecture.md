# Remora architecture

Status: v1 (Phase 1, 2026-10-17). The decision log (§7) records *why*; when a
decision changes, add a new entry rather than editing history.

## 1. Priorities

SECURITY > CORRECTNESS > LOW LATENCY > IMAGE CLARITY > RESOURCE EFFICIENCY > FEATURES.
When two goals conflict, the earlier one wins, and the trade-off is written down.

## 2. Workspace layout

A **Cargo workspace** is one repository with many crates (Rust packages) that
share one `Cargo.lock` and one `target/` directory, so every crate is built
against exactly the same dependency versions.

```
crates/
  remora-proto     wire types (protobuf via prost), framing, limits         lib  MIT/Apache
  remora-crypto    SPAKE2, Noise, identity keys, safety code, media AEAD    lib  MIT/Apache
  remora-net       RemoraSocket, STUN client, ICE driver (`is`), QUIC       lib  MIT/Apache
  remora-session   session state machine, roles, approval gate              lib  MIT/Apache
  remora-capture   ScreenCapture trait + macOS/Windows/X11 backends         lib  MIT/Apache
  remora-codec     Encoder/Decoder traits + VideoToolbox/MF/VAAPI/openh264  lib  MIT/Apache
  remora-input     InputInjector trait + CGEvent/SendInput/XTest            lib  MIT/Apache
  remora-testkit   test pattern, in-memory network, fake signaling, net-sim lib  MIT/Apache
  remora-app       key file + CLI helpers shared by host and viewer        lib  GPL-3.0-or-later
  remora-host      host application                                         bin  GPL-3.0-or-later
  remora-viewer    viewer application (wgpu + Slint)                        bin  GPL-3.0-or-later
  remora-signal    signaling server + STUN responder                        bin  GPL-3.0-or-later
docs/  scripts/  packaging/  .github/workflows/  (fuzz/ and benches/ arrive with the code they test)
```

### Dependency rules (enforced by review; a CI check comes with Phase 3)

```
remora-host / remora-viewer
   ├── remora-session ── remora-net ── remora-crypto ── remora-proto
   ├── remora-capture ─┐
   ├── remora-codec  ──┼── remora-proto (shared types only)
   └── remora-input  ──┘
remora-signal ── remora-proto (+ its own STUN responder, sharing parsing with remora-net)
```

* Lower layers never depend on higher ones.
* `capture`, `codec`, `input` know nothing about networking, so they can be
  benchmarked and tested alone.
* `session` contains **no I/O**: it is a state machine fed by events and
  producing actions. That makes the security gate (threat model INV1) easy to
  test exhaustively.

## 3. Data flow (one host → one viewer)

```
Host                                                               Viewer
ScreenCapture ─frame(IOSurface)─▶ Encoder ─NALs─▶ Packetiser+FEC ─▶ Media AEAD ─▶ QUIC datagrams ═╗
     │                                 ▲                                                         ║
     └─ dirty/idle info ─▶ RateController ◀── Feedback (50 ms) ◀── Noise control stream ◀─────────╢
                                                                                                  ║
InputInjector ◀── Session gate ◀── Noise control stream (keys, buttons) ◀────────────────────────╢
             ◀── Session gate ◀── pointer-motion datagrams ◀────────────────────────────────────╝
                                                                     ╚═▶ Reassembler ─▶ Decoder ─▶ wgpu renderer
                                                                                              Slint UI + stats overlay
```

### Threads and async

* **tokio** runs networking (sockets, QUIC, signaling, timers).
* **Capture and encode run on dedicated OS threads** (real-time-ish
  priority), not on tokio: encoders block and we don't want them to delay
  network tasks. Frames move between threads over bounded channels of depth
  1–2; **when the consumer is behind we drop the oldest frame, never queue** —
  queuing adds latency.
* The viewer's render loop is driven by the window system (winit via Slint).
  **Constraint D34: the video window is our own winit + wgpu surface; Slint
  never owns it, because Slint always presents with vsync (measured, D32).**

## 4. Platform backends

Each OS-specific crate exposes a small trait and keeps OS code in
`src/sys/<os>.rs`. Sketch (final signatures land in Phase 2 and are validated
against Windows in the Phase 2.5 spike):

```rust
pub trait ScreenCapture: Send {
    fn displays(&self) -> Result<Vec<DisplayInfo>, CaptureError>;
    fn start(&mut self, display: DisplayId, cfg: CaptureConfig,
             sink: Box<dyn FnMut(CapturedFrame) + Send>) -> Result<(), CaptureError>;
    fn stop(&mut self);
}
pub struct CapturedFrame { pub surface: GpuSurface, pub timestamp: Instant,
                           pub dirty: DirtyRegions, pub cursor: Option<CursorState> }

pub trait VideoEncoder: Send {
    fn encode(&mut self, frame: &CapturedFrame, hints: EncodeHints) -> Result<EncodedFrame, CodecError>;
    fn reconfigure(&mut self, target: EncoderTarget) -> Result<(), CodecError>; // bitrate/fps/res live
    fn request_recovery(&mut self, kind: RecoveryKind);
}

pub trait InputInjector: Send {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError>;
    fn release_all(&mut self);                       // INV10
    fn local_activity(&self) -> Option<Instant>;     // host physical input override
}
```

| OS | Capture | Encode (hardware first) | Input |
|---|---|---|---|
| macOS 13+ | ScreenCaptureKit | VideoToolbox (H.264, HEVC) | CGEvent; CGEventTap for local-activity detection |
| Windows 10 1903+ | DXGI Desktop Duplication | Media Foundation hardware MFTs (NVENC/QuickSync/AMF behind one API); direct NVENC if MF latency is poor | SendInput; raw input hook for local activity |
| Linux X11 | XShm (+ XDamage for dirty regions) | VAAPI | XTest |
| (all) | — | openh264 software fallback | — |
| Linux Wayland (later) | xdg-desktop-portal + PipeWire | VAAPI | portal RemoteDesktop |

### `unsafe` policy

* Every crate root has `#![forbid(unsafe_code)]` (cannot be overridden) —
  **except** `remora-capture`, `remora-codec`, `remora-input`, which use
  `#![deny(unsafe_code)]` so that only their `src/sys/*` FFI modules can opt in
  with `#[allow(unsafe_code)]`.
* Every `unsafe` block needs a `// SAFETY:` comment explaining why it is sound
  (clippy `undocumented_unsafe_blocks` is an error).
* FFI modules expose only safe functions; raw pointers never leave them.
* **One exception: decision D19** (below) — the counting allocator in
  `remora-testkit/src/sys/count_alloc.rs`. Not a precedent.
* **Enforced, not conventional:** `remora-testkit`'s policy test fails the build
  if `unsafe` appears outside `src/sys/`, if `spake2`/`snow` are used outside
  `remora-crypto`'s wrapper modules, or if `remora-testkit` is a non-dev
  dependency.

## 5. Extension seams (post-v0.1 features without rewrites)

| Feature | Seam already in the design |
|---|---|
| Relay fallback | `RemoraSocket` paths (nat-traversal.md §5); E2E encryption is unchanged through a relay |
| Multi-viewer (SFU, simulcast) | Per-sender media keys announced over pairwise Noise channels; `stream_id`/`layer_id` in the clear datagram header; session state machine holds a *set* of participants |
| Roles (Owner/Controller/Viewer, hand-off) | `Role` enum and `RoleChange` message reserved; input gate checks role, not just "is connected" |
| Clipboard, file transfer, audio, chat | Reserved `Control` variants 16–63; bulk transfers get their own announced key + QUIC stream |
| Multi-monitor | `monitor` field in input, `stream_id` per display |
| Mobile viewers | Viewer logic lives in libraries; only the UI shell is desktop-specific |
| Wayland | New `sys/wayland.rs` backends behind the same traits |

## 6. Licensing

* **Applications** (`remora-host`, `remora-viewer`, `remora-signal`):
  **GPL-3.0-or-later**. A remote-desktop tool is security-critical; copyleft
  keeps every distributed build's source available for audit.
* **Library crates:** **MIT OR Apache-2.0** (the Rust ecosystem default), so
  others can reuse the protocol, NAT-traversal and crypto pieces freely.
* Each crate directory carries its own license file(s) — `LICENSE-MIT` +
  `LICENSE-APACHE` for libraries, `LICENSE` (GPL text) for applications — so
  the license travels with the crate if it is ever published or vendored.
* **Slint** is used under its **GPL-3.0** option, which is compatible with our
  GPL apps. If the apps are ever relicensed permissively, we must switch to
  Slint's Royalty-free License 2.0 and add the required **"Made with Slint"**
  attribution (e.g. in the About dialog). Recorded here so it isn't forgotten.
* **OpenH264** is BSD-licensed, but Cisco's H.264 patent coverage applies only
  to Cisco's prebuilt binaries, not to copies compiled from source. Documented
  in distribution.md; hardware encoders are preferred anyway.
* cargo-deny enforces an allow-list of dependency licenses (`deny.toml`).

## 7. Decision log

| # | Date | Decision | Why |
|---|---|---|---|
| D1 | 2026-10-17 | Noise end-to-end **on top of** QUIC's TLS (double encryption); TLS exporter in the Noise prologue | quinn always runs TLS; replacing its crypto layer is risky and unmaintained elsewhere. Extra AEAD costs < 1 % CPU at 20 Mbps. Binding the exporter makes QUIC-layer tampering fail the Noise handshake. |
| D2 | 2026-10-17 | Handshake phase before streaming phase (old phases 3 ↔ 4) | "No plaintext mode, not even for debugging" — streaming must never exist without encryption. |
| D3 | 2026-10-17 | Stay on the RustCrypto generation used by snow 0.10 and spake2 0.4 (curve25519-dalek 4, digest 0.10, rand_core 0.6): ed25519-dalek 2.2, chacha20poly1305 0.10, hkdf 0.12, blake2 0.10 | Mixing generations compiles two copies of each primitive with incompatible traits. Revisit when snow/spake2 move to the new generation. |
| D4 | 2026-10-17 | Use `is` (str0m's sans-IO ICE agent) instead of our own ICE | ICE edge cases cost weeks; `is` is production-proven via str0m and sans-IO (see nat-traversal.md §3). |
| D5 | 2026-10-17 | `XXpsk0` (psk at first message), SAS commit-reveal | Wrong password fails before the host reveals anything; commit-reveal stops SAS grinding (threat-model.md §6.3). |
| D6 | 2026-10-17 | Per-sender media keys announced over Noise, SFrame-style datagram header | One code path for 1 viewer today and SFU fan-out later. |
| D7 | 2026-10-17 | Fixed roles: viewer = ICE controlling = QUIC client = SPAKE2 A = Noise initiator | Removes role negotiation bugs. |
| D8 | 2026-10-17 | rustls with the `ring` backend (not aws-lc-rs) | aws-lc-rs needs cmake + NASM on Windows; ring builds everywhere with just a C compiler. |
| D9 | 2026-10-17 | Dependency releases must be ≥ 14 days old; third-party GitHub Actions pinned by commit SHA | Supply-chain defence (threat model §7.8). |
| D10 | 2026-10-17 | musl static Linux artifact only for `remora-signal` | A fully static musl binary can't `dlopen` GPU drivers (Vulkan, VAAPI), so it can't be the GUI viewer/host. The server is exactly where a static binary helps (Docker `FROM scratch`). |
| D11 | 2026-10-17 | Licensing as in §6 | Owner decision. |
| D12 | 2026-10-17 | 6-digit attended OTP; ≥ 12-char unattended password enforced in code | Owner decision; reasoning in threat-model.md §6. |
| D13 | 2026-10-17 | Workspace MSRV = Rust 1.92; toolchain pinned via `rust-toolchain.toml` | Slint 1.18 requires 1.92. Pinning makes local and CI builds identical. |
| D14 | 2026-10-17 | macOS bundle ID **`io.github.anuradhapumudu.Remora`** (default in `scripts/macos/bundle.sh`) | The GitHub org `remora` is taken (organization since 2014, 16 public repos) and can't be claimed, so we use the owner's GitHub namespace, lowercase. **Changing the bundle ID after a release resets every user's Screen Recording and Accessibility permission** (TCC keys grants to bundle ID + signature) and breaks in-place updates, so treat it as permanent. |
| D15 | 2026-10-17 | Maintainer string has one source: `authors` in `[workspace.package]` = "Remora Maintainers <GitHub noreply address>" | .deb takes it via cargo-deb's `authors` fallback, .rpm `vendor` via `scripts/linux/package.sh`. No personal email in any published artifact. |
| D17 | 2026-10-17 | Windows fits the capture/input traits; four trait changes proposed (cursor event, `Interrupted`/`Resumed` with reason, optional move rects, optional `Idle`) | Phase 2.5 spike ran DXGI Desktop Duplication + SendInput successfully on GitHub's Windows runner; differences listed in docs/phase2.5-windows-spike.md. Owner scoping: `Interrupted`/`Resumed` in **Phase 4** (capture restart depends on it), with the macOS backend mapping its real behaviour (−3815 on display sleep / lid close / display removed) onto the same OS-neutral vocabulary so the session layer never needs to know the OS; cursor event, move rects and optional `Idle` in **Phase 6.5**. |
| D18 | 2026-10-17 | The Windows spike stays re-runnable: **Actions → Windows spike → Run workflow** (`.github/workflows/spike-windows.yml`, `spikes/windows-spike`). **Phase 6.5 starts by re-running it** (on the runner and on a real PC) before writing the Windows backends; both are deleted once those backends exist. | Cheap regression check of the assumptions the Windows design rests on. |
| D20 | 2026-10-17 | Protobuf messages are hand-written Rust structs using `prost`'s derive macro; `prost-build` / `protox` / `build.rs` are not used for now | Fewer dependencies and no build-time code generation for a small, stable message set; protocol.md stays the specification. Revisit if the schema grows or other languages need `.proto` files. |
| D19 | 2026-10-17 | **Narrow `unsafe` exception (owner-approved): `remora-testkit/src/sys/count_alloc.rs` only.** Scope: a **test-only crate**; implementing the **`GlobalAlloc` trait specifically** (unsafe by definition, not FFI); every call a **pass-through to the system allocator** plus thread-local counters. **Justification rests entirely on the policy check's dependency guarantee:** `remora-testkit` can never be a normal dependency, so this code can never ship. That policy check is therefore a **security control** — it is inside the mutation-testing gate (`.cargo/mutants.toml`; first run 56 caught, 0 missed) and is tested against a planted-violation workspace. **This is NOT a general precedent.** Any future request for `unsafe` outside `src/sys/` FFI modules must make its own case and get its own owner approval; "D19 already allows it" is not an argument. | Proving "rejected before allocating" (phase3-criteria A26, INV7) needs a counting allocator; the alternative (API-only tests) gives no evidence about actual memory use. |
| D24 | 2026-10-18 | The 14-day release-age rule (D9) is **enforced by CI** (`crate-age` job, `scripts/ci/check-crate-age.py`), not by memory | Two slips in a row (zeroize 1.9.1, then five more found by the first run of the check). cargo-deny 0.20.2 cannot express a release age; cargo's `-Z min-publish-age` is nightly-only. The check fails closed and self-tests with planted entries. |
| D25 | 2026-10-18 | Device IDs: the protocol compares the full 80-bit ID; users see a short code used only for display and routing lookup; the code is an address, not a credential | Owner decision. 80 bits cannot be typed as 9 digits (C23). Collision scheme proposed, awaiting approval. |
| D26 | 2026-10-18 | remora-session: `Host` owns the attempt limiter and all host sessions; a session exists only via `accept_connection` (admission before any crypto). What counts as a password attempt: a msg1 that fails to authenticate, or a SPAKE2 element our validator rejects — not oversized/malformed frames, not timeouts. The password cool-down is checked at the hello for **password mode only**, so trusted devices keep working while an attacker forces rotations. | Makes A03's "refused before any crypto" structural and the attempt count global by construction. Trusted devices being usable during an OTP-rotation attack narrows the accepted DoS in threat-model §9 (1b). |
| D27 | 2026-10-18 | Device ID short code: **11 digits + check digit for every device** (no 9-digit tier), derived from the key; extension digits on collision; proof of key ownership at registration; viewer pins the full key after the first confirmed safety code; Phase 7 UI marks unpinned devices "unverified" until the code is confirmed (protocol.md §3.2). Refines D25. | Owner: 9 digits reach 50 % collision at ~37 k devices and a tier system leaves two formats in the wild; 11 digits raise collision and grinding cost ~100×. "The window is small" is not a mitigation for squatting — the safety code is the compensating control, so the UI must make it prominent. |
| D28 | 2026-10-18 | **Security-fix exceptions** to the 14-day rule: a too-new release may be adopted only as the first patched release for RustSec advisories, listed in `.cargo/crate-age-exceptions.txt` and verified by CI against the advisory database. First use: rustls 0.23.46 (four advisories). **Pending owner approval.** | The 14-day rule and `cargo deny`'s advisory check collided: rustls 0.23.45 has four advisories, 0.23.46 was 4 days old. A rule that cannot express "security fix" gets disabled the first time it blocks one; an unverified allow-list would be a loophole. |
| D29 | 2026-10-18 | remora-net (Phase 3 scope): the host's async driver runs the sans-IO `Host` behind one mutex and performs its actions; one writer task per connection sends frames **and** the close, in order; an `AUTH_FAILED` close produced by a frame waits until arrival + 200 ms (`floor_deadline`, A04) and logs `timing_anomaly` if the work took ≥ 150 ms; the writer can close **before stream 0 exists** (slowloris, A24). Only real framing errors (bad length prefix, oversized frame) become `framing_error` → PROTOCOL_VIOLATION; a vanished connection is a disconnect. The viewer finishes its stream before an orderly close (QUIC discards unsent stream data on close). | Found while making the tests pass: the first driver could not close a connection whose stream was never opened, treated every receive error as a protocol violation, and lost the viewer's Goodbye. Each is now covered by a test (A24, F1 disconnect). Measured A04 at criteria size on an M4 (release, 9 × 200 samples): every AUTH_FAILED between 200.54 and 208.22 ms; A/A medians 0.038 ms apart. |
| D30 | 2026-10-18 | D28 **owner-approved** with conditions: an exception covers one crate, one version and its listed advisory IDs only; it **expires** when that release is 14 days old (the check then fails until the line is deleted, and it validates every exception on every run); each use is logged in dependencies.md. Also: INV15 consumption at authentication approved (D26 refined); the A04 timing claim rests on the 200-sample workflow alone, guarded by a CI freshness check. | Owner: "an exception and not a hole". Not a standing bypass flag. |
| D31 | 2026-10-19 | New crate **remora-app** (GPL-3.0-or-later, lib) shared by remora-host and remora-viewer; file I/O allowed. First module: the device key file (owner decision: file now, OS keychain before v0.1) — created exclusively and never overwritten, 0600 file / 0700 directory on Unix, refused if group/others have any access, exact size checked before reading; `DeviceKeys` encoding lives in remora-crypto so only it touches raw secrets. | Two apps need the same key handling; a library crate keeps it in one tested, mutation-gated place. |
| D16 | 2026-10-17 | Keep the `remora-*` crate names; no crate is named plain `remora` | Checked crates.io 2026-10-17: all 11 workspace names (`remora-proto`, `-crypto`, `-net`, `-capture`, `-codec`, `-input`, `-session`, `-signal`, `-testkit`, `-host`, `-viewer`) are **free**. Plain `remora` is **taken**: a 2023 placeholder (v0.0.1 only, no repository, description "remora", owner `nickfrosty`). We don't need it: all crates are `publish = false`, and users install via .dmg/.msi/packages, not `cargo install`. We do **not** publish placeholder crates to reserve names (crates.io's usage policy forbids name squatting). If a name is taken by the time we publish a library, fall back to the `remora-desktop-*` prefix (`remora-desktop` was free on 2026-10-17). |
| D21 | 2026-10-18 | The Noise handshake is a chain of **type-states** (`ViewerAwaitMsg2 → ViewerGotMsg2 → ViewerAwaitReveal → Established`, `HostAwaitMsg1 → HostGotMsg1 → HostAwaitMsg3 → HostGotMsg3 → Established`); each step consumes the previous state | Makes the SAS commit-then-reveal order a compile-time property instead of a runtime check (A17-S1/S2/S4): `n_r` is drawn in `read_msg1` (only after msg1 authenticates) and has no setter; `n_i` can only be drawn by `ViewerGotMsg2::write_msg3`, i.e. after `C_r` arrived; a `Sas` exists only on `Established`. A failed step leaves no state that could send anything. |
| D22 | 2026-10-18 | Hellos are **length-prefixed** (`u32_be(len) ‖ bytes`) before hashing into the prologue and transcript; `IdentityCert` is a fixed binary layout (not protobuf) with a length-prefixed name in the signed message | Plain concatenation `VH ‖ HH` lets a byte move across the boundary without changing the hash. A fixed layout with one length byte is simpler to parse and fuzz than protobuf for a security-critical structure (protocol.md §3.1–3.2). |
| D23 | 2026-10-18 | remora-crypto depends on remora-proto (for `DatagramHeader` and the `SasReveal` envelope) | Matches the layering in §2 (crypto sits above proto). Lets `read_reveal` parse the reveal itself, so the commitment check stays inside the mutation-tested crate. |
| D32 | 2026-10-19 | **Slint + wgpu render spike — findings** (`spikes/slint-wgpu`, README has commands and numbers; M4, battery, 1920×1080 NV12). (1) **Zero-copy IOSurface → wgpu works**: `newTextureWithDescriptor:iosurface:plane:` → `wgpu_hal::metal::Device::texture_from_raw` → `create_texture_from_hal`; read-back matches a CPU reference (worst error 2/255) and a planted wrong plane fails (255). (2) Per-frame cost to GPU completion, 3 runs: zero-copy p95 0.54–1.26 ms; **CPU upload from the locked CVPixelBuffer p95 0.75–0.80 ms**. (3) Slint `unstable-wgpu-30` works as documented (`require_wgpu_30`, notifier gives Slint's device, `Image::try_from(wgpu::Texture)`), but accepts only `Rgba8Unorm[Srgb]` (i-slint-core 1.18.1 `graphics/wgpu_30.rs:104`) and **always presents with `AutoVsync`** (i-slint-renderer-femtovg 1.18.1 `wgpu.rs:339`, no setting): measured 16.67 ms p50 interval at 60 Hz. (4) Plain winit + wgpu offers `Immediate` on Metal (wgpu-hal `metal/adapter.rs:462`): 2.2 ms p50 interval, not paced. Glass-to-glass benefit of `Immediate` in a composited window: **unverified**. | Owner asked for the spike before the Phase 4 criteria (it had been approved but never run — roadmap "Process slips"). Slint's forced vsync contradicts quality.md §2 ("never `Fifo`") for the video path; zero-copy is not needed to meet the budget. |
| D33 | 2026-10-19 | **PROPOSED (awaiting owner approval in phase4-criteria §2):** the Phase 4 video window is **winit 0.30 + wgpu 30 directly** (our own surface: `Immediate` when offered, else `Fifo` with `desired_maximum_frame_latency = 1`); Slint is not used in Phase 4. Frames reach wgpu by **CPU upload of the NV12 planes from the locked decoder buffer**, through a safe accessor in `remora-codec/src/sys/macos.rs` (no new `unsafe` location). Zero-copy import is deferred (roadmap D-18): it needs `unsafe` wgpu-hal calls outside the three FFI crates, i.e. an unsafe-policy change. How Slint UI and the video surface share a window is a Phase 7 design question (roadmap D-17). | D32: the CPU path is steady and ≈ 0.8 ms p95, so zero-copy buys ≈ 0.3 ms p50 at the cost of an unsafe-policy exception; Slint cannot present without vsync. |
| D34 | 2026-10-19 | **CONSTRAINT (discovered by measurement, owner-approved — D33 accepted as R1/R2 of phase4-criteria):** **Slint never owns the video surface.** Video is drawn on our own winit + wgpu surface with a present mode we choose; Slint may draw UI only (how they share a window: D-17, docs/d17-video-surface-options.md). Frames reach wgpu by **CPU upload** of the NV12 planes, not zero-copy. | **R1 — measured, not a preference:** Slint 1.18.1 hard-codes `PresentMode::AutoVsync` (i-slint-renderer-femtovg `wgpu.rs:339`, no setting); measured frame interval **16.67 ms p50 / 18.16 ms p95** at 60 Hz vs **2.21 / 5.32 ms** with our own `Immediate` surface (D32). A refresh wait of up to 16.7 ms would use most of the 20 ms budget before our own code ran — there is no version of this architecture where Slint owns the video surface. **Reversing this needs a new measurement and an owner decision, not a Phase 7 convenience.** **R2 — consistency, not just "no new unsafe":** CPU upload p95 **0.75–0.80 ms** across 3 runs vs zero-copy **0.54–1.26 ms**. The budget is judged at **p95**, so a steady path beats an occasionally faster one; zero-copy's ≈ 0.3 ms better *median* is not a reason to revisit. It would also need `unsafe` wgpu-hal calls outside the FFI crates. Revisit only if a measured p95 shows the upload stage over budget (roadmap D-18). |
| D35 | 2026-10-19 | The roadmap's deferred-items list, process slips and progress log are **checked by CI** (`roadmap` job, `scripts/ci/check-roadmap.py`): sections present, rows well-formed, deferred IDs never disappear (closing = moving the row to "Closed" with evidence), log and slips append-only versus the base commit. A built-in self-test plants 8 breakages (including the real 2026-10-19 truncation) on every run | Owner: the near-loss of the progress log (a scripted edit cut off everything after one row, caught by eye) showed the file is load-bearing but hand-edited. Same rule as D24: if we rely on it, a check enforces it. |
