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
* **Exception — pending owner approval (Phase 3 harness):** `remora-testkit/src/sys/count_alloc.rs`
  implements `GlobalAlloc` (unsafe by definition, not FFI) to prove inputs are
  rejected before allocation (phase3-criteria A26). It delegates every call to
  the system allocator, and `remora-testkit` may only be a dev-dependency.
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
| D16 | 2026-10-17 | Keep the `remora-*` crate names; no crate is named plain `remora` | Checked crates.io 2026-10-17: all 11 workspace names (`remora-proto`, `-crypto`, `-net`, `-capture`, `-codec`, `-input`, `-session`, `-signal`, `-testkit`, `-host`, `-viewer`) are **free**. Plain `remora` is **taken**: a 2023 placeholder (v0.0.1 only, no repository, description "remora", owner `nickfrosty`). We don't need it: all crates are `publish = false`, and users install via .dmg/.msi/packages, not `cargo install`. We do **not** publish placeholder crates to reserve names (crates.io's usage policy forbids name squatting). If a name is taken by the time we publish a library, fall back to the `remora-desktop-*` prefix (`remora-desktop` was free on 2026-10-17). |
