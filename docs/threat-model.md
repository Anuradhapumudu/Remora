# Remora threat model

Status: **v1, written before any networking code** (Phase 1, 2026-10-17).
This document is normative: if code and this document disagree, one of them is
a bug. Every invariant in §5 must have at least one automated test by v0.1.

Method: STRIDE (Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service, Elevation of privilege), applied per component and per
trust boundary.

---

## 1. What we protect (assets)

| ID | Asset | Why it matters |
|---|---|---|
| A1 | **Host screen content** (video, cursor, window titles) | Can contain passwords, banking, private messages |
| A2 | **Control of the host's input** (mouse, keyboard) | Equivalent to full control of the user's account |
| A3 | **Device identity private key** (Ed25519) + Noise static key (X25519) | Whoever holds it *is* the device; trusted-device logins rely on it |
| A4 | **One-time session password** (6 digits) and **unattended password** (≥ 12 chars) | Gate to A1 and A2 |
| A5 | **Trusted-device list** | Adding an entry grants future passwordless access (still needs host approval) |
| A6 | **Network metadata**: IP addresses, who connects to whom, when, for how long | Privacy; reveals location |
| A7 | **Viewer machine integrity** | The viewer parses data sent by the host (video bitstream, cursor images) |
| A8 | **Integrity of released binaries** | A trojaned Remora build is a perfect remote-access trojan |

Future assets (designed for, not built in v0.1): clipboard contents, transferred
files, audio, multiple viewers with roles.

## 2. Adversaries

| ID | Adversary | Capabilities | In scope? |
|---|---|---|---|
| ADV1 | **Passive network observer** (Wi-Fi sniffer, ISP, state) | Reads all packets | Yes |
| ADV2 | **Active network attacker** (on-path MITM, rogue router) | Reads, drops, modifies, injects, replays, reorders packets | Yes |
| ADV3 | **Malicious or compromised signaling server** (remora-signal) | Everything ADV2 can do on the signaling channel; sees device IDs, IPs, timing; can lie about who is online, swap connection info, impersonate either side's *signaling* messages | Yes |
| ADV4 | **Malicious STUN server** (ours, Google, Cloudflare) | Learns our public IP; returns false reflexive addresses; never responds | Yes |
| ADV5 | **Remote stranger** who knows or guesses a device ID | Can attempt connections, guess passwords, flood | Yes |
| ADV6 | **Attacker who learned the session password** (shoulder surfing, phished, overheard) | Can complete SPAKE2; may also be ADV2 | Yes — the safety code and the host's accept prompt are the defences |
| ADV7 | **Malicious host** (viewer connects to a hostile machine) | Sends arbitrary video bitstreams, cursor images, protocol messages | Yes — viewer must treat host data as untrusted |
| ADV8 | **Malicious viewer after approval** | Has legitimate input control | Partially: by design they control the session; we guarantee the host can always see that and end it, and that control ends with the session |
| ADV9 | **Supply-chain attacker** (malicious crate, compromised CI action) | Injects code at build time | Yes — mitigated, not eliminated |
| ADV10 | **Local unprivileged process on the host** | Same user, no root | Partially (see §7) |
| — | Root/admin malware on host or viewer, physical access, compromised OS, hardware attacks | — | **Out of scope.** Such an attacker can already read the screen and inject input without Remora. |

## 3. Trust boundaries

```
 ┌──────────── Host machine (trusted) ────────────┐                          ┌──── Viewer machine (trusted) ────┐
 │ remora-host ── keychain (A3, A5, unattended pw)│                          │ remora-viewer ── keychain (A3,A5)│
 │      │                                         │                          │      │                           │
 └──────┼─────────────────────────────────────────┘                          └──────┼───────────────────────────┘
        │ TB1: the Internet (UNTRUSTED: ADV1, ADV2)                                │
        ├──────────────── QUIC/UDP, end-to-end Noise ─────────────────────────────┤
        │                                                                          │
        ├── TB2: STUN servers (UNTRUSTED: ADV4) ──┐        ┌── TB2 ──────────────┤
        │                                          ▼        ▼                       │
        └── TB3: remora-signal (UNTRUSTED: ADV3) ◄──────────► ─────────────────────┘
        TB4: out-of-band human channel (phone call, chat) carries the password and the
             connection code. The password is trusted only if the channel is (voice: yes;
             chat: only as much as the chat). The connection code is NEVER trusted.
```

Key consequence: **nothing that arrives across TB1–TB3 is believed until it is
proven by cryptography that only the two endpoints can produce.** STUN answers,
signaling messages and connection codes only ever affect *where we try to
connect*, never *whom we trust*.

## 4. Security design summary (how the threats are answered)

Details live in [protocol.md](protocol.md); this is the security-relevant core.

1. **Transport:** QUIC (quinn) over a hole-punched UDP path. QUIC's TLS 1.3 uses
   throw-away self-signed certificates and is treated as *untrusted plumbing*.
   Its value to us is congestion control, loss recovery and path migration —
   not security.
2. **Password authentication (SPAKE2):** viewer and host run SPAKE2 over the
   QUIC connection with the 6-digit password. Identities bound into SPAKE2:
   protocol version, host device ID, connection nonce. Output: a 256-bit key `K`.
   A wrong password produces unrelated keys on each side; neither side learns
   anything about the other's password beyond "it did not match" (same
   conditions as above; see crypto-claims-audit.md C1–C2).
3. **End-to-end channel (Noise `XXpsk0`):** `psk = HKDF(K, transcript)` is
   mixed in at the very first Noise message, so a wrong password fails the
   first decryption on the host and the host reveals nothing (not even its
   identity) to that peer. The Noise prologue contains the protocol version,
   the **TLS exporter** of the QUIC connection, and the plaintext hello
   messages, so any tampering at the QUIC/TLS layer or with version negotiation
   makes the handshake fail.
4. **Identity:** each device has an Ed25519 identity key. It signs the device's
   X25519 Noise static key; that certificate travels *inside* the encrypted
   handshake. Device ID = truncated hash of the Ed25519 public key, so the
   signaling server cannot map an ID to a different key without detection.
5. **Safety code (SAS) with commit-reveal:** both screens show 6 digits derived
   from the Noise handshake hash **and** two nonces exchanged in commit-then-
   reveal order (§6.3). Without the commitment an active MITM could grind its
   ephemeral key until both sessions showed the same code.
6. **Host approval:** every connection — trusted or not — raises an accept/deny
   prompt on the host. Until the human clicks Accept, the session state machine
   rejects video, input and every other non-handshake message.
7. **Media encryption:** each datagram sender announces its own random
   per-session media key over the Noise channel; datagrams are encrypted with
   ChaCha20-Poly1305 using an explicit 64-bit counter nonce and checked against
   a sliding replay window. (This layering lets a future SFU forward media it
   cannot decrypt.)
8. **No plaintext mode.** There is no flag, build feature or debug option that
   disables encryption. Tests use the same encrypted path.

## 5. Security invariants (each must have a test)

| ID | Invariant | Test type |
|---|---|---|
| INV1 | No video, cursor, clipboard or input message is **processed** (not just displayed) before the session reaches `Active` (handshake done **and** host approved). | Unit (state machine), integration |
| INV2 | There is no code path that sends media or input without Noise/media-key encryption. | Code review + integration test that captures loopback traffic and asserts high entropy / no plaintext markers |
| INV3 | A wrong password never yields a working session, and costs the attacker one attempt. | Security test |
| INV4 | A replayed handshake message (from a recording) never yields a working session. | Security test |
| INV5 | Any single-bit modification of any handshake message, control frame or media datagram is detected and the data discarded. | Security test + fuzz |
| INV6 | A fake signaling server that swaps keys/candidates causes connection failure or a visible safety-code mismatch — never a silent MITM. | Security test (testkit `EvilSignal`) |
| INV7 | Every parser rejects input larger than its documented limit **before** allocating proportional memory. | Unit + fuzz |
| INV8 | Secrets (keys, passwords, SPAKE2/Noise state) are never written to logs, `Debug` output, panic messages or crash reports, and are zeroized on drop. | Unit test on `Debug` impls + grep lint in CI |
| INV9 | Screen pixels are never logged or written to disk (except the explicit `capture-to-file` benchmark tool, which writes only test-pattern or user-requested output). | Code review |
| INV10 | When a session ends for any reason (disconnect, crash of the viewer, network loss), all keys and mouse buttons the remote pressed are released on the host. | Integration test |
| INV11 | The host always shows a "session active" indicator while any session is `Active`, and one click ends it. | Manual test checklist |
| INV12 | 3 failed password attempts for a one-time password rotate the password and notify the host user. | Unit test |
| INV13 | The unattended-access password is rejected by code if shorter than 12 characters (after Unicode NFKC normalisation). | Unit test |
| INV14 | No `unsafe` outside `sys`/FFI modules; every `unsafe` block has a `// SAFETY:` comment. | `#![forbid(unsafe_code)]` / `#![deny(unsafe_code)]` lints + clippy `undocumented_unsafe_blocks` |
| INV15 | The one-time password is consumed the moment a viewer proves it (Noise msg1 authenticates): a new password is in effect before that session continues, whatever its outcome (used, denied, timed out, disconnected, failed later). The same password never authenticates twice — neither later nor concurrently. Wrong-password attempts do not consume it (they count toward INV12). | Unit test (remora-session `tests/inv15_one_time.rs`, phase3-criteria A36) |

## 6. Password and safety-code policy (and the reasoning)

### 6.1 Attended sessions: 6-digit one-time password

Requirement: a user must be able to read the password out over a phone call.

Why 6 digits (≈ 20 bits) is safe *here*:

* **SPAKE2 makes offline guessing impossible** — for the SPAKE2 construction,
  provided its constants are honestly generated and small-subgroup inputs are
  handled; for the crate we use, both are open points handled in our wrapper
  (crypto-claims-audit.md §1). A recorded handshake gives an attacker nothing to
  test guesses against; every guess requires a live
  protocol run with the real host. A passive observer learns nothing at all.
* **3 attempts, then rotate.** After 3 failed attempts the host generates a
  fresh password (and shows a notice). An attacker who guesses blindly has at
  most 3/10⁶ = 0.0003 % chance per password.
* **Exponential cool-down** between lockouts (30 s, doubling, capped at 1 h)
  stops an attacker from simply cycling through rotations.
* **A correct guess is still not enough.** In attended mode a human must click
  *Accept* on a prompt showing the device name, device ID and safety code.
* **Per-session lifetime.** The password is valid only while the host window is
  open and **for one use only** (INV15): it is consumed as soon as a viewer
  proves it, so a code seen over a shoulder, in a screenshot or in chat
  history cannot be used to reconnect later or to open a second session
  alongside the first. *History:* this sentence ("only for one successful
  session") was here from Phase 1, but nothing enforced it and no invariant
  or test covered it; it was found during the Phase 3 session implementation
  (2026-10-18) and made INV15.

Generation: uniform over 000000–999999 using the OS CSPRNG with rejection
sampling (no modulo bias). Displayed as `123 456`.

Accepted trade-off: an attacker who can reach the host can deliberately burn
attempts to force rotations (nuisance DoS). The host UI makes this visible
("3 failed attempts from <IP> — new password generated").

### 6.2 Unattended access: ≥ 12-character password

Unattended access (post-v0.1) removes the human from the loop: nobody clicks
Accept. The password becomes the only factor and it is long-lived, so the online
guessing budget over months matters:

* With a lockout of 5 failures → 15 min cool-down (doubling), an attacker gets
  at most a few hundred guesses per day. A 12-character password, even one
  chosen by a human, is far outside that budget, whereas 6 digits would fall
  within a year.
* Enforced **in code** (`remora_crypto::policy::validate_unattended_password`):
  minimum 12 characters after NFKC normalisation, maximum 128, rejected if on
  an embedded short list of the most common passwords. The UI cannot bypass it
  because the host refuses to *store* a non-conforming password.
* Unattended access still requires the device to be in the trusted list *or*
  the password; the policy (password-only vs trusted-device-only vs both) is
  decided when the feature is built and documented here.
* The host stores the unattended password only in the OS keychain.

### 6.3 Safety code (SAS) — why it needs commit-reveal

The safety code defends against **ADV6**: someone who knows the password and
sits in the middle, running one session with the viewer and one with the host.
SPAKE2 cannot stop them (they know the password); only a human comparing codes
can. A 6-digit code gives the attacker a 1-in-10⁶ chance *only if the attacker
cannot influence the code*.

Plain Noise XX lets the responder choose its ephemeral key after seeing the
initiator's, so the attacker could try ~10⁶ ephemeral keys (well under a second)
until both sessions' codes match. **Fix (same idea as Bluetooth numeric
comparison and ZRTP):**

1. Host (Noise responder) picks a random 256-bit `n_r` and sends only
   `C_r = BLAKE2s("remora/1/sas-commit" ‖ n_r)` in Noise message 2.
2. Viewer (initiator) sends its random `n_i` in Noise message 3.
3. Host reveals `n_r` in its first transport message; the viewer checks it
   against `C_r` and aborts on mismatch.
4. `SAS = BLAKE2s("remora/1/sas" ‖ handshake_hash ‖ n_i ‖ n_r)`, first 8 bytes
   as a big-endian integer mod 10⁶.

Neither side can choose its last input after seeing the other's, so grinding
gives no advantage.

When the codes must be compared: on the host before clicking Accept for a
**new** device. For trusted devices the pinned key already rules out MITM; the
code is still shown for transparency.

## 7. STRIDE analysis per component

Legend — **M** = mitigation, **T** = test that proves it, **R** = residual risk.

### 7.1 Network path (TB1) — ADV1, ADV2

| STRIDE | Threat | Mitigation / Test / Residual |
|---|---|---|
| S | Attacker impersonates host or viewer | M: SPAKE2 (password) or pinned static key (trusted) + Noise mutual auth. T: wrong-key, wrong-password tests. |
| T | Modify packets in flight | M: Noise AEAD (control), ChaCha20-Poly1305 (media), QUIC AEAD underneath. T: bit-flip tests (INV5). |
| T | Replay old handshake / old datagrams | M: fresh ephemeral keys per handshake; connection-code nonce single-use; media replay window (4096 packets). T: INV4. |
| T | Downgrade protocol version / capabilities | M: one fixed cipher suite (no negotiation); hello messages bound into Noise prologue. T: modified-hello test. |
| I | Read screen / keystrokes | M: end-to-end encryption; no plaintext mode. T: INV2. |
| I | Traffic analysis (frame sizes reveal typing, video activity) | R: **accepted.** Packet sizes and timing are visible. Padding is a possible future option, at bandwidth cost. |
| D | Drop / flood packets | M: QUIC anti-amplification, address validation; cheap rejection of garbage before crypto. R: an on-path attacker can always block the connection. |
| E | Exploit a parser with crafted packets | M: size limits before allocation, no unsafe in parsers, fuzzing of every parser (STUN, envelope, datagram header, connection code, handshake). |

### 7.2 Signaling server (TB3) — ADV3

| STRIDE | Threat | Mitigation / Test / Residual |
|---|---|---|
| S | Server claims "device 123 456 789" but routes to attacker's key | M: device ID is a hash of the Ed25519 key; viewer verifies the key presented inside Noise hashes to the ID it asked for. T: INV6 `EvilSignal` key-swap test. |
| S | Server impersonates a peer's signaling messages | M: signaling payloads are only hints (candidates). Registration messages are signed by the device key so the server can't forge "device X is at IP Y" for *other* clients without being detected. |
| T | Swap candidates to redirect traffic to attacker | M: E2E auth means redirected traffic fails; result is DoS, not compromise. T: INV6. |
| R | Server denies having relayed a connection | Not a security property we need. |
| I | Server learns device IDs, IPs, who connects to whom and when | R: **accepted and documented.** It never sees keys, passwords or media. Self-hosting is supported; copy-paste mode needs no server at all. |
| D | Server goes down or refuses service | M: copy-paste connection codes work without it. |
| E | Attack the server itself | M: small Rust codebase, strict size limits, rate limits, runs as non-root in a minimal container. The server holds no secrets of value. |

### 7.3 STUN servers (TB2) — ADV4

| STRIDE | Threat | Mitigation / Test / Residual |
|---|---|---|
| S/T | Fake binding responses (off-path spoofing) | M: 96-bit random transaction IDs, response must come from the queried server address, XOR-MAPPED-ADDRESS only. T: fuzz + unit. |
| T | Lie about our reflexive address | Result: failed connection attempts only (E2E auth still holds). Multiple servers are compared; disagreement is logged (non-secret). |
| I | Server learns our public IP | R: accepted for servers we choose. Public servers (Google, Cloudflare) can be disabled in settings; then only our own server (or none) is used. |
| D | No response | M: per-server timeout, parallel queries; host candidates still work on LAN / IPv6. |

### 7.4 Connection code (copy-paste, TB4)

| STRIDE | Threat | Mitigation / Test / Residual |
|---|---|---|
| S/T | Attacker who controls the chat swaps the code (their key, their candidates) | M: the code is not trusted. Password (sent separately) + SPAKE2 + safety code. If the attacker controls the chat **and** the password travels over the same chat, they are ADV6 → defeated by the safety-code comparison and the accept prompt. Docs tell users to read the password over voice when possible. |
| T | Replay an old code | M: 5-minute expiry + single-use nonce on the host. T: unit. |
| I | Code reveals IP addresses | R: accepted (inherent to P2P). The UI says so. |
| D | Oversized / malformed code | M: hard 1 KiB limit before decoding, CRC for typo detection, fuzzed. |

### 7.5 Host application

| STRIDE | Threat | Mitigation / Test / Residual |
|---|---|---|
| S | Connection from a device the user didn't expect | M: accept/deny prompt with device name, ID, trust status, safety code. |
| T | Remote input arrives before approval | M: state machine gate (INV1). |
| T | Remote input fights the local user | M: local physical input overrides remote input for a grace period (≈ 500 ms) — local user always wins. |
| R | "I never let anyone in" | M: local session log (time, device ID/name, duration, who approved). Contains no screen content or keystrokes. |
| I | Screen content leaks via logs, stats or crash dumps | M: INV8, INV9. No third-party crash reporting. |
| I | Session continues unnoticed | M: always-visible session indicator, OS notification on connect (INV11). |
| D | Handshake flood exhausts CPU/memory | M: ≤ 4 concurrent pending handshakes, ≤ 10 attempts/min per source IP, cheap pre-checks before crypto, QUIC retry tokens. |
| E | Remote user escalates beyond the logged-in user | M: host runs as the normal user; it cannot inject into elevated windows (Windows UIPI) or the secure desktop (Ctrl-Alt-Del, UAC), and it does not try to in v0.1. R: a remote controller can do anything the logged-in user can — that is the product. |
| E | Stuck keys after disconnect | M: INV10. |

### 7.6 Viewer application — ADV7

| STRIDE | Threat | Mitigation / Test / Residual |
|---|---|---|
| T/E | Malicious host sends crafted video bitstream to exploit the decoder | M: OS/hardware decoders (on macOS VideoToolbox *may* decode out of process — **unverified**, checked in Phase 4; crypto-claims-audit C12); frame size limits; resolution limits enforced before the decoder is configured, and only the H.264 subset our encoder produces accepted (Phase 4 M7, architecture D40; negotiation with the host: roadmap D-31); software decoder (openh264) is a C library — R: **decoder bugs are a real residual risk**; we keep decoders updated and fuzz our own depacketizer. |
| T/E | Crafted cursor image / protocol messages | M: cursor ≤ 256×256 RGBA, validated; all messages size-limited and fuzzed. |
| S | Viewer connects to the wrong host | M: device ID ↔ key binding, safety code, trusted-device pinning. |
| I | Host learns viewer's IP | R: inherent to P2P. |

### 7.7 Local storage (keychain, config files) — ADV10

| STRIDE | Threat | Mitigation / Test / Residual |
|---|---|---|
| I | Identity private key read from disk | M: stored in OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service), never in plain files. |
| T | Local process adds itself to trusted-device list | M: trusted list stored in the keychain alongside the identity key. R: a same-user process that can read the keychain is effectively a compromised account — out of scope. |
| I | Secrets left in memory / swap | M: `zeroize` on drop for **Remora's own** secret types. R: secrets inside third-party crates are **not** wiped (`spake2` and `snow` don't use `zeroize` — verified); we cannot prevent swap or hibernation files from containing them. |

### 7.8 Build and release pipeline — ADV9

| STRIDE | Threat | Mitigation / Test / Residual |
|---|---|---|
| T | Malicious crate version | M: `Cargo.lock` committed; cargo-deny (licenses, sources = crates.io only, banned crates, crypto duplicate checks); cargo-audit; **new releases must be ≥ 14 days old before adoption**; minimal dependency count. |
| T | Compromised GitHub Action | M: every third-party action pinned by full commit SHA; workflows use least-privilege `permissions:`; release job is the only one with `contents: write`; linted with zizmor. |
| S | Fake Remora binaries distributed by others | M: SHA256SUMS on every release; code signing + notarization once certificates are added; future: build provenance attestations. |
| I | Signing secrets leak | M: secrets only exposed to the signing steps on tag/dispatch runs from this repository, never to pull-request workflows. |

## 8. Message validation rules (summary)

Full table in [protocol.md](protocol.md#limits). Principles:

* Every length is checked **before** allocation.
* Every enum has an "unknown" handling path: reject the message, never panic.
* Every repeated field has a maximum count.
* Unknown protocol major version → close the connection with a clear error.
* Decoding errors close the session (fail closed), except for media datagrams,
  which are dropped individually (they are expected to be lossy).
* No `unwrap()`/`expect()` on data from the network (clippy `unwrap_used`,
  `expect_used` are errors outside tests).

## 9. Residual risks (accepted, documented)

1. **`spake2` crate (0.4.0) has not been independently audited.** It is a small
   implementation from the RustCrypto organisation that is **compatible with
   python-spake2 (magic-wormhole) — it is NOT an RFC 9382 implementation**
   (corrected 2026-10-17; an earlier version of this document said
   "RFC 9382-style"). It ships 13 tests. We wrap it behind `remora-crypto` so it
   can be replaced (e.g. by an RFC 9382 or CPace implementation) without
   protocol-wide changes; the protocol version would bump. What we rely on
   instead of an audit: phase3-criteria.md §6.
1a. **SPAKE2 implementation differs from RFC 9382** (crypto-claims-audit.md §1):
    no cofactor multiplication or small-order check (our wrapper rejects such
    elements — Phase 3 A32), constants copied from python-spake2 whose
    generation is not yet verified (A33), and no RFC key confirmation (we rely on
    implicit confirmation by the Noise message-1 tag). **v1.0 review question:**
    CPace or an RFC 9382 implementation.
1b. **OTP-rotation DoS:** an attacker who can reach the host can fail three
    times repeatedly to keep the one-time password rotating. Partially mitigated
    (exponential cool-down, per-IP limits, visible notice); accepted for v0.1;
    revisit with signaling in Phase 8.
2. **Metadata** (IPs, timing, device IDs) is visible to STUN/signaling servers
   and to the peer.
3. **Traffic analysis** of packet sizes/timing.
4. **Decoder vulnerabilities** in OS/hardware/openh264 decoders on the viewer.
5. **Human factors:** users may click Accept without comparing the safety code,
   or share the password over the same channel as the connection code.
6. **Availability:** P2P fails behind some NAT combinations (see
   [nat-traversal.md](nat-traversal.md)); no relay in v0.1.
7. **Duplicate RNG crates:** quinn uses `rand 0.10` internally for connection
   IDs; our cryptography uses `rand_core 0.6` + OS RNG. Both draw from the OS
   CSPRNG.

## 10. Review triggers

Update this document (and bump its version line) when adding: relay, multi-viewer
or roles, clipboard, file transfer, audio, unattended access, a background
service/daemon, IPC between processes, mobile clients, or any new parser.
