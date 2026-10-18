# Remora wire protocol

Status: **design v1 (Phase 1)**. Byte layouts here are what Phase 3/4 implement;
any change after v0.1 ships must bump the protocol version as described in §8.
Security reasoning lives in [threat-model.md](threat-model.md).

## 1. Layers

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Application: Control / Input (protobuf)          Media (video, cursor)   │
├───────────────────────────────────────────┬──────────────────────────────┤
│ Noise transport (ordered, reliable)       │ Media AEAD (per-sender key,  │
│ on QUIC bidirectional stream 0            │ explicit counter, replay win)│
│                                           │ on QUIC DATAGRAM frames      │
├───────────────────────────────────────────┴──────────────────────────────┤
│ QUIC (quinn) — TLS 1.3 with throw-away certs (untrusted plumbing)        │
├──────────────────────────────────────────────────────────────────────────┤
│ RemoraSocket: one UDP socket, demultiplexes STUN ⇄ ICE agent, QUIC ⇄ quinn│
└──────────────────────────────────────────────────────────────────────────┘
```

**Roles.** The *viewer* is always the ICE controlling agent, the QUIC client,
SPAKE2 side A and the Noise initiator. The *host* is the opposite in every
case. Fixing the roles removes a whole class of role-negotiation bugs.

## 2. Connection codes (copy-paste mode)

Hole punching needs both peers to learn each other's addresses, so the
copy-paste flow is an **offer/answer round trip**:

1. Host shows an **offer code**.
2. Viewer pastes it and shows an **answer code**.
3. Host pastes the answer. Both sides start connectivity checks.

With remora-signal (Phase 8) the same two blobs travel over the signaling
WebSocket and the user only types a device ID.

### Binary layout (before encoding)

| Field | Size | Notes |
|---|---|---|
| format version | 1 | `0x01` |
| kind | 1 | 0 = offer, 1 = answer |
| expiry | 4 | Unix time in **seconds**, big-endian; valid until this time; at most 5 min (+ 30 s clock-skew allowance) in the future when parsed (seconds, not minutes, so the A07 boundaries are exact) |
| nonce | 16 | Random; single-use on the host. The answer echoes the offer's nonce |
| identity key | 32 | Ed25519 public key of the sender |
| ICE ufrag | 4 | Random |
| ICE password | 16 | Random (128 bits) |
| candidate count | 1 | ≤ 8 |
| candidates | 7 or 19 each | `kind:u8` = low nibble type (0 host, 1 server-reflexive) · high nibble family (4 = IPv4 → 4 address bytes, 6 = IPv6 → 16) + address + port (2, big-endian, ≠ 0) |
| CRC-32 | 4 | **Typo detection only, not security** |

Encoded as **base64url without padding**, prefixed `remora1:`. Typical size with two IPv4 and two
IPv6 candidates: 79 fixed + 52 = ~131 bytes → ~175 characters. Hard limit: 1 KiB of text is rejected
before decoding.

The code is **untrusted** (threat model §7.4): a tampered code can only cause a
failed connection. It deliberately never contains the password.

## 3. Handshake

All steps happen on QUIC bidirectional stream 0 after the QUIC handshake
completes. Steps 1–3 are length-prefixed plaintext *inside QUIC TLS*;
everything after step 4 is Noise-encrypted.

```
Viewer (initiator)                                       Host (responder)
 │ ── QUIC handshake (TLS 1.3, throw-away certs) ──────────────────────▶ │
 │ 1. ViewerHello {versions, mode = Password|Trusted, nonce}   ───────▶ │
 │ ◀───────────── 2. HostHello {chosen version, host device ID}         │
 │ 3. (Password mode only) SPAKE2:                                       │
 │    SpakeA (33 B)                                             ───────▶ │
 │ ◀─────────────────────────────────────────────── SpakeB (33 B)       │
 │    both: K = SPAKE2 output (32 B)                                     │
 │ 4. Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s (Password mode)              │
 │    or Noise_XX_25519_ChaChaPoly_BLAKE2s   (Trusted mode)              │
 │    msg1: psk, e                                              ───────▶ │
 │ ◀─────── msg2: e, ee, s, es  + payload {IdentityCert_h, C_r}          │
 │    msg3: s, se + payload {IdentityCert_v, n_i}               ───────▶ │
 │ ◀─────── first transport msg: SasReveal {n_r}                         │
 │    viewer checks n_r against C_r (§3.3)                               │
 │    both display SAS                                                   │
 │ ◀─────── SessionPending (host shows accept prompt)                    │
 │ ◀─────── SessionAccept{role, media key announce} | SessionReject      │
 │ ═════════════════════ Active ════════════════════════════════════════ │
```

### 3.1 Key schedule

```
exporter  = QUIC.export_keying_material(len = 32, label = "EXPORTER-remora/1", context = "")
hellos    = u32_be(len VH) ‖ ViewerHello_bytes ‖ u32_be(len HH) ‖ HostHello_bytes
transcript= BLAKE2s(hellos ‖ SpakeA ‖ SpakeB)
psk       = HKDF-SHA256(salt = exporter, ikm = K, info = "remora/1/noise-psk" ‖ transcript)
prologue  = "remora/1" ‖ exporter ‖ BLAKE2s(hellos)
```

* **SPAKE2** behind Remora's own `Pake` abstraction (implementation: `spake2`
  crate, python-spake2 compatible — **not** RFC 9382; crypto-claims-audit.md §1).
  Before passing a received element to the crate, Remora checks its length and
  side byte and rejects non-decompressible, identity and non-torsion-free points.
  password = `"remora/1/otp:" ‖ six ASCII digits`;
  `id_a = "remora/1/viewer"`; `id_b = "remora/1/host:" ‖ host_device_id ‖ nonce`.
* Binding the **exporter** into the prologue means a MITM at the QUIC layer
  (two different TLS sessions) produces different prologues → Noise fails.
* Binding the **hellos** prevents tampering with version/mode selection. They
  are **length-prefixed** so no byte can move from one hello to the other
  without changing the hash (architecture.md D22; test A08).
* `psk0` means a wrong password fails when the host decrypts message 1; the
  host never sends its identity to a peer that doesn't know the password.

### 3.2 Identity certificate (inside Noise msg2 / msg3 payloads)

Fixed binary layout (architecture.md D22), at most 137 + 64 = 201 bytes:

| Field | Size | Notes |
|---|---|---|
| `ed25519_pub` | 32 | signer |
| `noise_static_pub` | 32 | X25519 key this cert vouches for |
| `created_unix` | 8 | u64 big-endian, informational |
| `name_len` | 1 | ≤ 64 |
| `device_name` | `name_len` | UTF-8, display only (untrusted text) |
| `sig` | 64 | Ed25519 over `"remora/1/cert" ‖ noise_static_pub ‖ name_len ‖ device_name ‖ u64_be(created_unix)` |

The signed message does not repeat `ed25519_pub`: Ed25519 already hashes the
public key into every signature. Parsing checks every length before
allocating; a cert with trailing bytes is rejected.

**Noise payloads:** msg2 = `IdentityCert_h ‖ C_r` (32 B), msg3 =
`IdentityCert_v ‖ n_i` (32 B). The cert's `name_len` frames it; the payload
must be exactly cert + 32 bytes, otherwise `ProtocolViolation`.

The receiver verifies (a) the signature, (b) `noise_static_pub` equals the Noise
remote static key just authenticated, (c) in Trusted mode, `ed25519_pub` is
pinned, and (d) when connecting by device ID, that `DeviceId(ed25519_pub)`
matches.

**Device ID** = first 80 bits of `BLAKE2s("remora/1/device-id" ‖ ed25519_pub)`.

**Full ID vs short code (owner decision 2026-10-18):**

* The **full 80-bit ID is the only ID the protocol compares** (`HostHello`,
  `PeerPolicy::DeviceId`, pinning). Nothing in the protocol ever treats the
  short code as the device's identity.
* Users see a **short code** derived from the full ID. It is used **only**
  for display and for a routing lookup on remora-signal.
* The short code is an **ADDRESS, not a credential.** Security comes from the
  one-time password (Noise msg1) and the safety code — never from the code
  being hard to guess. Someone who knows your code must gain nothing: they can
  try to connect, which still needs your password and your approval of the
  SAS. Codes may be shared, printed, and enumerated without harming security.
* Without a routing service (copy-paste connection codes) the short code
  plays no part: the connection code carries the full 32-byte identity key.
* Length, check digit and collision handling: **proposed 2026-10-18, awaiting
  owner approval** — not implemented.

(80 bits: forging an ID for *someone else's* key needs ~2⁸⁰ work; two keys of
the *same* attacker can collide after ~2⁴⁰, which is harmless because IDs only
route and the full key is always verified.)

Signatures are checked with `ed25519-dalek`'s **`verify_strict`** (rejects
small-order keys and malleable signatures); plain `verify` is not used.

### 3.3 Safety code (SAS)

`C_r = BLAKE2s("remora/1/sas-commit" ‖ n_r)` (in msg2), `n_i` (in msg3), `n_r`
revealed after the handshake. `SAS = u64_be(BLAKE2s("remora/1/sas" ‖ h ‖ n_i ‖ n_r)[0..8]) mod 10⁶`,
where `h` is the final Noise handshake hash. Rationale: threat model §6.3.

### 3.4 Failure behaviour

| Event | Behaviour |
|---|---|
| Wrong password | Host: Noise msg1 decryption fails → counts one attempt → closes connection with generic `AuthFailed`. No timing difference between "unknown device" and "wrong password" paths. |
| 3rd failure | Password rotates; host UI notified; cool-down starts. |
| Commitment mismatch | Viewer aborts with `ProtocolViolation`. |
| Any message too large / malformed | Close with `ProtocolViolation`. |
| Handshake not complete in 10 s | Close with `Timeout`. |
| Host user does not answer prompt in 60 s | `SessionReject{reason = Timeout}`. |

## 4. Reliable channel framing

Each frame on stream 0 after the handshake:

```
u16 big-endian length L (1..=65535)  ‖  Noise ciphertext (L bytes)
                                        └─ decrypts to: Envelope (protobuf)
```

Noise's own maximum message size is 65 535 bytes, so one frame = one Noise
message = one `Envelope`. The receiver reads exactly `L` bytes and decrypts
**in order** (QUIC streams are ordered, so Noise's implicit nonces work).

Plaintext handshake frames (steps 1–3) use the same `u16` length prefix and
a 4 KiB limit.

## 5. Messages (protobuf sketch — `remora-proto/proto/remora/v1/*.proto`)

```proto
syntax = "proto3";
package remora.v1;

message Envelope {
  oneof msg {
    Control control = 1;
    Input   input   = 2;
  }
}

message ViewerHello  { repeated uint32 versions = 1; Mode mode = 2; bytes nonce = 3; }
message HostHello    { uint32 version = 1; bytes host_device_id = 2; }
enum Mode            { MODE_UNSPECIFIED = 0; MODE_PASSWORD = 1; MODE_TRUSTED = 2; }

message Control {
  oneof kind {
    Capabilities      caps       = 1;
    SasReveal         sas_reveal = 2;
    SessionPending    pending    = 3;
    SessionAccept     accept     = 4;
    SessionReject     reject     = 5;
    MediaKeyAnnounce  media_key  = 6;
    StreamConfig      stream     = 7;   // resolution, fps, codec of a media stream
    QualityRequest    quality    = 8;   // viewer → host: mode + limits
    RecoveryRequest   recovery   = 9;   // viewer → host: lost frame ids → intra refresh / LTR
    Feedback          feedback   = 10;  // viewer → host every 50 ms: arrivals, loss, jitter
    ClockSync         clock      = 11;  // NTP-style offset estimation for latency stats
    CursorShape       cursor     = 12;  // ≤ 256×256 RGBA, sent only on change
    IceUpdate         ice        = 13;  // new candidates / ICE restart after network change
    Goodbye           bye        = 14;
    RoleChange        role       = 15;  // reserved for multi-viewer; MVP: owner + controller
    // 16–63 reserved: clipboard, file transfer, audio, monitors, chat.
  }
}

message Capabilities {
  repeated Codec decode = 1;   repeated Codec encode = 2;
  bool yuv444_decode = 3;      uint32 max_width = 4;  uint32 max_height = 5;  uint32 max_fps = 6;
}
enum Codec { CODEC_UNSPECIFIED = 0; H264 = 1; H265 = 2; AV1 = 3; }
enum Role  { ROLE_UNSPECIFIED = 0; OWNER = 1; CONTROLLER = 2; VIEWER = 3; }

message MediaKeyAnnounce { uint32 key_id = 1; bytes key = 2; /* 32 B */ }

message Input {
  oneof kind {
    MouseButton button = 1;  Key key = 2;  Scroll scroll = 3;  ReleaseAll release_all = 4;
  }
}
message MouseButton { Button button = 1; bool down = 2; float x = 3; float y = 4; uint32 monitor = 5; }
message Key { uint32 usb_hid_usage = 1; bool down = 2; }  // physical key, layout-independent
message Scroll { float dx = 1; float dy = 2; bool precise = 3; }
```

Notes:
* **Keys are USB HID usage codes** (physical positions), not characters, so a
  German keyboard on the viewer and a US layout on the host behave predictably.
  Text input (IME) is a later addition.
* **Mouse coordinates are normalised 0..1** within the monitor, so resolution
  changes never misplace clicks.
* **Mouse motion** goes as a media-style datagram (latest-wins, loss harmless);
  buttons/keys go on the reliable channel so a click is never lost.

## 6. Media datagrams

Each QUIC DATAGRAM frame carries exactly one Remora datagram. Payloads are
sized so the whole UDP packet stays ≤ 1200 bytes (safe on almost every
Internet path; PMTU discovery may raise it later).

```
Clear header (authenticated as AAD, 16 bytes)
 0      u8   kind        0x01 video fragment, 0x02 FEC repair, 0x03 pointer motion
 1      u8   flags       bit0 keyframe, bit1 last fragment, bit2 refinement frame
 2..4   u16  key_id      which announced sender key
 4..12  u64  counter     per-key packet counter → AEAD nonce, replay window
12..14  u16  stream_id   (monitor / future simulcast stream)
14      u8   layer_id    (future simulcast layer)
15      u8   reserved = 0
Encrypted body (ChaCha20-Poly1305, 16-byte tag)
 video:  frame_id u32, frag_index u16, frag_count u16, fec_group u16, capture_ts_us u64, data…
 motion: x f32, y f32, monitor u16, seq u32
```

* **Nonce** = 4 zero bytes ‖ `counter` (8 bytes). Each key is used by exactly
  one sender, so nonces never repeat. Keys rotate after 2³² packets or 1 hour.
* **Replay window:** 4096-bit sliding bitmap per key (WireGuard style).
  Duplicates and packets older than the window are dropped.
* **Why routing fields are in clear (but authenticated):** a future SFU must
  read `stream_id`, `layer_id` and `kind` to forward simulcast layers without
  holding the media key. On a direct connection they are still hidden from
  network observers by QUIC's own encryption.
* **FEC:** Reed–Solomon (reed-solomon-simd) over groups of fragments; repair
  ratio chosen by the rate controller from observed loss.

## 7. Limits

Enforced before allocation; violations are `ProtocolViolation` unless noted.

| Item | Limit |
|---|---|
| Connection code text | 1 KiB |
| Plaintext handshake frame | 4 KiB |
| Noise frame / `Envelope` | 65 535 B (Noise maximum) |
| `device_name` | 64 bytes UTF-8 |
| Candidates per code / `IceUpdate` | 8 |
| Repeated fields (generic) | 64 entries |
| `CursorShape` | 256×256 px, RGBA |
| Reassembled video frame | 8 MiB (dropped, not fatal) |
| Fragments per frame | 8192 |
| Frames in reassembly at once | 16 (oldest evicted) |
| Video resolution | ≤ negotiated `max_width × max_height`, ≤ 7680×4320 |
| Pending handshakes on host | 4 |
| Handshake attempts per source IP | 10 per minute |
| Protobuf nesting depth | prost default (100) — our schema never nests > 4 |

## 8. Versioning

* `remora/1` appears in every KDF label and the prologue: a new major version
  can never be confused with v1, even with the same keys.
* **Major** version changes when byte layouts or the handshake change. Peers
  negotiate the highest common major in `ViewerHello`/`HostHello`; with none in
  common, the host replies with its supported versions and closes, and the UI
  says "update Remora on <device>".
* **Minor** additions (new optional protobuf fields, new `Control` variants)
  don't change the major version. Unknown `oneof` variants are ignored if they
  are in the reserved "optional" range (≥ 32) and rejected otherwise.
