# Cryptographic claims audit (before Phase 3 implementation)

Date: 2026-10-17. Trigger: the threat model called the `spake2` crate
"RFC 9382-style"; reading its source showed it is not. Every cryptographic
claim in threat-model.md, protocol.md and phase3-criteria.md was then checked
against **what the crates actually implement** (source read from the exact
locked versions) and against primary documents (RFC 9382 text, Noise spec
behaviour in `snow`, crate READMEs). Nothing below is from memory.

Legend: ✅ verified · ⚠️ verified with a qualification · ❌ asserted, not true or
not verifiable as stated → corrected.

## 1. The SPAKE2 finding

**What the threat model asserted:** an "RFC 9382-style implementation".
**What `spake2` 0.4.0 actually is:** a port of **python-spake2** (the
magic-wormhole implementation), written before RFC 9382. Its README says so;
its tests compare against python-spake2, not RFC 9382 vectors; it has 13 tests.

Verified differences from RFC 9382 (RFC text vs crate source):

| Aspect | RFC 9382 | `spake2` 0.4.0 | Consequence for us |
|---|---|---|---|
| Shared element K | **K = h·x·(pB − w·N)** — "The multiplication by h prevents small subgroup confinement attacks" (§3.3) | K = x·(pB − w·N): **no cofactor multiplication**; `bytes_to_element` only decompresses — **no small-order / torsion / identity check** | The RFC's protection is absent — and so is python-spake2's own subgroup check, **which the port dropped** (C20). Not analysed whether this is exploitable in our composition. **Mitigation (Phase 3, test A32):** our wrapper rejects any received element that is not torsion-free or is the identity before the crate sees it. |
| Constants M, N (edwards25519) | M = `d048032c…cecdaf`, N = `d3bfb518…86c4ab`, derived by a documented procedure | M = `15cfd18e…a02312`, N = `f04f2e7e…e583c3`, copied from python-spake2 | Security needs nobody to know log_P(M), log_P(N). We have **not** verified python-spake2's generation. **Phase 3 task:** re-derive both from python-spake2's published seed procedure in a test; if it can't be reproduced, treat as unverified and prefer replacing the PAKE. |
| Key confirmation | **MUST** exchange MACs cA, cB over the transcript before completion | **None**; output is SHA-256 of a fixed-length transcript | We rely on **implicit confirmation**: the PSK is mixed at Noise message 1 (verified in `snow`, §2), so mismatched keys fail the first AEAD tag. Design argument, not an RFC-reviewed construction. |
| Password → scalar | SHOULD use a memory-hard function | HKDF-SHA256 (info "SPAKE2 pw") | Fine for online-only OTPs. For the stored unattended password (post-v0.1) the host keeps a password-equivalent value (true of any balanced PAKE). |
| Transcript | Length-prefixed TT incl. identities, messages, K, w | Fixed-length: SHA-256(pw), SHA-256(idA), SHA-256(idB), X, Y, K | Identities and messages **are** bound ✅ (unambiguous because every field is fixed-size). |
| Secret wiping | — | `Spake2` struct keeps the password and secret scalar; **no `zeroize`** | Our "zeroize on drop" claim cannot cover the crate's internals (narrowed in §2). |

**What this means:** the published security analysis of SPAKE2 as specified in
RFC 9382 does **not** directly apply to this crate. Security of our handshake
now rests on (a) the python-spake2 construction, (b) our hardening in the
wrapper, and (c) the Noise layer catching any key mismatch.

**Decisions taken / proposed:**

1. **Real abstraction boundary.** `remora-crypto` defines its own `Pake` trait
   with its own message type (fixed 33-byte array), its own error type, its own
   output type (`PakeKey`, zeroized), input validation (torsion-free,
   non-identity, length, side byte) done **in our code**, and the PAKE algorithm
   named in the protocol version. No `spake2` type appears in any public
   signature; the trait's test suite runs against every implementation. Swapping
   the PAKE = new impl + protocol version bump, nothing else.
2. **v1.0 review question:** move to **CPace** — a balanced PAKE being
   standardised by the IRTF CFRG (`draft-irtf-cfrg-cpace`, revision 21 as of
   2026-10-17; verified on the IETF datatracker) — or at least an RFC 9382
   implementation with cofactor clearing and key confirmation, instead of the
   python-spake2 variant. (I recalled CPace as the winner of the CFRG's 2020 PAKE
   selection; that is **not** verified against a primary source, so the
   decision must not rest on it.) Recorded in docs/roadmap.md.

## 2. All other cryptographic claims

| # | Claim (where) | Status | Evidence / correction |
|---|---|---|---|
| C1 | "SPAKE2 makes offline guessing impossible; a recorded handshake gives nothing" (threat-model §6.1) | ⚠️ | Holds for the SPAKE2 construction **if** M/N are honestly generated and small-subgroup inputs are handled — both open (§1). Corrected wording in threat model. |
| C2 | "Wrong password ⇒ unrelated keys; neither side learns more than 'no match'" (§4.2) | ⚠️ | Same conditions as C1. |
| C3 | "psk0: a wrong password fails when the host decrypts Noise message 1; the host reveals nothing, not even its identity" (§4.3, protocol §3.1) | ✅ | `snow` 0.10: `Token::Psk` → `mix_key_and_hash` sets the cipher key; in PSK handshakes `Token::E` also calls `mix_key`, which sets `has_key`, so the msg1 payload (even empty) carries an AEAD tag. Message 2 (host identity) is encrypted under keys that include the PSK. To be proven by test A01. Note: snow's `mix_key_and_hash` itself does not set `has_key`; correctness depends on the `e` token following — true for `XXpsk0`. |
| C4 | "Noise XX gives mutual authentication and forward secrecy" (§4.3) | ⚠️ | Forward secrecy ✅ (ephemeral DH). Authentication only of **static keys**: `snow` returns the peer's static key and decides nothing. *We* must verify the `IdentityCert` against it (A15) — the claim is true only with that check. |
| C5 | "TLS exporter in the prologue makes QUIC-layer tampering fail" (§4.1, D1) | ✅ (API) / test pending | quinn exposes `export_keying_material` (verified in Phase 1); TLS 1.3 exporters are bound to the handshake (RFC 8446 §7.5). Behaviour proven by A14. |
| C6 | "Device ID = 80 bits of BLAKE2s ⇒ second preimage ~2⁸⁰" (protocol §3.2) | ⚠️ | Correct for targeted second preimage. **Added:** *collisions* cost ~2⁴⁰ — an attacker can make two of **their own** keys share an ID; harmless, because IDs only route and the full key is verified. Stated in protocol.md. |
| C7 | "Ed25519 cert binds the Noise static key" (§4.4) | ⚠️ | Requires **`verify_strict`** (exists in ed25519-dalek 2.2; rejects small-order keys and malleable signatures). Plain `verify` is not acceptable. Added as a requirement (A15). |
| C8 | "SAS commit-reveal prevents grinding" (§6.3) | ⚠️ | Design argument by analogy to Bluetooth numeric comparison / ZRTP; no proof. Tested structurally (A18) — see phase3-criteria §3.4. |
| C9 | "SAS = first 8 bytes mod 10⁶: negligible bias" (protocol §3.3) | ✅ | 2⁶⁴ mod 10⁶ ⇒ bias < 10⁻¹³. |
| C10 | "ChaCha20-Poly1305, explicit 64-bit counter, unique nonces; rotate at 2³² packets / 1 h" (protocol §6) | ✅ | Well inside ChaCha20-Poly1305's limits; uniqueness enforced by construction (A13). |
| C11 | "All secret types zeroize on drop" (threat-model §7.7, INV8) | ❌ → narrowed | Verified: **neither `spake2` nor `snow` uses `zeroize`**. Corrected to: *Remora's own* secret types zeroize; secrets inside third-party crates (SPAKE2 state, Noise handshake/transport keys) are not wiped. Residual risk added. |
| C12 | "VideoToolbox decodes out of process on macOS" (threat-model §7.6) | ❌ → unverified | Never checked. Marked **unverified**; to be checked in Phase 4 (observe the decoder XPC service) before relying on it. |
| C13 | "chacha20poly1305 received an NCC Group audit" (phase3-criteria §6) | ✅ | Stated in the crate's README (funded by MobileCoin, no significant findings). |
| C14 | "curve25519-dalek / ed25519-dalek audited (Quarkslab, 2019)" (phase3-criteria §6, my draft) | ❌ → removed | Not stated in either crate's README; I wrote it from memory. Removed. Claims about audits must cite a source. |
| C15 | "snow runs the Noise spec test vectors" (phase3-criteria §6) | ⚠️ | snow ships vector tests (`tests/vectors.rs`, vector files incl. cacophony-format). We have not run them ourselves; Phase 3 runs snow's vector tests once in CI as evidence. |
| C16 | "Constant time via `subtle`" (phase3-criteria §6) | ⚠️ | Only where *our* code compares secrets (we use `subtle`); library internals rely on their design. |
| C17 | "QUIC anti-amplification and retry tokens limit floods" (threat-model §7.1) | ⚠️ | quinn implements both; retry must be **enabled in our server config**. Verified in Phase 5. |
| C18 | "3 attempts ⇒ 3/10⁶ per password" (§6.1) | ✅ | Arithmetic. |
| C19 | "SpakeA/B are 33 bytes" (protocol §3) | ✅ | `finish()` requires `1 + 32` bytes (side byte + compressed point). |

## 2b. Findings while building remora-crypto (2026-10-18)

| # | Claim / question | Status | Evidence |
|---|---|---|---|
| C20 | **A security check LOST IN THE PORT** — not a variant difference | ❌ → restored by A32 | python-spake2 0.9 (the reference the Rust crate ports; PyPI sdist sha256 `421fc4a8…a9334`), `src/spake2/ed25519_basic.py` `bytes_to_element`: **rejects** the identity (`P is Zero`) and any element with `L·P ≠ 0` (outside the prime-order subgroup). `spake2` 0.4.0 `src/ed25519.rs` `bytes_to_element`: **only decompresses**. So the Rust port silently dropped a check its own reference performs; this is a defect of the port, not a design choice of the python-spake2 variant. Our wrapper's A32 validator **restores** it (plus a canonical-encoding check python-spake2 also lacks). Consequences: (1) the wrapper is **necessary**, not belt-and-braces — without it we would run python-spake2's protocol minus one of its input checks; (2) the v1.0 PAKE review must treat "does the implementation validate peer elements?" as an explicit question for any replacement crate, and must not assume a port inherits its reference's checks. |
| C21 | M and N are "nothing-up-my-sleeve" constants (A33) | ✅ reproduced | Same sdist, `params.py` / `groups.py` / `ed25519_basic.py`: `HKDF-SHA256(salt="", ikm=b"M"/b"N"/b"symmetric", info="SPAKE2 arbitrary element", L=48)`, big-endian mod p, try-and-increment with the even x root, multiply by 8. Re-derived twice, independently: a stdlib-only Python script (integer arithmetic) and the Rust test `pake::a33_constants` (curve25519-dalek). Both give exactly the crate's M = `15cfd18e…a02312`, N = `f04f2e7e…e583c3`, S = `6f00dae8…b8e6f1`. This shows the crate uses hash-derived points; it does not prove try-and-increment hashing is sound (standard argument, not re-proven here). |
| C22 | "snow's own Noise test vectors cover our patterns" (A34) | ⚠️ partial | Ran snow 0.10.0's `tests/vectors.rs` with `--features vector-tests` on an unmodified copy of the registry source: 3/3 pass (`snow`, `snow_extended`, `cacophony`). Coverage of **our** patterns: `Noise_XX_25519_ChaChaPoly_BLAKE2s` — 1 vector in `snow.txt`, 1 in `cacophony.txt`. `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s` — **0 vectors**; only `XXpsk0+psk1`, `+psk2`, `+psk3`, `+psk1+psk2+psk3` variants. So the psk0 code path is exercised, our exact pattern is not. Gap → **v1.0 formal-modelling list item 2b** (roadmap.md, owner: critical path). Source found: flynn/noise `vectors.txt` has 3 exact `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s` vectors from an independent (Go) implementation. |
| C23 | "Device ID shown as a 9-digit code + checksum" (protocol §3.2) | ❌ → decided | 9 decimal digits hold ~30 bits, the ID is 80. Owner decision 2026-10-18: a short user-facing code for display and routing only; the protocol compares the full 80-bit ID; the code is an address, not a credential (protocol.md §3.2). Collision scheme pending owner review. |
| C24 | "`decompress` rejects non-canonical encodings" (would have been an easy assumption) | ❌ (not assumed) | curve25519-dalek 4.1.3 `edwards.rs` `decompress` + `field.rs` `from_bytes`: accepts `y ≥ p` (reduced) and the sign bit on x = 0. Our validator re-compresses and compares. An independent enumeration found 8 canonical + 6 non-canonical encodings of small-order points, and no torsion-free point has a non-canonical encoding (only y < 19 can be written as y + p). |

## 3. What changes in the docs

* threat-model.md: §6.1, §4.2, §7.6, §7.7 and §9 updated per C1, C2, C11, C12
  and §1; new residual risks: unanalysed small-subgroup handling (mitigated in
  the wrapper), unverified M/N generation, no RFC key confirmation, unwiped
  library secrets.
* protocol.md: device-ID collision note (C6); `verify_strict` (C7); wrapper
  validation of SPAKE2 elements (§1).
* phase3-criteria.md: tests A32 (element validation), A33 (M/N re-derivation),
  A34 (snow vectors run once), and the corrected §6.
* roadmap.md known gaps: CPace review question for v1.0; formal model; external
  review.
