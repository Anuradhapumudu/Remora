# Phase 3 acceptance criteria — encrypted, authenticated handshake

Status: **draft for owner approval (2026-10-17). No implementation code yet.**

Gate rule (as Phase 2): criteria are fixed before code. If a criterion fails,
work stops and is reported with evidence and a proposed design change; a
criterion changes only by a dated, owner-approved entry in §11.

## 0. Why these criteria are different from Phase 2's

A performance bug shows up as a bad number. **A security bug usually doesn't
show up at all**: a handshake that authenticates the wrong peer still completes,
still shows a safety code, and still streams video. So in Phase 3:

1. **Every criterion is an attack that must FAIL in a specific, stated way** —
   which error, at which layer, what the peer sees on the wire, and what is
   logged — not a measurement.
2. **Every attack test must be shown able to catch its bug.** A test that would
   also pass against broken code proves nothing. We use mutation testing
   (`cargo-mutants`): it deliberately breaks our security code one change at a
   time (deletes a check, flips a comparison, returns early) and re-runs the
   tests. Every mutant in the security-critical functions (§7) must be caught
   by a failing test, or be listed with a written reason why it is harmless.
   No deliberately weakened code is ever committed: the mutations exist only
   inside the mutation tool's temporary build.
3. All attack tests run in CI on macOS, Windows and Linux, with no network
   access needed (QUIC over 127.0.0.1 and in-process transports).

## 1. What Phase 3 builds (so the tests have something to attack)

| Crate | Phase 3 content |
|---|---|
| `remora-proto` | Envelope + framing (u16 length prefix), `ViewerHello`/`HostHello`, control messages needed for the handshake/approval, limits (protocol.md §7), connection-code encode/decode/validate, media-datagram header parse |
| `remora-crypto` | Ed25519 identity + `IdentityCert`, device ID, SPAKE2 wrapper, Noise `XXpsk0`/`XX` wrapper with prologue binding, SAS commit-reveal, media AEAD (per-sender key, explicit counter, 4096-packet replay window), one-time-password generation, unattended-password policy, `Debug`-redacting + zeroizing secret types |
| `remora-net` | QUIC over loopback (quinn), TLS exporter, stream-0 framing, connection close codes |
| `remora-session` | Pure state machine: `Idle → Hello → Spake → Noise → SasReveal → PendingApproval → Active → Closed`, approval gate, attempt limiter, pending-handshake cap |
| `remora-host` / `remora-viewer` | CLI: host shows OTP + SAS + accept/deny prompt; viewer connects by `IP:port` + expected device ID, shows SAS |
| `remora-testkit` | Scriptable MITM proxy (record / replay / flip / drop / reorder), `EvilSignal` key substitution, canary-secret log scanner, mock input injector / renderer that count calls |

Out of Phase 3 (later phases, tests marked as such in §5): real video (Phase 4),
real input injection (Phase 6), STUN/ICE and pasted codes over the internet
(Phase 5), signaling server (Phase 8), GUI indicator (Phase 4/7).

## 2. What "correct failure" means everywhere

Unless a test says otherwise, a failed attack must produce **all** of:

| Aspect | Required |
|---|---|
| Session | Never reaches `Active`. No application message (input, cursor, media key, video) is processed — proven by mock injector/renderer call counts of **0**. |
| Local error | The specific `remora_session::FailReason` named in the test (e.g. `AuthFailed`, `ProtocolViolation`, `IdentityMismatch`, `IdentityChanged`, `VersionUnsupported`, `Expired`, `NonceReused`, `RateLimited`, `Timeout`, `Rejected`). |
| Wire (what the peer sees) | QUIC `CONNECTION_CLOSE` with an application code from a fixed table: `0x10 AUTH_FAILED`, `0x11 PROTOCOL_VIOLATION`, `0x12 VERSION_UNSUPPORTED`, `0x13 REJECTED`, `0x14 TIMEOUT`, `0x15 RATE_LIMITED`. **Empty reason phrase.** `AUTH_FAILED` is used for *every* authentication failure — wrong password, wrong key, failed decryption — so a remote attacker cannot tell which one happened (no oracle). |
| Local log | Exactly one `WARN` event `handshake_failed` with fields `reason`, `peer_addr`, `attempt` (`n/3` where relevant) and `session_id` (random, non-secret). |
| Never logged | OTP or unattended password; any private key, PSK, SPAKE2 key `K`, Noise transport keys, media keys; SPAKE2 messages; handshake hash; SAS nonces; raw frame bytes. Enforced by test A25 (canary scan). |
| Resources | The connection's memory is released; pending-handshake count returns to its previous value. |

## 3. Attack tests (the criteria)

Each row: the attack, how the test stages it, and the **required** outcome.
"Layer" = where the failure must be detected first.

### 3.1 Password / PAKE

| ID | Attack | Required failure |
|---|---|---|
| **A01** | Viewer uses a **wrong 6-digit password** | Layer: host Noise msg1 decryption (psk0). `AuthFailed` both sides; wire `AUTH_FAILED`; host log `attempt 1/3`. Host sends **nothing** after `HostHello`/`SpakeB` (its identity is never revealed). |
| **A02** | **Three** wrong passwords in a row | 3rd failure rotates the OTP (old one rejected even if now guessed right), host UI event "3 failed attempts — new password", cool-down starts at 30 s and doubles; a correct new-password attempt during cool-down → `RateLimited` / `RATE_LIMITED`. |
| **A03** | **Parallel guessing**: 50 simultaneous connections with different guesses | At most 4 handshakes pending at once (others closed `RATE_LIMITED` before any crypto); attempts are counted **globally per OTP**, so the 3-attempt limit holds across connections; ≤ 10 attempts/min per source IP. |
| **A04** | **Error oracle**: compare host replies for wrong password vs. unknown/forged identity vs. corrupted msg1 | Byte-identical wire behaviour (`AUTH_FAILED`, empty reason, same message count). |

### 3.2 Replay, nonce reuse, expiry, downgrade

| ID | Attack | Required failure |
|---|---|---|
| **A05** | **Replay** a fully recorded successful handshake (viewer side) against the host on a new connection | Fails: new QUIC exporter ⇒ different prologue and SPAKE2 runs fresh ⇒ `AuthFailed` at Noise msg1. Session never `Active`. |
| **A06** | **Reused nonce**: second handshake reusing the `ViewerHello` nonce of an earlier one (same connection code) | `NonceReused` before SPAKE2; wire `AUTH_FAILED`. Nonces remembered until their code expires. |
| **A07** | **Expired connection code** (expiry in the past) and **future-dated** code (> 5 min + 30 s clock-skew allowance) | Rejected by `remora-proto` validation **before any network traffic**: `Expired`. |
| **A08** | **Downgrade**: MITM edits `ViewerHello` (removes/lowers versions, switches `Trusted`↔`Password`) or `HostHello` | Hello bytes are bound into the Noise prologue ⇒ `AuthFailed` at Noise. A genuine unknown major version (no tampering) ⇒ `VersionUnsupported` with the host's supported list. |

### 3.3 Tampering

| ID | Attack | Required failure |
|---|---|---|
| **A09** | **Flip every bit** (exhaustively, one at a time) of every recorded handshake message: hellos, SpakeA/B, Noise msg1–3, SasReveal | Every variant fails (`AuthFailed` or `ProtocolViolation`); **0 of N** variants reach `Active`. |
| **A10** | **Tamper control frames after `Active`**: flip a bit, truncate, duplicate, reorder, drop | Noise decryption fails ⇒ `ProtocolViolation`, session closed (fail closed); nothing from the bad frame is processed. |
| **A11** | **Tamper media datagrams**: flip bits in the clear header (AAD), ciphertext, tag; wrong `key_id` | Datagram dropped and counted; session continues; mock renderer receives nothing from it. |
| **A12** | **Replay media datagrams**: duplicate counter, counter older than the 4096 window, counter far ahead | Duplicates and too-old dropped; far-ahead accepted once (advances window), its replay dropped. |
| **A13** | **AEAD nonce reuse** on the sending side | The sender's counter can never repeat: wrap at 2³² packets forces key rotation; announcing a second key with an existing `key_id` is rejected; property test over random sequences finds no repeated (key, counter). |
| **A14** | **QUIC-layer MITM**: proxy terminates TLS on both sides and relays bytes, even with the correct password | The two TLS exporters differ ⇒ prologues differ ⇒ `AuthFailed` at Noise msg1. |

### 3.4 Identity and the wrong-peer problem

| ID | Attack | Required failure |
|---|---|---|
| **A15** | **Swapped identity key**: `IdentityCert` signed by key A but containing Noise static key B; or a valid cert replayed from another session/device | `AuthFailed` (cert's Noise key ≠ authenticated Noise remote static, or bad signature). |
| **A16** | **Malicious signaling (`EvilSignal`) substitutes its own key**: viewer asked for device ID X; attacker answers with key Y — *including when the attacker knows the password* | Viewer aborts with `IdentityMismatch` (`DeviceId(cert key) ≠ X`) **before** showing a SAS or reaching `PendingApproval`. |
| **A17** | **MITM that knows the password** (two separate sessions: viewer↔MITM↔host) | Both handshakes complete, but the two SAS values differ. Over 10 000 runs, equal SAS ≤ 0.1 % (expected ≈ 10⁻⁶ per run). The host prompt shows the SAS that differs from the viewer's — the human comparison is the defence; documented as residual risk. |
| **A18** | **SAS grinding** (commit-then-reveal): responder (attacker) reveals an `n_r` that doesn't match its commitment; responder tries 2¹⁶ choices of ephemeral key/nonce to steer the SAS to a target | Mismatch ⇒ `ProtocolViolation`, no SAS shown. Steering: hit rate statistically equal to 10⁻⁶ × tries' share (no advantage). **Mutant check:** removing the commitment verification or computing the SAS before the reveal must make this test fail. |
| **A19** | **Trusted device whose key changed** | `IdentityChanged` hard failure with a clear warning ("this device's identity changed") — never silently treated as a new device and never falling back to the password path. |

### 3.5 Approval gate and session state machine

| ID | Attack | Required failure |
|---|---|---|
| **A20** | **Input/cursor/media-key/video sent before approval**: in every pre-`Active` state, the viewer sends every application message type | `ProtocolViolation`, session closed; mock injector/renderer call count **0**. Exhaustive: every (state × message type) pair. |
| **A21** | **Role confusion**: viewer sends host-only messages (`SessionAccept`, `MediaKeyAnnounce`, `SasReveal`), host sends viewer-only ones | `ProtocolViolation`. |
| **A22** | **Approval confusion**: two sessions pending; host approves A | Only A becomes `Active`; B stays pending. Approval is bound to `session_id` **and** the SAS shown on the prompt. |
| **A23** | **"Accept" before the SAS exists** (prompt raced ahead of the reveal) | Impossible: `PendingApproval` is reached only after commit-reveal verification; an approve command in any earlier state is rejected. |
| **A24** | **Slow handshake / no answer** (slowloris; prompt left unanswered) | Handshake not complete in 10 s ⇒ `Timeout`; prompt unanswered 60 s ⇒ `Rejected`; resources freed. |

### 3.6 Trusted-device fast path (easy to get wrong)

| ID | Attack | Required failure |
|---|---|---|
| **A25-T** | Trusted (password-less) mode with each security check removed in turn | The fast path must still: verify the cert signature (A15), require the **pinned** key (A19), bind the exporter + hellos in the prologue (A14/A08), run commit-reveal (A18), **show the accept prompt** (owner requirement), and count against rate limits (A03). A dedicated test per item; mutants removing any one must be caught. |

### 3.7 Parsers, secrets, policy

| ID | Attack | Required failure |
|---|---|---|
| **A26** | **Oversized / malformed input** at every parser: frame length > limit, truncated frames, protobuf garbage, oversized repeated fields, oversized connection code, bad datagram header | Rejected **before allocating** proportional memory (test with a counting allocator: allocation ≤ fixed bound regardless of claimed length); `ProtocolViolation` (stream) or drop (datagram). |
| **A27** | **Fuzzing**: `cargo-fuzz` targets for envelope decode, frame reader, hello/handshake messages, connection code, datagram header, SAS/commit parsing | ≥ 10 min per target locally per release of Phase 3 and 60 s per target in CI; **0 crashes, 0 panics, 0 timeouts**; corpus kept. |
| **A28** | **Secret leakage**: run the whole suite with canary secrets (distinctive OTP, keys, unattended password) | No canary — raw, hex or base64 — in any log line, `Debug` output, error message or panic message; all secret types `ZeroizeOnDrop` (compile-time assertion). |
| **A29** | **Weak OTP generation** | 10⁶ generated OTPs pass a χ² uniformity test over 000000–999999 (no modulo bias); source is the OS CSPRNG. |
| **A30** | **Short unattended password** | `validate_unattended_password` rejects < 12 characters after NFKC normalisation (incl. combining-character tricks), > 128, and the embedded common-password list; accepts valid ones. |
| **A31** | **`unsafe` outside FFI modules** | CI check: `unsafe` appears only under `crates/*/src/sys/` (and the throwaway spike); every block has `// SAFETY:` (clippy `undocumented_unsafe_blocks` already denies). |

## 4. Negative cases called out explicitly (where bugs hide)

| Case | Covered by |
|---|---|
| Handshake **succeeds but authenticates the wrong peer** | A15, A16, A17, A19 |
| State machine **accepts input while pending approval** | A20, A23 |
| **Trusted-device fast path skips a check** | A25-T (one test per check) |
| Approval applied to the **wrong session** | A22 |
| Failure messages that **reveal why** (oracle) | A04 |
| SAS computed or shown **before the commitment is verified** | A18, A23 |
| Attempt limit bypassed by **parallel connections** | A03 |

## 5. Threat-model invariants → tests

| Invariant (threat-model.md §5) | Phase 3 tests | Coverage in Phase 3 | Remaining gap → where it closes |
|---|---|---|---|
| **INV1** nothing processed before `Active` | A20, A21, A22, A23, A25-T | **Full** at the protocol/session level | Real injector/renderer wiring re-tested in Phase 4 (video) and Phase 6 (input) |
| **INV2** no media/input without encryption | A11, A13 (media AEAD); A10 (control); no plaintext type exists in the API | **Partial** — no real media path yet | **Gap until Phase 4:** loopback capture test asserting the UDP payload is never plaintext (entropy + known-marker check) |
| **INV3** wrong password never works, costs one attempt | A01, A02, A03, A04 | **Full** | — |
| **INV4** replayed handshake never works | A05, A06, A09 | **Full** | — |
| **INV5** any bit flip detected | A09 (handshake), A10 (control), A11 (media) | **Full** | Re-run on the real media path in Phase 4 |
| **INV6** fake signaling → failure or visible SAS mismatch | A16, A17, A14 | **Full** at the handshake layer (signaling simulated) | Real signaling server in Phase 8 re-runs A16 end to end |
| **INV7** size limits before allocation | A26, A27 | **Full** for Phase 3 parsers | Each later parser (STUN Phase 5, signaling Phase 8) adds its own A26/A27 rows |
| **INV8** no secrets in logs/Debug/panics; zeroized | A28 | **Full** for Phase 3 code | Crash reports / OS logs outside our process: not testable (§6) |
| **INV9** no pixels logged / written to disk | — | **Gap** (no pixels flow in Phase 3) | Phase 4: test that the streaming path writes no file and logs no frame data; `bench-capture` stays the only writer (explicit `--out`) |
| **INV10** keys/buttons released on session end | — | **Gap** (no input injection yet) | Phase 6: kill viewer / drop network / panic mid-keypress ⇒ mock-injector `release_all` called; then on a real OS |
| **INV11** "session active" indicator + one-click end | Partial: state machine exposes `active` + `disconnect()` and a test that `disconnect()` from any state reaches `Closed` and stops all processing | **Partial** | Phase 4 (CLI/host indicator) + Phase 7 (GUI): manual checklist item; cannot be fully automated |
| **INV12** 3 failures rotate OTP and notify | A02 | **Full** | — |
| **INV13** unattended password ≥ 12 chars, NFKC | A30 (policy function) | **Full** for the policy | Unattended mode itself is post-v0.1; its use of the policy is tested then |
| **INV14** no `unsafe` outside FFI; SAFETY comments | A31 + existing lints | **Full** | — |

**Gaps (not dropped, scheduled):** INV2 (real media path), INV9, INV10, INV11
(automated part only partial). Added to docs/roadmap.md "Known gaps".

## 6. What our own tests cannot prove — and what we rely on instead

| Cannot be proven by us | Why | What we rely on |
|---|---|---|
| **Correctness of the `spake2` crate** (unaudited; python-spake2 / magic-wormhole compatible, **not RFC 9382**) | Tests can show our usage is right (different passwords ⇒ unrelated keys; same password ⇒ same key; transcript binding), not that the math is free of subtle flaws | Small, readable code from RustCrypto; its known-answer tests against python-spake2; our property tests; wrapped behind `remora-crypto` so it can be swapped (RFC 9382 / CPace) with a protocol-version bump. **Recommend an external review before v1.0.** |
| `snow` (Noise), `curve25519-dalek`, `ed25519-dalek`, `chacha20poly1305` | Same — math and implementation correctness | Noise spec test vectors that snow runs; public audits of the dalek crates (Quarkslab, 2019) and RustCrypto AEADs (NCC Group, 2020); our protocol-level tests |
| **Constant-time behaviour** (no timing side channels) | Tests can't reliably measure it | Crates designed for constant time (`subtle`); we never compare secrets with `==` (lint + review) |
| **Soundness of the protocol composition** (SPAKE2 → PSK → Noise XXpsk0 + exporter + SAS commit-reveal) | Tests check behaviour under attacks we thought of, not all attacks | Design reasoning in threat-model.md / protocol.md; **gap:** a formal model (ProVerif/Tamarin) is recommended before v1.0 |
| **OS CSPRNG quality** | Statistical tests catch only gross failures (A29) | The OS RNG via `getrandom` |
| **Human SAS comparison** | Users may click Accept without comparing | UI design (Phase 7): SAS large and side by side; residual risk in threat model §9 |
| **QUIC / rustls** | Deliberately untrusted (D1) | Nothing — security doesn't depend on them (A14 proves a QUIC-layer MITM fails) |
| **Secrets in OS crash reports, swap, hibernation files** | Outside our process | `zeroize` reduces the window; residual risk |

## 7. Mutation-testing gate

`cargo-mutants` runs on the security-critical code: `remora-crypto` (all),
`remora-session` (state machine, approval gate, attempt limiter), the handshake
driver in `remora-net`, and the validators in `remora-proto`.
**Pass:** every mutant in these is caught (`caught`/`timeout`), or listed in
§10 with a written reason it cannot weaken security (e.g. it only changes a log
message). Report: counts of caught / missed / unviable, and the list of missed.

## 8. Functional criteria (not security, but Phase 3 must work)

| ID | Criterion |
|---|---|
| F1 | Viewer and host on 127.0.0.1 complete password mode and trusted mode; both show the **same** 6-digit SAS; host CLI accept → `Active`, deny → `Rejected` |
| F2 | Handshake time on loopback reported (p50/p95 over 100 runs) — information only; the internet budget is set in Phase 5 |
| F3 | All tests green on macOS, Windows, Linux CI |

## 9. How Phase 3 is reported

For each attack: pass/fail, the observed failure (error, close code, log line),
and its mutation-test evidence. Plus the §5 table updated with real test names,
the §7 mutation counts, fuzz hours per target, and the gaps carried forward.

## 10. Results

*Not started — awaiting approval of this document.*

## 11. Changes to criteria

None.
