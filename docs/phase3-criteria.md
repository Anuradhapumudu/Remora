# Phase 3 acceptance criteria — encrypted, authenticated handshake

Status: **revision 2 for owner approval (2026-10-17)** — incorporates the owner's four required changes (A17 recalibration, SPAKE2 section + crypto-claims audit, A04 timing/logging/DoS, mutation-testing scope) and the test-first build order. No implementation code yet.

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
| `remora-crypto` | Ed25519 identity + `IdentityCert` (`verify_strict` only), device ID, `Pake` trait + SPAKE2 implementation with input validation, Noise `XXpsk0`/`XX` wrapper with prologue binding, SAS commit-reveal, media AEAD (per-sender key, explicit counter, 4096-packet replay window), one-time-password generation, unattended-password policy, `Debug`-redacting + zeroizing secret types |
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
| Wire (what the peer sees) — **generic** | QUIC `CONNECTION_CLOSE` with an application code from a fixed table: `0x10 AUTH_FAILED`, `0x11 PROTOCOL_VIOLATION`, `0x12 VERSION_UNSUPPORTED`, `0x13 REJECTED`, `0x14 TIMEOUT`, `0x15 RATE_LIMITED`. **Empty reason phrase.** `AUTH_FAILED` is used for *every* authentication failure, so a remote attacker cannot tell which check failed beyond what the protocol step itself reveals (A04). |
| Local log on the host — **specific** | Exactly one `WARN` event `handshake_failed` with the **precise** `FailReason` (e.g. `WrongPsk`, `CertSignatureInvalid`, `CertKeyMismatch`, `DeviceIdMismatch`, `PinnedKeyChanged`, `CommitmentMismatch`, `ReplayNonce`, `FrameTooLarge`), the protocol step, `peer_addr`, `attempt` (`n/3`), `session_id` (random, non-secret) and elapsed time. Generic on the wire, specific locally, so failures stay debuggable; A28 guarantees no secret is in it. |
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
| **A04** | **Error oracle** (bytes and timing) | See §3.1a. |
| **A36** | **Reuse of a one-time password** (required cases, owner: reconnect after success — `inv15_successful_session_then_same_password_fails`; concurrent session with the same password — `inv15_same_password_cannot_open_a_second_session_while_the_first_is_active`; reconnect after a denied prompt — `inv15_after_a_denied_prompt_the_same_password_fails`) (added 2026-10-18, owner; INV15): complete a session with the password, then reconnect with the same password; also try it concurrently while the first session is active, and after sessions that ended by deny, prompt timeout, disconnect, or a later handshake error | Every reuse fails at Noise msg1 with `AuthFailed`; no prompt is shown. The host emits `OtpUsed` once per password-mode session and a new password is in effect immediately. Wrong-password attempts do not consume the code (INV12 unchanged). Trusted-mode sessions do not touch it. |

#### 3.1a A04 in detail — what may and may not be distinguishable

**Correction to revision 1:** "wrong password vs unknown identity vs corrupted
msg1 are byte-identical" was wrong as stated. A wrong password fails at Noise
**message 1** (the host never sends message 2); a forged identity can only fail
at **message 3**, after the host has sent message 2. Which *step* fails is
inherent to the protocol and reveals only what the protocol already tells any
participant (passing message 1 *is* the PAKE saying "the password was right").
The requirement is therefore per step:

* **Bytes:** all failures **at the same step** are byte-identical on the wire
  (same close code `AUTH_FAILED`, empty reason, same messages sent before it).
  Step 1 set: wrong password, corrupted msg1, replayed msg1, wrong PSK from a
  tampered SPAKE2 message. Step 3 set: bad cert signature, cert/Noise key
  mismatch, untrusted or changed pinned key, device-ID mismatch.
* **Timing — approach: a fixed response-time floor.** Every `AUTH_FAILED` is
  sent no earlier than **200 ms after the failing message arrived**, and every
  check of that step runs to completion before the verdict (no early return).
  The real work at a step takes ≈ 1–5 ms, so the floor dominates. If the work
  ever exceeds 150 ms the host logs an anomaly (the floor would stop hiding it).
  Chosen over "measure and prove overlap" because a floor removes the signal by
  construction instead of hoping a measurement is sensitive enough.
* **Which job carries this claim — exactly one:** workflow **`A04 timing`**,
  job **`a04`** (`.github/workflows/timing.yml`). Nothing else may be cited
  as A04 timing evidence. Its health is **checked, not assumed**
  (`scripts/ci/check-a04-evidence.sh`, run by CI on every PR and by the
  `Evidence` workflow every 6 hours and on every push to main): it fails
  loudly if the workflow is disabled, has no successful run in 48 hours, or
  the latest merge to main has no successful run of its own after 6 hours.
  Planted failures for all three were seen failing (2026-10-19).
* Details of that job: the `A04 timing` workflow
  (`.github/workflows/timing.yml`: 200 samples per type, release build,
  nightly and on PRs touching net/session/crypto). It checks its own output
  has 9 measurements of n = 200 and that the medians were compared. Every
  other run (regular CI at 20 samples, the mutation gate at 3) checks only
  that every sample is ≥ 200 ms and below a loose 1 s ceiling (the strict
  225 ms ceiling is part of the statistical claim too: a busy macOS runner
  delayed one close to 229.6 ms) — which proves the floor exists (a
  missing floor shows in any sample) — and compares **no** medians: on
  shared CI machines their noise exceeds the 1 ms being judged (observed:
  1.07 ms at 3 samples on Linux, 1.14 ms at 20 on macOS, for types the
  200-sample run puts 0.001 ms apart). Because everything else would stay green
  if that workflow stopped running, the CI job `a04-evidence-fresh` fails
  when it has no successful run in the last 48 hours.
* **Test:** for each failure type of a step, 200 handshakes over loopback;
  record time from sending the failing message to receiving the close.
  **PASS** if every sample is ≥ 200 ms and ≤ 200 ms + 25 ms, and the medians of
  any two failure types at the same step differ by < 1 ms. An A/A control (the
  same failure type measured twice) is run first; if its medians differ by
  ≥ 1 ms the test is reported as *too noisy to judge* rather than passed.
* **Mutant check:** removing the floor or adding an early return must fail it.

**DoS interaction (named, not hidden):** an attacker who can reach the host can
fail three times on purpose, over and over, forcing the OTP to rotate so the
legitimate viewer's code keeps going stale. Mitigations: exponential cool-down
(30 s doubling to 1 h) limits the attacker to 3 attempts per window; per-source
IP limits; the host sees "3 failed attempts from <IP> — new password", can
read out the new code, and can disconnect/block. **Status: partially mitigated,
accepted residual risk for v0.1** — a determined attacker with many IPs who
knows the host's address can keep the code rotating. Revisit in Phase 8
(signaling can rate-limit per device ID and hide the host's address until
approval). Added to threat-model.md §9.

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
| **A17** | **MITM that knows the password** (two sessions viewer↔MITM↔host); the MITM tries to make both sessions show the same SAS | See §3.4a — structural tests are primary, the statistical test is secondary. |
| **A18** | **SAS grinding** via commit-then-reveal abuse | See §3.4a. |
| **A19** | **Trusted device whose key changed** | `IdentityChanged` hard failure with a clear warning ("this device's identity changed") — never silently treated as a new device and never falling back to the password path. |

#### 3.4a A17 / A18 in detail — structural proof first, statistics second

**Why sampling alone cannot carry this.** With a fair 6-digit SAS the chance
that two independent sessions show the same code is p = 10⁻⁶. Over N = 10 000
MITM runs the number of matches X is Binomial(N, p) ≈ Poisson(λ = 0.01):

| | P(X = 0) | P(X = 1) | P(X ≥ 2) |
|---|---|---|---|
| honest protocol (λ = 0.01) | 0.990 | 0.0099 | **5.0 × 10⁻⁵** |
| attacker advantage ×10 (λ = 0.1) | | | 0.0047 |
| attacker advantage ×100 (λ = 1) | | | 0.264 |
| attacker advantage ×1000 (λ = 10) | | | 0.9995 |

So the statistical test can only reliably catch advantages of roughly ×1000;
a ×100 attack slips through three times out of four. (Revision 1's "≤ 0.1 %"
threshold allowed 10 matches — 1000× the baseline — and was wrong.) The
structural tests below are the real check.

**Primary — structural tests (each must fail against a mutant that breaks it):**

| ID | Property | Test |
|---|---|---|
| A17-S1 | The responder's contribution `n_r` is **committed before** it learns anything that determines the SAS | Type-state: the host state machine can emit Noise msg2 (carrying `C_r = BLAKE2s(… ‖ n_r)`) only after `n_r` is drawn, and has no API to change `n_r` afterwards. Test drives a scripted responder that tries to reveal `n_r' ≠ n_r` **after** receiving msg3 (which carries `n_i`) ⇒ viewer rejects with `CommitmentMismatch` / `ProtocolViolation`, no SAS shown. Every bit-position of `n_r` tried. |
| A17-S2 | The initiator's `n_i` is revealed only **after** `C_r` is received | Type-state: the viewer cannot build msg3 before it has processed msg2; test feeds msg2 without a commitment (or with a malformed one) ⇒ `ProtocolViolation`, `n_i` never sent. |
| A17-S3 | The SAS depends on **all** of `h`, `n_i`, `n_r` | Flipping any single bit of any input changes the SAS (checked for every bit position; a collision is allowed only at the 10⁻⁶ rate and the test fixes inputs where none occurs). |
| A17-S4 | No SAS is computed or displayed before the reveal is verified | State machine exposes the SAS only in `PendingApproval`, reachable only through successful verification (also A23). |
| A17-S5 | `n_i`, `n_r` are fresh 256-bit CSPRNG values per session | Injected-RNG test: the code draws exactly one fresh value per session; values never repeat across 10⁵ sessions. |

**Secondary — statistical evidence:**

* **A17-stat:** 10 000 in-process MITM runs (attacker knows the password).
  **INVESTIGATE at 1 match** (expected in ≈ 1 % of honest runs), **FAIL at
  ≥ 2 matches** (false-alarm rate 5 × 10⁻⁵ for an honest implementation).
* **A18-stat:** fix every value the responder controls (ephemeral key, `n_r`) and
  vary only the initiator's `n_i` over 10⁶ runs; bucket SAS values into 1000
  bins (expected 1000 per bin). **FAIL if χ² (999 d.o.f.) > 1226.1** (the
  p = 10⁻⁶ critical value, so an honest implementation fails about once in a
  million runs). This shows the responder's fixed choices cannot pin the SAS;
  it detects gross bias only.

**Mutant checks:** removing the commitment check, computing the SAS before the
reveal, or dropping `n_i` or `n_r` from the SAS input must each fail at least
one A17-S test.

> **S1–S5 test the IMPLEMENTATION, not the DESIGN.** Green tests show the code
> does what the design says. They do not show the design is secure. Because the
> SPAKE2 crate gives no key confirmation, the safety-code commitment scheme is
> **Remora's own construction, covered by no published analysis**. Its design
> assurance is item #1 on the v1.0 formal-modelling list (docs/roadmap.md):
> **"Remora safety-code commitment scheme"**. Nobody may cite these tests as
> evidence that the scheme is sound.

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
| **A29** | **Weak OTP generation** | **Structural (primary):** the generator uses rejection sampling — with an injected RNG that returns values ≥ 4 294 000 000 (the biased tail of `u32 % 10⁶`), the generator must draw again, never map them; the production RNG is the OS CSPRNG (type-checked). **Statistical (secondary):** 10⁶ OTPs in 1000 bins, FAIL if χ² (999 d.o.f.) > 1226.1. Note: the statistical test **cannot** detect the modulo bias it was originally meant for (a 2.3 × 10⁻⁴ relative effect ≈ 0.1 counts per bin against a standard deviation of 31.6) — that is why the structural test is primary. |
| **A30** | **Short unattended password** | `validate_unattended_password` rejects < 12 characters after NFKC normalisation (incl. combining-character tricks), > 128, and the embedded common-password list; accepts valid ones. |
| **A31** | **`unsafe` outside FFI modules** | CI check: `unsafe` appears only under `crates/*/src/sys/` (and the throwaway spike); every block has `// SAFETY:` (clippy `undocumented_unsafe_blocks` already denies). |
| **A32** | **Small-order / torsion / identity SPAKE2 element** from the peer — **a first-class security control**: it compensates for a check the crate does not perform (crypto-claims-audit §1) | Our `Pake` wrapper rejects it **before** the crate sees it: `ProtocolViolation`, wire `AUTH_FAILED`. Tested with **known-bad vectors** — the actual encodings of all 8 small-order points of edwards25519 (including their non-canonical encodings), the identity, valid points with each torsion component added, wrong side byte, wrong length, non-decompressible bytes — not only a logic test. The validator is **inside the mutation-testing scope** (§7): every mutant of it must be killed. |
| **A35** | **Abstraction boundary erosion**: a `spake2` or `snow` type used outside the wrapper modules | **Mechanical check that fails the build:** (1) only `remora-crypto` may depend on `spake2` or `snow`; (2) inside it, only the wrapper modules (`src/pake/`, `src/noise/`) may mention `spake2::` or `snow::` — this also forbids re-exporting their types in public signatures; (3) the scanner itself is unit-tested against violating samples so it can't silently pass. |
| **A33** | **Unverifiable SPAKE2 constants** | A test re-derives M and N from python-spake2's published seed procedure and compares them to the crate's constants. If they cannot be reproduced, Phase 3 reports the PAKE as resting on unverified constants (owner decision). |
| **A34** | **Noise implementation correctness evidence** | snow's own Noise test-vector suite is run once in CI against the exact locked version, and the result recorded. |

### 3.8 Found during implementation (recorded, owner request)

**INV15 / A36 — the "one-time" password was not one-time.** threat-model.md
§6.1 has said since Phase 1 that the password is valid "only for one
successful session", but no invariant, criterion or test enforced it, and the
first session implementation only rotated it after 3 failures (INV12). Found
while implementing remora-session; owner decision 2026-10-18: consume it on
use. Implemented **at authentication** (msg1), which is before — and so covers
— every way a session can end, and also blocks a second, concurrent session
with the same code.

**Audit of other "one-time / single-use / fresh" claims (2026-10-18):**

| Claim | Enforced? |
|---|---|
| OTP "one-time" (threat-model A4, §6.1) | **Now** — INV15 / A36 |
| Connection-code nonce "single-use on the host" (protocol.md §2; threat-model replay rows) | **Now** — A06 in remora-session (`Host::issue_nonce`, checked before SPAKE2; tests/a06_nonce.rs). Over QUIC re-tested in remora-net |
| Fresh ephemeral keys and SAS nonces per handshake | Yes — A17-S5; `a17_sas_binds_the_handshake_transcript_not_only_the_nonces` |
| "Fresh password" after 3 failures | Yes — A02 / INV12 |
| One sender per media key; rotate at 2³² packets | Yes — A13 |
| Media key rotation after **1 hour** | **Not yet** — no media path; Phase 4 |

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
| **INV11** "session active" indicator + one-click end | `inv11_disconnect_from_every_state_reaches_closed_and_stops_processing`, `inv11_viewer_disconnect_from_every_state`; CLI end to end: `f1_password_mode_accept_makes_both_active_with_the_same_code` (host prints `SESSION ACTIVE <id>` for the session, `disconnect <id>` ends it) | **Partial → CLI part automated in Phase 3** (was scheduled for Phase 4) | Phase 7: GUI test that the indicator is visible for the whole `Active` period and its button reaches `Closed` within 1 s |
| **INV12** 3 failures rotate OTP and notify | A02 | **Full** | — |
| **INV13** unattended password ≥ 12 chars, NFKC | A30 (policy function) | **Full** for the policy | Unattended mode itself is post-v0.1; its use of the policy is tested then |
| **INV14** no `unsafe` outside FFI; SAFETY comments | A31 + existing lints | **Full** | — |
| **INV15** one-time password used once (added 2026-10-18) | A36 | **Full** | — |

**Gaps (not dropped, scheduled):** INV2 (real media path), INV9, INV10, INV11
(automated part only partial). Added to docs/roadmap.md "Known gaps".

## 6. The SPAKE2 finding (elevated)

The threat model asserted an "RFC 9382-style" SPAKE2. Reading the crate showed
it is **a port of python-spake2 (magic-wormhole), not RFC 9382**, and it differs
in ways that matter: **no cofactor multiplication or small-order check**,
**different M/N constants** whose generation we have not verified, **no key
confirmation**, no memory-hard password hashing, and no zeroizing of secrets.
The published analysis of RFC 9382 therefore does **not** directly cover what
we would ship. Full detail, evidence and every other cryptographic claim
re-checked: **docs/crypto-claims-audit.md**.

Consequences for Phase 3:

* The PAKE sits behind a **real abstraction boundary** (`remora-crypto::Pake`
  trait: own message/key/error types, input validation in our code, algorithm
  named by the protocol version; no `spake2` type in any public signature; one
  test suite run against every implementation).
* Hardening in our wrapper: reject non-torsion-free and identity elements (A32).
* Evidence tasks: re-derive the constants (A33).
* **v1.0 review question:** move to CPace (IRTF CFRG draft) or an RFC 9382
  implementation; external review of the composition. In docs/roadmap.md.

## 6b. What our own tests cannot prove — and what we rely on instead

| Cannot be proven by us | What we rely on |
|---|---|
| Correctness of the `spake2` construction and code | §6; property tests; wrapper hardening (A32); constant re-derivation (A33); replaceable behind the `Pake` trait; external review before v1.0 |
| `snow`, `curve25519-dalek`, `ed25519-dalek`, `chacha20poly1305` correctness | snow's Noise vector tests run once in CI (A34); **chacha20poly1305's NCC Group audit (stated in its README)**; for the dalek crates no audit is claimed here (revision 1's "Quarkslab 2019" line was from memory and has been removed — crypto-claims-audit C14); our protocol-level tests |
| Constant-time behaviour | Where *our* code compares secrets we use `subtle` (lint + review); library internals rely on their design |
| Soundness of the composition (SPAKE2 → PSK → Noise XXpsk0 + exporter + SAS commit-reveal, with implicit instead of RFC key confirmation) | Design reasoning; **gap:** formal model (ProVerif/Tamarin) before v1.0 |
| OS CSPRNG quality | `getrandom`/OS RNG; A29 only catches gross failures |
| Human SAS comparison | UI design (Phase 7); residual risk in threat model §9 |
| QUIC / rustls | Deliberately untrusted (D1); A14 proves a QUIC-layer MITM fails |
| Secrets left in memory by third-party crates (SPAKE2 state, Noise keys are **not** zeroized — verified), OS crash reports, swap, hibernation | Short-lived handshake state; our own secret types zeroize; residual risk |

## 6c. Statistical thresholds — re-checked against their baselines

| Test | Revision 1 | Problem | Revision 2 |
|---|---|---|---|
| A17 | ≤ 0.1 % matches in 10 000 runs | Allowed 10 matches = 1000× the 10⁻⁶ baseline | Structural primary; FAIL ≥ 2, INVESTIGATE at 1 (§3.4a) |
| A18 | "statistically equal to 10⁻⁶" (undefined) | No threshold, no stated power | Structural primary; χ² with 1000 bins, p = 10⁻⁶ critical value 1226.1 |
| A29 | χ² over 10⁶ categories with 10⁶ samples | Invalid (≈ 1 expected per category) **and** blind to modulo bias, the bug it targeted | Structural rejection-sampling test primary; valid χ² secondary, with its blind spot stated |
| A04 timing (new) | — | — | Fixed floor + bounded window + A/A noise control (§3.1a) |
| Others (A02, A03, A09, A12, A13, A26, A27) | deterministic | — | unchanged — counts and exhaustive checks, not samples |

## 7. Mutation-testing gate

* **Scope — security controls only** (listed in `.cargo/mutants.toml`; a file joins when it lands): `remora-testkit/src/policy.rs` (**the policy check is a security control** — it backs decision D19's dependency guarantee and A31/A35; first run 56 caught, 0 missed), `remora-crypto` (all — **explicitly including the A32 element validator**), `remora-session`
  (state machine, approval gate, attempt limiter), the handshake driver in
  `remora-net`, and the validators in `remora-proto`.
* **When:** a scheduled nightly workflow, and on pull requests that change those
  crates (path filter) — **not on every PR**.
* **How (since 2026-10-18):** one CI job **per crate**, in parallel. The job
  list is derived from `examine_globs` by `scripts/ci/mutants-matrix.py`, so a
  crate added to the scope gets a job automatically. A setup job proves the
  per-crate mutant lists add up exactly to the whole-workspace list and that
  no crate has 0 mutants; each job fails if it tested 0 mutants; one `gate`
  job is green only if all of them are. Same rule as before: 0 missed.
  (Why: the single job took 62 of its 120 minutes before remora-net joined —
  a gate that times out gets ignored, then disabled.)
* **Pass: 100 % kill rate.** Every surviving mutant must be either killed by a
  new test, or individually justified in **one line** in a committed survivors
  file (the `exclude_re` list in `.cargo/mutants.toml`, one comment per entry) — e.g. *equivalent mutant: replaces `<` with
  `<=` on a value that can never equal the bound*, or *changes only a log
  message*. Equivalent mutants are labelled as such. **A list of unexplained
  survivors fails the gate.**
* Report: caught / missed / unviable / timeout counts per crate and the
  justified list.

## 7b. Build order — tests written with each component, not at the end

Tests written after a finished implementation tend to describe what the code
does instead of what it must do — exactly what this criteria-first gate exists
to prevent. So:

1. **Test harness first** (`remora-testkit`): in-process transport, scriptable
   MITM proxy (record / replay / flip / drop / reorder), `EvilSignal`, canary-secret
   log scanner, counting allocator, mock injector/renderer, binomial/χ² helpers.
2. For each component, **its attack tests are written first** (they fail —
   "red"), then the component is implemented until they pass:
   * `remora-proto` (framing, limits, connection code) → A07, A26, A27 targets;
   * `remora-crypto` (`Pake` wrapper, identity/cert, Noise, SAS, media AEAD, OTP,
     password policy) → A01 (crypto part), A13, A15, A17-S*, A18, A29, A30, A32–A34;
   * `remora-session` (state machine, approval, limiter) → A02, A03, A20–A25-T;
   * `remora-net` (QUIC loopback, exporter, close codes, timing floor) → A04,
     A05, A06, A08, A09, A10, A14, A24;
   * host/viewer CLI → F1, A16, A17-stat, A19, A22 end to end.
3. Fuzz targets and the mutation gate run as each component lands; A28/A31 run
   over everything at the end.

The commit history must show each component's tests landing **before or with**
its implementation, never after.

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

**Status (2026-10-19): all criteria met, awaiting owner acceptance.** Built
test-first in six steps (proto, crypto, session, net, CLI + key storage);
each component's attack tests are committed before or with its
implementation (git history, phase-3 branch — merge with a merge commit).
324 tests in the six security crates (proto 33, crypto 130, session 88,
net 25, app 24, testkit 24), green on macOS, Windows and Linux CI.

### 10.1 Attacks

| ID | Result | Observed failure (and where it is tested) |
|---|---|---|
| A01 | PASS | Wrong password ⇒ host `Msg1Auth`, `AUTH_FAILED`, attempt 1/3; host sent only HostHello + SpakeB (its identity never). crypto `a01_*`, session `a01_wrong_password_*`, net logging test |
| A02 | PASS | 3rd failure rotates the OTP (old one fails afterwards), `OtpRotated`, cool-down 30 s doubling to 1 h, right new password during cool-down ⇒ `RATE_LIMITED` before SPAKE2; trusted devices not locked out. session `limiter.rs`, `a02_a03_host.rs` |
| A03 | PASS | 50 connections ⇒ 4 admitted, 46 `RATE_LIMITED` before any crypto; attempts global per OTP across connections; 10/min/IP with a sliding window and bounded memory |
| A04 | PASS | Bytes: one `AUTH_FAILED`, empty reason (net `a04_bytes_*`). Timing (200-sample workflow, Linux CI): all 9 × 200 closes in 200.43–202.15 ms, A/A medians 0.001 ms apart, every step's medians < 1 ms apart; local M4: 200.54–208.22 ms. Planted removal of the floor ⇒ "close after 0.15 ms < 200 ms" |
| A05 | PASS | Recorded handshake replayed with a fresh nonce ⇒ `AUTH_FAILED` at msg1 (new exporter); exact replay ⇒ `NonceReused` at the hello |
| A06 | PASS | Reused / unknown / expired nonce ⇒ refused before SPAKE2, `AUTH_FAILED`, nothing sent, no attempt counted |
| A07 | PASS | Expired / future-dated codes refused by remora-proto before any traffic (exact second boundaries) |
| A08 | PASS | Edited hellos ⇒ prologue mismatch (msg1 / msg2); boundary shift caught by length prefixes (D22); genuine unknown version ⇒ `VERSION_UNSUPPORTED` |
| A09 | PASS | Every bit of every handshake message flipped (crypto, exhaustive): 0 sessions; in flight over QUIC: never a prompt |
| A10 | PASS | Flip / truncate / replay after Active ⇒ `PROTOCOL_VIOLATION`, only the untampered input delivered |
| A11 | PASS | Every bit of a media datagram flipped ⇒ dropped and counted, session continues, forgeries do not burn counters |
| A12 | PASS | Duplicate / too-old dropped, far-ahead accepted once; model-based test of the 4096 window; a forged far-ahead counter does not slide it |
| A13 | PASS | No (key, counter) repeat over random sequences; refuse after 2³² packets; a key id is never reinstalled |
| A14 | PASS | TLS-terminating MITM with the right password ⇒ `AUTH_FAILED` at msg1 (password mode) / no session (trusted) |
| A15 | PASS | Cert for another Noise key / another device's genuine cert ⇒ `CertKeyMismatch`; `verify_strict` rejects the small-order-key forgery (planted `verify` accepts it) and malleated signatures |
| A16 | PASS | Device ID X answered with key Y ⇒ `IdentityMismatch` before any SAS (crypto, session); CLI `--device` with another code ⇒ refused before connecting, exit 3, the host never prompts |
| A17 | PASS | Structural S1–S5 (type-states D21; every bit of a wrong `n_r` caught; malformed msg2 rejected before `n_i` exists; one RNG draw per side); SAS binds the handshake hash. A17-stat: **0 matches in 10 000** MITM runs (INVESTIGATE at 1, FAIL ≥ 2); planted constant SAS ⇒ 10 000 matches |
| A18 | PASS | A18-stat: χ²(999) below the 10⁻⁶ critical value 1226.1 over 10⁶ initiator nonces with the responder's inputs fixed |
| A19 | PASS | Pinned key changed ⇒ `IdentityChanged`, never a password fallback (crypto, session); CLI: refused before connecting, exit 3 |
| A20 | PASS | Every pre-Active state × every application message: closed, injector/renderer count 0 (`ProtocolViolation`; `AuthFailed` at the Noise steps — §11) |
| A21 | PASS | Host-only messages from the viewer / input from the host ⇒ `WrongRole` |
| A22 | PASS | Approval bound to session ID and SAS (session); CLI: accepting the smaller and the larger of two pending IDs activates exactly that one (a planted "approve the largest" bug is caught) |
| A23 | PASS | Approve refused in every earlier state; the prompt appears only after the reveal is verified |
| A24 | PASS | Slowloris ⇒ `TIMEOUT` at 10 s (QUIC, measured 9.9–11 s); prompt 60 s ⇒ `Rejected` (reason 2); slots freed |
| A25-T | PASS | Trusted mode keeps signature, pinning, binding, commit-reveal, the accept prompt and rate limits; refuses without a pin |
| A26 | PASS | Oversized input refused before proportional allocation (counting allocator): frames, codes, certs, passwords, key files |
| A27 | PASS | 9 targets × 10 min locally, 0 crashes (≈ 618 M runs; §10.4); 60 s per target in CI on every relevant PR and nightly |
| A28 | PASS | Debug redaction per type; TRACE-level scan of real QUIC sessions (667 lines, 6 canaries): no leak; a planted log line is found |
| A29 | PASS | Rejection sampling proven with an injected RNG; χ² secondary |
| A30 | PASS | NFKC, combining marks not counted, control chars, common list, input size before normalising |
| A31 | PASS | Policy scanner (mutation-gated): `unsafe` only in FFI modules + D19 |
| A32 | PASS | All 14 encodings of the 8 small-order points (independently computed), torsion components, off-curve, wrong side — refused by our validator and by `finish()` |
| A33 | PASS | M, N, S re-derived from python-spake2's seed procedure (Rust and independent Python) = the crate's constants |
| A34 | PASS (with gap) | snow's vector suite passes; it covers our `XX` pattern but **not** `XXpsk0` (C22) — cross-implementation vector is v1.0 list item 2b (flynn/noise has three) |
| A35 | PASS | `spake2` / `snow` named only in the wrapper modules (scanner) |
| A36 | PASS | One-time password: reuse after success, concurrently, and after a denied prompt all fail at msg1 (INV15) |

### 10.2 Functional

| ID | Result |
|---|---|
| F1 | PASS — `remora-host serve` / `remora-viewer connect` on 127.0.0.1: same 6-digit SAS on both, accept ⇒ `SESSION ACTIVE`, deny ⇒ rejected (exit 2); password and trusted mode (end-to-end tests drive the real binaries) |
| F2 | connect → SAS shown, 100 runs over QUIC loopback (M4, release): **p50 0.95 ms, p95 2.64 ms**, max 4.88 ms (information only) |
| F3 | PASS — CI green on macOS 15, Windows 2025, Ubuntu 22.04 |

### 10.3 Mutation gate (§7)

CI run on `678cf96` (cargo-mutants 27.1.0, one job per crate, scope
verified to cover all mutants):

| Crate (scope) | Mutants | Caught | Missed | Unviable | Timeouts (detected: the mutant hangs) |
|---|---|---|---|---|---|
| remora-testkit (policy check) | 58 | 56 | **0** | 2 | 0 |
| remora-proto (validators) | 166 | 145 | **0** | 16 | 5 |
| remora-crypto (all) | 358 | 270 | **0** | 86 | 2 |
| remora-session (all) | 141 | 100 | **0** | 40 | 1 |
| remora-net (handshake driver) | 50 | 33 | **0** | 16 | 1 |
| remora-app (key file) | 20 | 15 | **0** | 5 | 0 |
| **Total** | **793** | **619** | **0** | **165** | **9** |

Justified exclusions (`.cargo/mutants.toml`), both **equivalent**: `|` → `^`
in `ConnectionCode::encode` (disjoint bits) and in `ReplayWindow::shift`
(disjoint bits). Every survivor found on the way became a test or removed
redundant code; none was excluded for convenience.

### 10.4 Fuzzing (A27)

| Target | Runs in 10 min (M4) | Crashes / panics / timeouts |
|---|---|---|
| connection_code | 186.4 M | 0 |
| frame_decoder | 70.8 M | 0 |
| messages | 41.2 M | 0 |
| datagram_header | 201.8 M | 0 |
| identity_cert | 20.0 M | 0 |
| pake_message | 6.8 M (corpus seeded with the A32 vectors) | 0 |
| handshake_payload | 54.1 M | 0 |
| media_open | 33.0 M | 0 |
| session_host | 4.0 M (reaches Hello/Spake only: random bytes cannot pass Noise) | 0 |

### 10.5 Found during Phase 3 (recorded)

* SPAKE2: a subgroup check **lost in the port** (C20), restored by A32.
* snow's vectors do not include our `XXpsk0` pattern (C22).
* The "one-time" password was not one-time (INV15, A36).
* Connection-code nonces were not single-use (A06 enforced in session).
* The 14-day dependency rule was broken three times while believed to
  hold; now a CI check with verified, expiring security exceptions (D24,
  D28, D30).
* The CI mutation gate had been failing on timeouts; then split per crate
  (32 instead of 62 minutes).
* Tests that passed for the wrong reason were caught by planted failures:
  A22 (random IDs let a wrong-session bug pass half the time) and a
  3-sample A04 median.
* The device-ID display could not hold 80 bits (C23 → D25/D27).

### 10.6 Gaps carried forward

Tracked in **docs/roadmap.md → "Deferred items"** (the one list; D-1…D-7
are the items below). Summary at the time of writing:

INV2, INV9 (Phase 4), INV10 (Phase 6), the INV11 GUI part (Phase 7; the
CLI part is now automated), A34's cross-implementation vector (v1.0 list
2b), the formal model of the commitment scheme (v1.0 list 1), device keys
in a file instead of the keychain (before v0.1), and everything Phase 5
adds (real NAT traversal, STUN parser fuzzing, QUIC retry).

### 10.7 Manual test steps (two terminals, one machine)

1. Terminal 1: `cargo run -p remora-host -- serve` — note `device:`,
   `code:` and `password:` (first run creates the key file in the
   per-user config directory).
2. Terminal 2: `cargo run -p remora-viewer -- connect '<code>'
   --password <password>` (or omit `--password` to be asked).
3. Both terminals show the **same** `safety code`. In terminal 1 type
   `accept <id>` (the id from the `prompt` line): both print `SESSION
   ACTIVE`. Type `disconnect <id>` to end it.
4. Wrong password: repeat with a wrong `--password` ⇒ viewer prints
   `failed:` and exits 4; host logs one `handshake_failed` WARN on stderr.
5. Deny: `deny <id>` ⇒ viewer prints `rejected` and exits 2; a retry needs
   the new `code:` / `password:` the host printed.
6. Trusted mode: `cargo run -p remora-viewer -- identity` prints the
   viewer's `identity:`; start the host with `serve --trust <that key>`,
   then connect with `--pin <host identity>` instead of `--password`.
7. Wrong device: connect with `--device <some other device code>` ⇒
   `identity mismatch`, exit 3, and the host never prompts.

## 11. Changes to criteria

**2026-10-18 — A20 at the Noise steps (owner-approved).**
New wording: *"`ProtocolViolation` where the frame is recognisable (plaintext
Hello/Spake states, every encrypted state); `AuthFailed` at the Noise steps
(host waiting for msg1 / msg3, viewer waiting for msg2). In every state:
closed, never processed, injector/renderer count 0."*

**Why — read this before "fixing" a test that expects `AuthFailed` for an
unauthorized message.** At a Noise step the only thing the receiver may do
with a frame is try to authenticate it as the next handshake message. An
application message sent there fails that authentication exactly like a
corrupted handshake message, and **that is the truthful outcome**: to report
`ProtocolViolation` instead, the receiver would have to inspect the frame's
content before authenticating it — decrypt-before-authenticate, which is
worse. At msg1 such a frame also counts as a password attempt, like any
msg1 that fails to authenticate. Tests: tests/a20_a21_gate.rs in
remora-session.
