//! Remora cryptography: SPAKE2, Noise handshake, device identity keys, safety
//! codes and media encryption (docs/protocol.md §3, §6; threat model §4).
//!
//! * [`pake`] — Remora's own `Pake` abstraction. The `spake2` crate is used only
//!   inside it, and every element it receives is validated **in our code**
//!   first (A32), because the crate does not check for small-order points.
//! * [`noise`] — the Noise `XXpsk0` / `XX` handshake as a chain of type-states,
//!   so the safety-code commit-then-reveal order cannot be broken by a caller
//!   (A17-S1/S2/S4). The `snow` crate is used only inside it.
//! * [`identity`] — Ed25519 device identity, `IdentityCert`, device ID.
//! * [`keyschedule`] — exporter / transcript → PSK and Noise prologue.
//! * [`sas`] — the 6-digit safety code and its commitment.
//! * [`media`] — per-sender ChaCha20-Poly1305 for media datagrams with an
//!   explicit counter and a 4096-packet replay window.
//! * [`otp`], [`password`] — one-time password and unattended-password policy.
//! * [`secret`] — secret types: `Debug` prints `[redacted]`, memory is wiped
//!   on drop. Secrets held **inside** `spake2` and `snow` are not wiped (those
//!   crates do not use `zeroize`; crypto-claims-audit.md C11).

#![forbid(unsafe_code)]

pub mod identity;
pub mod keyschedule;
pub mod media;
pub mod noise;
pub mod otp;
pub mod pake;
pub mod password;
pub mod sas;
pub mod secret;
