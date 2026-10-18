//! Safety code (SAS) with commit-then-reveal (protocol.md §3.3, threat model §6.3).
//!
//! ```text
//! C_r = BLAKE2s(COMMIT_CONTEXT ‖ n_r)                  host → viewer in Noise msg2
//! n_i                                                  viewer → host in Noise msg3
//! n_r                                                  host → viewer, first transport message
//! SAS = u64_be(BLAKE2s(SAS_CONTEXT ‖ h ‖ n_i ‖ n_r)[0..8]) mod 10⁶
//! ```
//!
//! The host commits to `n_r` before it sees `n_i`, and the viewer reveals
//! `n_i` only after it holds the commitment, so neither side (nor a MITM
//! playing both) can pick its nonce to steer the code. That ordering is
//! enforced by the type-states in [`crate::noise`].
//!
//! This is **Remora's own construction**, covered by no published analysis;
//! tests check the implementation against it, not its soundness (roadmap v1.0
//! formal-modelling item #1).

use std::fmt;

use blake2::{Blake2s256, Digest};
use subtle::ConstantTimeEq;

/// Commitment hash prefix.
pub const COMMIT_CONTEXT: &[u8] = b"remora/1/sas-commit";
/// SAS hash prefix.
pub const SAS_CONTEXT: &[u8] = b"remora/1/sas";
/// Number of distinct codes.
pub const SAS_SPACE: u64 = 1_000_000;

/// A six-digit safety code. Not secret (both users read it aloud).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sas(pub(crate) u32);

impl Sas {
    /// The code as a number below 10⁶.
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for Sas {
    /// Always six digits with leading zeros, e.g. `042917`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

/// `C_r = BLAKE2s(COMMIT_CONTEXT ‖ n_r)`.
pub fn commitment(n_r: &[u8; 32]) -> [u8; 32] {
    let mut d = Blake2s256::new();
    d.update(COMMIT_CONTEXT);
    d.update(n_r);
    d.finalize().into()
}

/// Constant-time check that `n_r` opens commitment `c_r`.
pub fn verify_commitment(c_r: &[u8; 32], n_r: &[u8; 32]) -> bool {
    commitment(n_r).ct_eq(c_r).into()
}

/// The SAS from the handshake hash `h` and both nonces.
pub fn sas(h: &[u8; 32], n_i: &[u8; 32], n_r: &[u8; 32]) -> Sas {
    let mut d = Blake2s256::new();
    d.update(SAS_CONTEXT);
    d.update(h);
    d.update(n_i);
    d.update(n_r);
    let out = d.finalize();
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&out[..8]);
    // < 10⁶, so it fits a u32. Bias of `mod 10⁶` on 64 bits is < 10⁻¹³ (C9).
    Sas((u64::from_be_bytes(first8) % SAS_SPACE) as u32)
}
