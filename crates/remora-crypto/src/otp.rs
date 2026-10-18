//! One-time password generation (phase3-criteria A29).
//!
//! `u32 % 1_000_000` would be biased: 2³² is not a multiple of 10⁶, so the
//! last partial block (values ≥ [`REJECT_FROM`]) would make the codes
//! 000000–967295 slightly more likely. We use **rejection sampling**: such a
//! draw is thrown away and a new one taken, so every code is exactly equally
//! likely.

use rand_core::{CryptoRng, RngCore};

use crate::secret::Otp;

/// Number of distinct codes.
pub const OTP_SPACE: u32 = 1_000_000;

/// First `u32` value that is rejected: the largest multiple of [`OTP_SPACE`]
/// that fits in a `u32` (4 294 × 10⁶). Values `>= REJECT_FROM` are redrawn.
pub const REJECT_FROM: u32 = (u32::MAX / OTP_SPACE) * OTP_SPACE;

/// The RNG production code uses: the operating system's CSPRNG. Kept as a
/// named type so a test can check, at compile time, that [`generate_otp_os`]
/// cannot be fed anything else.
pub type ProductionRng = rand_core::OsRng;

/// Draws a uniformly random six-digit OTP from `rng` by rejection sampling.
pub fn generate_otp<R: RngCore + CryptoRng>(rng: &mut R) -> Otp {
    let _ = rng;
    todo!()
}

/// [`generate_otp`] with the OS CSPRNG ([`ProductionRng`]).
pub fn generate_otp_os() -> Otp {
    generate_otp(&mut ProductionRng::default())
}
