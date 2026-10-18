//! [`Pake`] implementation on the `spake2` 0.4.0 crate (Ed25519 group).
//!
//! The crate is a port of python-spake2; see crypto-claims-audit.md §1 for how
//! it differs from RFC 9382. Its state keeps the password and secret scalar
//! in memory and does not wipe them (no `zeroize`) — residual risk, accepted
//! because the state lives only for one handshake.

use rand_core::{CryptoRng, RngCore};

use super::{Pake, PakeContext, PakeError, PakeMessage, PakeRole};
use crate::secret::{Otp, PakeKey};

/// SPAKE2 over edwards25519 (python-spake2 compatible).
pub struct Spake2Ed25519 {
    pub(crate) role: PakeRole,
    pub(crate) inner: ::spake2::Spake2<::spake2::Ed25519Group>,
}

impl std::fmt::Debug for Spake2Ed25519 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Pake for Spake2Ed25519 {
    const ALGORITHM: &'static str = "spake2-ed25519-python-compat";

    fn start<R: RngCore + CryptoRng>(
        role: PakeRole,
        password: &Otp,
        context: &PakeContext,
        rng: &mut R,
    ) -> (Self, PakeMessage) {
        let _ = (role, password, context, rng);
        todo!()
    }

    fn finish(self, peer: &PakeMessage) -> Result<PakeKey, PakeError> {
        let _ = peer;
        todo!()
    }
}
