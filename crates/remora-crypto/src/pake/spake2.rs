//! [`Pake`] implementation on the `spake2` 0.4.0 crate (Ed25519 group).
//!
//! The crate is a port of python-spake2; see crypto-claims-audit.md §1 for how
//! it differs from RFC 9382. Its state keeps the password and secret scalar
//! in memory and does not wipe them (no `zeroize`) — residual risk, accepted
//! because the state lives only for one handshake.

use rand_core::{CryptoRng, RngCore};

use zeroize::Zeroizing;

use super::{
    HOST_ID_PREFIX, PAKE_MESSAGE_LEN, PASSWORD_PREFIX, Pake, PakeContext, PakeError, PakeMessage,
    PakeRole, VIEWER_ID, validate_peer_message,
};
use crate::secret::{Otp, PakeKey};

type Inner = ::spake2::Spake2<::spake2::Ed25519Group>;

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
        let mut pw = Zeroizing::new(PASSWORD_PREFIX.to_vec());
        pw.extend_from_slice(password.reveal().as_bytes());
        let pw = ::spake2::Password::new(pw.as_slice());
        let id_a = ::spake2::Identity::new(VIEWER_ID);
        let mut id_b = HOST_ID_PREFIX.to_vec();
        id_b.extend_from_slice(context.host_device_id.as_bytes());
        id_b.extend_from_slice(&context.nonce);
        let id_b = ::spake2::Identity::new(&id_b);
        let (inner, msg) = match role {
            PakeRole::Viewer => Inner::start_a_with_rng(&pw, &id_a, &id_b, &mut *rng),
            PakeRole::Host => Inner::start_b_with_rng(&pw, &id_a, &id_b, &mut *rng),
        };
        // The crate always returns side byte + 32-byte point (C19). If that
        // ever changed, the zero-filled message fails the peer's validator
        // (wrong side byte) instead of being silently truncated.
        let mut out = [0u8; PAKE_MESSAGE_LEN];
        if msg.len() == PAKE_MESSAGE_LEN {
            out.copy_from_slice(&msg);
        }
        (Self { role, inner }, PakeMessage(out))
    }

    fn finish(self, peer: &PakeMessage) -> Result<PakeKey, PakeError> {
        // A32: our checks run BEFORE the crate sees the element.
        validate_peer_message(peer, self.role)?;
        let key = Zeroizing::new(
            self.inner
                .finish(peer.as_bytes())
                .map_err(|_| PakeError::Internal)?,
        );
        let mut out = [0u8; 32];
        if key.len() != out.len() {
            return Err(PakeError::Internal);
        }
        out.copy_from_slice(&key);
        Ok(PakeKey(out))
    }
}
