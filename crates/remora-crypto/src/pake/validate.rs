//! Validation of a received PAKE element (phase3-criteria A32).
//!
//! **A security control in its own right:** it compensates for a check the
//! `spake2` 0.4.0 crate does not perform. Its `bytes_to_element`
//! (src/ed25519.rs) only decompresses; RFC 9382 §3.3 instead multiplies by
//! the cofactor, and python-spake2 0.9 — which the crate ports — rejects
//! the identity and any element outside the prime-order subgroup in its own
//! `bytes_to_element` (src/spake2/ed25519_basic.py, read 2026-10-18).
//!
//! Checks, in order (all run; the first failure is reported):
//!
//! 1. exactly 33 bytes (enforced by [`PakeMessage`]'s type);
//! 2. side byte is the peer's;
//! 3. the 32 bytes decompress to a point (`curve25519-dalek` 4.1.3
//!    `CompressedEdwardsY::decompress`);
//! 4. the encoding is canonical — re-compressing gives the same bytes
//!    (`decompress` accepts `y ≥ p` and a "negative zero" x, verified in
//!    edwards.rs / field.rs);
//! 5. not of small order (the identity and the other 7 low-order points);
//! 6. torsion-free (in the prime-order subgroup).

use curve25519_dalek::edwards::CompressedEdwardsY;

use super::{PakeError, PakeMessage, PakeRole};

/// Checks a peer's PAKE message as described in the module docs.
pub fn validate_peer_message(msg: &PakeMessage, own_role: PakeRole) -> Result<(), PakeError> {
    let bytes = msg.as_bytes();
    if bytes[0] != own_role.peer_side() {
        return Err(PakeError::WrongSide);
    }
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&bytes[1..]);
    let point = CompressedEdwardsY(enc)
        .decompress()
        .ok_or(PakeError::NotOnCurve)?;
    if point.compress().to_bytes() != enc {
        return Err(PakeError::NonCanonical);
    }
    if point.is_small_order() {
        return Err(PakeError::SmallOrder);
    }
    if !point.is_torsion_free() {
        return Err(PakeError::NotTorsionFree);
    }
    Ok(())
}
