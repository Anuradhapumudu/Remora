//! Remora's PAKE abstraction (phase3-criteria §6, crypto-claims-audit §1).
//!
//! The only implementation today is [`Spake2Ed25519`], built on the `spake2`
//! crate — a port of **python-spake2**, not RFC 9382. That crate does not
//! check received elements for small order or torsion, so
//! [`validate_peer_message`] does it here, **before** the crate sees the
//! bytes (A32). No `spake2` type appears outside this module (A35); swapping
//! the PAKE means a new `impl Pake` and a protocol version bump.
//!
//! Inputs fixed by protocol.md §3.1:
//!
//! * password = [`PASSWORD_PREFIX`] ‖ six ASCII digits
//! * `id_a` = [`VIEWER_ID`]
//! * `id_b` = [`HOST_ID_PREFIX`] ‖ host_device_id (10 B) ‖ nonce (16 B)

#[cfg(test)]
mod a33_constants;
mod spake2;
mod validate;

use rand_core::{CryptoRng, RngCore};

use crate::identity::DeviceId;
use crate::secret::{Otp, PakeKey};

pub use self::spake2::Spake2Ed25519;
pub use self::validate::validate_peer_message;

/// Length of every PAKE message: side byte + compressed Edwards point.
pub const PAKE_MESSAGE_LEN: usize = 33;
/// Side byte of the viewer's (SPAKE2 side A) message.
pub const SIDE_VIEWER: u8 = 0x41;
/// Side byte of the host's (SPAKE2 side B) message.
pub const SIDE_HOST: u8 = 0x42;
/// Password prefix.
pub const PASSWORD_PREFIX: &[u8] = b"remora/1/otp:";
/// SPAKE2 identity of side A.
pub const VIEWER_ID: &[u8] = b"remora/1/viewer";
/// SPAKE2 identity of side B, followed by device ID and nonce.
pub const HOST_ID_PREFIX: &[u8] = b"remora/1/host:";

/// Which side of the exchange we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PakeRole {
    /// SPAKE2 side A.
    Viewer,
    /// SPAKE2 side B.
    Host,
}

impl PakeRole {
    /// The side byte this role puts on its own messages.
    pub fn own_side(self) -> u8 {
        match self {
            PakeRole::Viewer => SIDE_VIEWER,
            PakeRole::Host => SIDE_HOST,
        }
    }

    /// The side byte this role expects on the peer's message.
    pub fn peer_side(self) -> u8 {
        match self {
            PakeRole::Viewer => SIDE_HOST,
            PakeRole::Host => SIDE_VIEWER,
        }
    }
}

/// A PAKE message as sent on the wire (`SpakeA` / `SpakeB`). Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PakeMessage(pub(crate) [u8; PAKE_MESSAGE_LEN]);

impl PakeMessage {
    /// Takes bytes off the wire. Checks only the length; the content is
    /// checked by [`validate_peer_message`] inside [`Pake::finish`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PakeError> {
        let arr: [u8; PAKE_MESSAGE_LEN] = bytes
            .try_into()
            .map_err(|_| PakeError::WrongLength { len: bytes.len() })?;
        Ok(Self(arr))
    }

    /// The bytes to send.
    pub fn as_bytes(&self) -> &[u8; PAKE_MESSAGE_LEN] {
        &self.0
    }
}

/// Session context bound into the PAKE identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PakeContext {
    /// The host's device ID (from `HostHello`).
    pub host_device_id: DeviceId,
    /// The connection-code nonce (from `ViewerHello`).
    pub nonce: [u8; 16],
}

/// Why the PAKE failed. On the wire every variant is `AUTH_FAILED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PakeError {
    /// Message is not [`PAKE_MESSAGE_LEN`] bytes.
    #[error("PAKE message has {len} bytes")]
    WrongLength {
        /// Received length.
        len: usize,
    },
    /// Side byte is not the peer's (includes a reflected own message).
    #[error("PAKE message has the wrong side byte")]
    WrongSide,
    /// Not a point on edwards25519.
    #[error("PAKE element is not on the curve")]
    NotOnCurve,
    /// A non-canonical encoding of a point.
    #[error("PAKE element encoding is not canonical")]
    NonCanonical,
    /// The identity or another of the 8 small-order points.
    #[error("PAKE element has small order")]
    SmallOrder,
    /// Has a torsion component (not in the prime-order subgroup).
    #[error("PAKE element is not torsion-free")]
    NotTorsionFree,
    /// The underlying implementation refused after our checks passed.
    #[error("PAKE implementation error")]
    Internal,
}

/// A balanced PAKE between viewer and host.
pub trait Pake: Sized {
    /// Name used in logs and tied to the protocol version.
    const ALGORITHM: &'static str;

    /// Starts the exchange; returns our state and the message to send.
    fn start<R: RngCore + CryptoRng>(
        role: PakeRole,
        password: &Otp,
        context: &PakeContext,
        rng: &mut R,
    ) -> (Self, PakeMessage);

    /// Finishes with the peer's message. Validates it first.
    fn finish(self, peer: &PakeMessage) -> Result<PakeKey, PakeError>;
}
