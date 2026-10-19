//! The Noise handshake and transport (protocol.md §3), wrapping `snow` 0.10.
//!
//! Password mode: `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s` (PSK from the PAKE).
//! Trusted mode: `Noise_XX_25519_ChaChaPoly_BLAKE2s` (pinned keys).
//!
//! ```text
//! viewer                                          host
//! viewer_start ─── msg1 (psk, e) ──────────────▶  host_start → read_msg1 (draws n_r)
//!              ◀── msg2 (e, ee, s, es) ───────── write_msg2   payload: cert_h ‖ C_r
//! read_msg2 → write_msg3 (draws n_i) ── msg3 ──▶  read_msg3    payload: cert_v ‖ n_i
//!                                                 reveal → Established + n_r
//!              ◀── first transport message ───── (caller sends SasReveal{n_r})
//! read_reveal → Established
//! ```
//!
//! **Why type-states:** each step consumes the previous state, so the order
//! is enforced by the compiler.
//!
//! * A17-S1 — the host draws `n_r` in `read_msg1`, before it can build msg2
//!   (which carries `C_r`), and no method changes it afterwards.
//! * A17-S2 — the viewer can build msg3 (which carries `n_i`) only from the
//!   state that processed msg2, i.e. after it holds `C_r`.
//! * A17-S4 — a [`Sas`] exists only inside [`Established`], which the viewer
//!   reaches only through a verified reveal.
//!
//! Payload encoding (inside Noise, so encrypted and authenticated):
//! msg2 = `IdentityCert ‖ C_r (32)`, msg3 = `IdentityCert ‖ n_i (32)`.

mod handshake;
#[cfg(test)]
mod tests;

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::{CertError, NoiseStaticPublic};

pub use self::handshake::{
    Established, HostAwaitMsg1, HostAwaitMsg3, HostGotMsg1, HostGotMsg3, ViewerAwaitMsg2,
    ViewerAwaitReveal, ViewerGotMsg2, host_start, viewer_start,
};

/// Noise pattern for password mode.
pub const PATTERN_PASSWORD: &str = "Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s";
/// Noise pattern for trusted mode.
pub const PATTERN_TRUSTED: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Noise's maximum message size.
pub const NOISE_MAX_MESSAGE: usize = 65_535;
/// Noise AEAD tag length.
pub const NOISE_TAG_LEN: usize = 16;

/// A device's Noise static (X25519) key pair.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoiseStaticKeypair {
    pub(crate) secret: [u8; 32],
    #[zeroize(skip)]
    pub(crate) public: NoiseStaticPublic,
}

impl std::fmt::Debug for NoiseStaticKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl NoiseStaticKeypair {
    /// A fresh key pair from `rng`.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let public = curve25519_dalek::MontgomeryPoint::mul_base_clamped(secret).to_bytes();
        Self {
            secret,
            public: NoiseStaticPublic(public),
        }
    }

    /// Rebuilds a key pair from its secret (e.g. loaded from the OS
    /// keychain). The public key is derived, so the two cannot disagree.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let public = curve25519_dalek::MontgomeryPoint::mul_base_clamped(secret).to_bytes();
        Self {
            secret,
            public: NoiseStaticPublic(public),
        }
    }

    /// The public key (goes into our `IdentityCert`).
    pub fn public(&self) -> &NoiseStaticPublic {
        &self.public
    }
}

/// Which handshake to run.
pub enum HandshakeMode<'a> {
    /// Password mode: `XXpsk0` with this PSK.
    Password(&'a crate::secret::Psk),
    /// Trusted mode: `XX`; the peer must match a pinned key.
    Trusted,
}

/// What the peer's identity must satisfy (checked on its `IdentityCert`
/// after the signature and the Noise-key binding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerPolicy {
    /// Any valid identity (password mode: the password authenticates).
    AnyKey,
    /// The viewer connects by device ID: `DeviceId(cert key)` must equal it.
    DeviceId(crate::identity::DeviceId),
    /// Exactly this pinned key (trusted device, viewer side).
    Pinned(crate::identity::IdentityPublic),
    /// One of these trusted keys (trusted mode, host side).
    TrustedSet(Vec<crate::identity::IdentityPublic>),
}

/// Why the handshake failed. The variant is for the **local** log
/// (`FailReason`); on the wire all authentication failures look the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// Host: msg1 did not decrypt (wrong password ⇒ wrong PSK, tampering,
    /// wrong prologue, mode mismatch).
    #[error("noise message 1 failed to authenticate")]
    Msg1Auth,
    /// Viewer: msg2 did not decrypt.
    #[error("noise message 2 failed to authenticate")]
    Msg2Auth,
    /// Host: msg3 did not decrypt.
    #[error("noise message 3 failed to authenticate")]
    Msg3Auth,
    /// Viewer: the reveal did not decrypt.
    #[error("SAS reveal failed to authenticate")]
    RevealAuth,
    /// A handshake message larger than Noise allows.
    #[error("handshake message too large")]
    TooLarge,
    /// The decrypted payload does not have the expected layout.
    #[error("malformed handshake payload")]
    MalformedPayload,
    /// The first transport message is not a well-formed `SasReveal`.
    #[error("expected SAS reveal")]
    RevealExpected,
    /// The peer's cert is malformed or its signature invalid.
    #[error("peer certificate: {0}")]
    Cert(CertError),
    /// The cert's Noise key is not the key Noise authenticated.
    #[error("certificate does not match the Noise static key")]
    CertKeyMismatch,
    /// `DeviceId(cert key)` is not the device ID we asked for.
    #[error("peer device ID mismatch")]
    DeviceIdMismatch,
    /// A pinned (trusted) device presented a different key.
    #[error("pinned identity key changed")]
    PinnedKeyChanged,
    /// Trusted mode: the key is not in the trusted set.
    #[error("identity key not trusted")]
    UntrustedKey,
    /// Trusted mode needs [`PeerPolicy::Pinned`] or [`PeerPolicy::TrustedSet`].
    #[error("trusted mode requires a pinned key")]
    TrustedModeRequiresPin,
    /// The revealed `n_r` does not open the commitment `C_r`.
    #[error("SAS commitment mismatch")]
    CommitmentMismatch,
    /// `snow` refused an operation for a reason not listed above.
    #[error("noise internal error")]
    Internal,
}

/// Splits a decrypted msg2/msg3 payload into the sender's cert and the
/// trailing 32-byte value (`C_r` in msg2, `n_i` in msg3). The cert's own
/// name-length byte frames it; the payload must be exactly
/// `cert ‖ 32 bytes`. Checks lengths before allocating. Public so it can be
/// fuzzed directly (A27); the handshake calls it after decryption.
pub fn decode_handshake_payload(
    payload: &[u8],
) -> Result<(crate::identity::IdentityCert, [u8; 32]), HandshakeError> {
    use crate::identity::{CERT_FIXED_LEN, CERT_MAX_LEN, IdentityCert};
    const NAME_LEN_AT: usize = 72;
    let name_len = usize::from(
        *payload
            .get(NAME_LEN_AT)
            .ok_or(HandshakeError::MalformedPayload)?,
    );
    let cert_len = CERT_FIXED_LEN + name_len;
    // A name above the limit is a framing error here, before the cert parser.
    if cert_len > CERT_MAX_LEN || payload.len() != cert_len + 32 {
        return Err(HandshakeError::MalformedPayload);
    }
    let cert = IdentityCert::decode(&payload[..cert_len]).map_err(HandshakeError::Cert)?;
    let mut tail = [0u8; 32];
    tail.copy_from_slice(&payload[cert_len..]);
    Ok((cert, tail))
}

/// Errors on the established channel. Any of them closes the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// Decryption failed (tampered, truncated, reordered, replayed or dropped
    /// predecessor — Noise transport nonces are implicit and sequential).
    #[error("transport message failed to authenticate")]
    Auth,
    /// Plaintext or ciphertext above Noise's limit.
    #[error("transport message too large")]
    TooLarge,
    /// `snow` refused for another reason.
    #[error("noise internal error")]
    Internal,
}
