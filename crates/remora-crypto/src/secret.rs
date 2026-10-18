//! Secret types (threat model INV8, phase3-criteria A28).
//!
//! Every type here prints `[redacted]` under `Debug`, has no `Display`, and
//! wipes its bytes when dropped (`ZeroizeOnDrop`). Accessors that expose the
//! bytes are named so that a reviewer notices them.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! redacted_debug {
    ($($t:ty),*) => {$(
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("[redacted]")
            }
        }
    )*};
}

/// A six-digit one-time password shown on the host (ASCII digits).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Otp(pub(crate) [u8; 6]);

/// Why a typed-in OTP was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OtpError {
    /// Not exactly six characters.
    #[error("the password has 6 digits")]
    WrongLength,
    /// A character other than `0`–`9`.
    #[error("the password contains only digits")]
    NotDigit,
}

impl Otp {
    /// Parses what the viewer's user typed: exactly six ASCII digits.
    pub fn parse(text: &str) -> Result<Self, OtpError> {
        let _ = text;
        todo!()
    }

    /// The digits, for showing on the host's screen. Never log this.
    pub fn reveal(&self) -> &str {
        todo!()
    }
}

/// The 32-byte key output by the PAKE.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PakeKey(pub(crate) [u8; 32]);

impl PakeKey {
    /// Constant-time equality (tests and diagnostics; the handshake never
    /// compares keys directly — a mismatch fails Noise message 1).
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// The Noise pre-shared key derived from the PAKE key (protocol.md §3.1).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Psk(pub(crate) [u8; 32]);

impl Psk {
    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// The QUIC TLS exporter value (32 bytes, label `EXPORTER-remora/1`).
///
/// Treated as secret: anyone who has it and the PAKE key has the PSK.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Exporter(pub(crate) [u8; 32]);

impl Exporter {
    /// Wraps the bytes returned by the QUIC connection.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A ChaCha20-Poly1305 media key (one per sender, protocol.md §6).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MediaKey(pub(crate) [u8; 32]);

impl MediaKey {
    /// A fresh random key.
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        Self(k)
    }

    /// A key received in a `MediaKeyAnnounce` over the Noise channel.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw key, only for putting into a `MediaKeyAnnounce` that is about
    /// to be Noise-encrypted. Never log this.
    pub fn expose_for_announce(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An unattended-access password that passed [`crate::password`]'s policy
/// (stored NFKC-normalised).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UnattendedPassword(pub(crate) String);

impl UnattendedPassword {
    /// The normalised password. Never log this.
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

redacted_debug!(Otp, PakeKey, Psk, Exporter, MediaKey, UnattendedPassword);
