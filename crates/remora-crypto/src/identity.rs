//! Device identity (protocol.md §3.2): an Ed25519 key per device, the
//! `IdentityCert` that binds it to the device's Noise static key, and the
//! device ID derived from it.
//!
//! Signatures are checked only with `ed25519-dalek`'s `verify_strict`, which
//! also rejects small-order public keys and non-canonical (malleable)
//! signatures; plain `verify` is never used (crypto-claims-audit C7).
//!
//! # `IdentityCert` encoding (fixed layout, ≤ [`CERT_MAX_LEN`] bytes)
//!
//! ```text
//! identity_pub      32   Ed25519 public key
//! noise_static_pub  32   X25519 public key
//! created_unix       8   u64 big-endian
//! name_len           1   ≤ 64
//! device_name     name_len  UTF-8
//! signature         64   Ed25519 over CERT_CONTEXT ‖ noise_static_pub ‖ name_len ‖ device_name ‖ created_unix
//! ```

use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};

use remora_proto::limits::DEVICE_NAME_MAX;

/// Domain-separation prefix of the signed message.
pub const CERT_CONTEXT: &[u8] = b"remora/1/cert";
/// Domain-separation prefix of the device-ID hash.
pub const DEVICE_ID_CONTEXT: &[u8] = b"remora/1/device-id";
/// Fixed part of an encoded cert (everything except the name).
pub const CERT_FIXED_LEN: usize = 32 + 32 + 8 + 1 + 64;
/// Largest encoded cert.
pub const CERT_MAX_LEN: usize = CERT_FIXED_LEN + DEVICE_NAME_MAX;
/// Device ID length: 80 bits.
pub const DEVICE_ID_LEN: usize = 10;

/// An Ed25519 public identity key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityPublic(pub(crate) [u8; 32]);

impl IdentityPublic {
    /// The raw key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes (e.g. a pinned key loaded from storage). Validity is
    /// checked when a signature is verified against it.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A device's Noise (X25519) static public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoiseStaticPublic(pub(crate) [u8; 32]);

impl NoiseStaticPublic {
    /// The raw key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The first 80 bits of `BLAKE2s(DEVICE_ID_CONTEXT ‖ identity_pub)`.
///
/// IDs only route a connection; the full key is always verified. Forging an
/// ID for someone else's key costs ~2⁸⁰; one attacker can make two of their
/// own keys collide in ~2⁴⁰, which is harmless (protocol.md §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub(crate) [u8; DEVICE_ID_LEN]);

impl DeviceId {
    /// The device ID of `key`.
    pub fn of(key: &IdentityPublic) -> Self {
        let _ = key;
        todo!()
    }

    /// The raw 10 bytes (as carried in `HostHello`).
    pub fn as_bytes(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.0
    }

    /// Wraps raw bytes received on the wire or typed by the user.
    pub fn from_bytes(bytes: [u8; DEVICE_ID_LEN]) -> Self {
        Self(bytes)
    }
}

/// A device's Ed25519 signing key. Wiped on drop (by `ed25519-dalek`'s own
/// `ZeroizeOnDrop`, verified in signing.rs of 2.2.0).
pub struct IdentityKeypair(pub(crate) SigningKey);

impl std::fmt::Debug for IdentityKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl zeroize::ZeroizeOnDrop for IdentityKeypair {}

impl IdentityKeypair {
    /// A fresh key from `rng`.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(SigningKey::generate(rng))
    }

    /// The public half.
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic(self.0.verifying_key().to_bytes())
    }

    /// Signs a cert binding this identity to `noise_static`.
    pub fn sign_cert(
        &self,
        noise_static: &NoiseStaticPublic,
        device_name: &str,
        created_unix: u64,
    ) -> Result<IdentityCert, CertError> {
        let _ = (noise_static, device_name, created_unix);
        todo!()
    }
}

/// Why a cert was refused. All of these are authentication failures on the
/// wire (`AUTH_FAILED`); the variant is for the local log only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    /// Shorter than its own layout says.
    #[error("certificate truncated")]
    Truncated,
    /// Longer than [`CERT_MAX_LEN`] or than its layout says.
    #[error("certificate too long")]
    TooLong,
    /// `device_name` above 64 bytes.
    #[error("device name too long")]
    NameTooLong,
    /// `device_name` not UTF-8.
    #[error("device name is not UTF-8")]
    NameNotUtf8,
    /// The identity key is not a valid Ed25519 point.
    #[error("identity key invalid")]
    BadIdentityKey,
    /// `verify_strict` failed.
    #[error("certificate signature invalid")]
    SignatureInvalid,
}

/// Binds an identity key to a Noise static key (protocol.md §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCert {
    pub(crate) identity: IdentityPublic,
    pub(crate) noise_static: NoiseStaticPublic,
    pub(crate) device_name: String,
    pub(crate) created_unix: u64,
    pub(crate) signature: [u8; 64],
}

impl IdentityCert {
    /// The signer.
    pub fn identity(&self) -> &IdentityPublic {
        &self.identity
    }

    /// The Noise static key this cert vouches for.
    pub fn noise_static(&self) -> &NoiseStaticPublic {
        &self.noise_static
    }

    /// Human-readable device name (untrusted text — display only).
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Creation time chosen by the signer (informational).
    pub fn created_unix(&self) -> u64 {
        self.created_unix
    }

    /// Encodes the fixed layout above.
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    /// Parses an encoded cert. Checks lengths before allocating; does **not**
    /// verify the signature (call [`IdentityCert::verify`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, CertError> {
        let _ = bytes;
        todo!()
    }

    /// Checks the signature with `verify_strict`.
    pub fn verify(&self) -> Result<(), CertError> {
        todo!()
    }
}
