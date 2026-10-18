//! Failure reasons and wire close codes (phase3-criteria §2).
//!
//! **Generic on the wire, specific locally.** The peer only ever sees a
//! [`CloseCode`] from a fixed table with an empty reason phrase; every
//! authentication failure is the same `AUTH_FAILED`, so a remote attacker
//! cannot tell which check failed (A04). The host's log gets the precise
//! [`FailReason`], which never contains secret material (A28).

use remora_crypto::noise::HandshakeError;
use remora_crypto::pake::PakeError;
use remora_proto::messages::MessageError;

/// QUIC application close codes (the only thing the peer learns).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CloseCode {
    /// Orderly close (`Goodbye`, user disconnect).
    Normal = 0x00,
    /// Every authentication failure.
    AuthFailed = 0x10,
    /// Malformed, oversized, out-of-order or forbidden message.
    ProtocolViolation = 0x11,
    /// No common protocol version.
    VersionUnsupported = 0x12,
    /// The host user denied, or the prompt timed out.
    Rejected = 0x13,
    /// The handshake did not finish in time.
    Timeout = 0x14,
    /// Too many attempts / connections.
    RateLimited = 0x15,
}

/// Where in the protocol a failure happened (for the local log).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// Before any handshake message (admission).
    Admission,
    /// `ViewerHello` / `HostHello`.
    Hello,
    /// SPAKE2 messages.
    Spake,
    /// Noise message 1.
    NoiseMsg1,
    /// Noise message 2.
    NoiseMsg2,
    /// Noise message 3.
    NoiseMsg3,
    /// The `SasReveal`.
    Reveal,
    /// Waiting for the host user.
    Approval,
    /// After `Active`.
    Active,
}

/// The precise local reason a session ended badly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FailReason {
    /// Wrong password, bad signature, unknown key, tampered handshake.
    #[error("authentication failed: {0}")]
    AuthFailed(AuthDetail),
    /// Malformed or forbidden message.
    #[error("protocol violation: {0}")]
    ProtocolViolation(Violation),
    /// The peer is not the device ID we asked for (A16).
    #[error("peer identity does not match the requested device ID")]
    IdentityMismatch,
    /// A trusted device presented a different key (A19).
    #[error("this device's identity changed")]
    IdentityChanged,
    /// No common protocol version.
    #[error("no common protocol version")]
    VersionUnsupported,
    /// Pending cap, per-IP limit or cool-down.
    #[error("rate limited")]
    RateLimited,
    /// Handshake deadline passed.
    #[error("handshake timed out")]
    Timeout,
    /// Host user denied, or the prompt timed out.
    #[error("rejected by the host")]
    Rejected,
}

/// Which authentication check failed (local log only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthDetail {
    /// A handshake step failed in remora-crypto.
    #[error("{0}")]
    Handshake(HandshakeError),
    /// The SPAKE2 implementation refused after validation passed.
    #[error("PAKE failure")]
    Pake,
    /// Password mode while the host has no password enabled, or trusted
    /// mode with no trusted devices.
    #[error("mode not available")]
    ModeUnavailable,
}

/// What was malformed or forbidden (local log only).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    /// The frame did not parse as the message this state expects.
    #[error("malformed message: {0}")]
    Malformed(MessageError),
    /// A SPAKE2 element failed our validator (A32).
    #[error("invalid PAKE element: {0}")]
    PakeElement(PakeError),
    /// A handshake message with bad structure (payload, reveal, commitment).
    #[error("{0}")]
    Handshake(HandshakeError),
    /// An application message before `Active` (A20).
    #[error("application message before approval")]
    BeforeActive,
    /// A message this role may not send (A21).
    #[error("message not allowed from this role")]
    WrongRole,
    /// A datagram before `Active`.
    #[error("datagram before approval")]
    DatagramBeforeActive,
    /// A transport frame failed to decrypt (A10).
    #[error("transport frame failed to authenticate")]
    TransportAuth,
}

impl FailReason {
    /// The code the peer sees. Generic: every authentication-type failure,
    /// including a bad PAKE element (A32), is `AUTH_FAILED`.
    pub fn close_code(&self) -> CloseCode {
        todo!()
    }
}
