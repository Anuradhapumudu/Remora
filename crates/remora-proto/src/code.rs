//! Copy-paste connection codes (protocol.md §2): `remora1:` + base64url (no
//! padding) of a binary offer/answer with a CRC-32 typo check.
//!
//! The code is **untrusted** (threat model §7.4): it only says where to connect
//! and which key to expect; authentication happens in the handshake.

use std::net::SocketAddr;

/// Text prefix of every code.
pub const PREFIX: &str = "remora1:";
/// Binary format version.
pub const FORMAT_VERSION: u8 = 1;

/// Offer (host → viewer) or answer (viewer → host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeKind {
    /// Created by the host.
    Offer,
    /// Created by the viewer in reply.
    Answer,
}

/// Candidate type (ICE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// A local interface address.
    Host,
    /// The public address a STUN server saw.
    ServerReflexive,
}

/// One network address the peer can try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Candidate type.
    pub kind: CandidateKind,
    /// Address and port (port ≠ 0).
    pub addr: SocketAddr,
}

/// A decoded connection code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCode {
    /// Offer or answer.
    pub kind: CodeKind,
    /// Unix time (seconds) after which the code is invalid.
    pub expires_at: u32,
    /// Single-use nonce (the answer echoes the offer's).
    pub nonce: [u8; 16],
    /// Sender's Ed25519 identity public key (validated by `remora-crypto`).
    pub identity_key: [u8; 32],
    /// ICE username fragment.
    pub ice_ufrag: [u8; 4],
    /// ICE password.
    pub ice_pwd: [u8; 16],
    /// Up to [`crate::limits::MAX_CANDIDATES`] addresses.
    pub candidates: Vec<Candidate>,
}

/// Why a code was rejected. Checked in this order; nothing is decoded before
/// the length check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    /// Text longer than [`crate::limits::CODE_TEXT_MAX`].
    #[error("connection code too long")]
    TooLong,
    /// Missing `remora1:` prefix.
    #[error("not a Remora connection code")]
    BadPrefix,
    /// Not canonical base64url without padding.
    #[error("connection code is not valid base64url")]
    BadEncoding,
    /// Decoded length impossible for any valid code.
    #[error("connection code has an impossible length")]
    BadLength,
    /// CRC mismatch: almost certainly a copy-paste typo.
    #[error("connection code is damaged (typo?)")]
    Corrupted,
    /// A format version this build doesn't understand.
    #[error("unsupported connection code version {0}")]
    UnsupportedVersion(u8),
    /// Structurally invalid content.
    #[error("malformed connection code: {0}")]
    Malformed(&'static str),
    /// The code has expired.
    #[error("connection code expired")]
    Expired,
    /// Expiry further in the future than allowed (bad clock or forged code).
    #[error("connection code expiry is too far in the future")]
    FutureDated,
}

impl ConnectionCode {
    /// Encodes to `remora1:…` text.
    pub fn encode(&self) -> String {
        todo!("phase 3 step 2: implement after the tests")
    }

    /// Parses and validates `text` at time `now` (Unix seconds). Surrounding
    /// whitespace is ignored (pasted codes often carry a newline).
    pub fn parse(text: &str, now: u64) -> Result<Self, CodeError> {
        let _ = (text, now);
        todo!("phase 3 step 2: implement after the tests")
    }
}
