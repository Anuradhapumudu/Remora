//! Helpers shared by the host and viewer command-line apps.

use std::net::SocketAddr;

use remora_crypto::identity::{IdentityPublic, ShortCode};
use remora_crypto::sas::Sas;
use remora_proto::code::{Candidate, CandidateKind, CodeKind, ConnectionCode};

/// Viewer exit codes (stable: scripts and tests rely on them).
pub mod exit {
    /// The session ended normally.
    pub const OK: u8 = 0;
    /// Anything else went wrong (network, bad input).
    pub const ERROR: u8 = 1;
    /// The host user denied, or the prompt timed out.
    pub const REJECTED: u8 = 2;
    /// The host is not the device asked for, or a pinned key changed.
    pub const IDENTITY: u8 = 3;
    /// Authentication failed (wrong password, untrusted, tampering).
    pub const AUTH: u8 = 4;
}

/// Why a command-line value was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliError {
    /// An identity key is 64 hex digits.
    #[error("an identity key is 64 hexadecimal digits")]
    BadIdentity,
}

/// A safety code as people read it aloud: `123 456`.
pub fn format_sas(sas: Sas) -> String {
    let _ = sas;
    todo!()
}

/// An identity key as 64 lowercase hex digits.
pub fn identity_hex(key: &IdentityPublic) -> String {
    let _ = key;
    todo!()
}

/// Parses 64 hex digits (either case) into an identity key.
pub fn parse_identity(text: &str) -> Result<IdentityPublic, CliError> {
    let _ = text;
    todo!()
}

/// The device short code of an identity key.
pub fn short_code_of(key: &IdentityPublic) -> ShortCode {
    remora_crypto::identity::DeviceId::of(key).short_code()
}

/// Seconds since the Unix epoch (0 if the clock is before 1970).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The host's offer code: its identity key, a single-use nonce, expiry
/// `now + ttl_secs`, and one host candidate (Phase 3: loopback). The ICE
/// fields are random filler until Phase 5 uses them.
pub fn offer_code(
    addr: SocketAddr,
    identity: &IdentityPublic,
    nonce: [u8; 16],
    now: u64,
    ttl_secs: u64,
) -> String {
    let _ = (
        addr,
        identity,
        nonce,
        now,
        ttl_secs,
        Candidate {
            kind: CandidateKind::Host,
            addr,
        },
        CodeKind::Offer,
    );
    let _: Option<ConnectionCode> = None;
    todo!()
}
