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
    let s = sas.to_string(); // always six digits
    format!("{} {}", &s[..3], &s[3..])
}

/// An identity key as 64 lowercase hex digits.
pub fn identity_hex(key: &IdentityPublic) -> String {
    key.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses 64 hex digits (either case) into an identity key.
pub fn parse_identity(text: &str) -> Result<IdentityPublic, CliError> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(CliError::BadIdentity);
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        let pair =
            std::str::from_utf8(&bytes[2 * i..2 * i + 2]).map_err(|_| CliError::BadIdentity)?;
        *b = u8::from_str_radix(pair, 16).map_err(|_| CliError::BadIdentity)?;
    }
    Ok(IdentityPublic::from_bytes(key))
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
    use rand_core::RngCore;
    let mut ice_ufrag = [0u8; 4];
    let mut ice_pwd = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut ice_ufrag);
    rand_core::OsRng.fill_bytes(&mut ice_pwd);
    ConnectionCode {
        kind: CodeKind::Offer,
        expires_at: u32::try_from(now.saturating_add(ttl_secs)).unwrap_or(u32::MAX),
        nonce,
        identity_key: *identity.as_bytes(),
        ice_ufrag,
        ice_pwd,
        candidates: vec![Candidate {
            kind: CandidateKind::Host,
            addr,
        }],
    }
    .encode()
}
