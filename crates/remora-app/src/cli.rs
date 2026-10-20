//! Helpers shared by the host and viewer command-line apps.

use std::net::SocketAddr;
use std::path::Path;

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

/// Printed to stderr on **every** run that loads the device key file
/// (walkthrough finding F-UX2): while keys live in a plain file, the person
/// running the app must see that, every time, so the file storage cannot
/// quietly become the shipped behaviour (roadmap D-5: keychain before v0.1).
pub fn key_file_warning(path: &Path) -> String {
    format!(
        "WARNING: this device's identity keys are stored UNENCRYPTED in {} - anyone who can read that file can impersonate this device. \
         Development-stage storage, protected only by file permissions; Remora moves the keys to the OS keychain before v0.1.",
        path.display()
    )
}

/// What happened to the one-time password since it was last shown
/// (walkthrough finding F-UX3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordChange {
    /// Same password as last shown.
    Unchanged,
    /// A viewer proved it, which uses it up (INV15).
    UsedUp,
    /// Replaced after 3 failed attempts (INV12).
    ReplacedAfterFailures,
}

impl PasswordChange {
    /// Classifies a change: `rotated` is whether the host reported a
    /// replacement after failed attempts since the last time it was shown.
    pub fn between(previous: &str, current: &str, rotated: bool) -> Self {
        match (previous == current, rotated) {
            (true, _) => Self::Unchanged,
            (false, true) => Self::ReplacedAfterFailures,
            (false, false) => Self::UsedUp,
        }
    }

    /// The line printed before a new `code:` / `password:` pair, so it is
    /// clear which pair is current and why a new one appeared.
    pub fn note(self) -> &'static str {
        match self {
            Self::Unchanged => {
                "note: new connection code for the next viewer (each code works for one attempt); the password is unchanged"
            }
            Self::UsedUp => {
                "note: the previous code and password were used up when that viewer proved the password - each works for ONE connection. Give the next viewer these new ones:"
            }
            Self::ReplacedAfterFailures => {
                "note: the password was replaced after 3 failed attempts and the old one no longer works. Give the next viewer these new ones:"
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_warning_names_the_file_and_the_risk() {
        let w = key_file_warning(Path::new("/x/host-identity.key"));
        assert!(w.starts_with("WARNING: "), "{w}");
        assert!(w.contains("/x/host-identity.key"), "{w}");
        assert!(w.contains("UNENCRYPTED"), "{w}");
        assert!(w.contains("impersonate"), "{w}");
        assert!(w.contains("keychain"), "{w}");
    }

    #[test]
    fn password_change_is_classified_and_explained() {
        use PasswordChange::*;
        assert_eq!(
            PasswordChange::between("111111", "111111", false),
            Unchanged
        );
        assert_eq!(PasswordChange::between("111111", "111111", true), Unchanged);
        assert_eq!(PasswordChange::between("111111", "222222", false), UsedUp);
        assert_eq!(
            PasswordChange::between("111111", "222222", true),
            ReplacedAfterFailures
        );
        assert!(Unchanged.note().contains("unchanged"));
        assert!(UsedUp.note().contains("used up"));
        assert!(UsedUp.note().contains("ONE connection"));
        assert!(ReplacedAfterFailures.note().contains("3 failed attempts"));
        for c in [Unchanged, UsedUp, ReplacedAfterFailures] {
            assert!(c.note().starts_with("note: "));
        }
    }
}
