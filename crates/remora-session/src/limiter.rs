//! Attempt limiter (phase3-criteria A02, A03; threat model §6.1, INV12).
//!
//! * **Pending cap:** at most [`MAX_PENDING`] handshakes at once; more are
//!   refused before any crypto runs.
//! * **Per source IP:** at most [`PER_IP_PER_MINUTE`] connections in any
//!   60-second window.
//! * **Per one-time password, globally:** [`ATTEMPTS_PER_OTP`] failed
//!   password attempts — across all connections — rotate the password (the
//!   old one is then useless even if guessed right) and start a cool-down of
//!   [`COOLDOWN_START_MS`], doubling on every further rotation up to
//!   [`COOLDOWN_MAX_MS`]. Password-mode attempts during a cool-down are
//!   refused.
//!
//! Pure bookkeeping: no clock, no randomness — the [`crate::Host`] passes
//! the time in and generates the new password.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::Millis;

/// Handshakes that may be in progress at once.
pub const MAX_PENDING: usize = 4;
/// Connections per source IP per minute.
pub const PER_IP_PER_MINUTE: usize = 10;
/// Failed password attempts before the password rotates.
pub const ATTEMPTS_PER_OTP: u32 = 3;
/// First cool-down after a rotation.
pub const COOLDOWN_START_MS: u64 = 30_000;
/// Longest cool-down.
pub const COOLDOWN_MAX_MS: u64 = 3_600_000;
/// Length of the per-IP window.
pub const IP_WINDOW_MS: u64 = 60_000;

/// Why an admission or attempt was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// [`MAX_PENDING`] handshakes already in progress.
    TooManyPending,
    /// This IP made [`PER_IP_PER_MINUTE`] connections in the last minute.
    IpRateLimited,
    /// Password attempts are paused until this time.
    CoolingDown {
        /// When attempts are allowed again.
        until: Millis,
    },
}

/// What a failed password attempt led to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureOutcome {
    /// Failures counted against the current password, 1-based (`n/3`).
    pub attempt: u32,
    /// This failure was the last one: the password must rotate now.
    pub rotate: bool,
    /// Set when `rotate`: password attempts are refused until then.
    pub cooldown_until: Option<Millis>,
}

/// The limiter's state.
#[derive(Debug, Default)]
pub struct Limiter {
    pub(crate) pending: usize,
    pub(crate) failures: u32,
    pub(crate) rotations: u32,
    pub(crate) cooldown_until: Option<Millis>,
    pub(crate) per_ip: HashMap<IpAddr, VecDeque<Millis>>,
}

impl Limiter {
    /// Empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// A new connection from `ip`: checks the pending cap and the per-IP
    /// window, and on success counts it as pending.
    pub fn admit(&mut self, ip: IpAddr, now: Millis) -> Result<(), Refusal> {
        let _ = (ip, now);
        todo!()
    }

    /// A pending handshake ended (any outcome).
    pub fn release(&mut self) {
        todo!()
    }

    /// May a password-mode attempt start now?
    pub fn check_password_attempt(&self, now: Millis) -> Result<(), Refusal> {
        let _ = now;
        todo!()
    }

    /// Counts one failed password attempt against the current password.
    pub fn record_failure(&mut self, now: Millis) -> FailureOutcome {
        let _ = now;
        todo!()
    }

    /// Handshakes currently counted as pending.
    pub fn pending(&self) -> usize {
        self.pending
    }

    /// Failures counted against the current password.
    pub fn failures(&self) -> u32 {
        self.failures
    }
}
