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
/// Above this many tracked IPs, stale windows are swept out.
const MAX_TRACKED_IPS: usize = 1024;

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
        let window = self.per_ip.entry(ip).or_default();
        // Forget connections older than the window (the window slides).
        while window
            .front()
            .is_some_and(|&t| now.0.saturating_sub(t.0) >= IP_WINDOW_MS)
        {
            window.pop_front();
        }
        if window.len() >= PER_IP_PER_MINUTE {
            return Err(Refusal::IpRateLimited);
        }
        if self.pending >= MAX_PENDING {
            return Err(Refusal::TooManyPending);
        }
        window.push_back(now);
        self.pending += 1;
        if self.per_ip.len() > MAX_TRACKED_IPS {
            self.sweep(now);
        }
        Ok(())
    }

    /// A pending handshake ended (any outcome).
    pub fn release(&mut self) {
        self.pending = self.pending.saturating_sub(1);
    }

    /// Drops per-IP windows with no connection inside the window, so the map
    /// only holds IPs seen in the last minute.
    fn sweep(&mut self, now: Millis) {
        self.per_ip.retain(|_, w| {
            w.back()
                .is_some_and(|&t| now.0.saturating_sub(t.0) < IP_WINDOW_MS)
        });
    }

    /// May a password-mode attempt start now?
    pub fn check_password_attempt(&self, now: Millis) -> Result<(), Refusal> {
        match self.cooldown_until {
            Some(until) if now < until => Err(Refusal::CoolingDown { until }),
            _ => Ok(()),
        }
    }

    /// Counts one failed password attempt against the current password.
    pub fn record_failure(&mut self, now: Millis) -> FailureOutcome {
        self.failures += 1;
        let attempt = self.failures;
        if attempt < ATTEMPTS_PER_OTP {
            return FailureOutcome {
                attempt,
                rotate: false,
                cooldown_until: None,
            };
        }
        // 30 s · 2^rotations, capped at 1 h (checked_shl: no overflow panic).
        let cooldown = 1u64
            .checked_shl(self.rotations)
            .and_then(|m| COOLDOWN_START_MS.checked_mul(m))
            .map_or(COOLDOWN_MAX_MS, |d| d.min(COOLDOWN_MAX_MS));
        self.rotations = self.rotations.saturating_add(1);
        self.failures = 0;
        let until = now.plus(cooldown);
        self.cooldown_until = Some(until);
        FailureOutcome {
            attempt,
            rotate: true,
            cooldown_until: Some(until),
        }
    }

    /// Handshakes currently counted as pending.
    pub fn pending(&self) -> usize {
        self.pending
    }

    /// Source IPs with a per-IP window held in memory (bounded: stale
    /// windows are swept once more than 1024 are held).
    pub fn tracked_ips(&self) -> usize {
        self.per_ip.len()
    }

    /// Failures counted against the current password.
    pub fn failures(&self) -> u32 {
        self.failures
    }
}
