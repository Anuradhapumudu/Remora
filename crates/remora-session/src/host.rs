//! The host: admission, every host-side session, the approval gate.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use rand_core::{CryptoRng, RngCore};
use remora_crypto::identity::{DeviceId, IdentityCert, IdentityPublic};
use remora_crypto::noise::{Established, HostAwaitMsg1, HostAwaitMsg3, NoiseStaticKeypair};
use remora_crypto::pake::Spake2Ed25519;
use remora_crypto::sas::Sas;
use remora_crypto::secret::{Exporter, Otp};

use crate::limiter::Limiter;
use crate::{AppMessage, FailReason, Millis, State, Step};

/// A device's long-term identity: its Noise static key and the cert that
/// binds it to its Ed25519 identity key.
#[derive(Debug)]
pub struct Identity {
    /// Noise static key pair.
    pub noise: NoiseStaticKeypair,
    /// Cert for `noise`, signed by the device's identity key.
    pub cert: IdentityCert,
}

/// Random, non-secret identifier of one host-side session (for logs and for
/// binding an approval to exactly one prompt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

/// Host configuration.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// This host's identity.
    pub identity: Arc<Identity>,
    /// Accept password-mode connections (one-time password).
    pub password_enabled: bool,
    /// Viewer identity keys allowed to use trusted (password-less) mode.
    pub trusted: Vec<IdentityPublic>,
}

/// A connection refused at admission, before any crypto (A03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused(pub crate::limiter::Refusal);

/// Why an approval was not applied. The session's state is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApproveError {
    /// No such session.
    #[error("no such session")]
    UnknownSession,
    /// The session is not waiting for approval (A23).
    #[error("session is not pending approval")]
    NotPending,
    /// The safety code given does not match this session's (A22).
    #[error("safety code does not match this session")]
    SasMismatch,
}

/// What the host must do.
#[derive(Debug, Clone, PartialEq)]
pub enum HostAction {
    /// Send one frame (net adds the length prefix).
    Send {
        /// Session.
        id: SessionId,
        /// Frame payload.
        frame: Vec<u8>,
    },
    /// Close the connection with this code and an empty reason phrase.
    Close {
        /// Session.
        id: SessionId,
        /// Wire code.
        code: crate::CloseCode,
    },
    /// Show the accept/deny prompt with this safety code.
    Prompt {
        /// Session (pass it back to [`Host::approve`]).
        id: SessionId,
        /// The code to show; [`Host::approve`] must be given the same one.
        sas: Sas,
        /// The viewer's self-chosen device name (untrusted text).
        viewer_name: String,
        /// The viewer's identity key.
        viewer_key: IdentityPublic,
    },
    /// The prompt for this session is no longer valid (closed or timed out).
    PromptClosed {
        /// Session.
        id: SessionId,
    },
    /// The session became active: show the "session active" indicator.
    Active {
        /// Session.
        id: SessionId,
    },
    /// Deliver an application message (Active only).
    Deliver {
        /// Session.
        id: SessionId,
        /// The message.
        msg: AppMessage,
    },
    /// A handshake failed: log exactly one `handshake_failed` WARN event.
    Failed {
        /// Session.
        id: SessionId,
        /// Precise local reason.
        reason: FailReason,
        /// Where it failed.
        step: Step,
        /// Password attempt number counted for it (`n/3`), if any.
        attempt: Option<u32>,
    },
    /// Three failed attempts: a new password is in effect; tell the user
    /// ("3 failed attempts — new password") and show [`Host::otp`].
    OtpRotated {
        /// Password attempts are refused until then.
        cooldown_until: Millis,
    },
}

/// One host-side session's private state.
pub(crate) enum HostSessionState {
    Hello,
    Spake {
        vh: Vec<u8>,
        hh: Vec<u8>,
        pake: Spake2Ed25519,
    },
    Msg1(HostAwaitMsg1),
    Msg3(HostAwaitMsg3),
    Pending {
        est: Established,
        prompt_deadline: Millis,
    },
    Active(Established),
    Closed,
}

pub(crate) struct HostSession {
    pub(crate) state: HostSessionState,
    pub(crate) exporter: Exporter,
    pub(crate) deadline: Millis,
    pub(crate) password_mode: bool,
    pub(crate) holds_pending_slot: bool,
}

/// The host side of Remora: admission, sessions, approvals.
pub struct Host {
    pub(crate) config: HostConfig,
    pub(crate) device_id: DeviceId,
    pub(crate) otp: Otp,
    pub(crate) limiter: Limiter,
    pub(crate) sessions: HashMap<SessionId, HostSession>,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field("sessions", &self.sessions.len())
            .field("pending", &self.limiter.pending())
            .finish_non_exhaustive()
    }
}

impl Host {
    /// A host with a freshly generated one-time password.
    pub fn new<R: RngCore + CryptoRng>(config: HostConfig, rng: &mut R) -> Self {
        let _ = (config, rng);
        todo!()
    }

    /// The current one-time password (for the host's screen only).
    pub fn otp(&self) -> &Otp {
        &self.otp
    }

    /// The limiter (read-only, for the UI and tests).
    pub fn limiter(&self) -> &Limiter {
        &self.limiter
    }

    /// A QUIC connection from `peer_ip` completed its TLS handshake. Applies
    /// the pending cap and per-IP limit **before any crypto**; on success
    /// the new session waits for `ViewerHello`.
    pub fn accept_connection<R: RngCore + CryptoRng>(
        &mut self,
        peer_ip: IpAddr,
        exporter: Exporter,
        now: Millis,
        rng: &mut R,
    ) -> Result<SessionId, Refused> {
        let _ = (peer_ip, exporter, now, rng);
        todo!()
    }

    /// A frame arrived on session `id`'s reliable stream.
    pub fn on_frame<R: RngCore + CryptoRng>(
        &mut self,
        id: SessionId,
        frame: &[u8],
        now: Millis,
        rng: &mut R,
    ) -> Vec<HostAction> {
        let _ = (id, frame, now, rng);
        todo!()
    }

    /// A datagram arrived on session `id`. Before `Active` it closes the
    /// session; in Phase 3 an active session drops it (no media path yet).
    pub fn on_datagram(&mut self, id: SessionId, datagram: &[u8]) -> Vec<HostAction> {
        let _ = (id, datagram);
        todo!()
    }

    /// The clock advanced: handshake deadlines (10 s) and prompt deadlines
    /// (60 s) of every session.
    pub fn tick(&mut self, now: Millis) -> Vec<HostAction> {
        let _ = now;
        todo!()
    }

    /// The host user pressed "accept" on the prompt for `id` showing `sas`.
    /// Applies only if that session is pending approval **and** its safety
    /// code is `sas` (A22, A23).
    pub fn approve(&mut self, id: SessionId, sas: Sas) -> Result<Vec<HostAction>, ApproveError> {
        let _ = (id, sas);
        todo!()
    }

    /// The host user pressed "deny".
    pub fn deny(&mut self, id: SessionId) -> Vec<HostAction> {
        let _ = id;
        todo!()
    }

    /// One-click disconnect from any state (INV11).
    pub fn disconnect(&mut self, id: SessionId) -> Vec<HostAction> {
        let _ = id;
        todo!()
    }

    /// The state of session `id`, if it exists.
    pub fn state(&self, id: SessionId) -> Option<State> {
        let _ = id;
        todo!()
    }

    /// Sessions currently `Active` (for the always-visible indicator).
    pub fn active_sessions(&self) -> Vec<SessionId> {
        todo!()
    }
}
