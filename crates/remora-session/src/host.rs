//! The host: admission, every host-side session, the approval gate.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use prost::Message;
use rand_core::{CryptoRng, RngCore};
use remora_crypto::identity::{DeviceId, IdentityCert, IdentityPublic};
use remora_crypto::keyschedule::{derive_psk, prologue, transcript_hash};
use remora_crypto::noise::{
    Established, HandshakeMode, HostAwaitMsg1, HostAwaitMsg3, NoiseStaticKeypair, PeerPolicy,
    host_start,
};
use remora_crypto::otp::generate_otp;
use remora_crypto::pake::{Pake, PakeContext, PakeMessage, PakeRole, Spake2Ed25519};
use remora_crypto::sas::Sas;
use remora_crypto::secret::{Exporter, Otp};

use remora_proto::messages::{
    Control, Envelope, Goodbye, HostHello, Mode, SasReveal, SessionAccept, SessionPending,
    SessionReject, control, decode_envelope, decode_viewer_hello, envelope,
};

use crate::fail::{AuthDetail, Violation};
use crate::limiter::Limiter;
use crate::{
    AppMessage, CloseCode, FailReason, HANDSHAKE_TIMEOUT_MS, Millis, PROMPT_TIMEOUT_MS,
    PROTOCOL_VERSION, State, Step,
};

/// `SessionReject.reason` values (protocol.md §3.4).
const REJECT_DENIED: u32 = 1;
const REJECT_TIMEOUT: u32 = 2;
/// `SessionAccept.role`: owner (protocol.md §5).
const ROLE_OWNER: u32 = 1;

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
    /// The one-time password was used: a viewer proved it (Noise msg1
    /// authenticated), so it is consumed and a new one is already in effect
    /// — show [`Host::otp`] (INV15). Emitted once per password-mode session.
    OtpUsed {
        /// The session that used it.
        id: SessionId,
    },
    /// Three failed attempts: a new password is in effect; tell the user
    /// ("3 failed attempts — new password") and show [`Host::otp`].
    OtpRotated {
        /// Password attempts are refused until then.
        cooldown_until: Millis,
    },
}

/// One host-side session's private state.
#[allow(
    clippy::large_enum_variant,
    reason = "one state per connection and at most a few connections; boxing only adds allocations"
)]
pub(crate) enum HostSessionState {
    Hello,
    Spake {
        vh: Vec<u8>,
        hh: Vec<u8>,
        pake: Spake2Ed25519,
        spake_b: PakeMessage,
    },
    Msg1(HostAwaitMsg1),
    Msg3(HostAwaitMsg3),
    Pending {
        est: Established,
        sas: Sas,
        prompt_deadline: Millis,
    },
    Active(Established),
    Closed,
}

impl HostSessionState {
    fn public(&self) -> State {
        match self {
            HostSessionState::Hello => State::Hello,
            HostSessionState::Spake { .. } => State::Spake,
            HostSessionState::Msg1(_) | HostSessionState::Msg3(_) => State::Noise,
            HostSessionState::Pending { .. } => State::PendingApproval,
            HostSessionState::Active(_) => State::Active,
            HostSessionState::Closed => State::Closed,
        }
    }

    fn step(&self) -> Step {
        match self {
            HostSessionState::Hello => Step::Hello,
            HostSessionState::Spake { .. } => Step::Spake,
            HostSessionState::Msg1(_) => Step::NoiseMsg1,
            HostSessionState::Msg3(_) => Step::NoiseMsg3,
            HostSessionState::Pending { .. } => Step::Approval,
            HostSessionState::Active(_) | HostSessionState::Closed => Step::Active,
        }
    }
}

pub(crate) struct HostSession {
    pub(crate) state: HostSessionState,
    pub(crate) exporter: Exporter,
    pub(crate) deadline: Millis,
    pub(crate) password_mode: bool,
    pub(crate) holds_pending_slot: bool,
    pub(crate) policy: PeerPolicy,
}

/// The host side of Remora: admission, sessions, approvals.
pub struct Host {
    pub(crate) config: HostConfig,
    pub(crate) device_id: DeviceId,
    pub(crate) otp: Otp,
    pub(crate) limiter: Limiter,
    pub(crate) sessions: HashMap<SessionId, HostSession>,
    /// Issued connection-code nonces, oldest first (A06).
    pub(crate) nonces: VecDeque<IssuedNonce>,
}

/// One nonce the host put in an offer code.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IssuedNonce {
    pub(crate) nonce: [u8; 16],
    pub(crate) expires: Millis,
    pub(crate) used: bool,
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
        let device_id = DeviceId::of(config.identity.cert.identity());
        Self {
            config,
            device_id,
            otp: generate_otp(rng),
            limiter: Limiter::new(),
            sessions: HashMap::new(),
            nonces: VecDeque::new(),
        }
    }

    /// The current one-time password (for the host's screen only).
    pub fn otp(&self) -> &Otp {
        &self.otp
    }

    /// Registers the nonce of a connection code this host just issued (an
    /// offer code). A `ViewerHello` must carry an issued, unused, unexpired
    /// nonce; each nonce authenticates at most one connection (A06).
    pub fn issue_nonce(&mut self, nonce: [u8; 16], expires: Millis) {
        self.nonces.push_back(IssuedNonce {
            nonce,
            expires,
            used: false,
        });
        while self.nonces.len() > crate::MAX_OUTSTANDING_NONCES {
            self.nonces.pop_front();
        }
    }

    /// Issued nonces still held in memory (used ones are kept until they
    /// expire, so a replay is recognised as such).
    pub fn outstanding_nonces(&self) -> usize {
        self.nonces.len()
    }

    /// Checks and consumes the hello's nonce (A06): issued, unexpired,
    /// unused. Called before SPAKE2 starts.
    fn take_nonce(&mut self, nonce: &[u8; 16], now: Millis) -> Result<(), FailReason> {
        let entry = self
            .nonces
            .iter_mut()
            .find(|n| n.nonce == *nonce)
            .ok_or(FailReason::AuthFailed(AuthDetail::UnknownNonce))?;
        if now >= entry.expires {
            return Err(FailReason::Expired);
        }
        if entry.used {
            return Err(FailReason::NonceReused);
        }
        entry.used = true;
        Ok(())
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
        self.limiter.admit(peer_ip, now).map_err(Refused)?;
        let mut id = SessionId(rng.next_u64());
        while self.sessions.contains_key(&id) {
            id = SessionId(rng.next_u64());
        }
        self.sessions.insert(
            id,
            HostSession {
                state: HostSessionState::Hello,
                exporter,
                deadline: now.plus(HANDSHAKE_TIMEOUT_MS),
                password_mode: false,
                holds_pending_slot: true,
                policy: PeerPolicy::AnyKey,
            },
        );
        Ok(id)
    }

    /// A frame arrived on session `id`'s reliable stream.
    pub fn on_frame<R: RngCore + CryptoRng>(
        &mut self,
        id: SessionId,
        frame: &[u8],
        now: Millis,
        rng: &mut R,
    ) -> Vec<HostAction> {
        let Some(sess) = self.sessions.get_mut(&id) else {
            return Vec::new();
        };
        let state = std::mem::replace(&mut sess.state, HostSessionState::Closed);
        let step = state.step();
        let mut out = Vec::new();
        let result = match state {
            HostSessionState::Closed => return Vec::new(),
            HostSessionState::Hello => self.on_hello(id, frame, now, rng, &mut out),
            HostSessionState::Spake {
                vh,
                hh,
                pake,
                spake_b,
            } => self.on_spake(id, frame, vh, hh, pake, spake_b, &mut out),
            HostSessionState::Msg1(hs) => self.on_msg1(id, frame, hs, rng, &mut out),
            HostSessionState::Msg3(hs) => self.on_msg3(id, frame, hs, now, &mut out),
            HostSessionState::Pending { est, .. } => Self::on_pending(frame, est),
            HostSessionState::Active(est) => self.on_active(id, frame, est, &mut out),
        };
        match result {
            Ok(next) => {
                if let Some(sess) = self.sessions.get_mut(&id) {
                    sess.state = next;
                }
            }
            Err(Ending::Failed(reason, counts)) => {
                let attempt = if counts {
                    Some(self.count_attempt(now, rng, &mut out))
                } else {
                    None
                };
                // A failure while the prompt is open also withdraws the prompt.
                self.fail(id, reason, step, attempt, step == Step::Approval, &mut out);
            }
            Err(Ending::Normal { prompt_open }) => {
                self.close(id, CloseCode::Normal, prompt_open, &mut out)
            }
        }
        out
    }

    /// A datagram arrived on session `id`. Before `Active` it closes the
    /// session; in Phase 3 an active session drops it (no media path yet).
    pub fn on_datagram(&mut self, id: SessionId, datagram: &[u8]) -> Vec<HostAction> {
        let _ = datagram;
        let mut out = Vec::new();
        match self
            .sessions
            .get(&id)
            .map(|s| (s.state.public(), s.state.step()))
        {
            None | Some((State::Closed, _)) | Some((State::Active, _)) => {}
            Some((st, step)) => self.fail(
                id,
                FailReason::ProtocolViolation(Violation::DatagramBeforeActive),
                step,
                None,
                st == State::PendingApproval,
                &mut out,
            ),
        }
        out
    }

    /// The clock advanced: handshake deadlines (10 s) and prompt deadlines
    /// (60 s) of every session.
    pub fn tick(&mut self, now: Millis) -> Vec<HostAction> {
        let mut out = Vec::new();
        // Expired nonces are forgotten; a replay of one is then simply unknown.
        self.nonces.retain(|n| now < n.expires);
        let mut ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        ids.sort();
        for id in ids {
            let Some(sess) = self.sessions.get_mut(&id) else {
                continue;
            };
            match &mut sess.state {
                HostSessionState::Closed | HostSessionState::Active(_) => {}
                HostSessionState::Pending {
                    est,
                    prompt_deadline,
                    ..
                } => {
                    if now >= *prompt_deadline {
                        if let Ok(frame) =
                            est.encrypt(&control_env(control::Kind::Reject(SessionReject {
                                reason: REJECT_TIMEOUT,
                            })))
                        {
                            out.push(HostAction::Send { id, frame });
                        }
                        self.fail(
                            id,
                            FailReason::Rejected,
                            Step::Approval,
                            None,
                            true,
                            &mut out,
                        );
                    }
                }
                state => {
                    if now >= sess.deadline {
                        let step = state.step();
                        self.fail(id, FailReason::Timeout, step, None, false, &mut out);
                    }
                }
            }
        }
        out
    }

    /// The host user pressed "accept" on the prompt for `id` showing `sas`.
    /// Applies only if that session is pending approval **and** its safety
    /// code is `sas` (A22, A23).
    pub fn approve(&mut self, id: SessionId, sas: Sas) -> Result<Vec<HostAction>, ApproveError> {
        let sess = self
            .sessions
            .get_mut(&id)
            .ok_or(ApproveError::UnknownSession)?;
        let HostSessionState::Pending { sas: shown, .. } = &sess.state else {
            return Err(ApproveError::NotPending);
        };
        if *shown != sas {
            return Err(ApproveError::SasMismatch);
        }
        let state = std::mem::replace(&mut sess.state, HostSessionState::Closed);
        let HostSessionState::Pending { mut est, .. } = state else {
            return Err(ApproveError::NotPending);
        };
        let mut out = Vec::new();
        match est.encrypt(&control_env(control::Kind::Accept(SessionAccept {
            role: ROLE_OWNER,
        }))) {
            Ok(frame) => {
                out.push(HostAction::Send { id, frame });
                sess.state = HostSessionState::Active(est);
                if sess.holds_pending_slot {
                    sess.holds_pending_slot = false;
                    self.limiter.release();
                }
                out.push(HostAction::Active { id });
            }
            Err(_) => self.fail(
                id,
                FailReason::AuthFailed(AuthDetail::Handshake(
                    remora_crypto::noise::HandshakeError::Internal,
                )),
                Step::Approval,
                None,
                true,
                &mut out,
            ),
        }
        Ok(out)
    }

    /// The host user pressed "deny".
    pub fn deny(&mut self, id: SessionId) -> Vec<HostAction> {
        let mut out = Vec::new();
        if let Some(HostSession {
            state: HostSessionState::Pending { est, .. },
            ..
        }) = self.sessions.get_mut(&id)
        {
            if let Ok(frame) = est.encrypt(&control_env(control::Kind::Reject(SessionReject {
                reason: REJECT_DENIED,
            }))) {
                out.push(HostAction::Send { id, frame });
            }
            self.close(id, CloseCode::Rejected, true, &mut out);
        }
        out
    }

    /// One-click disconnect from any state (INV11).
    pub fn disconnect(&mut self, id: SessionId) -> Vec<HostAction> {
        let mut out = Vec::new();
        let Some(sess) = self.sessions.get_mut(&id) else {
            return out;
        };
        let prompt_open = matches!(sess.state, HostSessionState::Pending { .. });
        match &mut sess.state {
            HostSessionState::Closed => return out,
            HostSessionState::Pending { est, .. } | HostSessionState::Active(est) => {
                if let Ok(frame) = est.encrypt(&control_env(control::Kind::Bye(Goodbye {}))) {
                    out.push(HostAction::Send { id, frame });
                }
            }
            _ => {}
        }
        self.close(id, CloseCode::Normal, prompt_open, &mut out);
        out
    }

    /// The transport could not frame the stream (bad length prefix,
    /// oversized frame): the session ends as a protocol violation.
    pub fn framing_error(&mut self, id: SessionId) -> Vec<HostAction> {
        let mut out = Vec::new();
        let Some(sess) = self.sessions.get(&id) else {
            return out;
        };
        if matches!(sess.state, HostSessionState::Closed) {
            return out;
        }
        let step = sess.state.step();
        let prompt_open = matches!(sess.state, HostSessionState::Pending { .. });
        self.fail(
            id,
            FailReason::ProtocolViolation(Violation::Framing),
            step,
            None,
            prompt_open,
            &mut out,
        );
        out
    }

    /// The state of session `id`, if it exists.
    pub fn state(&self, id: SessionId) -> Option<State> {
        self.sessions.get(&id).map(|s| s.state.public())
    }

    /// Sessions currently `Active` (for the always-visible indicator).
    pub fn active_sessions(&self) -> Vec<SessionId> {
        let mut v: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, s)| matches!(s.state, HostSessionState::Active(_)))
            .map(|(id, _)| *id)
            .collect();
        v.sort();
        v
    }

    /// Forgets a closed session entirely (call once its connection is gone,
    /// so closed sessions do not accumulate). No effect on a live session.
    pub fn forget(&mut self, id: SessionId) {
        if matches!(
            self.sessions.get(&id).map(|s| &s.state),
            Some(HostSessionState::Closed)
        ) {
            self.sessions.remove(&id);
        }
    }

    // ------------------------------------------------------------ steps --

    fn on_hello<R: RngCore + CryptoRng>(
        &mut self,
        id: SessionId,
        frame: &[u8],
        now: Millis,
        rng: &mut R,
        out: &mut Vec<HostAction>,
    ) -> Result<HostSessionState, Ending> {
        let hello = decode_viewer_hello(frame)
            .map_err(|e| fail(FailReason::ProtocolViolation(Violation::Malformed(e))))?;
        if !hello.versions.contains(&PROTOCOL_VERSION) {
            return Err(fail(FailReason::VersionUnsupported));
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&hello.nonce); // length validated by decode_viewer_hello
        self.take_nonce(&nonce, now).map_err(fail)?;
        let hh = HostHello {
            version: PROTOCOL_VERSION,
            host_device_id: self.device_id.as_bytes().to_vec(),
        }
        .encode_to_vec();
        let vh = frame.to_vec();
        let Some(sess) = self.sessions.get_mut(&id) else {
            return Err(fail(FailReason::Timeout));
        };
        if hello.mode == Mode::Password as i32 {
            if !self.config.password_enabled {
                return Err(fail(FailReason::AuthFailed(AuthDetail::ModeUnavailable)));
            }
            self.limiter
                .check_password_attempt(now)
                .map_err(|_| fail(FailReason::RateLimited))?;
            sess.password_mode = true;
            sess.policy = PeerPolicy::AnyKey;
            let ctx = PakeContext {
                host_device_id: self.device_id,
                nonce,
            };
            let (pake, spake_b) = Spake2Ed25519::start(PakeRole::Host, &self.otp, &ctx, rng);
            out.push(HostAction::Send {
                id,
                frame: hh.clone(),
            });
            Ok(HostSessionState::Spake {
                vh,
                hh,
                pake,
                spake_b,
            })
        } else {
            if self.config.trusted.is_empty() {
                return Err(fail(FailReason::AuthFailed(AuthDetail::ModeUnavailable)));
            }
            sess.policy = PeerPolicy::TrustedSet(self.config.trusted.clone());
            let pro = prologue(&sess.exporter, &vh, &hh);
            let hs = host_start(HandshakeMode::Trusted, &pro, &self.config.identity.noise)
                .map_err(|e| fail(FailReason::from_handshake(e)))?;
            out.push(HostAction::Send { id, frame: hh });
            Ok(HostSessionState::Msg1(hs))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_spake(
        &mut self,
        id: SessionId,
        frame: &[u8],
        vh: Vec<u8>,
        hh: Vec<u8>,
        pake: Spake2Ed25519,
        spake_b: PakeMessage,
        out: &mut Vec<HostAction>,
    ) -> Result<HostSessionState, Ending> {
        let spake_a = PakeMessage::from_bytes(frame).map_err(|e| fail(FailReason::from_pake(e)))?;
        // A bad element is an attempt against the password: counted.
        let k = pake
            .finish(&spake_a)
            .map_err(|e| Ending::Failed(FailReason::from_pake(e), true))?;
        let exporter = self.exporter(id)?;
        let t = transcript_hash(&vh, &hh, &spake_a, &spake_b);
        let psk = derive_psk(&exporter, &k, &t);
        let pro = prologue(&exporter, &vh, &hh);
        let hs = host_start(
            HandshakeMode::Password(&psk),
            &pro,
            &self.config.identity.noise,
        )
        .map_err(|e| fail(FailReason::from_handshake(e)))?;
        out.push(HostAction::Send {
            id,
            frame: spake_b.as_bytes().to_vec(),
        });
        Ok(HostSessionState::Msg1(hs))
    }

    fn on_msg1<R: RngCore + CryptoRng>(
        &mut self,
        id: SessionId,
        frame: &[u8],
        hs: HostAwaitMsg1,
        rng: &mut R,
        out: &mut Vec<HostAction>,
    ) -> Result<HostSessionState, Ending> {
        let password_mode = self.sessions.get(&id).is_some_and(|s| s.password_mode);
        let hs = hs.read_msg1(frame, rng).map_err(|e| {
            // A msg1 that fails to authenticate in password mode is a wrong
            // (or tampered) password: one attempt (A01, INV3).
            let counts = password_mode && e == remora_crypto::noise::HandshakeError::Msg1Auth;
            Ending::Failed(FailReason::from_handshake(e), counts)
        })?;
        if password_mode {
            // INV15: the viewer just proved the one-time password, so it is
            // used up now - before this session goes on, whatever happens to
            // it later - and can never authenticate a second session.
            self.otp = generate_otp(rng);
            self.limiter.password_used();
            out.push(HostAction::OtpUsed { id });
        }
        let (hs, msg2) = hs
            .write_msg2(&self.config.identity.cert)
            .map_err(|e| fail(FailReason::from_handshake(e)))?;
        out.push(HostAction::Send { id, frame: msg2 });
        Ok(HostSessionState::Msg3(hs))
    }

    fn on_msg3(
        &mut self,
        id: SessionId,
        frame: &[u8],
        hs: HostAwaitMsg3,
        now: Millis,
        out: &mut Vec<HostAction>,
    ) -> Result<HostSessionState, Ending> {
        let policy = self
            .sessions
            .get(&id)
            .map(|s| s.policy.clone())
            .unwrap_or(PeerPolicy::AnyKey);
        let got = hs
            .read_msg3(frame, &policy)
            .map_err(|e| fail(FailReason::from_handshake(e)))?;
        let viewer = got.peer_cert().clone();
        let (mut est, n_r) = got.reveal();
        let internal = || {
            fail(FailReason::from_handshake(
                remora_crypto::noise::HandshakeError::Internal,
            ))
        };
        let reveal = est
            .encrypt(&control_env(control::Kind::SasReveal(SasReveal {
                n_r: n_r.to_vec(),
            })))
            .map_err(|_| internal())?;
        let pending = est
            .encrypt(&control_env(control::Kind::Pending(SessionPending {})))
            .map_err(|_| internal())?;
        out.push(HostAction::Send { id, frame: reveal });
        out.push(HostAction::Send { id, frame: pending });
        let sas = est.sas();
        out.push(HostAction::Prompt {
            id,
            sas,
            viewer_name: viewer.device_name().to_owned(),
            viewer_key: *viewer.identity(),
        });
        Ok(HostSessionState::Pending {
            est,
            sas,
            prompt_deadline: now.plus(PROMPT_TIMEOUT_MS),
        })
    }

    /// While the prompt is open the viewer may only say `Goodbye`; anything
    /// else — input above all — closes the session (A20, A21).
    fn on_pending(frame: &[u8], mut est: Established) -> Result<HostSessionState, Ending> {
        let env = decrypt_envelope(&mut est, frame).map_err(fail)?;
        match env.msg {
            Some(envelope::Msg::Control(Control {
                kind: Some(control::Kind::Bye(_)),
            })) => Err(Ending::Normal { prompt_open: true }),
            Some(envelope::Msg::Input(_)) => Err(Ending::Failed(
                FailReason::ProtocolViolation(Violation::BeforeActive),
                false,
            )),
            _ => Err(fail(FailReason::ProtocolViolation(Violation::WrongRole))),
        }
    }

    fn on_active(
        &mut self,
        id: SessionId,
        frame: &[u8],
        mut est: Established,
        out: &mut Vec<HostAction>,
    ) -> Result<HostSessionState, Ending> {
        let env = decrypt_envelope(&mut est, frame).map_err(|r| Ending::Failed(r, false))?;
        match env.msg {
            Some(envelope::Msg::Input(input)) => {
                out.push(HostAction::Deliver {
                    id,
                    msg: AppMessage::Input(input),
                });
                Ok(HostSessionState::Active(est))
            }
            Some(envelope::Msg::Control(Control {
                kind: Some(control::Kind::Bye(_)),
            })) => Err(Ending::Normal { prompt_open: false }),
            _ => Err(Ending::Failed(
                FailReason::ProtocolViolation(Violation::WrongRole),
                false,
            )),
        }
    }

    // ---------------------------------------------------------- helpers --

    fn exporter(&self, id: SessionId) -> Result<Exporter, Ending> {
        self.sessions
            .get(&id)
            .map(|s| s.exporter.clone())
            .ok_or_else(|| fail(FailReason::Timeout))
    }

    /// Counts a failed password attempt; rotates the OTP on the third.
    fn count_attempt<R: RngCore + CryptoRng>(
        &mut self,
        now: Millis,
        rng: &mut R,
        out: &mut Vec<HostAction>,
    ) -> u32 {
        let o = self.limiter.record_failure(now);
        if o.rotate {
            self.otp = generate_otp(rng);
            out.push(HostAction::OtpRotated {
                cooldown_until: o.cooldown_until.unwrap_or(now),
            });
        }
        o.attempt
    }

    /// Ends a session with a failure: exactly one `Failed` (for the log),
    /// then `PromptClosed` if a prompt was open, then the close code.
    fn fail(
        &mut self,
        id: SessionId,
        reason: FailReason,
        step: Step,
        attempt: Option<u32>,
        prompt_open: bool,
        out: &mut Vec<HostAction>,
    ) {
        let code = reason.close_code();
        out.push(HostAction::Failed {
            id,
            reason,
            step,
            attempt,
        });
        self.close(id, code, prompt_open, out);
    }

    fn close(
        &mut self,
        id: SessionId,
        code: CloseCode,
        prompt_open: bool,
        out: &mut Vec<HostAction>,
    ) {
        if let Some(sess) = self.sessions.get_mut(&id) {
            sess.state = HostSessionState::Closed;
            if sess.holds_pending_slot {
                sess.holds_pending_slot = false;
                self.limiter.release();
            }
        }
        if prompt_open {
            out.push(HostAction::PromptClosed { id });
        }
        out.push(HostAction::Close { id, code });
    }
}

/// How a step ended a session.
enum Ending {
    /// A failure; `true` if it counts as a password attempt.
    Failed(FailReason, bool),
    /// An orderly `Goodbye`.
    Normal { prompt_open: bool },
}

fn fail(reason: FailReason) -> Ending {
    Ending::Failed(reason, false)
}

fn control_env(kind: control::Kind) -> Vec<u8> {
    Envelope {
        msg: Some(envelope::Msg::Control(Control { kind: Some(kind) })),
    }
    .encode_to_vec()
}

/// Decrypts and decodes one transport frame (fail closed on either).
pub(crate) fn decrypt_envelope(
    est: &mut Established,
    frame: &[u8],
) -> Result<Envelope, FailReason> {
    let plain = est
        .decrypt(frame)
        .map_err(|_| FailReason::ProtocolViolation(Violation::TransportAuth))?;
    decode_envelope(&plain).map_err(|e| FailReason::ProtocolViolation(Violation::Malformed(e)))
}
