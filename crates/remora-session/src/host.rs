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
    SessionReject, StreamState, control, decode_envelope, decode_viewer_hello, envelope,
};

use remora_crypto::media::{MAX_PACKETS_PER_KEY, SealedDatagram};
use remora_proto::limits::VIDEO_FRAGMENT_DATA;
use remora_proto::video::{PacketizeError, packetize};

use crate::fail::{AuthDetail, Violation};
use crate::limiter::Limiter;
use crate::media::{KEYFRAME_REQUEST_INTERVAL_MS, MediaOut, video_header};
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

/// Why [`Host::send_video`] could not send a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendVideoError {
    /// The frame cannot be cut into fragments (empty, or over 8 MiB).
    #[error("frame not sendable: {0}")]
    Frame(PacketizeError),
    /// 2³² frames were sent (about 2 years at 60 fps): the stream must be
    /// restarted.
    #[error("frame ids used up")]
    FrameIdsExhausted,
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
    /// The next encoded frame must be a keyframe: capture came back after
    /// an interruption (the viewer's decoder state is stale), or a new
    /// viewer was approved (it can only start decoding at a keyframe).
    ForceKeyframe,
    /// Send one media datagram on session `id` (Active only). The type can
    /// only be made by sealing (phase4-criteria M2):
    ///
    /// ```compile_fail
    /// use remora_session::{HostAction, SessionId};
    /// let plain = HostAction::Media { id: SessionId(1), datagram: vec![0u8; 64] };
    /// ```
    Media {
        /// Session.
        id: SessionId,
        /// Header ‖ ciphertext ‖ tag, sealed under this session's key.
        datagram: SealedDatagram,
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
        media: MediaOut,
    },
    Active {
        est: Established,
        media: MediaOut,
    },
    Closed,
}

impl HostSessionState {
    fn public(&self) -> State {
        match self {
            HostSessionState::Hello => State::Hello,
            HostSessionState::Spake { .. } => State::Spake,
            HostSessionState::Msg1(_) | HostSessionState::Msg3(_) => State::Noise,
            HostSessionState::Pending { .. } => State::PendingApproval,
            HostSessionState::Active { .. } => State::Active,
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
            HostSessionState::Active { .. } | HostSessionState::Closed => Step::Active,
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
    /// What screen capture is doing (phase4-criteria §7).
    pub(crate) capture: crate::CaptureStatus,
    /// While the captured display is unavailable: when the host gives up
    /// (D-29), so a viewer approved later is told the time actually left.
    pub(crate) pause_deadline: Option<Millis>,
    /// `frame_id` of the next video frame (one stream for all sessions).
    pub(crate) next_frame_id: u32,
    /// Packets per media key before rotation (protocol.md §6: 2³²).
    pub(crate) rotate_after: u64,
    /// When a viewer's keyframe request last forced a keyframe (any
    /// session: the encoder is shared).
    pub(crate) keyframe_requested: Option<Millis>,
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
            capture: crate::CaptureStatus::Running,
            pause_deadline: None,
            next_frame_id: 0,
            rotate_after: MAX_PACKETS_PER_KEY,
            keyframe_requested: None,
        }
    }

    /// Rotates every session's media key after `packets` packets instead
    /// of 2³² (clamped to 1..=2³²). Shorter key lives only, for testing
    /// rotation (phase4-criteria M8); keys still also rotate hourly.
    pub fn set_key_rotation(&mut self, packets: u64) {
        self.rotate_after = packets.clamp(1, MAX_PACKETS_PER_KEY);
    }

    /// Sends one encoded video frame to every `Active` session: cuts it
    /// into fragments ([`VIDEO_FRAGMENT_DATA`] bytes each) and seals each
    /// fragment under each session's own key. Sessions in any other state
    /// get nothing (phase4-criteria M3). New key announcements, if a key
    /// rotated, come first in the returned actions.
    pub fn send_video<R: RngCore + CryptoRng>(
        &mut self,
        keyframe: bool,
        capture_ts_us: u64,
        data: &[u8],
        now: Millis,
        rng: &mut R,
    ) -> Result<Vec<HostAction>, SendVideoError> {
        let frame_id = self.next_frame_id;
        let fragments = packetize(frame_id, capture_ts_us, keyframe, data, VIDEO_FRAGMENT_DATA)
            .map_err(SendVideoError::Frame)?;
        self.next_frame_id = frame_id
            .checked_add(1)
            .ok_or(SendVideoError::FrameIdsExhausted)?;
        let mut out = Vec::new();
        for id in self.active_sessions() {
            let mut datagrams = Vec::with_capacity(fragments.len());
            let mut failed = None;
            if let Some(HostSession {
                state: HostSessionState::Active { est, media },
                ..
            }) = self.sessions.get_mut(&id)
            {
                for f in &fragments {
                    match media.seal(video_header(f.flags), &f.body, self.rotate_after, now, rng) {
                        Ok(datagram) => datagrams.push(HostAction::Media { id, datagram }),
                        Err(_) => {
                            failed = Some(Violation::MediaKey("key ids used up"));
                            break;
                        }
                    }
                }
                for announce in media.take_announcements() {
                    match est.encrypt(&control_env(control::Kind::MediaKey(announce))) {
                        Ok(frame) => out.push(HostAction::Send { id, frame }),
                        Err(_) => failed = Some(Violation::TransportAuth),
                    }
                }
            }
            match failed {
                None => out.extend(datagrams),
                Some(v) => self.fail(
                    id,
                    FailReason::ProtocolViolation(v),
                    Step::Active,
                    None,
                    false,
                    &mut out,
                ),
            }
        }
        Ok(out)
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
            HostSessionState::Msg3(hs) => self.on_msg3(id, frame, hs, now, rng, &mut out),
            HostSessionState::Pending { est, .. } => Self::on_pending(frame, est),
            HostSessionState::Active { est, media } => {
                self.on_active(id, frame, est, media, now, &mut out)
            }
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
                HostSessionState::Closed | HostSessionState::Active { .. } => {}
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
    pub fn approve(
        &mut self,
        id: SessionId,
        sas: Sas,
        now: Millis,
    ) -> Result<Vec<HostAction>, ApproveError> {
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
        if self.capture == crate::CaptureStatus::Stopped {
            // Nothing to stream until the user fixes capture at the host:
            // do not tell the viewer it is active and then cut it off.
            let mut out = Vec::new();
            self.close(id, CloseCode::CaptureStopped, true, &mut out);
            return Ok(out);
        }
        let state = std::mem::replace(&mut sess.state, HostSessionState::Closed);
        let HostSessionState::Pending {
            mut est, mut media, ..
        } = state
        else {
            return Err(ApproveError::NotPending);
        };
        let mut out = Vec::new();
        match est.encrypt(&control_env(control::Kind::Accept(SessionAccept {
            role: ROLE_OWNER,
        }))) {
            Ok(frame) => {
                out.push(HostAction::Send { id, frame });
                // The session's media keys (current and next) follow the
                // accept on the same ordered, encrypted stream.
                for announce in media.take_announcements() {
                    match est.encrypt(&control_env(control::Kind::MediaKey(announce))) {
                        Ok(frame) => out.push(HostAction::Send { id, frame }),
                        Err(_) => {
                            self.fail(
                                id,
                                FailReason::AuthFailed(AuthDetail::Handshake(
                                    remora_crypto::noise::HandshakeError::Internal,
                                )),
                                Step::Approval,
                                None,
                                true,
                                &mut out,
                            );
                            return Ok(out);
                        }
                    }
                }
                let Some(sess) = self.sessions.get_mut(&id) else {
                    return Ok(out);
                };
                sess.state = HostSessionState::Active { est, media };
                if sess.holds_pending_slot {
                    sess.holds_pending_slot = false;
                    self.limiter.release();
                }
                out.push(HostAction::Active { id });
                // A new viewer can only start decoding at a keyframe.
                out.push(HostAction::ForceKeyframe);
                // Approved while capture is paused: say so at once.
                if let crate::CaptureStatus::Interrupted(reason) = self.capture {
                    let left = self.pause_remaining(now).unwrap_or(0);
                    self.send_stream_state(id, true, reason.wire(), left, &mut out);
                }
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
            HostSessionState::Pending { est, .. } | HostSessionState::Active { est, .. } => {
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
            .filter(|(_, s)| matches!(s.state, HostSessionState::Active { .. }))
            .map(|(id, _)| *id)
            .collect();
        v.sort();
        v
    }

    /// Screen capture changed state (phase4-criteria §7). One capture serves
    /// every session, so this applies to all of them:
    ///
    /// * `Interrupted` → every Active session is told `StreamState{paused}`;
    ///   sessions stay Active. Repeating the same status does nothing.
    /// * `Running` after an interruption → `StreamState{resumed}` to every
    ///   Active session and [`HostAction::ForceKeyframe`].
    /// * `Stopped` → every Active session closes with
    ///   [`CloseCode::CaptureStopped`](crate::CloseCode::CaptureStopped).
    ///
    /// A session approved while capture is interrupted is told it is paused
    /// right after `SessionAccept` (with the time actually left if the
    /// display is unavailable); one approved while it is stopped closes with
    /// `CaptureStopped`.
    ///
    /// `Interrupted(DisplayUnavailable { remaining_ms })` sets a deadline
    /// `now + remaining_ms` (D-29). The capture reports it only when the
    /// deadline is new (the display went missing, again), so it is always
    /// sent, even if the status looks the same as before.
    pub fn capture_changed(
        &mut self,
        status: crate::CaptureStatus,
        now: Millis,
    ) -> Vec<HostAction> {
        use crate::{CaptureStatus, PauseReason};
        let mut out = Vec::new();
        let unavailable = matches!(
            status,
            CaptureStatus::Interrupted(PauseReason::DisplayUnavailable { .. })
        );
        if status == self.capture && !unavailable {
            return out;
        }
        let was = std::mem::replace(&mut self.capture, status);
        self.pause_deadline = match status {
            CaptureStatus::Interrupted(PauseReason::DisplayUnavailable { remaining_ms }) => {
                Some(now.plus(u64::from(remaining_ms)))
            }
            _ => None,
        };
        let active = self.active_sessions();
        match status {
            CaptureStatus::Interrupted(reason) => {
                for id in active {
                    let left = reason.remaining_ms();
                    self.send_stream_state(id, true, reason.wire(), left, &mut out);
                }
            }
            CaptureStatus::Running => {
                // Only a resume after an interruption is news to viewers;
                // Running after Stopped has no Active sessions left to tell.
                if matches!(was, CaptureStatus::Interrupted(_)) {
                    for id in active {
                        self.send_stream_state(id, false, 0, 0, &mut out);
                    }
                    // One shared encoder: one keyframe, however many viewers.
                    out.push(HostAction::ForceKeyframe);
                }
            }
            CaptureStatus::Stopped => {
                for id in active {
                    self.close(id, CloseCode::CaptureStopped, false, &mut out);
                }
            }
        }
        out
    }

    /// Sends `StreamState` on an Active session's encrypted stream.
    fn send_stream_state(
        &mut self,
        id: SessionId,
        paused: bool,
        reason: u32,
        remaining_ms: u32,
        out: &mut Vec<HostAction>,
    ) {
        let Some(HostSession {
            state: HostSessionState::Active { est, .. },
            ..
        }) = self.sessions.get_mut(&id)
        else {
            return;
        };
        // The validator's bound (1 h) is far above the 2-minute wait; the
        // clamp only keeps a misconfigured limit from breaking the message.
        let remaining_ms = remaining_ms.min(remora_proto::limits::PAUSE_REMAINING_MAX_MS);
        let env = control_env(control::Kind::StreamState(StreamState {
            paused,
            reason,
            remaining_ms,
        }));
        match est.encrypt(&env) {
            Ok(frame) => out.push(HostAction::Send { id, frame }),
            Err(_) => self.fail(
                id,
                FailReason::AuthFailed(AuthDetail::Handshake(
                    remora_crypto::noise::HandshakeError::Internal,
                )),
                Step::Active,
                None,
                false,
                out,
            ),
        }
    }

    /// What screen capture is doing, as last reported.
    pub fn capture_status(&self) -> crate::CaptureStatus {
        self.capture
    }

    /// While the captured display is unavailable: milliseconds at `now` until
    /// the host gives up waiting (D-29). `None` otherwise.
    pub fn pause_remaining(&self, now: Millis) -> Option<u32> {
        self.pause_deadline
            .map(|d| u32::try_from(d.0.saturating_sub(now.0)).unwrap_or(u32::MAX))
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

    fn on_msg3<R: RngCore + CryptoRng>(
        &mut self,
        id: SessionId,
        frame: &[u8],
        hs: HostAwaitMsg3,
        now: Millis,
        rng: &mut R,
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
            // Generated now (the step has a random source; approval does
            // not), announced only once the host user accepts.
            media: MediaOut::new(rng),
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
        media: MediaOut,
        now: Millis,
        out: &mut Vec<HostAction>,
    ) -> Result<HostSessionState, Ending> {
        let env = decrypt_envelope(&mut est, frame).map_err(|r| Ending::Failed(r, false))?;
        match env.msg {
            Some(envelope::Msg::Control(Control {
                kind: Some(control::Kind::Recovery(_)),
            })) => {
                // A viewer's decoder needs a keyframe (phase4-criteria M7).
                // One forced keyframe serves every viewer, so requests
                // inside the interval are answered by the last one.
                if self
                    .keyframe_requested
                    .is_none_or(|t| now.0 >= t.0.saturating_add(KEYFRAME_REQUEST_INTERVAL_MS))
                {
                    self.keyframe_requested = Some(now);
                    out.push(HostAction::ForceKeyframe);
                }
                Ok(HostSessionState::Active { est, media })
            }
            Some(envelope::Msg::Input(input)) => {
                out.push(HostAction::Deliver {
                    id,
                    msg: AppMessage::Input(input),
                });
                Ok(HostSessionState::Active { est, media })
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
