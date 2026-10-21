//! The viewer side of one connection.

use std::sync::Arc;

use prost::Message;
use rand_core::{CryptoRng, RngCore};
use remora_crypto::identity::{DeviceId, IdentityCert, IdentityPublic};
use remora_crypto::keyschedule::{derive_psk, prologue, transcript_hash};
use remora_crypto::noise::{
    Established, HandshakeError, HandshakeMode, PeerPolicy, ViewerAwaitMsg2, ViewerAwaitReveal,
    viewer_start,
};
use remora_crypto::pake::{Pake, PakeContext, PakeMessage, PakeRole, Spake2Ed25519};
use remora_crypto::sas::Sas;
use remora_crypto::secret::{Exporter, Otp};

use remora_proto::messages::{
    Control, Envelope, Goodbye, Mode, ViewerHello, control, decode_host_hello, envelope,
};

use crate::fail::Violation;
use crate::host::{Identity, decrypt_envelope};
use crate::media::{MediaIn, MediaStats};
use crate::{CloseCode, FailReason, HANDSHAKE_TIMEOUT_MS, Millis, PROTOCOL_VERSION, State, Step};

/// How the viewer authenticates.
#[derive(Debug, Clone)]
pub enum ViewerMode {
    /// One-time password typed by the user, optionally connecting to a
    /// specific device ID (A16).
    Password {
        /// The password.
        otp: Otp,
        /// The device ID asked for, if connecting by ID.
        expect: Option<DeviceId>,
    },
    /// Trusted device: the host's pinned identity key (A19, A25-T).
    Trusted {
        /// Pinned host key.
        pinned: IdentityPublic,
    },
}

/// Viewer configuration.
#[derive(Debug, Clone)]
pub struct ViewerConfig {
    /// This viewer's identity.
    pub identity: Arc<Identity>,
    /// Authentication mode.
    pub mode: ViewerMode,
}

/// What the viewer must do.
#[derive(Debug, Clone, PartialEq)]
pub enum ViewerAction {
    /// Send one frame.
    Send(Vec<u8>),
    /// Close the connection with this code.
    Close(CloseCode),
    /// Show the safety code (both screens must show the same).
    ShowSas {
        /// The code.
        sas: Sas,
        /// The host's verified identity.
        host: IdentityCert,
    },
    /// The host approved: the session is active.
    Active,
    /// The host's screen capture paused: keep the session, show "paused"
    /// with this reason (Active only).
    StreamPaused(crate::PauseReason),
    /// The stream resumed; a keyframe follows.
    StreamResumed,
    /// A complete video frame for the decoder (Active only; it came only
    /// from datagrams that opened under an announced media key).
    Video(remora_proto::video::VideoFrame),
    /// The session failed (log it, tell the user).
    Failed {
        /// Precise local reason.
        reason: FailReason,
        /// Where.
        step: Step,
    },
}

#[allow(
    clippy::large_enum_variant,
    reason = "one state per connection and at most a few connections; boxing only adds allocations"
)]
pub(crate) enum ViewerState {
    Hello {
        vh: Vec<u8>,
        nonce: [u8; 16],
    },
    Spake {
        vh: Vec<u8>,
        hh: Vec<u8>,
        pake: Spake2Ed25519,
        spake_a: PakeMessage,
    },
    Msg2(ViewerAwaitMsg2),
    Reveal(ViewerAwaitReveal),
    Pending(Established),
    Active(Established),
    Closed,
}

/// One viewer-side connection.
pub struct ViewerSession {
    pub(crate) config: ViewerConfig,
    pub(crate) exporter: Exporter,
    pub(crate) state: ViewerState,
    pub(crate) deadline: Millis,
    pub(crate) media: MediaIn,
}

impl std::fmt::Debug for ViewerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewerSession")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl ViewerSession {
    /// Starts a connection: returns the session and its first action
    /// (sending `ViewerHello` with `nonce` from the connection code).
    pub fn start(
        config: ViewerConfig,
        nonce: [u8; 16],
        exporter: Exporter,
        now: Millis,
    ) -> (Self, Vec<ViewerAction>) {
        let mode = match config.mode {
            ViewerMode::Password { .. } => Mode::Password,
            ViewerMode::Trusted { .. } => Mode::Trusted,
        };
        let vh = ViewerHello {
            versions: vec![PROTOCOL_VERSION],
            mode: mode as i32,
            nonce: nonce.to_vec(),
        }
        .encode_to_vec();
        let first = vec![ViewerAction::Send(vh.clone())];
        (
            Self {
                config,
                exporter,
                state: ViewerState::Hello { vh, nonce },
                deadline: now.plus(HANDSHAKE_TIMEOUT_MS),
                media: MediaIn::default(),
            },
            first,
        )
    }

    /// A frame arrived from the host.
    pub fn on_frame<R: RngCore + CryptoRng>(
        &mut self,
        frame: &[u8],
        now: Millis,
        rng: &mut R,
    ) -> Vec<ViewerAction> {
        let _ = now;
        let state = std::mem::replace(&mut self.state, ViewerState::Closed);
        let step = step_of(&state);
        let mut out = Vec::new();
        let result = match state {
            ViewerState::Closed => return out,
            ViewerState::Hello { vh, nonce } => self.on_hello(frame, vh, nonce, rng, &mut out),
            ViewerState::Spake {
                vh,
                hh,
                pake,
                spake_a,
            } => self.on_spake(frame, vh, hh, pake, spake_a, &mut out),
            ViewerState::Msg2(hs) => self.on_msg2(frame, hs, rng, &mut out),
            ViewerState::Reveal(hs) => match hs.read_reveal(frame) {
                Ok(est) => {
                    out.push(ViewerAction::ShowSas {
                        sas: est.sas(),
                        host: est.peer_cert().clone(),
                    });
                    Ok(ViewerState::Pending(est))
                }
                Err(e) => Err(Some(reveal_failure(e))),
            },
            ViewerState::Pending(est) => on_pending(frame, est, &mut out),
            ViewerState::Active(est) => on_active(frame, est, &mut self.media, &mut out),
        };
        match result {
            Ok(next) => self.state = next,
            Err(Some(reason)) => fail(reason, step, &mut out),
            Err(None) => out.push(ViewerAction::Close(CloseCode::Normal)),
        }
        out
    }

    /// A datagram arrived.
    ///
    /// * `Active`: opened, and complete frames are delivered as
    ///   [`ViewerAction::Video`]; anything else is counted
    ///   ([`ViewerSession::media_stats`]) and the session goes on (M5).
    /// * Waiting for approval: dropped unread and counted. The host sends
    ///   `SessionAccept` on the ordered stream and media as datagrams, which
    ///   can overtake it when a packet is lost (M3).
    /// * Earlier (handshake): no host can have sent media yet, so the
    ///   session closes (A20).
    pub fn on_datagram(&mut self, datagram: &[u8], now: Millis) -> Vec<ViewerAction> {
        let mut out = Vec::new();
        match self.state() {
            State::Closed => {}
            State::Active => out.extend(
                self.media
                    .datagram(datagram, now)
                    .into_iter()
                    .map(ViewerAction::Video),
            ),
            _ => {
                let step = step_of(&self.state);
                self.state = ViewerState::Closed;
                fail(
                    FailReason::ProtocolViolation(Violation::DatagramBeforeActive),
                    step,
                    &mut out,
                );
            }
        }
        out
    }

    /// The clock advanced (handshake deadline; it stops applying once the
    /// safety code is shown — the host's 60 s prompt limit takes over).
    pub fn tick(&mut self, now: Millis) -> Vec<ViewerAction> {
        let mut out = Vec::new();
        self.media.tick(now);
        let waiting = matches!(
            self.state,
            ViewerState::Hello { .. }
                | ViewerState::Spake { .. }
                | ViewerState::Msg2(_)
                | ViewerState::Reveal(_)
        );
        if waiting && now >= self.deadline {
            let step = step_of(&self.state);
            self.state = ViewerState::Closed;
            fail(FailReason::Timeout, step, &mut out);
        }
        out
    }

    /// Send an input event (Active only; otherwise `None`).
    pub fn send_input(&mut self, input: remora_proto::messages::Input) -> Option<ViewerAction> {
        let ViewerState::Active(est) = &mut self.state else {
            return None;
        };
        let env = Envelope {
            msg: Some(envelope::Msg::Input(input)),
        }
        .encode_to_vec();
        est.encrypt(&env).ok().map(ViewerAction::Send)
    }

    /// One-click disconnect from any state.
    pub fn disconnect(&mut self) -> Vec<ViewerAction> {
        let mut out = Vec::new();
        match &mut self.state {
            ViewerState::Closed => return out,
            ViewerState::Pending(est) | ViewerState::Active(est) => {
                let bye = control_env(control::Kind::Bye(Goodbye {}));
                if let Ok(frame) = est.encrypt(&bye) {
                    out.push(ViewerAction::Send(frame));
                }
            }
            _ => {}
        }
        self.state = ViewerState::Closed;
        out.push(ViewerAction::Close(CloseCode::Normal));
        out
    }

    // ------------------------------------------------------------ steps --

    fn on_hello<R: RngCore + CryptoRng>(
        &mut self,
        frame: &[u8],
        vh: Vec<u8>,
        nonce: [u8; 16],
        rng: &mut R,
        out: &mut Vec<ViewerAction>,
    ) -> Result<ViewerState, Option<FailReason>> {
        let hello = decode_host_hello(frame)
            .map_err(|e| Some(FailReason::ProtocolViolation(Violation::Malformed(e))))?;
        if hello.version != PROTOCOL_VERSION {
            return Err(Some(FailReason::VersionUnsupported));
        }
        let mut id = [0u8; 10];
        id.copy_from_slice(&hello.host_device_id); // length validated by decode_host_hello
        let host_id = DeviceId::from_bytes(id);
        let hh = frame.to_vec();
        match &self.config.mode {
            ViewerMode::Password { otp, expect } => {
                // Early, unauthenticated hint; the cert check at msg2 is the
                // real one (A16).
                if expect.is_some_and(|want| want != host_id) {
                    return Err(Some(FailReason::IdentityMismatch));
                }
                let ctx = PakeContext {
                    host_device_id: host_id,
                    nonce,
                };
                let (pake, spake_a) = Spake2Ed25519::start(PakeRole::Viewer, otp, &ctx, rng);
                out.push(ViewerAction::Send(spake_a.as_bytes().to_vec()));
                Ok(ViewerState::Spake {
                    vh,
                    hh,
                    pake,
                    spake_a,
                })
            }
            ViewerMode::Trusted { .. } => {
                let pro = prologue(&self.exporter, &vh, &hh);
                let (hs, msg1) =
                    viewer_start(HandshakeMode::Trusted, &pro, &self.config.identity.noise)
                        .map_err(|e| Some(FailReason::from_handshake(e)))?;
                out.push(ViewerAction::Send(msg1));
                Ok(ViewerState::Msg2(hs))
            }
        }
    }

    fn on_spake(
        &mut self,
        frame: &[u8],
        vh: Vec<u8>,
        hh: Vec<u8>,
        pake: Spake2Ed25519,
        spake_a: PakeMessage,
        out: &mut Vec<ViewerAction>,
    ) -> Result<ViewerState, Option<FailReason>> {
        let spake_b = PakeMessage::from_bytes(frame).map_err(|e| Some(FailReason::from_pake(e)))?;
        let k = pake
            .finish(&spake_b)
            .map_err(|e| Some(FailReason::from_pake(e)))?;
        let t = transcript_hash(&vh, &hh, &spake_a, &spake_b);
        let psk = derive_psk(&self.exporter, &k, &t);
        let pro = prologue(&self.exporter, &vh, &hh);
        let (hs, msg1) = viewer_start(
            HandshakeMode::Password(&psk),
            &pro,
            &self.config.identity.noise,
        )
        .map_err(|e| Some(FailReason::from_handshake(e)))?;
        out.push(ViewerAction::Send(msg1));
        Ok(ViewerState::Msg2(hs))
    }

    fn on_msg2<R: RngCore + CryptoRng>(
        &mut self,
        frame: &[u8],
        hs: ViewerAwaitMsg2,
        rng: &mut R,
        out: &mut Vec<ViewerAction>,
    ) -> Result<ViewerState, Option<FailReason>> {
        let policy = match &self.config.mode {
            ViewerMode::Password { expect: None, .. } => PeerPolicy::AnyKey,
            ViewerMode::Password {
                expect: Some(id), ..
            } => PeerPolicy::DeviceId(*id),
            ViewerMode::Trusted { pinned } => PeerPolicy::Pinned(*pinned),
        };
        let got = hs
            .read_msg2(frame, &policy)
            .map_err(|e| Some(FailReason::from_handshake(e)))?;
        let (hs, msg3) = got
            .write_msg3(&self.config.identity.cert, rng)
            .map_err(|e| Some(FailReason::from_handshake(e)))?;
        out.push(ViewerAction::Send(msg3));
        Ok(ViewerState::Reveal(hs))
    }

    /// What happened to the media datagrams received so far.
    pub fn media_stats(&self) -> MediaStats {
        self.media.stats
    }

    /// Current state.
    pub fn state(&self) -> State {
        match self.state {
            ViewerState::Hello { .. } => State::Hello,
            ViewerState::Spake { .. } => State::Spake,
            ViewerState::Msg2(_) => State::Noise,
            ViewerState::Reveal(_) => State::SasReveal,
            ViewerState::Pending(_) => State::PendingApproval,
            ViewerState::Active(_) => State::Active,
            ViewerState::Closed => State::Closed,
        }
    }
}

fn step_of(state: &ViewerState) -> Step {
    match state {
        ViewerState::Hello { .. } => Step::Hello,
        ViewerState::Spake { .. } => Step::Spake,
        ViewerState::Msg2(_) => Step::NoiseMsg2,
        ViewerState::Reveal(_) => Step::Reveal,
        ViewerState::Pending(_) => Step::Approval,
        ViewerState::Active(_) | ViewerState::Closed => Step::Active,
    }
}

/// The reveal could not be read: a frame that does not decrypt is an
/// authentication failure; anything decrypted but not a valid, matching
/// `SasReveal` is a protocol violation (A17-S1, A20).
fn reveal_failure(e: HandshakeError) -> FailReason {
    match e {
        HandshakeError::RevealAuth => FailReason::ProtocolViolation(Violation::TransportAuth),
        other => FailReason::from_handshake(other),
    }
}

/// Waiting for the host user: only `SessionPending`, `SessionAccept`,
/// `SessionReject` or `Goodbye` may arrive (A20, A21).
fn on_pending(
    frame: &[u8],
    mut est: Established,
    out: &mut Vec<ViewerAction>,
) -> Result<ViewerState, Option<FailReason>> {
    let env = decrypt_envelope(&mut est, frame).map_err(Some)?;
    match env.msg {
        Some(envelope::Msg::Control(Control { kind: Some(kind) })) => match kind {
            control::Kind::Pending(_) => Ok(ViewerState::Pending(est)),
            control::Kind::Accept(_) => {
                out.push(ViewerAction::Active);
                Ok(ViewerState::Active(est))
            }
            control::Kind::Reject(_) => Err(Some(FailReason::Rejected)),
            control::Kind::Bye(_) => Err(None),
            control::Kind::MediaKey(_) | control::Kind::StreamState(_) => {
                Err(Some(FailReason::ProtocolViolation(Violation::BeforeActive)))
            }
            control::Kind::SasReveal(_) => {
                Err(Some(FailReason::ProtocolViolation(Violation::WrongRole)))
            }
        },
        // Input (or anything else) from the host is role confusion.
        _ => Err(Some(FailReason::ProtocolViolation(Violation::WrongRole))),
    }
}

/// Active: the host may send media keys and `Goodbye`; input from the host
/// is role confusion (A21). A media key is installed here and never leaves
/// the session.
fn on_active(
    frame: &[u8],
    mut est: Established,
    media: &mut MediaIn,
    out: &mut Vec<ViewerAction>,
) -> Result<ViewerState, Option<FailReason>> {
    let env = decrypt_envelope(&mut est, frame).map_err(Some)?;
    match env.msg {
        Some(envelope::Msg::Control(Control {
            kind: Some(control::Kind::MediaKey(k)),
        })) => {
            media
                .announce(&k)
                .map_err(|v| Some(FailReason::ProtocolViolation(v)))?;
            Ok(ViewerState::Active(est))
        }
        Some(envelope::Msg::Control(Control {
            kind: Some(control::Kind::Bye(_)),
        })) => Err(None),
        Some(envelope::Msg::Control(Control {
            kind: Some(control::Kind::StreamState(st)),
        })) => {
            // Shape (paused <=> reason != 0) is checked by the envelope
            // validator; an unknown reason is a newer host's: "other".
            out.push(if st.paused {
                ViewerAction::StreamPaused(crate::PauseReason::from_wire(st.reason))
            } else {
                ViewerAction::StreamResumed
            });
            Ok(ViewerState::Active(est))
        }
        _ => Err(Some(FailReason::ProtocolViolation(Violation::WrongRole))),
    }
}

fn fail(reason: FailReason, step: Step, out: &mut Vec<ViewerAction>) {
    let code = reason.close_code();
    out.push(ViewerAction::Failed { reason, step });
    out.push(ViewerAction::Close(code));
}

fn control_env(kind: control::Kind) -> Vec<u8> {
    Envelope {
        msg: Some(envelope::Msg::Control(Control { kind: Some(kind) })),
    }
    .encode_to_vec()
}
