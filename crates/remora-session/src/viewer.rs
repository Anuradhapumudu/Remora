//! The viewer side of one connection.

use std::sync::Arc;

use rand_core::{CryptoRng, RngCore};
use remora_crypto::identity::{DeviceId, IdentityCert, IdentityPublic};
use remora_crypto::noise::{Established, ViewerAwaitMsg2, ViewerAwaitReveal};
use remora_crypto::pake::Spake2Ed25519;
use remora_crypto::sas::Sas;
use remora_crypto::secret::{Exporter, Otp};

use crate::host::Identity;
use crate::{AppMessage, CloseCode, FailReason, Millis, State, Step};

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
    /// Deliver an application message (Active only).
    Deliver(AppMessage),
    /// The session failed (log it, tell the user).
    Failed {
        /// Precise local reason.
        reason: FailReason,
        /// Where.
        step: Step,
    },
}

pub(crate) enum ViewerState {
    Hello {
        vh: Vec<u8>,
    },
    Spake {
        vh: Vec<u8>,
        hh: Vec<u8>,
        pake: Spake2Ed25519,
        spake_a: remora_crypto::pake::PakeMessage,
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
        let _ = (config, nonce, exporter, now);
        todo!()
    }

    /// A frame arrived from the host.
    pub fn on_frame<R: RngCore + CryptoRng>(
        &mut self,
        frame: &[u8],
        now: Millis,
        rng: &mut R,
    ) -> Vec<ViewerAction> {
        let _ = (frame, now, rng);
        todo!()
    }

    /// A datagram arrived. Before `Active` it closes the session.
    pub fn on_datagram(&mut self, datagram: &[u8]) -> Vec<ViewerAction> {
        let _ = datagram;
        todo!()
    }

    /// The clock advanced (handshake deadline).
    pub fn tick(&mut self, now: Millis) -> Vec<ViewerAction> {
        let _ = now;
        todo!()
    }

    /// Send an input event (Active only; otherwise `None`).
    pub fn send_input(&mut self, input: remora_proto::messages::Input) -> Option<ViewerAction> {
        let _ = input;
        todo!()
    }

    /// One-click disconnect from any state.
    pub fn disconnect(&mut self) -> Vec<ViewerAction> {
        todo!()
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
