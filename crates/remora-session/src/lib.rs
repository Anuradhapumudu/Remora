//! Remora session state machine: handshake, host approval gate, attempt
//! limiter (protocol.md §3; phase3-criteria §3.1, §3.5, §3.6).
//!
//! **No I/O** (architecture.md §2): every function takes an event — a frame
//! that arrived, a datagram, a tick of the clock, a user decision — and
//! returns the actions to perform: frames to send, a connection to close, a
//! prompt to show, an application message to deliver. Time is passed in as
//! [`Millis`], so tests control the clock exactly.
//!
//! * [`Host`] owns the [`limiter::Limiter`] and every host-side session. A
//!   session can only be created through [`Host::accept_connection`], which
//!   applies the pending-handshake cap and per-IP limit **before any crypto**
//!   (A03), and every failure is counted against the current one-time
//!   password globally, across connections.
//! * [`ViewerSession`] drives one viewer-side connection.
//! * Application messages (input, media keys) are delivered **only** in
//!   [`State::Active`]; in every earlier state they close the session (INV1,
//!   A20). The host reaches `Active` only through [`Host::approve`] with the
//!   session ID **and** the safety code shown on the prompt (A22, A23).

#![forbid(unsafe_code)]

pub mod fail;
mod host;
pub mod limiter;
mod viewer;

pub use fail::{AuthDetail, CloseCode, FailReason, Step, Violation};
pub use host::{ApproveError, Host, HostAction, HostConfig, Identity, Refused, SessionId};
pub use viewer::{ViewerAction, ViewerConfig, ViewerMode, ViewerSession};

/// Milliseconds on a monotonic clock chosen by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millis(pub u64);

impl Millis {
    /// `self + ms`, saturating.
    pub fn plus(self, ms: u64) -> Millis {
        Millis(self.0.saturating_add(ms))
    }
}

/// Issued connection-code nonces the host keeps at once (A06); beyond this
/// the oldest is dropped.
pub const MAX_OUTSTANDING_NONCES: usize = 64;

/// Protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;
/// The handshake must reach the approval prompt within this time (A24).
pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
/// An unanswered prompt is rejected after this time (A24).
pub const PROMPT_TIMEOUT_MS: u64 = 60_000;

/// Session states (phase3-criteria §1). The host passes `SasReveal`
/// instantly (it sends the reveal); the viewer waits in it for the reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// Waiting for `ViewerHello` (host) / `HostHello` (viewer).
    Hello,
    /// Password mode: SPAKE2 exchange.
    Spake,
    /// Noise handshake messages 1–3.
    Noise,
    /// Viewer: handshake done, waiting for the host's `SasReveal`.
    SasReveal,
    /// Safety code shown; host prompt open.
    PendingApproval,
    /// Host approved: application messages flow.
    Active,
    /// Ended (any reason). Nothing is processed any more.
    Closed,
}

/// An application message delivered in [`State::Active`] only.
#[derive(Debug, Clone, PartialEq)]
pub enum AppMessage {
    /// Viewer → host: an input event for the injector.
    Input(remora_proto::messages::Input),
    /// Host → viewer: a media key to install.
    MediaKey(remora_proto::messages::MediaKeyAnnounce),
}

/// Why the stream paused (OS-neutral: each capture backend maps its own
/// errors onto these; the session never learns which OS it runs on — D17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PauseReason {
    /// The display is asleep, closed or gone (macOS: SCStream error −3815).
    DisplayUnavailable,
    /// The OS took the capture surface away (Windows: ACCESS_LOST).
    AccessLost,
    /// Anything else the backend expects to recover from.
    Other,
}

impl PauseReason {
    /// The value in `StreamState.reason` (protocol.md §5).
    pub fn wire(self) -> u32 {
        match self {
            PauseReason::DisplayUnavailable => 1,
            PauseReason::AccessLost => 2,
            PauseReason::Other => 3,
        }
    }

    /// From a paused `StreamState.reason` (non-zero; checked by the
    /// envelope validator). Unknown values are a newer host's reason: other.
    pub fn from_wire(v: u32) -> Self {
        match v {
            1 => PauseReason::DisplayUnavailable,
            2 => PauseReason::AccessLost,
            _ => PauseReason::Other,
        }
    }
}

/// What the host's screen capture is doing, as the session sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureStatus {
    /// Frames flow.
    Running,
    /// Paused; the backend keeps trying and will report `Running` again.
    Interrupted(PauseReason),
    /// Gone until the user acts (e.g. permission revoked).
    Stopped,
}
