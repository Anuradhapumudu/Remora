//! The viewer's connect form and session window (phase4.5-criteria §6).
//!
//! * **V1** The pasted code goes to the existing parser, which checks its
//!   length (`CODE_TEXT_MAX`) before anything else; the host's device ID
//!   from the code is shown before connecting.
//! * **V2** The password is parsed into [`Otp`] (zeroized on drop); the GUI
//!   clears its field at Connect.
//! * **V3** After the handshake: the safety code, "Unverified - compare this
//!   code with the person at the host", and the line that the host decides.
//! * **V4** Verified only by **The codes match**, for this session only;
//!   **They don't match** ends the session and says why.
//! * **V5** Denied or timed out: "The host declined. Ask for a new code to
//!   try again." (D-21).
//! * **V6** "Display unavailable - N s left", counting down locally between
//!   the host's updates (D-33).

use std::net::SocketAddr;

use remora_crypto::identity::{DeviceId, IdentityPublic};
use remora_crypto::sas::Sas;
use remora_crypto::secret::Otp;
use remora_proto::code::{CodeKind, ConnectionCode};
use remora_session::{CloseCode, Millis};

/// Where the code says to connect, read before connecting (V1).
#[derive(Debug, Clone)]
pub struct Target {
    /// The host's address from the code.
    pub addr: SocketAddr,
    /// The host's identity key from the code.
    pub host_key: IdentityPublic,
    /// The host's device ID, shown before connecting.
    pub host_device: String,
    /// The code's single-use nonce.
    pub nonce: [u8; 16],
}

/// Reads a pasted connection code (V1). The parser checks the length
/// before anything else, so a huge paste is refused without being parsed.
pub fn read_code(text: &str, now_unix: u64) -> Result<Target, String> {
    let code = ConnectionCode::parse(text.trim(), now_unix)
        .map_err(|e| format!("This is not a valid connection code: {e}."))?;
    if code.kind != CodeKind::Offer {
        return Err("This is an answer code, not the host's connection code.".into());
    }
    let addr = code
        .candidates
        .first()
        .map(|c| c.addr)
        .ok_or_else(|| "The connection code has no address.".to_owned())?;
    let host_key = IdentityPublic::from_bytes(code.identity_key);
    Ok(Target {
        addr,
        host_device: DeviceId::of(&host_key).short_code().to_string(),
        host_key,
        nonce: code.nonce,
    })
}

/// Reads the typed password (V2) into a buffer that is zeroized on drop.
pub fn read_password(text: &str) -> Result<Otp, String> {
    Otp::parse(text.trim())
        .map_err(|e| format!("The password is the 6 digits shown at the host ({e})."))
}

/// What a request from the viewer window asks the connection to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerRequest {
    /// End the session (Disconnect, or "They don't match").
    Disconnect,
}

/// Where the viewer is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// The form: code and password.
    Form,
    /// Connecting and running the handshake.
    Connecting,
    /// The safety code is shown; the host has not answered yet.
    Comparing,
    /// The host accepted: the video window shows the screen.
    Active,
    /// Over, with the message to show.
    Ended(String),
}

/// What the viewer windows show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerView {
    /// Where the viewer is.
    pub stage: Stage,
    /// The safety code, "123 456", once known.
    pub sas: Option<String>,
    /// "Verified for this session" or "Unverified - compare this code with
    /// the person at the host" (V3, V4).
    pub verification: Option<&'static str>,
    /// The line under the code while the host decides (F-UX4).
    pub waiting: Option<&'static str>,
    /// "Display unavailable - N s left" (V6), or "The host's display is
    /// back." just after it resumed.
    pub display: Option<String>,
}

/// Shown while the safety code is unverified (V3).
pub const UNVERIFIED: &str = "Unverified \u{2014} compare this code with the person at the host";
/// Shown once the person said the codes match (V4).
pub const VERIFIED: &str = "Verified for this session";
/// Shown while the host decides (F-UX4).
pub const WAITING: &str =
    "Waiting for the person at the host to accept or deny (nothing to type here).";
/// Denied or timed out (V5, D-21).
pub const DECLINED: &str = "The host declined. Ask for a new code to try again.";
/// The person said the codes differ (V4).
pub const MISMATCH: &str = "You said the codes don't match, so the session was ended. \
Someone may be between you and the host: do not reconnect with this code; ask for a new one.";

#[derive(Debug, Clone, Copy)]
struct Pause {
    remaining_ms: u64,
    at: Millis,
}

/// The viewer GUI's decisions.
#[derive(Debug)]
pub struct ViewerDesk {
    stage: Stage,
    sas: Option<Sas>,
    verified: bool,
    pause: Option<Pause>,
    resumed: bool,
}

impl Default for ViewerDesk {
    fn default() -> Self {
        Self {
            stage: Stage::Form,
            sas: None,
            verified: false,
            pause: None,
            resumed: false,
        }
    }
}

impl ViewerDesk {
    /// The form, nothing else.
    pub fn new() -> Self {
        Self::default()
    }

    /// Connect was pressed with a valid code and password.
    pub fn connecting(&mut self) {
        *self = Self {
            stage: Stage::Connecting,
            ..Self::default()
        };
    }

    /// The handshake finished: show the safety code, unverified (V3).
    pub fn show_sas(&mut self, sas: Sas) {
        if self.stage == Stage::Connecting {
            self.sas = Some(sas);
            self.verified = false;
            self.stage = Stage::Comparing;
        }
    }

    /// **The codes match** (V4): verified for this session. Only once a
    /// code is on screen; never set by connecting or by the host accepting.
    pub fn codes_match(&mut self) {
        if matches!(self.stage, Stage::Comparing | Stage::Active) && self.sas.is_some() {
            self.verified = true;
        }
    }

    /// **They don't match** (V4): ends the session and says why.
    pub fn codes_differ(&mut self) -> Option<ViewerRequest> {
        if !matches!(self.stage, Stage::Comparing | Stage::Active) {
            return None;
        }
        self.stage = Stage::Ended(MISMATCH.into());
        Some(ViewerRequest::Disconnect)
    }

    /// The host accepted.
    pub fn active(&mut self) {
        if self.stage == Stage::Comparing {
            self.stage = Stage::Active;
        }
    }

    /// The host's display is unavailable, `remaining_ms` left (V6).
    pub fn display_unavailable(&mut self, remaining_ms: u32, now: Millis) {
        self.pause = Some(Pause {
            remaining_ms: u64::from(remaining_ms),
            at: now,
        });
        self.resumed = false;
    }

    /// The stream resumed.
    pub fn resumed(&mut self) {
        if self.pause.take().is_some() {
            self.resumed = true;
        }
    }

    /// **Disconnect** (V6).
    pub fn disconnect(&mut self) -> Option<ViewerRequest> {
        match self.stage {
            Stage::Connecting | Stage::Comparing | Stage::Active => {
                self.stage = Stage::Ended("You ended the session.".into());
                Some(ViewerRequest::Disconnect)
            }
            Stage::Form | Stage::Ended(_) => None,
        }
    }

    /// The connection ended with `code` from the host (or ours). A message
    /// already set by the person's own action is kept.
    pub fn ended(&mut self, code: Option<CloseCode>) {
        if matches!(self.stage, Stage::Ended(_)) {
            return;
        }
        let text = match code {
            Some(CloseCode::Normal) => "The session ended.",
            Some(CloseCode::Rejected) => DECLINED,
            Some(CloseCode::HostBusy) => {
                "The host is busy: someone else is connected. Try again when their session ends."
            }
            Some(CloseCode::AuthFailed) => {
                "The host did not accept the password (wrong, already used, or replaced after 3 failed attempts). Ask for the current code and password."
            }
            Some(CloseCode::CaptureStopped) => {
                "The host's screen capture stopped; it needs attention at the host."
            }
            Some(CloseCode::RateLimited) => "Too many attempts: wait a minute and try again.",
            Some(CloseCode::Timeout) => "The connection took too long to set up.",
            Some(CloseCode::ProtocolViolation | CloseCode::VersionUnsupported) | None => {
                "The connection failed."
            }
        };
        self.stage = Stage::Ended(text.into());
        self.pause = None;
    }

    /// The session failed locally before or during the handshake, for a
    /// reason no close code carries.
    pub fn failed(&mut self, reason: &remora_session::FailReason) {
        use remora_session::FailReason;
        if matches!(self.stage, Stage::Ended(_)) {
            return;
        }
        let text = match reason {
            FailReason::Rejected => DECLINED.to_owned(),
            FailReason::IdentityMismatch => {
                "The host is not the device in the code: not connecting. Ask for a new code.".to_owned()
            }
            FailReason::IdentityChanged => {
                "This device's identity changed: not connecting.".to_owned()
            }
            FailReason::AuthFailed(_) => {
                "The host did not accept the password (wrong, already used, or replaced after 3 failed attempts). Ask for the current code and password.".to_owned()
            }
            other => format!("The connection failed: {other}."),
        };
        self.stage = Stage::Ended(text);
        self.pause = None;
    }

    /// The connection could not be set up here (network, key file): ends
    /// with that reason, unless one is already shown.
    pub fn error(&mut self, what: &str) {
        if !matches!(self.stage, Stage::Ended(_)) {
            self.stage = Stage::Ended(format!("The connection failed: {what}"));
            self.pause = None;
        }
    }

    /// The connection died without a close (V6's end reason for a silent
    /// host).
    pub fn lost(&mut self) {
        if !matches!(self.stage, Stage::Ended(_)) {
            self.stage = Stage::Ended("The connection was lost: no reply from the host.".into());
            self.pause = None;
        }
    }

    /// Whether the host was verified for this session.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// What the windows show at `now`.
    pub fn view(&self, now: Millis) -> ViewerView {
        let showing_code = matches!(self.stage, Stage::Comparing | Stage::Active);
        ViewerView {
            stage: self.stage.clone(),
            sas: self
                .sas
                .filter(|_| showing_code)
                .map(crate::cli::format_sas),
            verification: showing_code.then_some(if self.verified { VERIFIED } else { UNVERIFIED }),
            waiting: (self.stage == Stage::Comparing).then_some(WAITING),
            display: match (self.pause, self.resumed) {
                (Some(p), _) => {
                    let left = p.remaining_ms.saturating_sub(now.0.saturating_sub(p.at.0));
                    Some(format!(
                        "Display unavailable \u{2014} {} s left",
                        left.div_ceil(1000)
                    ))
                }
                (None, true) => Some("The host's display is back.".into()),
                (None, false) => None,
            },
        }
    }
}
