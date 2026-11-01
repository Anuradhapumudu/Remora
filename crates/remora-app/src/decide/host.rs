//! The host's session indicator and main window (phase4.5-criteria §4, §5).
//!
//! * **I1** From `Active` until the session ends the indicator is shown:
//!   "<device> is viewing your screen", the time since it started, and
//!   **End session**. It is shown exactly while a session is Active.
//! * **I2** **End session** is one click and asks the session layer to
//!   disconnect that session.
//! * **H10** While a session is Active the main window hides the code and
//!   password (the screen is streamed to the viewer); **Show** reveals them
//!   until the session ends. Each new session starts hidden again.

use remora_session::{Millis, SessionId};

use super::dialog::{Answer, Dialogs};
use super::name::display_name;

/// What the session indicator shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndicatorView {
    /// The session it ends.
    pub id: SessionId,
    /// "<device> is viewing your screen" (the name escaped, H6).
    pub text: String,
    /// Whole seconds since the session became Active.
    pub seconds: u64,
}

/// A request from the host window to the session layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRequest {
    /// The person answered a dialog.
    Answer(Answer),
    /// End this session (I2).
    Disconnect(SessionId),
}

#[derive(Debug, Clone)]
struct ActiveSession {
    id: SessionId,
    text: String,
    since: Millis,
}

/// The host GUI's decisions: the dialogs, the indicator and the hidden
/// code. The GUI feeds it session events and clicks and does what the
/// returned requests say; it decides nothing itself.
#[derive(Debug, Default)]
pub struct HostDesk {
    /// The Accept/Deny dialogs.
    pub dialogs: Dialogs,
    active: Option<ActiveSession>,
    show_secrets: bool,
    refused_busy: u64,
}

impl HostDesk {
    /// Nothing open, nothing active.
    pub fn new() -> Self {
        Self::default()
    }

    /// Session `id` became Active (`raw_name` is the viewer's untrusted
    /// name). The indicator appears, the code and password are hidden, and
    /// every other open dialog is denied: one viewer at a time (H9; the
    /// session layer refuses a second approval as well).
    pub fn session_active(
        &mut self,
        id: SessionId,
        raw_name: &str,
        now: Millis,
    ) -> Vec<HostRequest> {
        self.dialogs.close(id, now);
        self.active = Some(ActiveSession {
            id,
            text: format!("{} is viewing your screen", display_name(raw_name)),
            since: now,
        });
        self.show_secrets = false;
        self.dialogs
            .deny_all(now)
            .into_iter()
            .map(HostRequest::Answer)
            .collect()
    }

    /// Session `id` ended, however it ended: its dialog or indicator goes.
    pub fn session_ended(&mut self, id: SessionId, now: Millis) {
        self.dialogs.close(id, now);
        if self.active.as_ref().is_some_and(|a| a.id == id) {
            self.active = None;
            self.show_secrets = false;
        }
    }

    /// A connection was refused because a session is active (H9): counted
    /// so the window shows repeated tries.
    pub fn refused_busy(&mut self) {
        self.refused_busy = self.refused_busy.saturating_add(1);
    }

    /// Connections refused as busy so far.
    pub fn refused_busy_count(&self) -> u64 {
        self.refused_busy
    }

    /// The indicator at `now`, shown exactly while a session is Active (I1).
    pub fn indicator(&self, now: Millis) -> Option<IndicatorView> {
        self.active.as_ref().map(|a| IndicatorView {
            id: a.id,
            text: a.text.clone(),
            seconds: now.0.saturating_sub(a.since.0) / 1000,
        })
    }

    /// The indicator's **End session** (I2).
    pub fn end_session(&self) -> Option<HostRequest> {
        self.active.as_ref().map(|a| HostRequest::Disconnect(a.id))
    }

    /// Whether the main window shows the code and password (H10).
    pub fn secrets_visible(&self) -> bool {
        self.active.is_none() || self.show_secrets
    }

    /// The main window's **Show** while a session is Active (H10).
    pub fn show_secrets(&mut self) {
        self.show_secrets = true;
    }

    /// **Hide** again.
    pub fn hide_secrets(&mut self) {
        self.show_secrets = false;
    }
}
