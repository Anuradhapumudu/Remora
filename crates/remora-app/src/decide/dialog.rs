//! The host's Accept/Deny dialogs (phase4.5-criteria §4): who sees the
//! screen is decided here, so every rule is plain code with a test.
//!
//! * **H2** Accept is bound to the dialog's own session ID **and** safety
//!   code; a dialog whose session ended is gone and can accept nothing.
//! * **H3** Deny is the default: Return, Space and Escape deny; no key
//!   accepts.
//! * **H4** Accept is armed [`ARM_DELAY_MS`] after the dialogs last changed
//!   (one opened or closed); a click counts only if **both** its press and
//!   its release happen after that (owner, 2026-10-25).
//! * **H5** No timer of its own: the session layer ends an unanswered prompt
//!   after `PROMPT_TIMEOUT_MS`; the dialog only shows the time left.
//! * **R4** At most [`MAX_DIALOGS`] at once (the session layer's pending cap).

use remora_crypto::sas::Sas;
use remora_session::limiter::MAX_PENDING;
use remora_session::{Millis, PROMPT_TIMEOUT_MS, SessionId};

use super::name::display_name;

/// How long Accept stays disabled after the dialogs change (H4).
pub const ARM_DELAY_MS: u64 = 1000;
/// Dialogs that may be open at once: one per pending handshake (R4).
pub const MAX_DIALOGS: usize = MAX_PENDING;

/// Whether the viewer's key is already known to this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// A pinned (trusted) device.
    Pinned,
    /// Never seen before.
    New,
}

/// A key pressed while a dialog has the keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Return / Enter.
    Return,
    /// The space bar.
    Space,
    /// Escape.
    Escape,
    /// Anything else.
    Other,
}

/// What the person decided; the app passes it to the session layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Approve exactly this session with exactly this safety code (A22).
    Accept {
        /// The dialog's session.
        id: SessionId,
        /// The safety code the dialog showed.
        sas: Sas,
    },
    /// Deny this session.
    Deny {
        /// The dialog's session.
        id: SessionId,
    },
}

/// A dialog could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// [`MAX_DIALOGS`] are open: the app denies this session (R4).
    #[error("{MAX_DIALOGS} dialogs are already open")]
    TooMany,
    /// A dialog for this session is already open.
    #[error("a dialog for this session is already open")]
    Duplicate,
}

/// What one dialog shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogView {
    /// The session this dialog answers.
    pub id: SessionId,
    /// The safety code, "123 456".
    pub sas: String,
    /// The viewer's name, escaped (H6); shown with the label "name chosen by
    /// the other computer, not checked".
    pub name: String,
    /// The viewer's device ID as shown everywhere else.
    pub device: String,
    /// "known device" / "new device".
    pub trust: &'static str,
    /// Whole seconds until the session layer denies it (H5), rounded up.
    pub seconds_left: u64,
    /// Accept can be clicked (H4).
    pub accept_enabled: bool,
}

#[derive(Debug, Clone)]
struct Dialog {
    id: SessionId,
    sas: Sas,
    name: String,
    device: String,
    trust: Trust,
    opened: Millis,
}

/// A pointer press on Accept that has not been released yet.
#[derive(Debug, Clone, Copy)]
struct Press {
    id: SessionId,
    at: Millis,
}

/// Every open dialog and the Accept arming state.
#[derive(Debug, Default)]
pub struct Dialogs {
    open: Vec<Dialog>,
    /// Accept is armed from this time on (H4).
    armed_at: Millis,
    press: Option<Press>,
}

impl Dialogs {
    /// No dialogs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Any change re-arms every dialog and cancels a press in progress (H4:
    /// "again after any change").
    fn changed(&mut self, now: Millis) {
        self.armed_at = now.plus(ARM_DELAY_MS);
        self.press = None;
    }

    /// A prompt arrived: opens its dialog. `raw_name` is the viewer's
    /// untrusted name; it is escaped here (H6).
    pub fn open(
        &mut self,
        id: SessionId,
        sas: Sas,
        raw_name: &str,
        device: String,
        trust: Trust,
        now: Millis,
    ) -> Result<(), OpenError> {
        if self.open.iter().any(|d| d.id == id) {
            return Err(OpenError::Duplicate);
        }
        if self.open.len() >= MAX_DIALOGS {
            return Err(OpenError::TooMany);
        }
        self.open.push(Dialog {
            id,
            sas,
            name: display_name(raw_name),
            device,
            trust,
            opened: now,
        });
        self.changed(now);
        Ok(())
    }

    /// The session behind a dialog ended or its prompt was withdrawn (viewer
    /// left, timed out, denied): the dialog goes and can never accept (H2).
    pub fn close(&mut self, id: SessionId, now: Millis) {
        let before = self.open.len();
        self.open.retain(|d| d.id != id);
        if self.open.len() != before {
            self.changed(now);
        }
    }

    /// Closes every dialog, returning a deny for each (a session became
    /// Active: one viewer at a time, H9).
    pub fn deny_all(&mut self, now: Millis) -> Vec<Answer> {
        let answers: Vec<Answer> = self
            .open
            .iter()
            .map(|d| Answer::Deny { id: d.id })
            .collect();
        if !answers.is_empty() {
            self.open.clear();
            self.changed(now);
        }
        answers
    }

    /// The pointer went down on dialog `id`'s Accept.
    pub fn press_accept(&mut self, id: SessionId, now: Millis) {
        self.press = self
            .open
            .iter()
            .any(|d| d.id == id)
            .then_some(Press { id, at: now });
    }

    /// The pointer left Accept before release, or the press was cancelled.
    pub fn cancel_press(&mut self) {
        self.press = None;
    }

    /// The pointer came up on dialog `id`'s Accept. Accepts only if the
    /// press was on the same dialog and both press and release came after
    /// the arming time (H4); the dialog then closes.
    pub fn release_accept(&mut self, id: SessionId, now: Millis) -> Option<Answer> {
        let press = self.press.take()?;
        if press.id != id || press.at < self.armed_at || now < self.armed_at {
            return None;
        }
        let pos = self.open.iter().position(|d| d.id == id)?;
        let d = self.open.remove(pos);
        self.changed(now);
        Some(Answer::Accept {
            id: d.id,
            sas: d.sas,
        })
    }

    /// A click on dialog `id`'s Deny: always allowed, no delay.
    pub fn deny(&mut self, id: SessionId, now: Millis) -> Option<Answer> {
        let pos = self.open.iter().position(|d| d.id == id)?;
        self.open.remove(pos);
        self.changed(now);
        Some(Answer::Deny { id })
    }

    /// A key on dialog `id` (H3): Return, Space and Escape deny; no key
    /// accepts.
    pub fn key(&mut self, id: SessionId, key: Key, now: Millis) -> Option<Answer> {
        match key {
            Key::Return | Key::Space | Key::Escape => self.deny(id, now),
            Key::Other => None,
        }
    }

    /// Whether Accept is armed at `now`.
    pub fn armed(&self, now: Millis) -> bool {
        now >= self.armed_at
    }

    /// Number of open dialogs.
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether no dialog is open.
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// What every open dialog shows at `now`, oldest first.
    pub fn view(&self, now: Millis) -> Vec<DialogView> {
        self.open
            .iter()
            .map(|d| {
                let ends = d.opened.plus(PROMPT_TIMEOUT_MS);
                DialogView {
                    id: d.id,
                    sas: crate::cli::format_sas(d.sas),
                    name: d.name.clone(),
                    device: d.device.clone(),
                    trust: match d.trust {
                        Trust::Pinned => "known device",
                        Trust::New => "new device",
                    },
                    seconds_left: ends.0.saturating_sub(now.0).div_ceil(1000),
                    accept_enabled: self.armed(now),
                }
            })
            .collect()
    }
}
