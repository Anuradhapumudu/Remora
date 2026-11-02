//! The input guard: everything between a decoded `Input` message and the
//! OS injector (phase4.6-criteria L2, L3, L4).
//!
//! * **INV10 / L2:** the guard remembers every key and button the viewer
//!   holds and releases them when it is dropped. The host owns one guard
//!   per session and drops it when the session ends, however it ends, so
//!   release does not depend on the viewer sending `ReleaseAll` (a crashed
//!   viewer sends nothing).
//! * **L3:** a key outside our table ([`crate::keymap`]) never reaches the
//!   OS; it is dropped and counted. The other fields were checked when the
//!   envelope was decoded (`remora_proto::messages::decode_envelope`).
//! * **L4:** more than [`MAX_EVENTS_PER_SEC`] events in a second, or more
//!   than [`MAX_HELD`] keys and buttons held, is refused; the host ends the
//!   session.
//!
//! No I/O: the OS side is a [`Backend`].

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use remora_proto::messages::{Input, input};

/// Events per second above which the session is ended (L4). A fast typist
/// sends ~20 key events/s and the viewer at most ~125 pointer moves/s.
pub const MAX_EVENTS_PER_SEC: u32 = 2000;

/// Keys and buttons held at once above which the session is ended (L4).
pub const MAX_HELD: usize = 32;

/// The OS failed to inject an event.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("input backend: {0}")]
pub struct BackendError(pub String);

/// Why the guard refused an event; the host ends the session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// More than [`MAX_EVENTS_PER_SEC`] events in one second.
    #[error("more than {MAX_EVENTS_PER_SEC} input events in a second")]
    TooFast,
    /// More than [`MAX_HELD`] keys and buttons held at once.
    #[error("more than {MAX_HELD} keys and buttons held at once")]
    TooManyHeld,
    /// The OS side failed.
    #[error(transparent)]
    Backend(#[from] BackendError),
}

/// Injects input into the OS (one per platform under `sys/`, and fakes in
/// tests). Coordinates are 0..=1 within the shared monitor; keys are USB
/// HID usages already checked against [`crate::keymap`].
pub trait Backend {
    /// Moves the pointer.
    fn move_to(&mut self, x: f32, y: f32) -> Result<(), BackendError>;
    /// Presses or releases a mouse button (1 left, 2 right, 3 middle, 4 back, 5 forward).
    fn button(&mut self, button: u32, down: bool) -> Result<(), BackendError>;
    /// Presses or releases a key.
    fn key(&mut self, usb_hid_usage: u32, down: bool) -> Result<(), BackendError>;
    /// Scrolls: lines, or pixels when `precise`.
    fn scroll(&mut self, dx: f32, dy: f32, precise: bool) -> Result<(), BackendError>;
}

/// One session's input path. Drop it when the session ends (INV10).
pub struct Guard<B: Backend> {
    backend: B,
    keys: BTreeSet<u32>,
    buttons: BTreeSet<u32>,
    window_start: Option<Instant>,
    in_window: u32,
    dropped_keys: u64,
}

impl<B: Backend> Guard<B> {
    /// A guard over `backend`, holding nothing.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            keys: BTreeSet::new(),
            buttons: BTreeSet::new(),
            window_start: None,
            in_window: 0,
            dropped_keys: 0,
        }
    }

    /// The backend (tests; a host may need it for a status line).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Key events dropped because the key is not in our table (L3).
    pub fn dropped_keys(&self) -> u64 {
        self.dropped_keys
    }

    /// Applies one input message received at `now`. An error means the
    /// host must end the session; whatever is held is still released when
    /// the guard is dropped.
    pub fn apply(&mut self, msg: &Input, now: Instant) -> Result<(), Refused> {
        self.count(now)?;
        match &msg.kind {
            None => Ok(()),
            Some(input::Kind::Move(m)) => Ok(self.backend.move_to(m.x, m.y)?),
            Some(input::Kind::Button(b)) => {
                if b.down {
                    self.hold_room()?;
                    self.backend.move_to(b.x, b.y)?;
                    self.backend.button(b.button, true)?;
                    self.buttons.insert(b.button);
                } else if self.buttons.remove(&b.button) {
                    self.backend.move_to(b.x, b.y)?;
                    self.backend.button(b.button, false)?;
                }
                Ok(())
            }
            Some(input::Kind::Key(k)) => {
                if crate::keymap::evdev_key(k.usb_hid_usage).is_none() {
                    self.dropped_keys += 1;
                    return Ok(());
                }
                if k.down {
                    if !self.keys.contains(&k.usb_hid_usage) {
                        self.hold_room()?;
                    }
                    self.backend.key(k.usb_hid_usage, true)?;
                    self.keys.insert(k.usb_hid_usage);
                } else if self.keys.remove(&k.usb_hid_usage) {
                    self.backend.key(k.usb_hid_usage, false)?;
                }
                Ok(())
            }
            Some(input::Kind::Scroll(s)) => Ok(self.backend.scroll(s.dx, s.dy, s.precise)?),
            Some(input::Kind::ReleaseAll(_)) => {
                self.release_all();
                Ok(())
            }
        }
    }

    /// Releases every key and button held, and forgets them. Keeps going
    /// past backend errors: one failed release must not leave the rest held.
    pub fn release_all(&mut self) {
        for k in std::mem::take(&mut self.keys) {
            let _ = self.backend.key(k, false);
        }
        for b in std::mem::take(&mut self.buttons) {
            let _ = self.backend.button(b, false);
        }
    }

    fn hold_room(&self) -> Result<(), Refused> {
        if self.keys.len() + self.buttons.len() >= MAX_HELD {
            return Err(Refused::TooManyHeld);
        }
        Ok(())
    }

    fn count(&mut self, now: Instant) -> Result<(), Refused> {
        let start = *self.window_start.get_or_insert(now);
        if now.saturating_duration_since(start) >= Duration::from_secs(1) {
            self.window_start = Some(now);
            self.in_window = 0;
        }
        if self.in_window >= MAX_EVENTS_PER_SEC {
            return Err(Refused::TooFast);
        }
        self.in_window += 1;
        Ok(())
    }
}

impl<B: Backend> Drop for Guard<B> {
    /// INV10: however the session ended.
    fn drop(&mut self) {
        self.release_all();
    }
}
