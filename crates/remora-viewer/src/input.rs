//! Mouse and keyboard in the video window → `Input` messages for the host
//! (phase4.6-criteria step 3; protocol.md §5).
//!
//! * Keys travel as USB HID usages (physical positions): the Mac's ⌘ is the
//!   host's Super (owner, 2026-11-02, Q3). Key repeats are not sent; the
//!   host's own system repeats a held key.
//! * The picture fills the window (render.rs stretches it), so a pointer
//!   position is simply its fraction of the window's size, clamped to 0..1.
//! * Pointer motion is coalesced: at most one `PointerMove` per
//!   [`MOVE_EVERY`]; the latest position waits and goes out with the next
//!   event or [`InputState::flush`] (called once per drawn picture).
//! * Losing focus sends `ReleaseAll` and forgets what was held, so nothing
//!   stays pressed on the host while the person types elsewhere. The host
//!   releases everything at session end itself (INV10) and does not rely
//!   on this.
//!
//! No I/O here: events in, messages out (tested without a window).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use remora_proto::limits::SCROLL_MAX;
use remora_proto::messages::{Input, Key, MouseButton, PointerMove, ReleaseAll, Scroll, input};
use winit::event::{ElementState, MouseScrollDelta, WindowEvent};
use winit::keyboard::PhysicalKey;

/// Pointer motion is sent at most this often (≈ 125/s, one per frame at
/// 120 Hz; phase4.6-criteria Q2).
pub(crate) const MOVE_EVERY: Duration = Duration::from_millis(8);

/// The translation state of one video window.
#[derive(Debug, Default)]
pub(crate) struct InputState {
    /// Window size in physical pixels.
    size: (u32, u32),
    /// Last pointer position, 0..1.
    at: Option<(f32, f32)>,
    /// A position not sent yet (coalescing).
    pending_move: bool,
    last_move: Option<Instant>,
    keys: BTreeSet<u32>,
    buttons: BTreeSet<u32>,
}

fn msg(kind: input::Kind) -> Input {
    Input { kind: Some(kind) }
}

impl InputState {
    /// The window's size changed (physical pixels).
    pub(crate) fn resized(&mut self, width: u32, height: u32) {
        self.size = (width, height);
    }

    /// One window event; returns the messages to send now.
    pub(crate) fn event(&mut self, event: &WindowEvent, now: Instant) -> Vec<Input> {
        match event {
            WindowEvent::Resized(s) => {
                self.resized(s.width, s.height);
                vec![]
            }
            WindowEvent::CursorMoved { position, .. } => self.moved(position.x, position.y, now),
            WindowEvent::MouseInput { state, button, .. } => {
                let b = match button {
                    winit::event::MouseButton::Left => 1,
                    winit::event::MouseButton::Right => 2,
                    winit::event::MouseButton::Middle => 3,
                    winit::event::MouseButton::Back => 4,
                    winit::event::MouseButton::Forward => 5,
                    winit::event::MouseButton::Other(_) => return vec![],
                };
                self.button(b, *state == ElementState::Pressed)
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let (dx, dy, precise) = match delta {
                    MouseScrollDelta::LineDelta(x, y) => (*x, *y, false),
                    MouseScrollDelta::PixelDelta(p) => (p.x as f32, p.y as f32, true),
                };
                self.scroll(dx, dy, precise)
            }
            WindowEvent::KeyboardInput { event, .. } => match event.physical_key {
                PhysicalKey::Code(code) => match crate::keymap::hid_usage(code) {
                    Some(usage) => {
                        self.key(usage, event.state == ElementState::Pressed, event.repeat)
                    }
                    None => vec![],
                },
                PhysicalKey::Unidentified(_) => vec![],
            },
            WindowEvent::Focused(false) => self.focus_lost(),
            _ => vec![],
        }
    }

    /// The pointer is at (x, y) physical pixels inside the window.
    pub(crate) fn moved(&mut self, x: f64, y: f64, now: Instant) -> Vec<Input> {
        let (w, h) = self.size;
        if w == 0 || h == 0 || !x.is_finite() || !y.is_finite() {
            return vec![];
        }
        let fx = (x / f64::from(w)).clamp(0.0, 1.0) as f32;
        let fy = (y / f64::from(h)).clamp(0.0, 1.0) as f32;
        self.at = Some((fx, fy));
        self.pending_move = true;
        if self
            .last_move
            .is_some_and(|t| now.duration_since(t) < MOVE_EVERY)
        {
            return vec![];
        }
        self.flush(now).into_iter().collect()
    }

    /// The coalesced pointer position, if one is waiting.
    pub(crate) fn flush(&mut self, now: Instant) -> Option<Input> {
        if !self.pending_move {
            return None;
        }
        let (x, y) = self.at?;
        self.pending_move = false;
        self.last_move = Some(now);
        Some(msg(input::Kind::Move(PointerMove { x, y })))
    }

    /// Button 1..=5 pressed or released at the last pointer position.
    pub(crate) fn button(&mut self, button: u32, down: bool) -> Vec<Input> {
        let Some((x, y)) = self.at else {
            return vec![]; // never moved inside the window: no position to click at
        };
        if down {
            self.buttons.insert(button);
        } else if !self.buttons.remove(&button) {
            return vec![]; // a release for a press the host never saw
        }
        // The position first, so the click lands where the pointer is.
        let mut out: Vec<Input> = self.flush_now();
        out.push(msg(input::Kind::Button(MouseButton { button, down, x, y })));
        out
    }

    fn flush_now(&mut self) -> Vec<Input> {
        self.flush(Instant::now()).into_iter().collect()
    }

    /// Scroll by (dx, dy): lines, or pixels when `precise`.
    pub(crate) fn scroll(&mut self, dx: f32, dy: f32, precise: bool) -> Vec<Input> {
        if !dx.is_finite() || !dy.is_finite() || (dx == 0.0 && dy == 0.0) {
            return vec![];
        }
        let c = |v: f32| v.clamp(-SCROLL_MAX, SCROLL_MAX);
        let mut out = self.flush_now();
        out.push(msg(input::Kind::Scroll(Scroll {
            dx: c(dx),
            dy: c(dy),
            precise,
        })));
        out
    }

    /// A key (USB HID usage) pressed or released; repeats are dropped.
    pub(crate) fn key(&mut self, usage: u32, down: bool, repeat: bool) -> Vec<Input> {
        if repeat {
            return vec![];
        }
        if down {
            self.keys.insert(usage);
        } else if !self.keys.remove(&usage) {
            return vec![]; // pressed before the window had focus
        }
        vec![msg(input::Kind::Key(Key {
            usb_hid_usage: usage,
            down,
        }))]
    }

    /// The window lost focus: release everything on the host.
    pub(crate) fn focus_lost(&mut self) -> Vec<Input> {
        let held = !self.keys.is_empty() || !self.buttons.is_empty();
        self.keys.clear();
        self.buttons.clear();
        if held {
            vec![msg(input::Kind::ReleaseAll(ReleaseAll {}))]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> InputState {
        let mut s = InputState::default();
        s.resized(2000, 1000);
        s
    }

    fn kind(i: &Input) -> &input::Kind {
        i.kind.as_ref().expect("kind")
    }

    #[test]
    fn position_is_a_fraction_of_the_window_clamped() {
        let mut s = state();
        let t = Instant::now();
        let out = s.moved(500.0, 250.0, t);
        assert_eq!(
            out.iter().map(kind).collect::<Vec<_>>(),
            [&input::Kind::Move(PointerMove { x: 0.25, y: 0.25 })]
        );
        let out = s.moved(-50.0, 5000.0, t + MOVE_EVERY);
        assert_eq!(
            kind(&out[0]),
            &input::Kind::Move(PointerMove { x: 0.0, y: 1.0 })
        );
    }

    #[test]
    fn motion_is_coalesced_and_the_latest_goes_out() {
        let mut s = state();
        let t = Instant::now();
        assert_eq!(s.moved(0.0, 0.0, t).len(), 1);
        for i in 1..50 {
            assert!(
                s.moved(f64::from(i), 0.0, t + Duration::from_millis(1))
                    .is_empty()
            );
        }
        let late = s.flush(t + MOVE_EVERY).expect("pending move");
        assert_eq!(
            kind(&late),
            &input::Kind::Move(PointerMove {
                x: 49.0 / 2000.0,
                y: 0.0
            })
        );
        assert!(s.flush(t + MOVE_EVERY * 2).is_none(), "sent once");
    }

    #[test]
    fn a_click_sends_the_waiting_position_first() {
        let mut s = state();
        let t = Instant::now();
        s.moved(0.0, 0.0, t);
        s.moved(1000.0, 500.0, t + Duration::from_millis(1)); // coalesced
        let out = s.button(1, true);
        assert_eq!(out.len(), 2);
        assert_eq!(
            kind(&out[0]),
            &input::Kind::Move(PointerMove { x: 0.5, y: 0.5 })
        );
        assert_eq!(
            kind(&out[1]),
            &input::Kind::Button(MouseButton {
                button: 1,
                down: true,
                x: 0.5,
                y: 0.5
            })
        );
    }

    #[test]
    fn no_click_before_the_pointer_was_inside() {
        let mut s = state();
        assert!(s.button(1, true).is_empty());
    }

    #[test]
    fn unmatched_releases_and_repeats_are_not_sent() {
        let mut s = state();
        assert!(
            s.key(0x04, false, false).is_empty(),
            "release without press"
        );
        assert_eq!(s.key(0x04, true, false).len(), 1);
        assert!(s.key(0x04, true, true).is_empty(), "repeat");
        assert_eq!(s.key(0x04, false, false).len(), 1);
    }

    #[test]
    fn losing_focus_releases_everything_once() {
        let mut s = state();
        s.moved(10.0, 10.0, Instant::now());
        s.key(0xE3, true, false); // ⌘ held while switching apps (⌘-Tab)
        s.button(1, true);
        let out = s.focus_lost();
        assert_eq!(
            out.iter().map(kind).collect::<Vec<_>>(),
            [&input::Kind::ReleaseAll(ReleaseAll {})]
        );
        assert!(s.focus_lost().is_empty(), "nothing held any more");
        assert!(s.key(0xE3, false, false).is_empty(), "already released");
    }

    #[test]
    fn scroll_is_clamped_and_empty_scrolls_are_dropped() {
        let mut s = state();
        assert!(s.scroll(0.0, 0.0, false).is_empty());
        assert!(s.scroll(f32::NAN, 1.0, false).is_empty());
        let out = s.scroll(0.0, -1e9, true);
        assert_eq!(
            kind(&out[0]),
            &input::Kind::Scroll(Scroll {
                dx: 0.0,
                dy: -SCROLL_MAX,
                precise: true
            })
        );
    }

    #[test]
    fn command_is_super_and_letters_are_physical() {
        use winit::keyboard::KeyCode;
        assert_eq!(crate::keymap::hid_usage(KeyCode::SuperLeft), Some(0xE3));
        assert_eq!(crate::keymap::hid_usage(KeyCode::KeyA), Some(0x04));
        assert_eq!(crate::keymap::hid_usage(KeyCode::Fn), None);
    }

    /// Every message this module can produce passes the host's decode
    /// checks (L3), so a correct viewer never ends its own session.
    #[test]
    fn everything_sent_passes_the_protocol_checks() {
        use prost::Message;
        use remora_proto::messages::{Envelope, decode_envelope, envelope};
        let mut s = state();
        let t = Instant::now();
        let mut all = s.moved(1999.9, 999.9, t);
        all.extend(s.button(5, true));
        all.extend(s.scroll(1e9, -1e9, false));
        all.extend(s.key(0xE7, true, false));
        all.extend(s.focus_lost());
        assert_eq!(all.len(), 5);
        for i in all {
            let bytes = Envelope {
                msg: Some(envelope::Msg::Input(i)),
            }
            .encode_to_vec();
            decode_envelope(&bytes).expect("valid on the wire");
        }
    }
}
