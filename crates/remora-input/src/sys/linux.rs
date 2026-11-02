//! Linux: input through the desktop portal's RemoteDesktop session that
//! is also showing the screen (`remora_capture::PortalInput`, D48).
//!
//! Everything here has already passed the decode checks and the
//! [`crate::guard::Guard`] (L3/L4); this module only translates units:
//!
//! * pointer 0..=1 → the shared monitor's logical pixels;
//! * buttons 1..=5 → evdev `BTN_LEFT`, `BTN_RIGHT`, `BTN_MIDDLE`,
//!   `BTN_SIDE` (back), `BTN_EXTRA` (forward) — linux/input-event-codes.h
//!   (kernel-headers 7.2.4, Fedora 44) lines 357–361; side/extra are what
//!   mice's thumb buttons send, which desktops treat as back/forward;
//! * keys: USB HID usage → evdev code from the generated table
//!   ([`crate::keymap`]);
//! * scroll: the viewer sends winit's convention (positive = content moves
//!   right/down, i.e. the person scrolled left/up); the portal's is the
//!   wheel's (positive = scroll down/right), so both axes are negated.
//!   Wheel lines become discrete steps, fractions carried to the next event;
//!   trackpad pixels become smooth scroll.

use remora_capture::PortalInput;

use crate::guard::{Backend, BackendError};

/// evdev button codes, linux/input-event-codes.h.
const BTN_LEFT: u32 = 0x110;
const BTN_RIGHT: u32 = 0x111;
const BTN_MIDDLE: u32 = 0x112;
const BTN_SIDE: u32 = 0x113;
const BTN_EXTRA: u32 = 0x114;

/// The injector for one session.
#[derive(Debug)]
pub struct PortalBackend {
    input: PortalInput,
    /// Wheel lines not yet sent as a whole step (vertical, horizontal).
    carry: (f32, f32),
}

impl PortalBackend {
    /// Injects through `input`.
    pub fn new(input: PortalInput) -> Self {
        Self {
            input,
            carry: (0.0, 0.0),
        }
    }
}

fn e(err: remora_capture::CaptureError) -> BackendError {
    BackendError(err.to_string())
}

/// Viewer button number → evdev code.
pub(crate) fn evdev_button(button: u32) -> Option<u32> {
    Some(match button {
        1 => BTN_LEFT,
        2 => BTN_RIGHT,
        3 => BTN_MIDDLE,
        4 => BTN_SIDE,
        5 => BTN_EXTRA,
        _ => return None,
    })
}

/// Whole wheel steps in `lines` plus what was carried; returns the steps
/// (portal sign) and keeps the rest.
pub(crate) fn steps(carry: &mut f32, lines: f32) -> i32 {
    let total = *carry - lines; // negate: winit → wheel convention
    let whole = total.trunc();
    *carry = total - whole;
    // |lines| ≤ SCROLL_MAX (10 000) after decode: fits an i32.
    whole as i32
}

impl Backend for PortalBackend {
    fn move_to(&mut self, x: f32, y: f32) -> Result<(), BackendError> {
        let (w, h) = self.input.size();
        let px = |v: f32, side: u32| f64::from(v.clamp(0.0, 1.0)) * f64::from(side);
        self.input.motion(px(x, w), px(y, h)).map_err(e)
    }

    fn button(&mut self, button: u32, down: bool) -> Result<(), BackendError> {
        let code = evdev_button(button).ok_or_else(|| BackendError(format!("button {button}")))?;
        self.input.button(code, down).map_err(e)
    }

    fn key(&mut self, usb_hid_usage: u32, down: bool) -> Result<(), BackendError> {
        let code = crate::keymap::evdev_key(usb_hid_usage)
            .ok_or_else(|| BackendError("key not in the table".into()))?;
        self.input.key(code, down).map_err(e)
    }

    fn scroll(&mut self, dx: f32, dy: f32, precise: bool) -> Result<(), BackendError> {
        if precise {
            return self
                .input
                .scroll_pixels(-f64::from(dx), -f64::from(dy))
                .map_err(e);
        }
        let v = steps(&mut self.carry.0, dy);
        let h = steps(&mut self.carry.1, dx);
        if v == 0 && h == 0 {
            return Ok(());
        }
        self.input.scroll_steps(v, h).map_err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buttons_map_to_evdev() {
        let got: Vec<_> = (0..=6).map(evdev_button).collect();
        assert_eq!(
            got,
            [
                None,
                Some(0x110),
                Some(0x111),
                Some(0x112),
                Some(0x113),
                Some(0x114),
                None
            ]
        );
    }

    #[test]
    fn wheel_lines_become_steps_with_the_sign_flipped_and_fractions_kept() {
        let mut c = 0.0;
        assert_eq!(steps(&mut c, 1.0), -1, "content down = scrolled up");
        assert_eq!(steps(&mut c, -3.0), 3);
        assert_eq!(steps(&mut c, -0.4), 0);
        assert_eq!(steps(&mut c, -0.4), 0);
        assert_eq!(steps(&mut c, -0.4), 1, "0.4 × 3 = one step");
        assert!((c - 0.2).abs() < 1e-5, "carry {c}");
    }
}
