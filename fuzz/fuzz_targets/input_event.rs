//! phase4.6-criteria L3: a sequence of input messages built from the fuzz
//! bytes, encoded, then through the host's decoder and the input guard. Whatever reaches
//! the backend (the OS, on a real host) must be in range: x and y finite in
//! 0..=1, button 1..=5, a key from our table, scroll finite and bounded,
//! never more than MAX_HELD held. And no panic, ever.
#![no_main]
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use prost::Message;
use remora_input::guard::{Backend, BackendError, Guard, MAX_HELD};
use remora_proto::limits::SCROLL_MAX;
use remora_proto::messages::{
    Envelope, Input, Key, MouseButton, PointerMove, ReleaseAll, Scroll, decode_envelope, envelope,
    input,
};

#[derive(Default)]
struct Checking {
    held: BTreeSet<(bool, u32)>,
}

fn unit(v: f32) -> bool {
    v.is_finite() && (0.0..=1.0).contains(&v)
}

impl Checking {
    fn hold(&mut self, id: (bool, u32), down: bool) {
        if down {
            self.held.insert(id);
        } else {
            self.held.remove(&id);
        }
        assert!(
            self.held.len() <= MAX_HELD,
            "more than MAX_HELD reached the OS"
        );
    }
}

impl Backend for Checking {
    fn move_to(&mut self, x: f32, y: f32) -> Result<(), BackendError> {
        assert!(unit(x) && unit(y), "pointer ({x}, {y}) reached the OS");
        Ok(())
    }
    fn button(&mut self, button: u32, down: bool) -> Result<(), BackendError> {
        assert!((1..=5).contains(&button), "button {button} reached the OS");
        self.hold((false, button), down);
        Ok(())
    }
    fn key(&mut self, usb_hid_usage: u32, down: bool) -> Result<(), BackendError> {
        assert!(
            remora_input::keymap::evdev_key(usb_hid_usage).is_some(),
            "key {usb_hid_usage:#x} reached the OS"
        );
        self.hold((true, usb_hid_usage), down);
        Ok(())
    }
    fn scroll(&mut self, dx: f32, dy: f32, _precise: bool) -> Result<(), BackendError> {
        let ok = |v: f32| v.is_finite() && v.abs() <= SCROLL_MAX;
        assert!(ok(dx) && ok(dy), "scroll ({dx}, {dy}) reached the OS");
        Ok(())
    }
}

/// Reads fields off the front of the fuzz input (zeros when it runs out).
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn u8(&mut self) -> u8 {
        let (b, rest) = self.0.split_first().map_or((0, &[][..]), |(b, r)| (*b, r));
        self.0 = rest;
        b
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    /// Any bit pattern: NaN, infinities, huge, negative.
    fn f32(&mut self) -> f32 {
        f32::from_bits(self.u32())
    }
    fn small(&mut self) -> u32 {
        // Most usages and buttons worth trying are small; mix both.
        if self.u8() & 1 == 0 {
            u32::from(self.u8())
        } else {
            self.u32()
        }
    }
}

/// One `Input` built from the bytes (so every run reaches the guard, not
/// just the protobuf parser, which the `messages` target already covers).
fn next_input(b: &mut Bytes) -> Input {
    let kind = match b.u8() % 6 {
        0 => input::Kind::Move(PointerMove {
            x: b.f32(),
            y: b.f32(),
        }),
        1 => input::Kind::Button(MouseButton {
            button: b.small(),
            down: b.u8() & 1 == 1,
            x: b.f32(),
            y: b.f32(),
        }),
        2 => input::Kind::Key(Key {
            usb_hid_usage: b.small(),
            down: b.u8() & 1 == 1,
        }),
        3 => input::Kind::Scroll(Scroll {
            dx: b.f32(),
            dy: b.f32(),
            precise: b.u8() & 1 == 1,
        }),
        4 => input::Kind::ReleaseAll(ReleaseAll {}),
        _ => return Input { kind: None },
    };
    Input { kind: Some(kind) }
}

fuzz_target!(|data: &[u8]| {
    let mut guard = Guard::new(Checking::default());
    let t0 = Instant::now();
    let mut b = Bytes(data);
    let mut us = 0u64;
    while !b.0.is_empty() {
        us += u64::from(b.u8()) * 50; // the clock moves, so the rate window does too
        let wire = Envelope {
            msg: Some(envelope::Msg::Input(next_input(&mut b))),
        }
        .encode_to_vec();
        // The host's path: bytes from the network -> decode checks -> guard.
        let Ok(env) = decode_envelope(&wire) else {
            continue;
        };
        if let Some(envelope::Msg::Input(input)) = env.msg {
            if guard.apply(&input, t0 + Duration::from_micros(us)).is_err() {
                break; // the host ends the session here
            }
        }
    }
    drop(guard); // INV10 releases go through the same checks
});
