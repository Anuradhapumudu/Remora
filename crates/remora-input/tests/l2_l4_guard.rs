//! phase4.6-criteria L2 (INV10), L3 and L4: the input guard between the
//! network and the OS injector. Written before the guard does anything.

use std::time::{Duration, Instant};

use remora_input::guard::{Backend, BackendError, Guard, MAX_EVENTS_PER_SEC, MAX_HELD, Refused};
use remora_proto::messages::{Input, Key, MouseButton, PointerMove, ReleaseAll, Scroll, input};

/// What the fake OS received.
#[derive(Debug, Clone, PartialEq)]
enum Op {
    Move(f32, f32),
    Button(u32, bool),
    Key(u32, bool),
    Scroll(f32, f32, bool),
}

#[derive(Default)]
struct Fake {
    ops: std::sync::Arc<std::sync::Mutex<Vec<Op>>>,
    fail: bool,
    /// Fail this one operation only.
    fail_on: Option<Op>,
}

impl Backend for Fake {
    fn move_to(&mut self, x: f32, y: f32) -> Result<(), BackendError> {
        self.push(Op::Move(x, y))
    }
    fn button(&mut self, button: u32, down: bool) -> Result<(), BackendError> {
        self.push(Op::Button(button, down))
    }
    fn key(&mut self, usb_hid_usage: u32, down: bool) -> Result<(), BackendError> {
        self.push(Op::Key(usb_hid_usage, down))
    }
    fn scroll(&mut self, dx: f32, dy: f32, precise: bool) -> Result<(), BackendError> {
        self.push(Op::Scroll(dx, dy, precise))
    }
}

impl Fake {
    fn push(&mut self, op: Op) -> Result<(), BackendError> {
        if self.fail || self.fail_on.as_ref() == Some(&op) {
            return Err(BackendError("the portal session is gone".into()));
        }
        self.ops
            .lock()
            .map_err(|_| BackendError("poisoned".into()))?
            .push(op);
        Ok(())
    }
}

fn guard() -> (Guard<Fake>, std::sync::Arc<std::sync::Mutex<Vec<Op>>>) {
    let fake = Fake::default();
    let ops = fake.ops.clone();
    (Guard::new(fake), ops)
}

fn key(usage: u32, down: bool) -> Input {
    Input {
        kind: Some(input::Kind::Key(Key {
            usb_hid_usage: usage,
            down,
        })),
    }
}

fn button(b: u32, down: bool) -> Input {
    Input {
        kind: Some(input::Kind::Button(MouseButton {
            button: b,
            down,
            x: 0.5,
            y: 0.5,
        })),
    }
}

fn mv(x: f32, y: f32) -> Input {
    Input {
        kind: Some(input::Kind::Move(PointerMove { x, y })),
    }
}

const A: u32 = 0x04;
const SUPER: u32 = 0xE3;

#[test]
fn events_reach_the_backend() {
    let (mut g, ops) = guard();
    let t = Instant::now();
    g.apply(&mv(0.25, 0.75), t).unwrap();
    g.apply(&button(1, true), t).unwrap();
    g.apply(&key(A, true), t).unwrap();
    let s = Input {
        kind: Some(input::Kind::Scroll(Scroll {
            dx: 0.0,
            dy: -2.0,
            precise: false,
        })),
    };
    g.apply(&s, t).unwrap();
    assert_eq!(
        *ops.lock().unwrap(),
        [
            Op::Move(0.25, 0.75),
            Op::Move(0.5, 0.5), // a click goes where it says
            Op::Button(1, true),
            Op::Key(A, true),
            Op::Scroll(0.0, -2.0, false),
        ]
    );
}

/// INV10: dropping the guard (any session end: Goodbye, timeout, the
/// viewer crashing, a host error, a panic unwinding) releases every key
/// and button the viewer holds.
#[test]
fn inv10_dropping_the_guard_releases_everything_held() {
    let (mut g, ops) = guard();
    let t = Instant::now();
    g.apply(&key(SUPER, true), t).unwrap();
    g.apply(&key(A, true), t).unwrap();
    g.apply(&button(1, true), t).unwrap();
    g.apply(&button(3, true), t).unwrap();
    g.apply(&button(3, false), t).unwrap(); // released by the viewer already
    ops.lock().unwrap().clear();
    drop(g);
    let released = ops.lock().unwrap().clone();
    // The order does not matter; each release exactly once.
    assert_eq!(released.len(), 3, "{released:?}");
    for want in [
        Op::Button(1, false),
        Op::Key(A, false),
        Op::Key(SUPER, false),
    ] {
        assert!(
            released.contains(&want),
            "{want:?} not released: {released:?}"
        );
    }
}

#[test]
fn inv10_release_all_from_the_viewer_releases_and_forgets() {
    let (mut g, ops) = guard();
    let t = Instant::now();
    g.apply(&key(A, true), t).unwrap();
    g.apply(
        &Input {
            kind: Some(input::Kind::ReleaseAll(ReleaseAll {})),
        },
        t,
    )
    .unwrap();
    assert_eq!(ops.lock().unwrap().last(), Some(&Op::Key(A, false)));
    ops.lock().unwrap().clear();
    drop(g);
    assert!(ops.lock().unwrap().is_empty(), "nothing left to release");
}

#[test]
fn inv10_release_happens_even_when_the_backend_failed() {
    let (mut g, ops) = guard();
    let t = Instant::now();
    g.apply(&key(A, true), t).unwrap();
    g.backend_mut().fail = true;
    assert!(matches!(
        g.apply(&key(SUPER, true), t),
        Err(Refused::Backend(_))
    ));
    g.backend_mut().fail = false; // e.g. the portal came back for the release
    ops.lock().unwrap().clear();
    drop(g);
    assert_eq!(*ops.lock().unwrap(), [Op::Key(A, false)]);
}

/// L3: a HID usage outside our key table never reaches the OS; it is
/// dropped and counted, the session goes on.
#[test]
fn l3_unknown_keys_are_dropped_and_counted() {
    let (mut g, ops) = guard();
    let t = Instant::now();
    for usage in [0x01, 0x66 /* Power */, 0xA5, 0xFFFF] {
        g.apply(&key(usage, true), t).unwrap();
    }
    assert!(ops.lock().unwrap().is_empty());
    assert_eq!(g.dropped_keys(), 4);
}

#[test]
fn releases_for_keys_never_pressed_are_ignored() {
    let (mut g, ops) = guard();
    g.apply(&key(A, false), Instant::now()).unwrap();
    g.apply(&button(2, false), Instant::now()).unwrap();
    assert!(ops.lock().unwrap().is_empty());
}

/// L4: a flood ends the session (the host closes it with a counted
/// reason) instead of driving the OS.
#[test]
fn l4_a_flood_is_refused() {
    let (mut g, ops) = guard();
    let t = Instant::now();
    let mut refused_at = None;
    for i in 0..10_000u32 {
        if let Err(e) = g.apply(&mv(0.5, 0.5), t + Duration::from_micros(u64::from(i))) {
            assert_eq!(e, Refused::TooFast);
            refused_at = Some(i);
            break;
        }
    }
    assert_eq!(refused_at, Some(MAX_EVENTS_PER_SEC));
    assert_eq!(ops.lock().unwrap().len(), MAX_EVENTS_PER_SEC as usize);
}

#[test]
fn l4_the_rate_is_per_second() {
    let (mut g, _) = guard();
    let t = Instant::now();
    for s in 0..5u64 {
        for i in 0..MAX_EVENTS_PER_SEC {
            let at = t + Duration::from_secs(s) + Duration::from_micros(u64::from(i) * 400);
            g.apply(&mv(0.5, 0.5), at).unwrap();
        }
    }
}

#[test]
fn l4_too_many_keys_held_is_refused() {
    let (mut g, _) = guard();
    let t = Instant::now();
    let usages: Vec<u32> = (0x04..=0x27).collect(); // A..Z, 1..0: 36 keys
    let mut n = 0;
    for u in usages {
        match g.apply(&key(u, true), t) {
            Ok(()) => n += 1,
            Err(e) => {
                assert_eq!(e, Refused::TooManyHeld);
                break;
            }
        }
    }
    assert_eq!(n, MAX_HELD);
}

/// INV10: one release the OS refuses must not leave the others held.
#[test]
fn inv10_one_failed_release_does_not_stop_the_others() {
    let (mut g, ops) = guard();
    let t = Instant::now();
    for u in [0x04, 0x05, 0x06] {
        g.apply(&key(u, true), t).unwrap();
    }
    g.apply(&button(1, true), t).unwrap();
    g.backend_mut().fail_on = Some(Op::Key(0x04, false)); // the first one released
    ops.lock().unwrap().clear();
    drop(g);
    let released = ops.lock().unwrap().clone();
    for want in [
        Op::Key(0x05, false),
        Op::Key(0x06, false),
        Op::Button(1, false),
    ] {
        assert!(released.contains(&want), "{want:?} left held: {released:?}");
    }
}
