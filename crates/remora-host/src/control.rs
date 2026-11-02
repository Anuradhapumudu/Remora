//! Remote control on the host: session events → one input guard per
//! Active session (phase4.6-criteria L1, L2, L4).
//!
//! * **L1 (INV1):** a guard exists only from `Active` until the session
//!   ends, so input for a session that is not Active never reaches the OS.
//!   The session layer already refuses input before Active (A20/A21);
//!   this is the second, independent check.
//! * **L2 (INV10):** every way a session ends arrives here as an event
//!   (`Closed` with any code: Goodbye, `disconnect`, a protocol violation;
//!   `Lost`: viewer crash, network gone, idle timeout). Each one drops the
//!   session's guard, and dropping a guard releases everything held. If the
//!   host itself stops, `Control` is dropped with it and so are the guards.
//! * **L4:** a guard refusal (flood, too many held, the OS injector failing)
//!   is returned so the host ends that session.
//!
//! No I/O and no OS code: the injector comes from a `connect` function
//! (the GNOME portal on Linux; none on macOS yet, Phase 6).

use std::collections::HashMap;
use std::time::Instant;

use remora_input::guard::{Backend, BackendError, Guard, Refused};
use remora_net::HostEvent;
use remora_session::{AppMessage, SessionId};

/// Opens the OS injector for a new session.
pub(crate) type Connect<B> = Box<dyn FnMut() -> Result<B, BackendError> + Send>;

/// What the host does after an event.
#[derive(Debug, PartialEq)]
pub(crate) enum Outcome {
    /// Nothing to do.
    None,
    /// The first input event of session `id` reached the OS.
    FirstInput(SessionId),
    /// Input arrived but this host has no injector (counted, not applied).
    NoInjector(SessionId),
    /// End session `id`: the guard refused (L4) or the injector failed.
    End(SessionId, Refused),
    /// The injector could not be opened for session `id`; the session
    /// stays view-only.
    ConnectFailed(SessionId, BackendError),
}

/// One host's remote-control state.
pub(crate) struct Control<B: Backend> {
    connect: Option<Connect<B>>,
    guards: HashMap<SessionId, Guard<B>>,
    /// Sessions that are Active (with or without an injector).
    active: HashMap<SessionId, u64>,
}

impl<B: Backend> Control<B> {
    /// `connect` is `None` where this OS has no injector yet.
    pub(crate) fn new(connect: Option<Connect<B>>) -> Self {
        Self {
            connect,
            guards: HashMap::new(),
            active: HashMap::new(),
        }
    }

    /// Whether remote control is available on this host.
    pub(crate) fn can_control(&self) -> bool {
        self.connect.is_some()
    }

    /// Applies one host event received at `now`.
    pub(crate) fn on_event(&mut self, ev: &HostEvent, now: Instant) -> Outcome {
        match ev {
            HostEvent::Active { id } => {
                self.active.insert(*id, 0);
                let Some(connect) = self.connect.as_mut() else {
                    return Outcome::None;
                };
                match connect() {
                    Ok(b) => {
                        self.guards.insert(*id, Guard::new(b));
                        Outcome::None
                    }
                    Err(e) => Outcome::ConnectFailed(*id, e),
                }
            }
            HostEvent::Deliver {
                id,
                msg: AppMessage::Input(input),
            } => {
                // L1: not Active (or already over) → nothing reaches the OS.
                let Some(count) = self.active.get_mut(id) else {
                    return Outcome::None;
                };
                *count += 1;
                let first = *count == 1;
                let Some(guard) = self.guards.get_mut(id) else {
                    return if first {
                        Outcome::NoInjector(*id)
                    } else {
                        Outcome::None
                    };
                };
                match guard.apply(input, now) {
                    Ok(()) if first => Outcome::FirstInput(*id),
                    Ok(()) => Outcome::None,
                    Err(r) => {
                        // Release now, not when the close comes back.
                        self.end(*id);
                        Outcome::End(*id, r)
                    }
                }
            }
            HostEvent::Closed { id, .. } | HostEvent::Lost { id } => {
                self.end(*id);
                Outcome::None
            }
            // A handshake failure: never Active, but forget it anyway.
            HostEvent::Failed { id, .. } | HostEvent::PromptClosed { id } => {
                self.end(*id);
                Outcome::None
            }
            HostEvent::Prompt { .. }
            | HostEvent::OtpRotated
            | HostEvent::ForceKeyframe
            | HostEvent::OtpUsed { .. }
            | HostEvent::RefusedBusy { .. } => Outcome::None,
        }
    }

    /// Session `id` is over: its guard is dropped, releasing what it held.
    fn end(&mut self, id: SessionId) {
        self.active.remove(&id);
        self.guards.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use remora_proto::messages::{Input, Key, PointerMove, input};
    use remora_session::{CloseCode, FailReason, Step};

    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    enum Op {
        Move,
        Key(u32, bool),
    }

    type Log = Arc<Mutex<Vec<Op>>>;

    struct Fake(Log);

    impl Fake {
        /// Still records while a failed assertion unwinds (the guard's
        /// Drop runs then); a second panic would abort every test.
        fn push(&self, op: Op) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(op);
        }
    }

    impl Backend for Fake {
        fn move_to(&mut self, _: f32, _: f32) -> Result<(), BackendError> {
            self.push(Op::Move);
            Ok(())
        }
        fn button(&mut self, _: u32, _: bool) -> Result<(), BackendError> {
            Ok(())
        }
        fn key(&mut self, k: u32, down: bool) -> Result<(), BackendError> {
            self.push(Op::Key(k, down));
            Ok(())
        }
        fn scroll(&mut self, _: f32, _: f32, _: bool) -> Result<(), BackendError> {
            Ok(())
        }
    }

    fn control() -> (Control<Fake>, Log) {
        let log = Log::default();
        let l = log.clone();
        (
            Control::new(Some(Box::new(move || Ok(Fake(l.clone()))))),
            log,
        )
    }

    const ID: SessionId = SessionId(7);
    const A: u32 = 0x04;

    fn deliver(id: SessionId, i: input::Kind) -> HostEvent {
        HostEvent::Deliver {
            id,
            msg: AppMessage::Input(Input { kind: Some(i) }),
        }
    }

    fn key_down(id: SessionId) -> HostEvent {
        deliver(
            id,
            input::Kind::Key(Key {
                usb_hid_usage: A,
                down: true,
            }),
        )
    }

    fn peer() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 9))
    }

    /// L1: input for a session that is not Active never reaches the OS:
    /// before Active (pending prompt), for an unknown session, and after
    /// the session ended.
    #[test]
    fn l1_input_reaches_the_os_only_while_active() {
        let (mut c, log) = control();
        let t = Instant::now();
        assert_eq!(c.on_event(&key_down(ID), t), Outcome::None, "before Active");
        assert!(
            log.lock().expect("log").is_empty(),
            "pending input injected"
        );

        c.on_event(&HostEvent::Active { id: ID }, t);
        assert_eq!(
            c.on_event(&key_down(SessionId(8)), t),
            Outcome::None,
            "another session's id"
        );
        assert!(log.lock().expect("log").is_empty());
        assert_eq!(c.on_event(&key_down(ID), t), Outcome::FirstInput(ID));
        assert_eq!(*log.lock().expect("log"), [Op::Key(A, true)]);

        c.on_event(
            &HostEvent::Closed {
                id: ID,
                code: CloseCode::Normal,
            },
            t,
        );
        log.lock().expect("log").clear();
        c.on_event(&key_down(ID), t);
        let after = log.lock().expect("log").clone();
        assert!(
            !after.contains(&Op::Key(A, true)),
            "input after the end: {after:?}"
        );
    }

    /// L2 (INV10): every end path releases what the viewer held.
    #[test]
    fn l2_every_end_path_releases_held_keys() {
        let ends = [
            ("Goodbye / disconnect", CloseCode::Normal),
            ("protocol violation", CloseCode::ProtocolViolation),
            ("capture stopped", CloseCode::CaptureStopped),
            ("timeout", CloseCode::Timeout),
        ]
        .map(|(what, code)| (what, HostEvent::Closed { id: ID, code }))
        .into_iter()
        .chain([
            (
                "viewer crash / network lost / idle timeout",
                HostEvent::Lost { id: ID },
            ),
            (
                "failure",
                HostEvent::Failed {
                    id: ID,
                    reason: FailReason::Timeout,
                    step: Step::Approval,
                    attempt: None,
                    peer: peer(),
                },
            ),
        ]);
        for (what, end) in ends {
            let (mut c, log) = control();
            let t = Instant::now();
            c.on_event(&HostEvent::Active { id: ID }, t);
            c.on_event(&key_down(ID), t);
            log.lock().expect("log").clear();
            c.on_event(&end, t);
            assert_eq!(
                *log.lock().expect("log"),
                [Op::Key(A, false)],
                "{what}: held key not released"
            );
        }
    }

    /// L2: the host stopping (Control dropped) releases too.
    #[test]
    fn l2_host_stopping_releases_held_keys() {
        let (mut c, log) = control();
        let t = Instant::now();
        c.on_event(&HostEvent::Active { id: ID }, t);
        c.on_event(&key_down(ID), t);
        log.lock().expect("log").clear();
        drop(c);
        assert_eq!(*log.lock().expect("log"), [Op::Key(A, false)]);
    }

    /// L4: a flood ends the session, and what was held is released at
    /// once (not when the close round trip comes back).
    #[test]
    fn l4_a_flood_ends_the_session_and_releases() {
        let (mut c, log) = control();
        let t = Instant::now();
        c.on_event(&HostEvent::Active { id: ID }, t);
        c.on_event(&key_down(ID), t);
        let mv = deliver(ID, input::Kind::Move(PointerMove { x: 0.5, y: 0.5 }));
        let mut ended = None;
        for _ in 0..10_000 {
            match c.on_event(&mv, t) {
                Outcome::End(id, r) => {
                    ended = Some((id, r));
                    break;
                }
                Outcome::None => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(ended, Some((ID, Refused::TooFast)));
        assert_eq!(log.lock().expect("log").last(), Some(&Op::Key(A, false)));
    }

    #[test]
    fn without_an_injector_input_is_counted_not_applied() {
        let mut c: Control<Fake> = Control::new(None);
        assert!(!c.can_control());
        let t = Instant::now();
        c.on_event(&HostEvent::Active { id: ID }, t);
        assert_eq!(c.on_event(&key_down(ID), t), Outcome::NoInjector(ID));
        assert_eq!(c.on_event(&key_down(ID), t), Outcome::None, "said once");
    }

    #[test]
    fn an_injector_that_cannot_open_leaves_the_session_view_only() {
        let mut c: Control<Fake> =
            Control::new(Some(Box::new(|| Err(BackendError("no portal".into())))));
        assert!(
            c.can_control(),
            "an injector is configured, even if it fails to open"
        );
        let t = Instant::now();
        assert_eq!(
            c.on_event(&HostEvent::Active { id: ID }, t),
            Outcome::ConnectFailed(ID, BackendError("no portal".into()))
        );
        assert_eq!(c.on_event(&key_down(ID), t), Outcome::NoInjector(ID));
    }
}
