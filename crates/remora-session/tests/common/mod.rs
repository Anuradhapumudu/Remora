//! Shared harness: an in-memory host ↔ viewer pump over the sans-IO API.
#![allow(dead_code, unreachable_pub)] // each test binary uses a subset
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

pub mod evil;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rand_core::OsRng;
use remora_crypto::identity::{DeviceId, IdentityKeypair};
use remora_crypto::noise::NoiseStaticKeypair;
use remora_crypto::sas::Sas;
use remora_crypto::secret::{Exporter, Otp};
use remora_session::{
    AppMessage, CloseCode, FailReason, Host, HostAction, HostConfig, Identity, Millis, SessionId,
    State, ViewerAction, ViewerConfig, ViewerMode, ViewerSession,
};
use remora_testkit::mock::CallLog;

pub struct Device {
    pub key: IdentityKeypair,
    pub identity: Arc<Identity>,
}

pub fn device(name: &str) -> Device {
    let key = IdentityKeypair::generate(&mut OsRng);
    let noise = NoiseStaticKeypair::generate(&mut OsRng);
    let cert = key.sign_cert(noise.public(), name, 1_760_000_000).unwrap();
    Device {
        key,
        identity: Arc::new(Identity { noise, cert }),
    }
}

pub fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

pub fn exporter(b: u8) -> Exporter {
    Exporter::from_bytes([b; 32])
}

pub const T0: Millis = Millis(1_000_000);

pub fn host_with(host: &Device, trusted: Vec<remora_crypto::identity::IdentityPublic>) -> Host {
    Host::new(
        HostConfig {
            identity: host.identity.clone(),
            password_enabled: true,
            trusted,
        },
        &mut OsRng,
    )
}

/// Everything that happened on one connection, both sides.
#[derive(Default)]
pub struct Log {
    pub host: Vec<HostAction>,
    pub viewer: Vec<ViewerAction>,
}

impl Log {
    pub fn host_close(&self) -> Option<CloseCode> {
        self.host.iter().find_map(|a| match a {
            HostAction::Close { code, .. } => Some(*code),
            _ => None,
        })
    }
    pub fn viewer_close(&self) -> Option<CloseCode> {
        self.viewer.iter().find_map(|a| match a {
            ViewerAction::Close(c) => Some(*c),
            _ => None,
        })
    }
    pub fn host_failure(&self) -> Option<FailReason> {
        self.host.iter().find_map(|a| match a {
            HostAction::Failed { reason, .. } => Some(reason.clone()),
            _ => None,
        })
    }
    pub fn viewer_failure(&self) -> Option<FailReason> {
        self.viewer.iter().find_map(|a| match a {
            ViewerAction::Failed { reason, .. } => Some(reason.clone()),
            _ => None,
        })
    }
    pub fn prompt(&self) -> Option<(SessionId, Sas)> {
        self.host.iter().find_map(|a| match a {
            HostAction::Prompt { id, sas, .. } => Some((*id, *sas)),
            _ => None,
        })
    }
    pub fn viewer_sas(&self) -> Option<Sas> {
        self.viewer.iter().find_map(|a| match a {
            ViewerAction::ShowSas { sas, .. } => Some(*sas),
            _ => None,
        })
    }
    /// Application messages delivered on either side — a mock injector /
    /// renderer call log (A20: must stay at 0 before Active).
    pub fn delivered(&self) -> CallLog {
        let log = CallLog::new();
        for a in &self.host {
            if let HostAction::Deliver { msg, .. } = a {
                log.record(format!("host got {msg:?}"));
            }
        }
        for a in &self.viewer {
            if let ViewerAction::Video(frame) = a {
                log.record(format!("viewer got {frame:?}"));
            }
        }
        log
    }
}

/// A host and one connected viewer, pumped in memory.
pub struct Conn {
    pub id: SessionId,
    /// The connection-code nonce this connection's hello carries.
    pub nonce: [u8; 16],
    pub viewer: ViewerSession,
    pub log: Log,
    pub now: Millis,
    /// Frames the viewer sent, in order (for replay / tamper tests).
    pub v2h: Vec<Vec<u8>>,
    /// Frames the host sent, in order.
    pub h2v: Vec<Vec<u8>>,
}

pub fn viewer_cfg(viewer: &Device, mode: ViewerMode) -> ViewerConfig {
    ViewerConfig {
        identity: viewer.identity.clone(),
        mode,
    }
}

pub fn password_mode(host: &Host, expect: Option<DeviceId>) -> ViewerMode {
    ViewerMode::Password {
        otp: host.otp().clone(),
        expect,
    }
}

pub fn wrong_password_mode(host: &Host) -> ViewerMode {
    let right: u32 = host.otp().reveal().parse().unwrap();
    let wrong = Otp::parse(&format!("{:06}", (right + 1) % 1_000_000)).unwrap();
    ViewerMode::Password {
        otp: wrong,
        expect: None,
    }
}

/// Admits a connection and starts the viewer, without sending anything yet.
pub fn start(
    host: &mut Host,
    viewer: &Device,
    mode: ViewerMode,
    from: IpAddr,
    now: Millis,
) -> (Conn, Vec<ViewerAction>) {
    let id = host
        .accept_connection(from, exporter(7), now, &mut OsRng)
        .expect("admitted");
    // Every connection uses a fresh nonce the host issued (A06: nonces are
    // single-use, as with real connection codes).
    let mut nonce = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce);
    host.issue_nonce(nonce, now.plus(300_000));
    let (viewer, first) = ViewerSession::start(viewer_cfg(viewer, mode), nonce, exporter(7), now);
    let c = Conn {
        id,
        nonce,
        viewer,
        log: Log::default(),
        now,
        v2h: Vec::new(),
        h2v: Vec::new(),
    };
    (c, first)
}

/// Admits a connection and runs it as far as it goes.
pub fn connect(
    host: &mut Host,
    viewer: &Device,
    mode: ViewerMode,
    from: IpAddr,
    now: Millis,
) -> Conn {
    let (mut c, first) = start(host, viewer, mode, from, now);
    c.feed_viewer_actions(host, first);
    c
}

impl Conn {
    /// Routes viewer actions to the host (and host actions back), until
    /// nothing more is sent. `tamper(dir_is_v2h, index, frame)` may change
    /// or drop (return None) a frame in flight.
    pub fn feed_viewer_actions(&mut self, host: &mut Host, actions: Vec<ViewerAction>) {
        self.pump(host, actions, Vec::new(), &mut |_, _, f| Some(f));
    }

    pub fn pump(
        &mut self,
        host: &mut Host,
        mut viewer_out: Vec<ViewerAction>,
        mut host_out: Vec<HostAction>,
        tamper: &mut dyn FnMut(bool, usize, Vec<u8>) -> Option<Vec<u8>>,
    ) {
        loop {
            let mut progressed = false;
            for a in std::mem::take(&mut viewer_out) {
                if let ViewerAction::Send(frame) = &a {
                    let idx = self.v2h.len();
                    self.v2h.push(frame.clone());
                    if let Some(f) = tamper(true, idx, frame.clone()) {
                        host_out.extend(host.on_frame(self.id, &f, self.now, &mut OsRng));
                        progressed = true;
                    }
                }
                self.log.viewer.push(a);
            }
            for a in std::mem::take(&mut host_out) {
                if let HostAction::Send { id, frame } = &a
                    && *id == self.id
                {
                    let idx = self.h2v.len();
                    self.h2v.push(frame.clone());
                    if let Some(f) = tamper(false, idx, frame.clone()) {
                        viewer_out.extend(self.viewer.on_frame(&f, self.now, &mut OsRng));
                        progressed = true;
                    }
                }
                self.log.host.push(a);
            }
            if !progressed && viewer_out.is_empty() && host_out.is_empty() {
                break;
            }
        }
    }

    /// Host-side actions produced outside the pump (approve, tick, …).
    pub fn host_actions(&mut self, host: &mut Host, actions: Vec<HostAction>) {
        self.pump(host, Vec::new(), actions, &mut |_, _, f| Some(f));
    }

    pub fn approve(&mut self, host: &mut Host) {
        let (id, sas) = self.log.prompt().expect("prompt shown");
        let acts = host.approve(id, sas, T0).expect("approve");
        self.host_actions(host, acts);
    }
}

/// Full password-mode connection up to the prompt.
pub fn to_prompt(host: &mut Host, viewer: &Device, from: IpAddr) -> Conn {
    let mode = password_mode(host, None);
    connect(host, viewer, mode, from, T0)
}

/// Full password-mode connection, approved.
pub fn to_active(host: &mut Host, viewer: &Device, from: IpAddr) -> Conn {
    let mut c = to_prompt(host, viewer, from);
    c.approve(host);
    c
}

/// Encoded application messages of every type, as plaintext envelopes.
pub fn app_envelopes() -> Vec<(&'static str, Vec<u8>)> {
    use prost::Message;
    use remora_proto::messages::*;
    let input = |k: input::Kind| {
        Envelope {
            msg: Some(envelope::Msg::Input(Input { kind: Some(k) })),
        }
        .encode_to_vec()
    };
    let control = |k: control::Kind| {
        Envelope {
            msg: Some(envelope::Msg::Control(Control { kind: Some(k) })),
        }
        .encode_to_vec()
    };
    vec![
        (
            "mouse button",
            input(input::Kind::Button(MouseButton {
                button: 1,
                down: true,
                x: 0.5,
                y: 0.5,
            })),
        ),
        (
            "key",
            input(input::Kind::Key(Key {
                usb_hid_usage: 4,
                down: true,
            })),
        ),
        (
            "media key",
            control(control::Kind::MediaKey(MediaKeyAnnounce {
                key_id: 1,
                key: vec![9; 32],
            })),
        ),
        (
            "accept",
            control(control::Kind::Accept(SessionAccept { role: 1 })),
        ),
        (
            "sas reveal",
            control(control::Kind::SasReveal(SasReveal { n_r: vec![1; 32] })),
        ),
        // Phase 4 §7: host → viewer, Active only. Appended so the A20/A21
        // loops put it through every state too.
        (
            "stream state",
            control(control::Kind::StreamState(StreamState {
                paused: true,
                reason: 1,
                remaining_ms: 0,
            })),
        ),
        // Phase 4 step 5: viewer → host keyframe request, Active only.
        (
            "recovery request",
            control(control::Kind::Recovery(RecoveryRequest {})),
        ),
    ]
}

pub fn state_of(host: &Host, c: &Conn) -> (Option<State>, State) {
    (host.state(c.id), c.viewer.state())
}

pub fn delivered_count(c: &Conn) -> usize {
    c.log.delivered().count()
}

pub fn input_click() -> remora_proto::messages::Input {
    use remora_proto::messages::{Input, MouseButton, input};
    Input {
        kind: Some(input::Kind::Button(MouseButton {
            button: 1,
            down: true,
            x: 0.25,
            y: 0.75,
        })),
    }
}

pub fn is_input(msg: &AppMessage) -> bool {
    matches!(msg, AppMessage::Input(_))
}
