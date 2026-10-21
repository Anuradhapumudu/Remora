//! M7 (phase4-criteria §5), session half: "decoder errors handled →
//! keyframe request". The viewer asks with `RecoveryRequest` (protocol.md
//! §5 tag 9); the host answers with one forced keyframe. Both sides limit
//! the rate to one per `KEYFRAME_REQUEST_INTERVAL_MS`, the host for all
//! viewers together (one shared encoder), so no viewer can make the host
//! send keyframes only.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::evil::{control_envelope, evil_host_viewer_pending};
use common::*;
use rand_core::OsRng;
use remora_proto::messages::{Envelope, RecoveryRequest, SessionAccept, control};
use remora_session::media::KEYFRAME_REQUEST_INTERVAL_MS;
use remora_session::{FailReason, Host, HostAction, State, ViewerAction, Violation};

fn keyframes(acts: &[HostAction]) -> usize {
    acts.iter()
        .filter(|a| **a == HostAction::ForceKeyframe)
        .count()
}

/// The viewer asks at `c.now`; returns how many keyframes the host forced.
fn ask(host: &mut Host, c: &mut Conn) -> Option<usize> {
    let a = c.viewer.request_keyframe(c.now)?;
    let before = c.log.host.len();
    c.feed_viewer_actions(host, vec![a]);
    Some(keyframes(&c.log.host[before..]))
}

fn active_host() -> (Host, Conn) {
    let mut host = host_with(&device("host"), vec![]);
    let c = to_active(&mut host, &device("viewer"), ip(1));
    (host, c)
}

#[test]
fn m7_a_keyframe_request_makes_the_host_force_a_keyframe() {
    let (mut host, mut c) = active_host();
    c.now = c.now.plus(KEYFRAME_REQUEST_INTERVAL_MS);
    let a = c.viewer.request_keyframe(c.now).expect("request sent");
    // Encrypted: the request is a Noise transport frame, not a plaintext
    // envelope.
    let ViewerAction::Send(frame) = &a else {
        panic!("{a:?}")
    };
    let plain = prost::Message::encode_to_vec(&Envelope {
        msg: Some(remora_proto::messages::envelope::Msg::Control(
            remora_proto::messages::Control {
                kind: Some(control::Kind::Recovery(RecoveryRequest {})),
            },
        )),
    });
    assert_ne!(frame, &plain);
    let before = c.log.host.len();
    c.feed_viewer_actions(&mut host, vec![a]);
    assert_eq!(keyframes(&c.log.host[before..]), 1);
    assert_eq!(host.state(c.id), Some(State::Active), "session continues");
    assert_eq!(c.viewer.state(), State::Active);
}

#[test]
fn m7_the_viewer_asks_at_most_once_per_interval() {
    let (mut host, mut c) = active_host();
    let t = c.now.plus(10_000);
    assert!(c.viewer.request_keyframe(t).is_some());
    assert!(c.viewer.request_keyframe(t).is_none(), "same instant");
    let almost = t.plus(KEYFRAME_REQUEST_INTERVAL_MS - 1);
    assert!(c.viewer.request_keyframe(almost).is_none(), "1 ms early");
    let next = t.plus(KEYFRAME_REQUEST_INTERVAL_MS);
    assert!(c.viewer.request_keyframe(next).is_some(), "interval over");
    // The first request after Active is never held back.
    let mut fresh = to_active(&mut host, &device("viewer2"), ip(2));
    assert!(fresh.viewer.request_keyframe(fresh.now).is_some());
}

#[test]
fn m7_the_host_forces_at_most_one_keyframe_per_interval_for_all_viewers() {
    let mut host = host_with(&device("host"), vec![]);
    let mut a = to_active(&mut host, &device("viewer-a"), ip(1));
    let mut b = to_active(&mut host, &device("viewer-b"), ip(2));
    let t = a.now.plus(10_000);
    a.now = t;
    b.now = t;
    assert_eq!(ask(&mut host, &mut a), Some(1));
    // Viewer B asks within the interval: answered by the same keyframe.
    b.now = t.plus(KEYFRAME_REQUEST_INTERVAL_MS - 1);
    assert_eq!(ask(&mut host, &mut b), Some(0));
    assert_eq!(host.state(b.id), Some(State::Active), "not a violation");
    // After the interval, B's next request is answered.
    b.now = t.plus(KEYFRAME_REQUEST_INTERVAL_MS);
    assert_eq!(ask(&mut host, &mut b), Some(1));
    // A, asking at its own pace, just inside the host's interval from B's.
    a.now = b.now.plus(KEYFRAME_REQUEST_INTERVAL_MS - 1);
    assert_eq!(ask(&mut host, &mut a), Some(0));
}

#[test]
fn m7_no_keyframe_request_before_active() {
    let mut host = host_with(&device("host"), vec![]);
    let mut c = to_prompt(&mut host, &device("viewer"), ip(1));
    assert_eq!(c.viewer.state(), State::PendingApproval);
    assert!(c.viewer.request_keyframe(c.now).is_none());
    c.approve(&mut host);
    assert!(c.viewer.request_keyframe(c.now).is_some());
    c.viewer.disconnect();
    assert!(c.viewer.request_keyframe(c.now.plus(60_000)).is_none());
}

#[test]
fn m7_a_host_sending_a_keyframe_request_breaks_the_protocol() {
    // Tag 9 is viewer → host only: an Active viewer receiving one closes.
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    let mut e = evil_host_viewer_pending(&v, &h, &otp);
    let accept = e
        .est
        .encrypt(&control_envelope(control::Kind::Accept(SessionAccept {
            role: 1,
        })))
        .unwrap();
    let acts = e.viewer.on_frame(&accept, T0, &mut OsRng);
    assert!(acts.contains(&ViewerAction::Active));
    let req = e
        .est
        .encrypt(&control_envelope(control::Kind::Recovery(
            RecoveryRequest {},
        )))
        .unwrap();
    let acts = e.viewer.on_frame(&req, T0, &mut OsRng);
    let reason = acts.iter().find_map(|a| match a {
        ViewerAction::Failed { reason, .. } => Some(reason.clone()),
        _ => None,
    });
    assert_eq!(
        reason,
        Some(FailReason::ProtocolViolation(Violation::WrongRole)),
        "{acts:?}"
    );
}
