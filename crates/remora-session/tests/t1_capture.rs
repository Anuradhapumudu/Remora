//! phase4-criteria §7, T1: screen capture interrupted / resumed / stopped,
//! as the sans-IO session sees it (a "fake capture" is simply calling
//! `Host::capture_changed`). The session never learns the OS: reasons are
//! the OS-neutral `PauseReason` (D17). Written before the implementation.
//!
//! What would these still pass with if the behaviour were removed? Each
//! test checks what the VIEWER ends up showing (paused / resumed / closed
//! with CaptureStopped), not only that the host emitted *something*, so a
//! host that sent nothing, the wrong message, or to the wrong sessions fails.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::evil::*;
use common::*;
use rand_core::OsRng;
use remora_proto::messages::{SessionAccept, StreamState, control};
use remora_session::{
    CaptureStatus, CloseCode, FailReason, HostAction, PauseReason, State, ViewerAction, Violation,
};

const ASLEEP: CaptureStatus = CaptureStatus::Interrupted(PauseReason::DisplayUnavailable);

fn sent_to(acts: &[HostAction], id: remora_session::SessionId) -> usize {
    acts.iter()
        .filter(|a| matches!(a, HostAction::Send { id: i, .. } if *i == id))
        .count()
}

fn viewer_saw(c: &Conn, want: &ViewerAction) -> usize {
    c.log.viewer.iter().filter(|a| *a == want).count()
}

fn closes(acts: &[HostAction]) -> Vec<(remora_session::SessionId, CloseCode)> {
    acts.iter()
        .filter_map(|a| match a {
            HostAction::Close { id, code } => Some((*id, *code)),
            _ => None,
        })
        .collect()
}

#[test]
fn t1_interruption_pauses_every_active_session_and_keeps_it_active() {
    let (h, v1, v2, v3) = (device("host"), device("v1"), device("v2"), device("v3"));
    let mut host = host_with(&h, vec![]);
    let mut a = to_active(&mut host, &v1, ip(1));
    let mut b = to_active(&mut host, &v2, ip(2));
    let p = to_prompt(&mut host, &v3, ip(3));
    let acts = host.capture_changed(ASLEEP);
    assert_eq!(sent_to(&acts, a.id), 1);
    assert_eq!(sent_to(&acts, b.id), 1);
    assert_eq!(sent_to(&acts, p.id), 0, "a pending session gets nothing");
    assert!(closes(&acts).is_empty(), "an interruption never closes");
    assert!(!acts.contains(&HostAction::ForceKeyframe));
    a.host_actions(&mut host, acts.clone());
    b.host_actions(&mut host, acts);
    let paused = ViewerAction::StreamPaused(PauseReason::DisplayUnavailable);
    assert_eq!(viewer_saw(&a, &paused), 1);
    assert_eq!(viewer_saw(&b, &paused), 1);
    assert_eq!(state_of(&host, &a), (Some(State::Active), State::Active));
    assert_eq!(state_of(&host, &b), (Some(State::Active), State::Active));
    assert_eq!(host.capture_status(), ASLEEP);
}

#[test]
fn t1_each_reason_reaches_the_viewer_unchanged() {
    for reason in [
        PauseReason::DisplayUnavailable,
        PauseReason::AccessLost,
        PauseReason::Other,
    ] {
        let (h, v) = (device("host"), device("viewer"));
        let mut host = host_with(&h, vec![]);
        let mut c = to_active(&mut host, &v, ip(1));
        let acts = host.capture_changed(CaptureStatus::Interrupted(reason));
        c.host_actions(&mut host, acts);
        assert_eq!(
            viewer_saw(&c, &ViewerAction::StreamPaused(reason)),
            1,
            "{reason:?}"
        );
    }
}

#[test]
fn t1_repeating_a_status_does_nothing() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let _c = to_active(&mut host, &v, ip(1));
    assert!(
        host.capture_changed(CaptureStatus::Running).is_empty(),
        "already running"
    );
    assert!(!host.capture_changed(ASLEEP).is_empty());
    assert!(host.capture_changed(ASLEEP).is_empty(), "already paused");
}

#[test]
fn t1_a_new_reason_while_paused_is_passed_on() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_active(&mut host, &v, ip(1));
    let acts = host.capture_changed(ASLEEP);
    c.host_actions(&mut host, acts);
    let other = CaptureStatus::Interrupted(PauseReason::Other);
    let acts = host.capture_changed(other);
    c.host_actions(&mut host, acts);
    assert_eq!(
        viewer_saw(&c, &ViewerAction::StreamPaused(PauseReason::Other)),
        1
    );
    assert_eq!(host.capture_status(), other);
}

#[test]
fn t1_resume_tells_viewers_and_forces_one_keyframe() {
    let (h, v1, v2) = (device("host"), device("v1"), device("v2"));
    let mut host = host_with(&h, vec![]);
    let mut a = to_active(&mut host, &v1, ip(1));
    let mut b = to_active(&mut host, &v2, ip(2));
    let acts = host.capture_changed(ASLEEP);
    a.host_actions(&mut host, acts.clone());
    b.host_actions(&mut host, acts);
    let acts = host.capture_changed(CaptureStatus::Running);
    assert_eq!(
        acts.iter()
            .filter(|a| **a == HostAction::ForceKeyframe)
            .count(),
        1,
        "one keyframe for the shared encoder, not one per viewer"
    );
    a.host_actions(&mut host, acts.clone());
    b.host_actions(&mut host, acts);
    assert_eq!(viewer_saw(&a, &ViewerAction::StreamResumed), 1);
    assert_eq!(viewer_saw(&b, &ViewerAction::StreamResumed), 1);
    assert_eq!(host.capture_status(), CaptureStatus::Running);
}

#[test]
fn t1_stopped_closes_every_active_session_with_capture_stopped() {
    let (h, v1, v2, v3) = (device("host"), device("v1"), device("v2"), device("v3"));
    let mut host = host_with(&h, vec![]);
    let a = to_active(&mut host, &v1, ip(1));
    let b = to_active(&mut host, &v2, ip(2));
    let p = to_prompt(&mut host, &v3, ip(3));
    let acts = host.capture_changed(CaptureStatus::Stopped);
    let mut c = closes(&acts);
    c.sort_by_key(|x| x.0);
    let mut want = vec![
        (a.id, CloseCode::CaptureStopped),
        (b.id, CloseCode::CaptureStopped),
    ];
    want.sort_by_key(|x| x.0);
    assert_eq!(c, want);
    assert!(host.active_sessions().is_empty());
    assert_eq!(
        host.state(p.id),
        Some(State::PendingApproval),
        "the prompt stays"
    );
}

#[test]
fn t1_approving_while_paused_tells_the_new_viewer_it_is_paused() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_prompt(&mut host, &v, ip(1));
    assert!(host.capture_changed(ASLEEP).is_empty(), "nobody active yet");
    c.approve(&mut host);
    assert!(c.log.viewer.contains(&ViewerAction::Active));
    let paused = ViewerAction::StreamPaused(PauseReason::DisplayUnavailable);
    assert_eq!(viewer_saw(&c, &paused), 1);
    let active_at = c.log.viewer.iter().position(|a| *a == ViewerAction::Active);
    let paused_at = c.log.viewer.iter().position(|a| *a == paused);
    assert!(active_at < paused_at, "paused comes after the accept");
}

#[test]
fn t1_approving_after_capture_stopped_closes_with_capture_stopped() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = to_prompt(&mut host, &v, ip(1));
    host.capture_changed(CaptureStatus::Stopped);
    let (id, sas) = c.log.prompt().unwrap();
    let acts = host.approve(id, sas).unwrap();
    assert_eq!(closes(&acts), vec![(c.id, CloseCode::CaptureStopped)]);
    assert!(host.active_sessions().is_empty());
}

#[test]
fn t1_running_again_after_stopped_sends_nothing_to_closed_sessions() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let _c = to_active(&mut host, &v, ip(1));
    host.capture_changed(CaptureStatus::Stopped);
    let acts = host.capture_changed(CaptureStatus::Running);
    assert!(acts.iter().all(|a| !matches!(a, HostAction::Send { .. })));
    assert_eq!(host.capture_status(), CaptureStatus::Running);
}

// ------------------------------------------------- viewer-side checks --

fn viewer_reason(acts: &[ViewerAction]) -> Option<FailReason> {
    acts.iter().find_map(|a| match a {
        ViewerAction::Failed { reason, .. } => Some(reason.clone()),
        _ => None,
    })
}

#[test]
fn t1_viewer_rejects_stream_state_before_active() {
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    let mut e = evil_host_viewer_pending(&v, &h, &otp);
    let f = e
        .est
        .encrypt(&control_envelope(control::Kind::StreamState(StreamState {
            paused: true,
            reason: 1,
        })))
        .unwrap();
    let acts = e.viewer.on_frame(&f, T0, &mut OsRng);
    assert_eq!(
        viewer_reason(&acts),
        Some(FailReason::ProtocolViolation(Violation::BeforeActive))
    );
}

#[test]
fn t1_viewer_maps_wire_reasons_and_unknown_ones_to_other() {
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    for (wire, want) in [
        (1, PauseReason::DisplayUnavailable),
        (2, PauseReason::AccessLost),
        (3, PauseReason::Other),
        (77, PauseReason::Other),
    ] {
        let mut e = evil_host_viewer_pending(&v, &h, &otp);
        let accept = e
            .est
            .encrypt(&control_envelope(control::Kind::Accept(SessionAccept {
                role: 1,
            })))
            .unwrap();
        e.viewer.on_frame(&accept, T0, &mut OsRng);
        let f = e
            .est
            .encrypt(&control_envelope(control::Kind::StreamState(StreamState {
                paused: true,
                reason: wire,
            })))
            .unwrap();
        let acts = e.viewer.on_frame(&f, T0, &mut OsRng);
        assert_eq!(acts, vec![ViewerAction::StreamPaused(want)], "wire {wire}");
        assert_eq!(e.viewer.state(), State::Active);
        let f = e
            .est
            .encrypt(&control_envelope(control::Kind::StreamState(StreamState {
                paused: false,
                reason: 0,
            })))
            .unwrap();
        let acts = e.viewer.on_frame(&f, T0, &mut OsRng);
        assert_eq!(acts, vec![ViewerAction::StreamResumed]);
    }
}

#[test]
fn t1_a_viewer_sending_stream_state_is_role_confusion() {
    // A21: StreamState is host -> viewer only.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    let mut e = evil_viewer_pending(&mut host, &v, &otp);
    let (pid, sas) = e
        .host_log
        .iter()
        .find_map(|a| match a {
            HostAction::Prompt { id, sas, .. } => Some((*id, *sas)),
            _ => None,
        })
        .unwrap();
    host.approve(pid, sas).unwrap();
    let f = e
        .est
        .encrypt(&control_envelope(control::Kind::StreamState(StreamState {
            paused: true,
            reason: 1,
        })))
        .unwrap();
    let acts = host.on_frame(e.id, &f, T0, &mut OsRng);
    assert!(acts.iter().any(|a| matches!(
        a,
        HostAction::Failed {
            reason: FailReason::ProtocolViolation(Violation::WrongRole),
            ..
        }
    )));
}
