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

const ASLEEP: CaptureStatus = CaptureStatus::Interrupted(PauseReason::DisplayAsleep);

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
    let acts = host.capture_changed(ASLEEP, T0);
    assert_eq!(sent_to(&acts, a.id), 1);
    assert_eq!(sent_to(&acts, b.id), 1);
    assert_eq!(sent_to(&acts, p.id), 0, "a pending session gets nothing");
    assert!(closes(&acts).is_empty(), "an interruption never closes");
    assert!(!acts.contains(&HostAction::ForceKeyframe));
    a.host_actions(&mut host, acts.clone());
    b.host_actions(&mut host, acts);
    let paused = ViewerAction::StreamPaused(PauseReason::DisplayAsleep);
    assert_eq!(viewer_saw(&a, &paused), 1);
    assert_eq!(viewer_saw(&b, &paused), 1);
    assert_eq!(state_of(&host, &a), (Some(State::Active), State::Active));
    assert_eq!(state_of(&host, &b), (Some(State::Active), State::Active));
    assert_eq!(host.capture_status(), ASLEEP);
}

#[test]
fn t1_each_reason_reaches_the_viewer_unchanged() {
    for reason in [
        PauseReason::DisplayAsleep,
        PauseReason::AccessLost,
        PauseReason::Other,
    ] {
        let (h, v) = (device("host"), device("viewer"));
        let mut host = host_with(&h, vec![]);
        let mut c = to_active(&mut host, &v, ip(1));
        let acts = host.capture_changed(CaptureStatus::Interrupted(reason), T0);
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
        host.capture_changed(CaptureStatus::Running, T0).is_empty(),
        "already running"
    );
    assert!(!host.capture_changed(ASLEEP, T0).is_empty());
    assert!(
        host.capture_changed(ASLEEP, T0).is_empty(),
        "already paused"
    );
}

#[test]
fn t1_a_new_reason_while_paused_is_passed_on() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_active(&mut host, &v, ip(1));
    let acts = host.capture_changed(ASLEEP, T0);
    c.host_actions(&mut host, acts);
    let other = CaptureStatus::Interrupted(PauseReason::Other);
    let acts = host.capture_changed(other, T0);
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
    let acts = host.capture_changed(ASLEEP, T0);
    a.host_actions(&mut host, acts.clone());
    b.host_actions(&mut host, acts);
    let acts = host.capture_changed(CaptureStatus::Running, T0);
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
    let acts = host.capture_changed(CaptureStatus::Stopped, T0);
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
    assert!(
        host.capture_changed(ASLEEP, T0).is_empty(),
        "nobody active yet"
    );
    c.approve(&mut host);
    assert!(c.log.viewer.contains(&ViewerAction::Active));
    let paused = ViewerAction::StreamPaused(PauseReason::DisplayAsleep);
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
    host.capture_changed(CaptureStatus::Stopped, T0);
    let (id, sas) = c.log.prompt().unwrap();
    let acts = host.approve(id, sas, T0).unwrap();
    assert_eq!(closes(&acts), vec![(c.id, CloseCode::CaptureStopped)]);
    assert!(host.active_sessions().is_empty());
}

#[test]
fn t1_running_again_after_stopped_sends_nothing_to_closed_sessions() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let _c = to_active(&mut host, &v, ip(1));
    host.capture_changed(CaptureStatus::Stopped, T0);
    let acts = host.capture_changed(CaptureStatus::Running, T0);
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
            remaining_ms: 0,
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
    for (wire, left, want) in [
        (1, 0, PauseReason::DisplayAsleep),
        (2, 0, PauseReason::AccessLost),
        (3, 0, PauseReason::Other),
        (77, 0, PauseReason::Other),
        // D-29: the time left is kept with "display removed" only.
        (
            4,
            90_000,
            PauseReason::DisplayUnavailable {
                remaining_ms: 90_000,
            },
        ),
        (1, 90_000, PauseReason::DisplayAsleep),
        (77, 90_000, PauseReason::Other),
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
                remaining_ms: left,
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
                remaining_ms: 0,
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
    host.approve(pid, sas, T0).unwrap();
    let f = e
        .est
        .encrypt(&control_envelope(control::Kind::StreamState(StreamState {
            paused: true,
            reason: 1,
            remaining_ms: 0,
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

// ------------------------------------------- D-29: display removed --

const fn unavailable(remaining_ms: u32) -> CaptureStatus {
    CaptureStatus::Interrupted(PauseReason::DisplayUnavailable { remaining_ms })
}

fn at(ms: u64) -> remora_session::Millis {
    T0.plus(ms)
}

/// Roadmap D-29: the viewer is told the display was removed and how long
/// the host will wait; the host keeps the deadline.
#[test]
fn d29_display_unavailable_tells_the_viewer_the_time_left() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_active(&mut host, &v, ip(1));
    let acts = host.capture_changed(unavailable(120_000), T0);
    c.host_actions(&mut host, acts);
    assert_eq!(
        viewer_saw(&c, &ViewerAction::StreamPaused(unavailable_reason(120_000))),
        1
    );
    assert_eq!(host.pause_remaining(T0), Some(120_000));
    assert_eq!(host.pause_remaining(at(42_000)), Some(78_000));
    assert_eq!(host.pause_remaining(at(500_000)), Some(0), "never negative");
}

fn unavailable_reason(remaining_ms: u32) -> PauseReason {
    PauseReason::DisplayUnavailable { remaining_ms }
}

/// A viewer approved during the wait is told the time actually left, not
/// the full wait (the deadline does not move because someone joined).
#[test]
fn d29_a_viewer_approved_during_the_wait_gets_the_time_actually_left() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_prompt(&mut host, &v, ip(1));
    assert!(host.capture_changed(unavailable(120_000), T0).is_empty());
    let (id, sas) = c.log.prompt().unwrap();
    let acts = host.approve(id, sas, at(42_000)).unwrap();
    c.host_actions(&mut host, acts);
    assert_eq!(
        viewer_saw(&c, &ViewerAction::StreamPaused(unavailable_reason(78_000))),
        1
    );
    assert_eq!(
        viewer_saw(&c, &ViewerAction::StreamPaused(unavailable_reason(120_000))),
        0
    );
}

/// The capture reports "removed" only when the display goes missing (again):
/// each report is a new deadline and reaches the viewer, even though the
/// status looks the same as the last one.
#[test]
fn d29_a_new_deadline_is_sent_even_if_the_status_looks_the_same() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_active(&mut host, &v, ip(1));
    let acts = host.capture_changed(unavailable(120_000), T0);
    c.host_actions(&mut host, acts);
    let acts = host.capture_changed(unavailable(120_000), at(50_000));
    assert_eq!(sent_to(&acts, c.id), 1, "the new deadline is sent");
    c.host_actions(&mut host, acts);
    assert_eq!(
        viewer_saw(&c, &ViewerAction::StreamPaused(unavailable_reason(120_000))),
        2
    );
    assert_eq!(host.pause_remaining(at(50_000)), Some(120_000));
}

/// The deadline belongs to "removed" only: the display back but asleep, or
/// capture running again, clears it; a viewer approved then gets no time.
#[test]
fn d29_the_deadline_ends_with_the_removal() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_prompt(&mut host, &v, ip(1));
    host.capture_changed(unavailable(120_000), T0);
    host.capture_changed(ASLEEP, at(10_000));
    assert_eq!(host.pause_remaining(at(10_000)), None);
    let (id, sas) = c.log.prompt().unwrap();
    let acts = host.approve(id, sas, at(20_000)).unwrap();
    c.host_actions(&mut host, acts);
    assert_eq!(
        viewer_saw(&c, &ViewerAction::StreamPaused(PauseReason::DisplayAsleep)),
        1
    );
    host.capture_changed(unavailable(120_000), at(30_000));
    host.capture_changed(CaptureStatus::Running, at(31_000));
    assert_eq!(host.pause_remaining(at(31_000)), None);
}
