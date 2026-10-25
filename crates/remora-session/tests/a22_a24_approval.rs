//! phase3-criteria A22 (approval bound to session ID AND the SAS shown), A23
//! (no approval before the SAS exists), A24 (handshake 10 s, prompt 60 s,
//! resources freed), INV11 (disconnect from any state). Written before the
//! implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use rand_core::OsRng;
use remora_crypto::sas::Sas;
use remora_session::{
    ApproveError, CloseCode, FailReason, HANDSHAKE_TIMEOUT_MS, HostAction, Millis,
    PROMPT_TIMEOUT_MS, SessionId, State,
};

fn some_sas(c: &Conn) -> Sas {
    c.log.prompt().unwrap().1
}

#[test]
fn timeouts_match_the_criteria() {
    assert_eq!(HANDSHAKE_TIMEOUT_MS, 10_000);
    assert_eq!(PROMPT_TIMEOUT_MS, 60_000);
}

#[test]
fn a22_two_pending_sessions_approving_a_activates_only_a() {
    let (h, va, vb) = (device("host"), device("viewer A"), device("viewer B"));
    let mut host = host_with(&h, vec![]);
    let mut a = to_prompt(&mut host, &va, ip(1));
    let b = to_prompt(&mut host, &vb, ip(2));
    assert_ne!(a.id, b.id);
    a.approve(&mut host);
    assert_eq!(host.state(a.id), Some(State::Active));
    assert_eq!(
        host.state(b.id),
        Some(State::PendingApproval),
        "B stays pending"
    );
    assert_eq!(host.active_sessions(), vec![a.id]);
}

#[test]
fn a22_approval_with_the_other_sessions_sas_is_refused_and_changes_nothing() {
    let (h, va, vb) = (device("host"), device("viewer A"), device("viewer B"));
    let mut host = host_with(&h, vec![]);
    let a = to_prompt(&mut host, &va, ip(1));
    let b = to_prompt(&mut host, &vb, ip(2));
    let (sa, sb) = (some_sas(&a), some_sas(&b));
    if sa == sb {
        return; // 10⁻⁶: the codes collide, the binding cannot be observed
    }
    assert_eq!(host.approve(a.id, sb, T0), Err(ApproveError::SasMismatch));
    assert_eq!(host.approve(b.id, sa, T0), Err(ApproveError::SasMismatch));
    assert_eq!(host.state(a.id), Some(State::PendingApproval));
    assert_eq!(host.state(b.id), Some(State::PendingApproval));
    assert!(host.active_sessions().is_empty());
}

#[test]
fn a22_approval_with_any_wrong_code_is_refused() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = to_prompt(&mut host, &v, ip(1));
    let right = some_sas(&c);
    let wrong = remora_crypto::sas::sas(&[1; 32], &[2; 32], &[3; 32]);
    if wrong != right {
        assert_eq!(
            host.approve(c.id, wrong, T0),
            Err(ApproveError::SasMismatch)
        );
    }
    assert_eq!(
        host.approve(SessionId(c.id.0 ^ 1), right, T0),
        Err(ApproveError::UnknownSession)
    );
    assert!(host.approve(c.id, right, T0).is_ok());
    assert_eq!(
        host.approve(c.id, right, T0),
        Err(ApproveError::NotPending),
        "approve twice"
    );
}

#[test]
fn a23_approve_in_every_earlier_state_is_refused() {
    let (h, v) = (device("host"), device("viewer"));
    let sas = remora_crypto::sas::sas(&[0; 32], &[0; 32], &[0; 32]);
    // Hello, Spake, Noise (msg1), Noise (msg3)
    for stop_after in 0..4usize {
        let mut host = host_with(&h, vec![]);
        let mode = password_mode(&host, None);
        let (mut c, first) = start(&mut host, &v, mode, ip(1), T0);
        let mut n = 0;
        c.pump(&mut host, first, vec![], &mut |v2h, _, f| {
            if v2h {
                n += 1;
                if n > stop_after {
                    return None;
                }
            }
            Some(f)
        });
        let st = host.state(c.id);
        assert_ne!(st, Some(State::PendingApproval));
        assert_eq!(
            host.approve(c.id, sas, T0),
            Err(ApproveError::NotPending),
            "state {st:?}"
        );
        assert_eq!(host.state(c.id), st, "unchanged");
        assert!(
            c.log.prompt().is_none(),
            "no prompt before the reveal is verified"
        );
    }
}

#[test]
fn a23_prompt_appears_only_after_the_whole_handshake() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = to_prompt(&mut host, &v, ip(1));
    let prompt_at = c
        .log
        .host
        .iter()
        .position(|a| matches!(a, HostAction::Prompt { .. }))
        .unwrap();
    let sends_before = c.log.host[..prompt_at]
        .iter()
        .filter(|a| matches!(a, HostAction::Send { .. }))
        .count();
    // HostHello, SpakeB, msg2, SasReveal, SessionPending — all before the prompt.
    assert_eq!(sends_before, 5);
}

#[test]
fn a24_slow_handshake_times_out_after_10_s_and_frees_the_slot() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mode = password_mode(&host, None);
    let (mut c, first) = start(&mut host, &v, mode, ip(1), T0);
    // Slowloris: only the hello ever arrives.
    let mut sent = 0;
    c.pump(&mut host, first, vec![], &mut |v2h, _, f| {
        if v2h {
            sent += 1;
            if sent > 1 {
                return None;
            }
        }
        Some(f)
    });
    assert!(host.tick(Millis(T0.0 + 9_999)).is_empty());
    let acts = host.tick(Millis(T0.0 + 10_000));
    assert!(acts.contains(&HostAction::Close {
        id: c.id,
        code: CloseCode::Timeout
    }));
    assert!(acts.iter().any(|a| matches!(
        a,
        HostAction::Failed {
            reason: FailReason::Timeout,
            ..
        }
    )));
    assert_eq!(host.state(c.id), Some(State::Closed));
    assert_eq!(host.limiter().pending(), 0);
    assert!(host.tick(Millis(T0.0 + 20_000)).is_empty(), "reported once");
}

#[test]
fn a24_viewer_side_handshake_deadline() {
    let (h, v) = (device("host"), device("viewer"));
    let host = host_with(&h, vec![]);
    let (mut viewer, _) = remora_session::ViewerSession::start(
        viewer_cfg(&v, password_mode(&host, None)),
        [3; 16],
        exporter(7),
        T0,
    );
    assert!(viewer.tick(Millis(T0.0 + 9_999)).is_empty());
    let acts = viewer.tick(Millis(T0.0 + 10_000));
    assert!(acts.contains(&remora_session::ViewerAction::Close(CloseCode::Timeout)));
    assert_eq!(viewer.state(), State::Closed);
}

#[test]
fn a24_unanswered_prompt_is_rejected_after_60_s() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_prompt(&mut host, &v, ip(1));
    // The 10 s handshake deadline no longer applies once the prompt is up.
    assert!(host.tick(Millis(T0.0 + 59_999)).is_empty());
    let acts = host.tick(Millis(T0.0 + 60_000));
    assert!(acts.contains(&HostAction::PromptClosed { id: c.id }));
    assert!(acts.contains(&HostAction::Close {
        id: c.id,
        code: CloseCode::Rejected
    }));
    c.host_actions(&mut host, acts);
    assert_eq!(c.viewer.state(), State::Closed);
    assert_eq!(c.log.viewer_failure(), Some(FailReason::Rejected));
    assert_eq!(host.limiter().pending(), 0);
    assert_eq!(
        host.approve(c.id, some_sas(&c), T0),
        Err(ApproveError::NotPending),
        "too late"
    );
}

#[test]
fn a24_reject_sent_on_prompt_timeout_says_timeout() {
    use prost::Message;
    use remora_proto::messages::{Envelope, control, envelope};
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    let mut e = common::evil::evil_viewer_pending(&mut host, &v, &otp);
    let acts = host.tick(Millis(T0.0 + 60_000));
    let frame = acts
        .iter()
        .find_map(|a| match a {
            HostAction::Send { frame, .. } => Some(frame.clone()),
            _ => None,
        })
        .expect("SessionReject sent");
    let env = Envelope::decode(e.est.decrypt(&frame).unwrap().as_slice()).unwrap();
    match env.msg {
        Some(envelope::Msg::Control(c)) => match c.kind {
            Some(control::Kind::Reject(r)) => assert_eq!(r.reason, 2, "2 = prompt timed out"),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

#[test]
fn inv11_disconnect_from_every_state_reaches_closed_and_stops_processing() {
    let (h, v) = (device("host"), device("viewer"));
    // Hello, Spake, Noise, Noise, PendingApproval, Active
    for stop_after in 0..6usize {
        let mut host = host_with(&h, vec![]);
        let mode = password_mode(&host, None);
        let (mut c, first) = start(&mut host, &v, mode, ip(1), T0);
        let mut n = 0;
        c.pump(&mut host, first, vec![], &mut |v2h, _, f| {
            if v2h {
                n += 1;
                if n > stop_after.min(4) {
                    return None;
                }
            }
            Some(f)
        });
        if stop_after == 5 {
            c.approve(&mut host);
            assert_eq!(host.state(c.id), Some(State::Active));
        }
        let before = host.state(c.id);
        let acts = host.disconnect(c.id);
        assert!(
            acts.contains(&HostAction::Close {
                id: c.id,
                code: CloseCode::Normal
            }),
            "{before:?}"
        );
        assert_eq!(host.state(c.id), Some(State::Closed));
        assert_eq!(host.limiter().pending(), 0, "{before:?}");
        assert!(host.active_sessions().is_empty());
        // Nothing is processed after: frames, datagrams, ticks, approvals.
        for f in &c.v2h {
            assert!(host.on_frame(c.id, f, T0, &mut OsRng).is_empty());
        }
        assert!(host.on_datagram(c.id, &[1; 64]).is_empty());
        assert!(host.tick(Millis(T0.0 + 100_000)).is_empty());
        assert!(host.disconnect(c.id).is_empty(), "idempotent");
    }
}

#[test]
fn inv11_viewer_disconnect_from_every_state() {
    let (h, v) = (device("host"), device("viewer"));
    for stop_after in 0..5usize {
        let mut host = host_with(&h, vec![]);
        let mode = password_mode(&host, None);
        let (mut c, first) = start(&mut host, &v, mode, ip(1), T0);
        let mut n = 0;
        c.pump(&mut host, first, vec![], &mut |v2h, _, f| {
            if !v2h {
                n += 1;
                if n > stop_after {
                    return None;
                }
            }
            Some(f)
        });
        let before = c.viewer.state();
        let acts = c.viewer.disconnect();
        assert!(
            acts.contains(&remora_session::ViewerAction::Close(CloseCode::Normal)),
            "{before:?}"
        );
        assert_eq!(c.viewer.state(), State::Closed);
        assert!(c.viewer.disconnect().is_empty());
        assert!(c.viewer.tick(Millis(T0.0 + 100_000)).is_empty());
        let _ = host.disconnect(c.id);
    }
}

// ------------------------------------------- mutation-gate findings ----

#[test]
fn host_disconnect_of_an_active_session_says_goodbye_to_the_viewer() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_active(&mut host, &v, ip(1));
    let acts = host.disconnect(c.id);
    assert!(
        acts.iter().any(|a| matches!(a, HostAction::Send { .. })),
        "Goodbye sent"
    );
    c.host_actions(&mut host, acts);
    assert_eq!(c.viewer.state(), State::Closed);
    assert_eq!(c.log.viewer_close(), Some(CloseCode::Normal));
    assert!(
        c.log.viewer_failure().is_none(),
        "an orderly close, not a failure"
    );
}

#[test]
fn host_disconnect_while_pending_says_goodbye_and_withdraws_the_prompt() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_prompt(&mut host, &v, ip(1));
    let acts = host.disconnect(c.id);
    assert!(acts.contains(&HostAction::PromptClosed { id: c.id }));
    c.host_actions(&mut host, acts);
    assert_eq!(c.log.viewer_close(), Some(CloseCode::Normal));
}

#[test]
fn datagram_while_pending_withdraws_the_prompt_but_not_in_earlier_states() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = to_prompt(&mut host, &v, ip(1));
    let acts = host.on_datagram(c.id, &[1; 64]);
    assert!(acts.contains(&HostAction::PromptClosed { id: c.id }));
    let mut host = host_with(&h, vec![]);
    let id = host
        .accept_connection(ip(2), exporter(7), T0, &mut OsRng)
        .unwrap();
    let acts = host.on_datagram(id, &[1; 64]);
    assert!(
        !acts
            .iter()
            .any(|a| matches!(a, HostAction::PromptClosed { .. })),
        "no prompt was open"
    );
}

#[test]
fn datagrams_in_active_are_dropped_without_ending_the_session() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_active(&mut host, &v, ip(1));
    assert!(host.on_datagram(c.id, &[3; 64]).is_empty());
    assert_eq!(host.state(c.id), Some(State::Active));
    assert!(c.viewer.on_datagram(&[1; 64], T0).is_empty());
    assert_eq!(c.viewer.state(), State::Active);
    c.viewer.disconnect();
    assert!(
        c.viewer.on_datagram(&[1; 64], T0).is_empty(),
        "closed: nothing happens"
    );
}

#[test]
fn forget_drops_closed_sessions_only() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let live = to_prompt(&mut host, &v, ip(1));
    let gone = to_prompt(&mut host, &v, ip(2));
    host.disconnect(gone.id);
    host.forget(gone.id);
    host.forget(live.id);
    assert_eq!(host.state(gone.id), None);
    assert_eq!(host.state(live.id), Some(State::PendingApproval));
}

#[test]
fn oversized_msg1_is_a_protocol_violation_not_a_password_attempt() {
    // Only a msg1 that fails to AUTHENTICATE costs an attempt; a frame that
    // is simply too large says nothing about the password.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mode = password_mode(&host, None);
    let (mut c, first) = start(&mut host, &v, mode, ip(1), T0);
    c.pump(&mut host, first, vec![], &mut |v2h, idx, f| {
        if v2h && idx == 2 {
            Some(vec![0; 65_536])
        } else {
            Some(f)
        }
    });
    assert_eq!(c.log.host_close(), Some(CloseCode::ProtocolViolation));
    assert!(
        c.log
            .host
            .iter()
            .any(|a| matches!(a, HostAction::Failed { attempt: None, .. }))
    );
    assert_eq!(host.limiter().failures(), 0);
}

#[test]
fn debug_output_shows_state_but_never_the_password() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = to_prompt(&mut host, &v, ip(1));
    let hd = format!("{host:?}");
    assert!(
        hd.contains("sessions: 1") && hd.contains("pending: 1"),
        "{hd}"
    );
    assert!(!hd.contains(host.otp().reveal()));
    let vd = format!("{:?}", c.viewer);
    assert!(vd.contains("PendingApproval"), "{vd}");
}

#[test]
fn a26_framing_error_from_the_transport_ends_the_session_as_a_protocol_violation() {
    // remora-net reports an oversized / malformed length prefix (A26); the
    // session must end exactly like any other malformed message: one
    // Failed, prompt withdrawn if open, PROTOCOL_VIOLATION, slot freed.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = to_prompt(&mut host, &v, ip(1));
    let acts = host.framing_error(c.id);
    assert!(acts.iter().any(|a| matches!(
        a,
        HostAction::Failed {
            reason: FailReason::ProtocolViolation(remora_session::Violation::Framing),
            ..
        }
    )));
    assert!(acts.contains(&HostAction::PromptClosed { id: c.id }));
    assert!(acts.contains(&HostAction::Close {
        id: c.id,
        code: CloseCode::ProtocolViolation
    }));
    assert_eq!(host.state(c.id), Some(State::Closed));
    assert_eq!(host.limiter().pending(), 0);
    assert!(host.framing_error(c.id).is_empty(), "nothing after close");
    // In an earlier state there is no prompt to withdraw.
    let mut host = host_with(&h, vec![]);
    let id = host
        .accept_connection(ip(2), exporter(7), T0, &mut OsRng)
        .unwrap();
    let acts = host.framing_error(id);
    assert!(
        !acts
            .iter()
            .any(|a| matches!(a, HostAction::PromptClosed { .. }))
    );
    assert!(acts.contains(&HostAction::Close {
        id,
        code: CloseCode::ProtocolViolation
    }));
}
