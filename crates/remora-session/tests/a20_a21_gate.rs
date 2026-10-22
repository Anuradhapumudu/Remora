//! phase3-criteria A20 (no application message before approval — every
//! state × every message type), A21 (role confusion), INV1. The mock
//! injector / renderer is the delivered-message call log: it must stay at
//! 0. Written before the implementation.
//!
//! Expected outcome per state. Where a frame is encrypted and decryptable
//! (host PendingApproval; viewer SasReveal / PendingApproval / Active) the
//! session recognises the forbidden message: ProtocolViolation. In the
//! plaintext states (Hello, Spake) the frame does not parse as the expected
//! message: ProtocolViolation. At the Noise steps an application message
//! cannot be told apart from a corrupted handshake message, so it fails as
//! one: AuthFailed (see the report: criteria refinement proposed in §11).
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::evil::*;
use common::*;
use rand_core::OsRng;
use remora_proto::messages::{Goodbye, SessionAccept, control};
use remora_session::fail::{AuthDetail, Violation};
use remora_session::{CloseCode, FailReason, HostAction, State, ViewerAction};

fn host_close(acts: &[HostAction]) -> Option<CloseCode> {
    acts.iter().find_map(|a| match a {
        HostAction::Close { code, .. } => Some(*code),
        _ => None,
    })
}
fn host_reason(acts: &[HostAction]) -> Option<FailReason> {
    acts.iter().find_map(|a| match a {
        HostAction::Failed { reason, .. } => Some(reason.clone()),
        _ => None,
    })
}
fn no_host_delivery(acts: &[HostAction]) -> bool {
    !acts
        .iter()
        .any(|a| matches!(a, HostAction::Deliver { .. } | HostAction::Active { .. }))
}
fn viewer_close(acts: &[ViewerAction]) -> Option<CloseCode> {
    acts.iter().find_map(|a| match a {
        ViewerAction::Close(c) => Some(*c),
        _ => None,
    })
}
fn viewer_reason(acts: &[ViewerAction]) -> Option<FailReason> {
    acts.iter().find_map(|a| match a {
        ViewerAction::Failed { reason, .. } => Some(reason.clone()),
        _ => None,
    })
}
fn no_viewer_delivery(acts: &[ViewerAction]) -> bool {
    !acts
        .iter()
        .any(|a| matches!(a, ViewerAction::Video(_) | ViewerAction::Active))
}

// ------------------------------------------------------------ host side --

#[test]
fn a20_host_hello_and_spake_states_reject_plaintext_app_messages() {
    let (h, v) = (device("host"), device("viewer"));
    for (what, env) in app_envelopes() {
        // Hello state: the app message instead of ViewerHello.
        let mut host = host_with(&h, vec![]);
        let id = host
            .accept_connection(ip(1), exporter(7), T0, &mut OsRng)
            .unwrap();
        let acts = host.on_frame(id, &env, T0, &mut OsRng);
        assert_eq!(
            host_close(&acts),
            Some(CloseCode::ProtocolViolation),
            "Hello: {what}"
        );
        assert!(no_host_delivery(&acts));
        assert_eq!(host.state(id), Some(State::Closed));
        // Spake state: the app message instead of SpakeA.
        let mut host = host_with(&h, vec![]);
        host.issue_nonce(NONCE, T0.plus(300_000));
        let id = host
            .accept_connection(ip(1), exporter(7), T0, &mut OsRng)
            .unwrap();
        host.on_frame(
            id,
            &viewer_hello(remora_proto::messages::Mode::Password),
            T0,
            &mut OsRng,
        );
        assert_eq!(host.state(id), Some(State::Spake));
        let acts = host.on_frame(id, &env, T0, &mut OsRng);
        assert_eq!(
            host_close(&acts),
            Some(CloseCode::ProtocolViolation),
            "Spake: {what}"
        );
        assert!(no_host_delivery(&acts));
    }
    let _ = v;
}

#[test]
fn a20_host_noise_states_fail_app_messages_as_corrupted_handshake() {
    let (h, v) = (device("host"), device("viewer"));
    for (what, env) in app_envelopes() {
        for msg_index in [2usize, 3] {
            // v2h frames: 0 hello, 1 SpakeA, 2 msg1, 3 msg3.
            let mut host = host_with(&h, vec![]);
            let mode = password_mode(&host, None);
            let (mut c, first) = start(&mut host, &v, mode, ip(1), T0);
            let env2 = env.clone();
            c.pump(&mut host, first, vec![], &mut |v2h, idx, f| {
                if v2h && idx == msg_index {
                    Some(env2.clone())
                } else {
                    Some(f)
                }
            });
            assert_eq!(
                c.log.host_close(),
                Some(CloseCode::AuthFailed),
                "msg{} := {what}",
                msg_index * 2 - 3
            );
            assert!(matches!(
                c.log.host_failure(),
                Some(FailReason::AuthFailed(AuthDetail::Handshake(_)))
            ));
            assert_eq!(delivered_count(&c), 0);
            assert!(c.log.prompt().is_none());
        }
    }
}

#[test]
fn a20_host_pending_approval_rejects_every_encrypted_app_message() {
    let (h, v) = (device("host"), device("viewer"));
    for (what, env) in app_envelopes() {
        let mut host = host_with(&h, vec![]);
        let otp = host.otp().clone();
        let mut e = evil_viewer_pending(&mut host, &v, &otp);
        assert_eq!(host.state(e.id), Some(State::PendingApproval));
        let frame = e.est.encrypt(&env).unwrap();
        let acts = host.on_frame(e.id, &frame, T0, &mut OsRng);
        assert_eq!(
            host_close(&acts),
            Some(CloseCode::ProtocolViolation),
            "{what}"
        );
        assert!(
            matches!(host_reason(&acts), Some(FailReason::ProtocolViolation(_))),
            "{what}"
        );
        assert!(no_host_delivery(&acts), "{what}");
        assert!(
            acts.contains(&HostAction::PromptClosed { id: e.id }),
            "the prompt goes away"
        );
        assert_eq!(host.state(e.id), Some(State::Closed));
        // And nothing is processed afterwards.
        let frame = e.est.encrypt(&env).unwrap();
        assert!(host.on_frame(e.id, &frame, T0, &mut OsRng).is_empty());
        assert!(
            host.approve(e.id, e.est.sas(), T0).is_err(),
            "cannot approve a closed session"
        );
    }
}

#[test]
fn a20_host_input_before_approval_is_before_active_violation() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    let mut e = evil_viewer_pending(&mut host, &v, &otp);
    let frame = e.est.encrypt(&app_envelopes()[0].1).unwrap();
    let acts = host.on_frame(e.id, &frame, T0, &mut OsRng);
    assert_eq!(
        host_reason(&acts),
        Some(FailReason::ProtocolViolation(Violation::BeforeActive))
    );
}

#[test]
fn a20_host_unencrypted_or_tampered_frame_in_pending_fails_closed() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    let e = evil_viewer_pending(&mut host, &v, &otp);
    let acts = host.on_frame(e.id, &app_envelopes()[0].1, T0, &mut OsRng);
    assert_eq!(
        host_reason(&acts),
        Some(FailReason::ProtocolViolation(Violation::TransportAuth))
    );
    assert_eq!(host_close(&acts), Some(CloseCode::ProtocolViolation));
}

#[test]
fn a20_datagrams_before_active_close_the_session_in_every_host_state() {
    let (h, v) = (device("host"), device("viewer"));
    let dgram = vec![0x03u8; 64];
    // Hello, Spake, Noise(msg1), Noise(msg3), PendingApproval
    for stop_after in 0..5usize {
        let mut host = host_with(&h, vec![]);
        let mode = password_mode(&host, None);
        let (mut c, first) = start(&mut host, &v, mode, ip(1), T0);
        if stop_after > 0 {
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
        }
        let before = host.state(c.id);
        let acts = host.on_datagram(c.id, &dgram);
        assert_eq!(
            host_close(&acts),
            Some(CloseCode::ProtocolViolation),
            "state {before:?}"
        );
        assert_eq!(
            host_reason(&acts),
            Some(FailReason::ProtocolViolation(
                Violation::DatagramBeforeActive
            ))
        );
        assert!(no_host_delivery(&acts));
    }
}

#[test]
fn a21_viewer_sending_host_only_messages_in_active_is_wrong_role() {
    use remora_proto::messages::{MediaKeyAnnounce, SasReveal, SessionPending, SessionReject};
    let (h, v) = (device("host"), device("viewer"));
    for k in [
        control::Kind::Accept(SessionAccept { role: 1 }),
        control::Kind::MediaKey(MediaKeyAnnounce {
            key_id: 1,
            key: vec![0; 32],
        }),
        control::Kind::SasReveal(SasReveal { n_r: vec![0; 32] }),
        control::Kind::Pending(SessionPending {}),
        control::Kind::Reject(SessionReject { reason: 1 }),
    ] {
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
        assert_eq!(host.state(e.id), Some(State::Active));
        let frame = e.est.encrypt(&control_envelope(k.clone())).unwrap();
        let acts = host.on_frame(e.id, &frame, T0, &mut OsRng);
        assert_eq!(
            host_reason(&acts),
            Some(FailReason::ProtocolViolation(Violation::WrongRole)),
            "{k:?}"
        );
        assert_eq!(host_close(&acts), Some(CloseCode::ProtocolViolation));
        assert!(host.active_sessions().is_empty());
    }
}

#[test]
fn goodbye_in_pending_closes_normally_without_failure() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    let mut e = evil_viewer_pending(&mut host, &v, &otp);
    let frame = e
        .est
        .encrypt(&control_envelope(control::Kind::Bye(Goodbye {})))
        .unwrap();
    let acts = host.on_frame(e.id, &frame, T0, &mut OsRng);
    assert_eq!(host_close(&acts), Some(CloseCode::Normal));
    assert!(host_reason(&acts).is_none());
    assert!(acts.contains(&HostAction::PromptClosed { id: e.id }));
}

// ---------------------------------------------------------- viewer side --

#[test]
fn a20_viewer_awaiting_reveal_rejects_app_messages_instead_of_the_reveal() {
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    for (what, env) in app_envelopes() {
        if what == "sas reveal" {
            continue; // that is the expected message (with a wrong n_r: A17-S1)
        }
        let (mut e, _) = evil_host_viewer_awaiting_reveal(&v, &h, &otp);
        assert_eq!(e.viewer.state(), State::SasReveal);
        let frame = e.est.encrypt(&env).unwrap();
        let acts = e.viewer.on_frame(&frame, T0, &mut OsRng);
        assert_eq!(
            viewer_close(&acts),
            Some(CloseCode::ProtocolViolation),
            "{what}"
        );
        assert!(no_viewer_delivery(&acts));
        assert!(
            !acts
                .iter()
                .any(|a| matches!(a, ViewerAction::ShowSas { .. })),
            "no SAS shown"
        );
    }
}

#[test]
fn a17_viewer_rejects_a_reveal_that_does_not_open_the_commitment() {
    use remora_proto::messages::SasReveal;
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    let (mut e, mut n_r) = evil_host_viewer_awaiting_reveal(&v, &h, &otp);
    n_r[0] ^= 1;
    let frame = e
        .est
        .encrypt(&control_envelope(control::Kind::SasReveal(SasReveal {
            n_r: n_r.to_vec(),
        })))
        .unwrap();
    let acts = e.viewer.on_frame(&frame, T0, &mut OsRng);
    assert_eq!(viewer_close(&acts), Some(CloseCode::ProtocolViolation));
    assert!(
        !acts
            .iter()
            .any(|a| matches!(a, ViewerAction::ShowSas { .. })),
        "A17-S4: no SAS"
    );
}

#[test]
fn a20_a21_viewer_pending_rejects_host_messages_before_accept() {
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    for (what, env) in app_envelopes() {
        if what == "accept" {
            continue; // the legitimate next message
        }
        let mut e = evil_host_viewer_pending(&v, &h, &otp);
        assert_eq!(e.viewer.state(), State::PendingApproval);
        let frame = e.est.encrypt(&env).unwrap();
        let acts = e.viewer.on_frame(&frame, T0, &mut OsRng);
        assert_eq!(
            viewer_close(&acts),
            Some(CloseCode::ProtocolViolation),
            "{what}"
        );
        assert!(matches!(
            viewer_reason(&acts),
            Some(FailReason::ProtocolViolation(_))
        ));
        assert!(no_viewer_delivery(&acts), "{what}");
    }
}

#[test]
fn a21_host_sending_input_to_the_viewer_in_active_is_wrong_role() {
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
    for (what, env) in app_envelopes()
        .into_iter()
        .filter(|(w, _)| *w == "mouse button" || *w == "key")
    {
        let mut e2 = evil_host_viewer_pending(&v, &h, &otp);
        let accept = e2
            .est
            .encrypt(&control_envelope(control::Kind::Accept(SessionAccept {
                role: 1,
            })))
            .unwrap();
        e2.viewer.on_frame(&accept, T0, &mut OsRng);
        let frame = e2.est.encrypt(&env).unwrap();
        let acts = e2.viewer.on_frame(&frame, T0, &mut OsRng);
        assert_eq!(
            viewer_reason(&acts),
            Some(FailReason::ProtocolViolation(Violation::WrongRole)),
            "{what}"
        );
    }
    // A media key AFTER accept is legitimate: installed inside the session
    // (it never reaches the application), and the session goes on.
    let mk = e.est.encrypt(&app_envelopes()[2].1).unwrap();
    let acts = e.viewer.on_frame(&mk, T0, &mut OsRng);
    assert!(acts.is_empty(), "{acts:?}");
    assert_eq!(e.viewer.state(), State::Active);
}

#[test]
fn a20_viewer_datagrams_during_the_handshake_close_the_session() {
    // No host can have sent media before the safety code is even shown.
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    let (mut e, _) = evil_host_viewer_awaiting_reveal(&v, &h, &otp);
    assert_eq!(e.viewer.state(), State::SasReveal);
    let acts = e.viewer.on_datagram(&[1u8; 64], T0);
    assert_eq!(viewer_close(&acts), Some(CloseCode::ProtocolViolation));
    assert_eq!(
        viewer_reason(&acts),
        Some(FailReason::ProtocolViolation(
            Violation::DatagramBeforeActive
        ))
    );
}

#[test]
fn m3_viewer_datagrams_while_pending_are_dropped_unread() {
    // Changed in Phase 4 (phase4-criteria M3, §12 2026-10-21): the host
    // approves, then streams; a datagram can overtake the SessionAccept on
    // the ordered stream, so closing here would break real sessions. It is
    // dropped without being opened, and counted.
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    let mut e = evil_host_viewer_pending(&v, &h, &otp);
    let acts = e.viewer.on_datagram(&[1u8; 64], T0);
    assert!(acts.is_empty(), "{acts:?}");
    assert_eq!(e.viewer.state(), State::PendingApproval);
    assert_eq!(e.viewer.media_stats().before_active, 1);
    assert_eq!(e.viewer.media_stats().opened, 0);
}

#[test]
fn a20_viewer_hello_and_spake_states_reject_plaintext_app_messages() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut n = 30u8;
    for (what, env) in app_envelopes() {
        for idx in [0usize, 1] {
            n += 1;
            let mode = password_mode(&host, None);
            let (mut c, first) = start(&mut host, &v, mode, ip(n), T0);
            let env2 = env.clone();
            c.pump(&mut host, first, vec![], &mut |v2h, i, f| {
                if !v2h && i == idx {
                    Some(env2.clone())
                } else {
                    Some(f)
                }
            });
            assert_eq!(
                c.log.viewer_close(),
                Some(CloseCode::ProtocolViolation),
                "h2v[{idx}] := {what}"
            );
            assert_eq!(delivered_count(&c), 0);
            let id = c.id;
            host.disconnect(id);
        }
    }
}

#[test]
fn send_input_is_refused_before_active() {
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    let mut e = evil_host_viewer_pending(&v, &h, &otp);
    assert_eq!(e.viewer.send_input(input_click()), None);
}
