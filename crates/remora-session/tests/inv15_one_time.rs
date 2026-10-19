//! INV15 (owner, 2026-10-18): the one-time password is ONE-time. Found
//! during implementation: the docs called it one-time but only INV12
//! (3 failures) ever rotated it, so a code survived a successful session —
//! anyone who saw it (shoulder, screenshot, chat history) could reconnect
//! later and face only the accept prompt.
//!
//! Rule: the password is consumed the moment a viewer proves it (Noise
//! msg1 authenticates) — before, and therefore regardless of, how the
//! session ends: approved and used, denied, prompt timeout, disconnect,
//! protocol error. Attempts that never present the right password keep
//! counting toward INV12 instead (rotating on those would let one wrong
//! guess invalidate the code). Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use rand_core::OsRng;
use remora_session::{CloseCode, FailReason, HostAction, Millis, State, ViewerMode};

fn reuse(
    host: &mut remora_session::Host,
    v: &Device,
    otp: &remora_crypto::secret::Otp,
    from: u8,
    now: Millis,
) -> Conn {
    let mode = ViewerMode::Password {
        otp: otp.clone(),
        expect: None,
    };
    connect(host, v, mode, ip(from), now)
}

#[test]
fn inv15_successful_session_then_same_password_fails() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    let mut c = to_active(&mut host, &v, ip(1));
    assert!(c.log.host.contains(&HostAction::OtpUsed { id: c.id }));
    assert_ne!(
        host.otp().reveal(),
        otp.reveal(),
        "a new password is in effect"
    );
    let acts = c.viewer.disconnect();
    c.feed_viewer_actions(&mut host, acts);
    let again = reuse(&mut host, &v, &otp, 2, T0);
    assert_eq!(again.log.host_close(), Some(CloseCode::AuthFailed));
    assert!(matches!(
        again.log.host_failure(),
        Some(FailReason::AuthFailed(_))
    ));
    assert!(
        again.log.prompt().is_none(),
        "never reaches the accept prompt"
    );
}

#[test]
fn inv15_same_password_cannot_open_a_second_session_while_the_first_is_active() {
    let (h, v, eve) = (device("host"), device("viewer"), device("shoulder surfer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    let c = to_active(&mut host, &v, ip(1));
    assert_eq!(host.state(c.id), Some(State::Active));
    let second = reuse(&mut host, &eve, &otp, 2, T0);
    assert_eq!(second.log.host_close(), Some(CloseCode::AuthFailed));
    assert!(second.log.prompt().is_none());
}

#[test]
fn inv15_password_is_consumed_whatever_way_the_session_ends() {
    let (h, v) = (device("host"), device("viewer"));
    for ending in [
        "deny",
        "prompt timeout",
        "host disconnect",
        "viewer goodbye",
        "protocol error",
    ] {
        let mut host = host_with(&h, vec![]);
        let otp = host.otp().clone();
        let mut c = to_prompt(&mut host, &v, ip(1));
        let acts = match ending {
            "deny" => host.deny(c.id),
            "prompt timeout" => host.tick(Millis(T0.0 + 60_000)),
            "host disconnect" => host.disconnect(c.id),
            "viewer goodbye" => c
                .viewer
                .disconnect()
                .into_iter()
                .flat_map(|a| match a {
                    remora_session::ViewerAction::Send(f) => {
                        host.on_frame(c.id, &f, T0, &mut OsRng)
                    }
                    _ => vec![],
                })
                .collect(),
            _ => host.on_datagram(c.id, &[1; 64]),
        };
        c.host_actions(&mut host, acts);
        assert_eq!(host.state(c.id), Some(State::Closed), "{ending}");
        let again = reuse(&mut host, &v, &otp, 2, Millis(T0.0 + 60_001));
        assert_eq!(
            again.log.host_close(),
            Some(CloseCode::AuthFailed),
            "{ending}: old password still worked"
        );
    }
}

#[test]
fn inv15_consumed_at_authentication_even_if_the_handshake_then_fails() {
    // msg1 authenticated (right password), then msg3 is corrupted: the
    // password was still proven, so it is still consumed.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    let mode = password_mode(&host, None);
    let (mut c, first) = start(&mut host, &v, mode, ip(1), T0);
    c.pump(&mut host, first, vec![], &mut |v2h, idx, mut f| {
        if v2h && idx == 3 {
            f[10] ^= 1;
        }
        Some(f)
    });
    assert_eq!(c.log.host_close(), Some(CloseCode::AuthFailed));
    assert!(c.log.host.contains(&HostAction::OtpUsed { id: c.id }));
    let again = reuse(&mut host, &v, &otp, 2, T0);
    assert_eq!(again.log.host_close(), Some(CloseCode::AuthFailed));
}

#[test]
fn inv15_new_password_works_and_is_itself_one_time() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c1 = to_active(&mut host, &v, ip(1));
    let second = host.otp().clone();
    let c2 = to_prompt(&mut host, &v, ip(2));
    assert!(c2.log.prompt().is_some(), "the new password works once");
    assert!(c2.log.host.contains(&HostAction::OtpUsed { id: c2.id }));
    let third = reuse(&mut host, &v, &second, 3, T0);
    assert_eq!(third.log.host_close(), Some(CloseCode::AuthFailed));
    let _ = c1;
}

#[test]
fn inv15_wrong_passwords_do_not_consume_the_code() {
    // INV12 unchanged: two wrong guesses leave the code valid.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    for n in 1..=2u8 {
        let mode = wrong_password_mode(&host);
        let c = connect(&mut host, &v, mode, ip(n), T0);
        assert!(
            !c.log
                .host
                .iter()
                .any(|a| matches!(a, HostAction::OtpUsed { .. }))
        );
    }
    assert_eq!(host.otp().reveal(), otp.reveal());
    let ok = reuse(&mut host, &v, &otp, 9, T0);
    assert!(ok.log.prompt().is_some());
}

#[test]
fn inv15_a_used_code_starts_a_fresh_attempt_count_without_cooldown() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    for n in 1..=2u8 {
        let mode = wrong_password_mode(&host);
        connect(&mut host, &v, mode, ip(n), T0);
    }
    assert_eq!(host.limiter().failures(), 2);
    let _ok = to_prompt(&mut host, &v, ip(5));
    assert_eq!(host.limiter().failures(), 0, "count is per password");
    // The very next attempt with the new password is not cooling down.
    let next = to_prompt(&mut host, &v, ip(6));
    assert!(next.log.prompt().is_some());
}

#[test]
fn inv15_trusted_sessions_do_not_touch_the_password() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![v.key.public()]);
    let otp = host.otp().clone();
    let mode = ViewerMode::Trusted {
        pinned: h.key.public(),
    };
    let mut c = connect(&mut host, &v, mode, ip(1), T0);
    c.approve(&mut host);
    assert_eq!(host.otp().reveal(), otp.reveal());
    assert!(
        !c.log
            .host
            .iter()
            .any(|a| matches!(a, HostAction::OtpUsed { .. }))
    );
}

#[test]
fn inv15_after_a_denied_prompt_the_same_password_fails() {
    // Owner (2026-10-18): one of the three required cases, named on its own.
    // The password was proven before the prompt, so denying does not give
    // it back: the user needs a fresh code (a Phase 7 UI requirement makes
    // that obvious instead of looking like a bug).
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().clone();
    let mut c = to_prompt(&mut host, &v, ip(1));
    let acts = host.deny(c.id);
    c.host_actions(&mut host, acts);
    assert_eq!(c.log.viewer_failure(), Some(FailReason::Rejected));
    let retry = reuse(&mut host, &v, &otp, 2, T0);
    assert_eq!(retry.log.host_close(), Some(CloseCode::AuthFailed));
    assert!(retry.log.prompt().is_none());
    // The fresh code works.
    let fresh = to_prompt(&mut host, &v, ip(3));
    assert!(fresh.log.prompt().is_some());
}
