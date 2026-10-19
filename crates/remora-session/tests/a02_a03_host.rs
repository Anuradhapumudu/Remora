//! phase3-criteria A01 (attempt counting), A02, A03 through the real Host:
//! wrong passwords rotate the OTP globally, the cool-down refuses even the
//! right new password, admission refuses before any crypto. Written before
//! the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use rand_core::OsRng;
use remora_session::limiter::Refusal;
use remora_session::{CloseCode, FailReason, HostAction, Millis, Refused, State, Step};

fn attempts(c: &Conn) -> Vec<Option<u32>> {
    c.log
        .host
        .iter()
        .filter_map(|a| match a {
            HostAction::Failed { attempt, .. } => Some(*attempt),
            _ => None,
        })
        .collect()
}

#[test]
fn a01_wrong_password_is_auth_failed_at_msg1_and_counts_one_attempt() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mode = wrong_password_mode(&host);
    let c = connect(&mut host, &v, mode, ip(1), T0);
    assert_eq!(c.log.host_close(), Some(CloseCode::AuthFailed));
    assert!(matches!(
        c.log.host_failure(),
        Some(FailReason::AuthFailed(_))
    ));
    assert!(c.log.host.iter().any(|a| matches!(
        a,
        HostAction::Failed {
            step: Step::NoiseMsg1,
            ..
        }
    )));
    assert_eq!(attempts(&c), vec![Some(1)]);
    // Host sent HostHello and SpakeB, then nothing (its identity in msg2
    // is never sent to a peer without the password).
    assert_eq!(c.h2v.len(), 2);
    assert_eq!(host.state(c.id), Some(State::Closed));
    assert_eq!(host.limiter().pending(), 0);
    assert!(c.log.prompt().is_none());
}

#[test]
fn a02_three_wrong_passwords_rotate_and_the_old_one_stops_working() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let old = host.otp().clone();
    let mut rotated = Vec::new();
    for n in 1..=3u32 {
        let mode = wrong_password_mode(&host);
        let c = connect(&mut host, &v, mode, ip(n as u8), T0);
        assert_eq!(attempts(&c), vec![Some(n)]);
        rotated.extend(
            c.log
                .host
                .iter()
                .filter(|a| matches!(a, HostAction::OtpRotated { .. }))
                .cloned(),
        );
    }
    assert_eq!(
        rotated,
        vec![HostAction::OtpRotated {
            cooldown_until: Millis(T0.0 + 30_000)
        }]
    );
    assert_ne!(
        host.otp().reveal(),
        old.reveal(),
        "a new password is in effect"
    );
    // After the cool-down, the OLD password (now "guessed right") fails.
    let later = Millis(T0.0 + 30_000);
    let mode = remora_session::ViewerMode::Password {
        otp: old,
        expect: None,
    };
    let c = connect(&mut host, &v, mode, ip(9), later);
    assert_eq!(c.log.host_close(), Some(CloseCode::AuthFailed));
}

#[test]
fn a02_right_new_password_during_cooldown_is_rate_limited_before_crypto() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    for n in 1..=3u8 {
        let mode = wrong_password_mode(&host);
        connect(&mut host, &v, mode, ip(n), T0);
    }
    let during = Millis(T0.0 + 29_999);
    let mode = password_mode(&host, None);
    let c = connect(&mut host, &v, mode, ip(9), during);
    assert_eq!(c.log.host_close(), Some(CloseCode::RateLimited));
    assert_eq!(c.log.host_failure(), Some(FailReason::RateLimited));
    assert_eq!(
        c.h2v.len(),
        0,
        "refused at the hello: no SPAKE2, nothing sent"
    );
    assert_eq!(attempts(&c), vec![None], "a refusal is not an attempt");
    // Right after the cool-down it works.
    let mode = password_mode(&host, None);
    let c = connect(&mut host, &v, mode, ip(10), Millis(T0.0 + 30_000));
    assert!(c.log.prompt().is_some());
}

#[test]
fn a02_trusted_devices_are_not_locked_out_by_a_password_cooldown() {
    let (h, v, t) = (device("host"), device("attacker"), device("trusted laptop"));
    let mut host = host_with(&h, vec![t.key.public()]);
    for n in 1..=3u8 {
        let mode = wrong_password_mode(&host);
        connect(&mut host, &v, mode, ip(n), T0);
    }
    let mode = remora_session::ViewerMode::Trusted {
        pinned: h.key.public(),
    };
    let c = connect(&mut host, &t, mode, ip(20), Millis(T0.0 + 1));
    assert!(c.log.prompt().is_some());
}

#[test]
fn a03_fifty_simultaneous_connections_at_most_four_pending() {
    let (h, _) = (device("host"), ());
    let mut host = host_with(&h, vec![]);
    let mut admitted = 0;
    let mut refused = 0;
    for i in 0..50u8 {
        match host.accept_connection(ip(i), exporter(1), T0, &mut OsRng) {
            Ok(_) => admitted += 1,
            Err(Refused(Refusal::TooManyPending)) => refused += 1,
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!((admitted, refused), (4, 46));
    assert_eq!(host.limiter().pending(), 4);
}

#[test]
fn a03_parallel_wrong_guesses_share_one_global_attempt_count() {
    // Four connections admitted at once (the cap), each with a different
    // wrong password, then each handshake runs. The count is per password,
    // not per connection: the 3rd failure rotates; the 4th connection's
    // hello then arrives during the cool-down and is refused (no attempt).
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp_before = host.otp().clone();
    let started: Vec<_> = (0..4u8)
        .map(|i| {
            let mode = wrong_password_mode(&host);
            start(&mut host, &v, mode, ip(i), T0)
        })
        .collect();
    assert_eq!(host.limiter().pending(), 4);
    let mut all = Vec::new();
    for (mut c, first) in started {
        c.feed_viewer_actions(&mut host, first);
        all.extend(attempts(&c));
    }
    assert_eq!(all, vec![Some(1), Some(2), Some(3), None]);
    assert_ne!(host.otp().reveal(), otp_before.reveal());
    assert_eq!(host.limiter().pending(), 0);
}

#[test]
fn a03_eleventh_connection_from_one_ip_in_a_minute_is_refused() {
    let (h, _) = (device("host"), ());
    let mut host = host_with(&h, vec![]);
    for k in 0..10u64 {
        let id = host
            .accept_connection(ip(1), exporter(1), Millis(T0.0 + k), &mut OsRng)
            .unwrap();
        host.disconnect(id);
    }
    assert_eq!(
        host.accept_connection(ip(1), exporter(1), Millis(T0.0 + 10), &mut OsRng),
        Err(Refused(Refusal::IpRateLimited))
    );
    assert!(
        host.accept_connection(ip(2), exporter(1), Millis(T0.0 + 10), &mut OsRng)
            .is_ok()
    );
}
