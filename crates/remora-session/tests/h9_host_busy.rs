//! H9 (phase4.5-criteria §4; owner, 2026-10-25, §1 Q5): one active session
//! at a time. While a session is `Active`, a new connection is refused as
//! "host busy" **before the handshake**: it never reaches the password check,
//! so it is not a password guess (INV12 untouched), does not consume the
//! one-time password (INV15 untouched), takes no pending slot and does not use
//! up the per-IP window (a legitimate viewer behind the same address can
//! connect once the session ends). Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use rand_core::OsRng;
use remora_session::limiter::{PER_IP_PER_MINUTE, Refusal};
use remora_session::{CloseCode, Millis, Refused, State};

#[test]
fn h9_connection_while_active_is_refused_busy_before_any_crypto() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = to_active(&mut host, &v, ip(1));
    assert_eq!(state_of(&host, &c).0, Some(State::Active));
    let otp = host.otp().reveal().to_owned();
    let failures = host.limiter().failures();
    for k in 0..(3 * PER_IP_PER_MINUTE as u64) {
        assert_eq!(
            host.accept_connection(ip(2), exporter(2), Millis(T0.0 + k), &mut OsRng),
            Err(Refused(Refusal::HostBusy)),
            "attempt {k}"
        );
    }
    // Nothing was counted: no pending slot, no password attempt, same password.
    assert_eq!(host.limiter().pending(), 0);
    assert_eq!(host.limiter().failures(), failures);
    assert_eq!(host.otp().reveal(), otp);
}

#[test]
fn h9_after_the_session_ends_the_same_address_and_password_work() {
    let (h, v1, v2) = (device("host"), device("viewer 1"), device("viewer 2"));
    let mut host = host_with(&h, vec![]);
    let c = to_active(&mut host, &v1, ip(1));
    for k in 0..(2 * PER_IP_PER_MINUTE as u64) {
        assert!(
            host.accept_connection(ip(2), exporter(2), Millis(T0.0 + k), &mut OsRng)
                .is_err()
        );
    }
    host.disconnect(c.id);
    // The password shown now was never spent by the refused attempts, and
    // ip(2)'s per-IP window is untouched: viewer 2 gets to the prompt.
    let c2 = to_prompt(&mut host, &v2, ip(2));
    assert_eq!(state_of(&host, &c2).0, Some(State::PendingApproval));
}

#[test]
fn h9_pending_sessions_do_not_make_the_host_busy() {
    // Only Active counts: viewers waiting at the prompt are the dialogs the
    // person chooses between (up to MAX_PENDING, A03).
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let _waiting = to_prompt(&mut host, &v, ip(1));
    assert!(
        host.accept_connection(ip(2), exporter(2), T0, &mut OsRng)
            .is_ok()
    );
}

#[test]
fn h9_a_viewer_already_waiting_cannot_be_approved_next_to_an_active_one() {
    // Two viewers reach the prompt before either is approved (admission only
    // blocks NEW connections). Approving the second while the first is
    // Active is refused and changes nothing.
    let (h, v1, v2) = (device("host"), device("viewer 1"), device("viewer 2"));
    let mut host = host_with(&h, vec![]);
    let mut c1 = to_prompt(&mut host, &v1, ip(1));
    let c2 = to_prompt(&mut host, &v2, ip(2));
    c1.approve(&mut host);
    assert_eq!(host.state(c1.id), Some(State::Active));
    let (_, sas2) = c2.log.prompt().expect("second prompt");
    assert_eq!(
        host.approve(c2.id, sas2, T0),
        Err(remora_session::ApproveError::AnotherSessionActive)
    );
    assert_eq!(host.state(c2.id), Some(State::PendingApproval));
    // Once the first has ended, the waiting one can be approved.
    host.disconnect(c1.id);
    assert!(host.approve(c2.id, sas2, T0).is_ok());
    assert_eq!(host.state(c2.id), Some(State::Active));
}

#[test]
fn h9_a_multi_viewer_host_still_admits_while_active() {
    // The rule is the apps' (HostConfig::one_active_session), not a limit of
    // the session layer: the multi-viewer tests keep working.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_multi_viewer(&h);
    let first = to_active(&mut host, &v, ip(1));
    // Admitted, and approved next to the first.
    let second = to_active(&mut host, &device("viewer 2"), ip(2));
    assert_eq!(host.state(first.id), Some(State::Active));
    assert_eq!(host.state(second.id), Some(State::Active));
}

#[test]
fn h9_host_busy_has_its_own_close_code() {
    // The viewer must be able to say "the host is busy", not "rate limited".
    assert_eq!(CloseCode::HostBusy as u16, 0x17);
    assert!(CloseCode::ALL.contains(&CloseCode::HostBusy));
    assert_ne!(CloseCode::HostBusy, CloseCode::RateLimited);
}
