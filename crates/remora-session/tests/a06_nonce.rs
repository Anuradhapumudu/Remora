//! phase3-criteria A06 (and the connection-code part of INV4): a
//! connection-code nonce authenticates at most one connection. The host
//! remembers the nonces it issued; a ViewerHello must carry one that is
//! issued, unused and unexpired, checked BEFORE SPAKE2 (nothing is sent,
//! no password attempt is counted). On the wire: AUTH_FAILED. Written
//! before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use rand_core::OsRng;
use remora_session::fail::AuthDetail;
use remora_session::{CloseCode, FailReason, HostAction, Millis, ViewerSession};

/// Starts a viewer with a given nonce, without issuing it.
fn connect_with_nonce(
    host: &mut remora_session::Host,
    v: &Device,
    nonce: [u8; 16],
    from: u8,
    now: Millis,
) -> Conn {
    let id = host
        .accept_connection(ip(from), exporter(7), now, &mut OsRng)
        .unwrap();
    let mode = password_mode(host, None);
    let (viewer, first) = ViewerSession::start(viewer_cfg(v, mode), nonce, exporter(7), now);
    let mut c = Conn {
        id,
        nonce,
        viewer,
        log: Log::default(),
        now,
        v2h: vec![],
        h2v: vec![],
    };
    c.feed_viewer_actions(host, first);
    c
}

fn failed_attempt(c: &Conn) -> Option<Option<u32>> {
    c.log.host.iter().find_map(|a| match a {
        HostAction::Failed { attempt, .. } => Some(*attempt),
        _ => None,
    })
}

#[test]
fn a06_a_nonce_works_once() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let nonce = [0x5A; 16];
    host.issue_nonce(nonce, Millis(T0.0 + 300_000));
    let first = connect_with_nonce(&mut host, &v, nonce, 1, T0);
    assert!(first.log.prompt().is_some());
    let second = connect_with_nonce(&mut host, &v, nonce, 2, T0);
    assert_eq!(second.log.host_failure(), Some(FailReason::NonceReused));
    assert_eq!(second.log.host_close(), Some(CloseCode::AuthFailed));
    assert_eq!(second.h2v.len(), 0, "rejected before SPAKE2: nothing sent");
    assert_eq!(
        failed_attempt(&second),
        Some(None),
        "not a password attempt"
    );
}

#[test]
fn a06_nonce_is_used_up_even_if_that_handshake_failed() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let nonce = [0x6B; 16];
    host.issue_nonce(nonce, Millis(T0.0 + 300_000));
    let id = host
        .accept_connection(ip(1), exporter(7), T0, &mut OsRng)
        .unwrap();
    let (viewer, first) = ViewerSession::start(
        viewer_cfg(&v, wrong_password_mode(&host)),
        nonce,
        exporter(7),
        T0,
    );
    let mut c = Conn {
        id,
        nonce,
        viewer,
        log: Log::default(),
        now: T0,
        v2h: vec![],
        h2v: vec![],
    };
    c.feed_viewer_actions(&mut host, first);
    assert_eq!(c.log.host_close(), Some(CloseCode::AuthFailed));
    let again = connect_with_nonce(&mut host, &v, nonce, 2, T0);
    assert_eq!(again.log.host_failure(), Some(FailReason::NonceReused));
}

#[test]
fn a06_a_nonce_the_host_never_issued_is_refused() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = connect_with_nonce(&mut host, &v, [0x77; 16], 1, T0);
    assert_eq!(
        c.log.host_failure(),
        Some(FailReason::AuthFailed(AuthDetail::UnknownNonce))
    );
    assert_eq!(c.log.host_close(), Some(CloseCode::AuthFailed));
    assert_eq!(c.h2v.len(), 0);
}

#[test]
fn a06_an_expired_nonce_is_refused_exactly_at_expiry() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    host.issue_nonce([1; 16], Millis(T0.0 + 1_000));
    host.issue_nonce([2; 16], Millis(T0.0 + 1_000));
    let ok = connect_with_nonce(&mut host, &v, [1; 16], 1, Millis(T0.0 + 999));
    assert!(ok.log.prompt().is_some(), "valid until just before expiry");
    let late = connect_with_nonce(&mut host, &v, [2; 16], 2, Millis(T0.0 + 1_000));
    assert_eq!(late.log.host_failure(), Some(FailReason::Expired));
    assert_eq!(late.log.host_close(), Some(CloseCode::AuthFailed));
    assert_eq!(late.h2v.len(), 0);
}

#[test]
fn a06_used_nonces_are_remembered_until_expiry_then_forgotten() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    host.issue_nonce([1; 16], Millis(T0.0 + 300_000));
    host.issue_nonce([2; 16], Millis(T0.0 + 600_000));
    assert_eq!(host.outstanding_nonces(), 2);
    connect_with_nonce(&mut host, &v, [1; 16], 1, T0);
    assert_eq!(
        host.outstanding_nonces(),
        2,
        "a used nonce stays, to recognise replays"
    );
    // After its expiry the first is dropped (a replay is then simply unknown).
    host.tick(Millis(T0.0 + 300_000));
    assert_eq!(host.outstanding_nonces(), 1);
    host.tick(Millis(T0.0 + 600_000));
    assert_eq!(host.outstanding_nonces(), 0);
}

#[test]
fn a06_outstanding_nonces_are_bounded() {
    // Issuing is a local action, but memory must still be bounded: beyond
    // the cap the oldest issued nonce is dropped (and no longer works).
    use remora_session::MAX_OUTSTANDING_NONCES;
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    for n in 0..=MAX_OUTSTANDING_NONCES {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&(n as u64).to_be_bytes());
        host.issue_nonce(nonce, Millis(T0.0 + 300_000));
    }
    assert_eq!(host.outstanding_nonces(), MAX_OUTSTANDING_NONCES);
    let oldest = connect_with_nonce(&mut host, &v, [0; 16], 1, T0);
    assert_eq!(
        oldest.log.host_failure(),
        Some(FailReason::AuthFailed(AuthDetail::UnknownNonce))
    );
}

#[test]
fn a06_close_codes_are_auth_failed() {
    assert_eq!(FailReason::NonceReused.close_code(), CloseCode::AuthFailed);
    assert_eq!(FailReason::Expired.close_code(), CloseCode::AuthFailed);
    assert_eq!(
        FailReason::AuthFailed(AuthDetail::UnknownNonce).close_code(),
        CloseCode::AuthFailed
    );
}

#[test]
fn a06_trusted_mode_needs_an_issued_nonce_too() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![v.key.public()]);
    let id = host
        .accept_connection(ip(1), exporter(7), T0, &mut OsRng)
        .unwrap();
    let mode = remora_session::ViewerMode::Trusted {
        pinned: h.key.public(),
    };
    let (viewer, first) = ViewerSession::start(viewer_cfg(&v, mode), [9; 16], exporter(7), T0);
    let mut c = Conn {
        id,
        nonce: [9; 16],
        viewer,
        log: Log::default(),
        now: T0,
        v2h: vec![],
        h2v: vec![],
    };
    c.feed_viewer_actions(&mut host, first);
    assert_eq!(
        c.log.host_failure(),
        Some(FailReason::AuthFailed(AuthDetail::UnknownNonce))
    );
}

#[test]
fn a06_expiry_pruning_keeps_exactly_the_unexpired_nonces() {
    // Mutation-gate finding: counting alone did not show WHICH nonces a
    // tick keeps.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    host.issue_nonce([1; 16], Millis(T0.0 + 300_000));
    host.issue_nonce([2; 16], Millis(T0.0 + 600_000));
    host.tick(Millis(T0.0 + 1));
    assert_eq!(host.outstanding_nonces(), 2, "nothing expired yet");
    host.tick(Millis(T0.0 + 300_000));
    assert_eq!(host.outstanding_nonces(), 1);
    // The survivor is the later one, and it still works.
    let c = connect_with_nonce(&mut host, &v, [2; 16], 1, Millis(T0.0 + 300_001));
    assert!(c.log.prompt().is_some());
    let gone = connect_with_nonce(&mut host, &v, [1; 16], 2, Millis(T0.0 + 300_001));
    assert_eq!(
        gone.log.host_failure(),
        Some(FailReason::AuthFailed(AuthDetail::UnknownNonce))
    );
}
