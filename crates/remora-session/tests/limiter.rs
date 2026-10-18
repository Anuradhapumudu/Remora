//! phase3-criteria A02 / A03 / INV12: the limiter's arithmetic, in isolation.
//! Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use std::net::{IpAddr, Ipv4Addr};

use remora_session::Millis;
use remora_session::limiter::{
    ATTEMPTS_PER_OTP, COOLDOWN_MAX_MS, COOLDOWN_START_MS, IP_WINDOW_MS, Limiter, MAX_PENDING,
    PER_IP_PER_MINUTE, Refusal,
};

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, n))
}
const T: Millis = Millis(5_000_000);

#[test]
fn constants_match_the_criteria() {
    assert_eq!(MAX_PENDING, 4);
    assert_eq!(PER_IP_PER_MINUTE, 10);
    assert_eq!(ATTEMPTS_PER_OTP, 3);
    assert_eq!(COOLDOWN_START_MS, 30_000);
    assert_eq!(COOLDOWN_MAX_MS, 3_600_000);
    assert_eq!(IP_WINDOW_MS, 60_000);
}

#[test]
fn a03_at_most_four_pending_and_release_frees_a_slot() {
    let mut l = Limiter::new();
    for i in 0..4 {
        assert_eq!(l.admit(ip(i), T), Ok(()));
    }
    assert_eq!(l.pending(), 4);
    assert_eq!(l.admit(ip(9), T), Err(Refusal::TooManyPending));
    assert_eq!(l.pending(), 4, "a refusal does not count as pending");
    l.release();
    assert_eq!(l.pending(), 3);
    assert_eq!(l.admit(ip(9), T), Ok(()));
}

#[test]
fn release_never_underflows() {
    let mut l = Limiter::new();
    l.release();
    assert_eq!(l.pending(), 0);
    assert_eq!(l.admit(ip(1), T), Ok(()));
    assert_eq!(l.pending(), 1);
}

#[test]
fn a03_ten_connections_per_ip_per_sliding_minute() {
    let mut l = Limiter::new();
    for k in 0..10u64 {
        assert_eq!(l.admit(ip(1), Millis(T.0 + k)), Ok(()), "connection {k}");
        l.release();
    }
    assert_eq!(
        l.admit(ip(1), Millis(T.0 + 10)),
        Err(Refusal::IpRateLimited)
    );
    // Another IP is unaffected.
    assert_eq!(l.admit(ip(2), Millis(T.0 + 10)), Ok(()));
    l.release();
    // The window slides: 60 s after the first, one slot frees up.
    assert_eq!(
        l.admit(ip(1), Millis(T.0 + IP_WINDOW_MS - 1)),
        Err(Refusal::IpRateLimited)
    );
    assert_eq!(l.admit(ip(1), Millis(T.0 + IP_WINDOW_MS)), Ok(()));
    l.release();
    assert_eq!(
        l.admit(ip(1), Millis(T.0 + IP_WINDOW_MS)),
        Err(Refusal::IpRateLimited)
    );
}

#[test]
fn a03_refused_by_ip_does_not_consume_a_pending_slot() {
    let mut l = Limiter::new();
    for k in 0..10u64 {
        l.admit(ip(1), Millis(T.0 + k)).unwrap();
        l.release();
    }
    for _ in 0..20 {
        assert_eq!(l.admit(ip(1), T), Err(Refusal::IpRateLimited));
    }
    assert_eq!(l.pending(), 0);
}

#[test]
fn a02_third_failure_rotates_and_starts_a_30s_cooldown() {
    let mut l = Limiter::new();
    let o1 = l.record_failure(T);
    assert_eq!((o1.attempt, o1.rotate, o1.cooldown_until), (1, false, None));
    let o2 = l.record_failure(T);
    assert_eq!((o2.attempt, o2.rotate), (2, false));
    assert_eq!(
        l.check_password_attempt(T),
        Ok(()),
        "no cool-down before the 3rd"
    );
    let o3 = l.record_failure(T);
    assert_eq!(o3.attempt, 3);
    assert!(o3.rotate);
    assert_eq!(o3.cooldown_until, Some(Millis(T.0 + 30_000)));
    assert_eq!(
        l.failures(),
        0,
        "the new password starts with a clean count"
    );
    assert_eq!(
        l.check_password_attempt(Millis(T.0 + 29_999)),
        Err(Refusal::CoolingDown {
            until: Millis(T.0 + 30_000)
        })
    );
    assert_eq!(l.check_password_attempt(Millis(T.0 + 30_000)), Ok(()));
}

#[test]
fn a02_cooldown_doubles_up_to_one_hour() {
    let mut l = Limiter::new();
    let mut now = T;
    let mut seen = Vec::new();
    for _ in 0..10 {
        for _ in 0..2 {
            l.record_failure(now);
        }
        let o = l.record_failure(now);
        assert!(o.rotate);
        let until = o.cooldown_until.unwrap();
        seen.push(until.0 - now.0);
        now = until;
    }
    assert_eq!(
        seen,
        vec![
            30_000, 60_000, 120_000, 240_000, 480_000, 960_000, 1_920_000, 3_600_000, 3_600_000,
            3_600_000
        ]
    );
}

#[test]
fn a03_failures_are_global_not_per_connection() {
    // Three failures from three different "connections" (the limiter does
    // not know about connections at all): the third rotates.
    let mut l = Limiter::new();
    for i in 0..3 {
        l.admit(ip(i), T).unwrap();
    }
    l.record_failure(T);
    l.release();
    l.record_failure(T);
    l.release();
    assert!(l.record_failure(T).rotate);
}
