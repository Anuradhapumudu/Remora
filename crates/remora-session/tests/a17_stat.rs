//! phase3-criteria A17-stat (§3.4a, SECONDARY evidence): 10 000 runs of a
//! man in the middle that KNOWS the password and runs one complete session
//! with the viewer (as a host) and one with the host (as a viewer). It
//! wins only if the two safety codes are equal, so both users would read
//! the same code.
//!
//! Matches X ~ Binomial(10⁴, 10⁻⁶) ≈ Poisson(0.01) for an honest protocol:
//! INVESTIGATE at 1 match (≈ 1 % of honest runs), FAIL at ≥ 2 (≈ 5 × 10⁻⁵).
//! This detects only gross advantages (≈ ×1000); the structural A17-S1..S5
//! tests in remora-crypto are the real check.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::evil::{evil_host_viewer_pending, evil_viewer_pending};
use common::*;
use remora_session::{HostAction, ViewerAction};
use remora_testkit::stats::binomial_tail_ge;

const RUNS: u32 = 10_000;

#[test]
fn a17_stat_mitm_knowing_the_password_cannot_make_the_codes_match() {
    let (h, v, m) = (device("host"), device("viewer"), device("mitm"));
    let mut matches = 0u32;
    for _ in 0..RUNS {
        // Session 1: real host <-> MITM (as viewer), with the host's password.
        let mut host = host_with(&h, vec![]);
        let otp = host.otp().clone();
        let to_host = evil_viewer_pending(&mut host, &m, &otp);
        let host_sas = to_host
            .host_log
            .iter()
            .find_map(|a| match a {
                HostAction::Prompt { sas, .. } => Some(*sas),
                _ => None,
            })
            .unwrap();
        // Session 2: real viewer <-> MITM (as host), with the same password.
        let to_viewer = evil_host_viewer_pending(&v, &m, &otp);
        let viewer_sas = to_viewer
            .log
            .viewer
            .iter()
            .find_map(|a| match a {
                ViewerAction::ShowSas { sas, .. } => Some(*sas),
                _ => None,
            })
            .unwrap();
        if host_sas == viewer_sas {
            matches += 1;
        }
    }
    let p_ge = |k| binomial_tail_ge(u64::from(RUNS), 1e-6, k);
    eprintln!(
        "A17-stat: {matches} match(es) in {RUNS} MITM runs (honest: P(X>=1) = {:.4}, P(X>=2) = {:.1e})",
        p_ge(1),
        p_ge(2)
    );
    if matches == 1 {
        eprintln!("A17-stat: INVESTIGATE - one match (expected in about 1 % of honest runs)");
    }
    assert!(
        matches < 2,
        "A17-stat FAIL: {matches} matches in {RUNS} runs"
    );
}
