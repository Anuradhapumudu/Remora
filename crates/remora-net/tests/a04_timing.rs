//! phase3-criteria A04 timing (§3.1a): every AUTH_FAILED is sent no
//! earlier than 200 ms after the failing message arrived, and failures at
//! the same step are indistinguishable in time.
//!
//! PASS iff every sample is in [200, 225] ms (measured at the client from
//! sending the failing message to seeing the close) and the medians of any
//! two failure types at the same step differ by < 1 ms. An A/A control
//! (one type measured twice) runs first; if ITS medians differ by ≥ 1 ms
//! the run is "too noisy to judge" — reported as such, never as a pass.
//!
//! Samples per type: env `A04_SAMPLES` (default 20; the criteria run uses
//! 200). One test function in its own binary, so nothing runs alongside it.
//! Each sample uses a fresh host (rate limits and password rotation would
//! otherwise interfere). Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use rand_core::OsRng;
use remora_crypto::identity::{DeviceId, IdentityCert};
use remora_crypto::pake::{Pake, PakeContext, PakeRole, Spake2Ed25519};
use remora_net::{AUTH_FAILURE_FLOOR, TIMING_ANOMALY, floor_deadline};
use remora_session::{CloseCode, Identity, ViewerMode};

const LOW_MS: f64 = 200.0;
/// Below this many samples per type, medians are dominated by single
/// noisy samples (seen on a busy 2-core CI runner with 3 samples: a 1.07 ms
/// "difference" between two types that the 200-sample run puts 0.001 ms
/// apart), so they are not compared. The window check still runs on every
/// sample, and that is what catches a missing floor.
const MIN_SAMPLES_FOR_MEDIANS: usize = 20;
const HIGH_MS: f64 = 225.0;

fn samples() -> usize {
    std::env::var("A04_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20)
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    // step 1: the host fails at Noise msg1
    WrongPassword,
    CorruptedMsg1,
    ReplayedMsg1,
    SwappedSpakeA,
    // step 3: the host fails at Noise msg3
    BadCertSignature,
    CertKeyMismatch,
    UntrustedKey,
}

/// A msg1 recorded from a separate host (for the replay type).
async fn record_msg1(v: &Device) -> Vec<u8> {
    let h = device("other host");
    let host = start_host(&h, vec![]).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let otp = host.server.otp();
    let mut msg1 = None;
    let _ = run_viewer(host.addr, viewer_cfg(v, password(&otp)), nonce, |i, f| {
        if i == 2 {
            msg1 = Some(f.clone());
        }
        Some(f)
    })
    .await;
    msg1.unwrap()
}

/// One measurement: ms from sending the failing message to the close.
async fn sample(kind: Kind, v: &Device, replay: &[u8]) -> f64 {
    let h = device("host");
    let trusted = matches!(kind, Kind::UntrustedKey);
    let host = start_host(
        &h,
        if trusted {
            vec![device("someone").key.public()]
        } else {
            vec![]
        },
    )
    .await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let otp = host.server.otp();
    let other = device("other");
    let identity = match kind {
        Kind::BadCertSignature => {
            let mut b = v.identity.cert.encode();
            let n = b.len();
            b[n - 3] ^= 0x01;
            std::sync::Arc::new(Identity {
                noise: clone_noise(v),
                cert: IdentityCert::decode(&b).unwrap(),
            })
        }
        Kind::CertKeyMismatch => std::sync::Arc::new(Identity {
            noise: clone_noise(v),
            cert: v
                .key
                .sign_cert(other.identity.noise.public(), "viewer", 1)
                .unwrap(),
        }),
        _ => v.identity.clone(),
    };
    let mode = match kind {
        Kind::WrongPassword => wrong(&otp),
        Kind::UntrustedKey => ViewerMode::Trusted {
            pinned: h.key.public(),
        },
        _ => password(&otp),
    };
    let cfg = remora_session::ViewerConfig { identity, mode };
    let replay = replay.to_vec();
    let out = run_viewer(host.addr, cfg, nonce, move |i, f| match (kind, i) {
        (Kind::CorruptedMsg1, 2) => {
            let mut f = f;
            f[7] ^= 0x20;
            Some(f)
        }
        (Kind::ReplayedMsg1, 2) => Some(replay.clone()),
        (Kind::SwappedSpakeA, 1) => {
            // A different but VALID element: the host derives another K.
            let ctx = PakeContext {
                host_device_id: DeviceId::from_bytes([0; 10]),
                nonce: [0; 16],
            };
            let (_, m) = Spake2Ed25519::start(PakeRole::Viewer, &otp, &ctx, &mut OsRng);
            Some(m.as_bytes().to_vec())
        }
        _ => Some(f),
    })
    .await;
    assert_eq!(
        out.host_close,
        Some(CloseCode::AuthFailed),
        "{kind:?}: {out:?}"
    );
    assert!(!out.reached_active());
    out.close_after_last_send.unwrap().as_secs_f64() * 1000.0
}

/// The viewer's Noise key again, for a second Identity with a bad cert.
fn clone_noise(v: &Device) -> remora_crypto::noise::NoiseStaticKeypair {
    remora_crypto::noise::NoiseStaticKeypair::from_secret(v.noise_secret)
}

async fn measure(kind: Kind, n: usize, v: &Device, replay: &[u8]) -> Vec<f64> {
    let mut xs = Vec::with_capacity(n);
    for _ in 0..n {
        xs.push(sample(kind, v, replay).await);
    }
    xs
}

fn check_window(kind: Kind, xs: &[f64]) {
    let lo = xs.iter().cloned().fold(f64::INFINITY, f64::min);
    let hi = xs.iter().cloned().fold(0.0, f64::max);
    eprintln!("A04 {kind:?}: n={} min={lo:.2} ms max={hi:.2} ms", xs.len());
    assert!(
        lo >= LOW_MS,
        "{kind:?}: a close came after {lo:.2} ms < {LOW_MS} ms (floor missing)"
    );
    assert!(
        hi <= HIGH_MS,
        "{kind:?}: a close came after {hi:.2} ms > {HIGH_MS} ms"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a04_failures_at_the_same_step_are_indistinguishable_in_time() {
    let n = samples();
    let v = device("viewer");
    let replay = record_msg1(&v).await;

    // A/A control: the same type twice.
    let mut a1 = measure(Kind::WrongPassword, n, &v, &replay).await;
    let mut a2 = measure(Kind::WrongPassword, n, &v, &replay).await;
    check_window(Kind::WrongPassword, &a1);
    check_window(Kind::WrongPassword, &a2);
    let compare = n >= MIN_SAMPLES_FOR_MEDIANS;
    if !compare {
        eprintln!(
            "A04: n = {n} < {MIN_SAMPLES_FOR_MEDIANS}: window checked on every sample, medians NOT compared (not a statistical result)"
        );
    }
    let aa = (median(&mut a1) - median(&mut a2)).abs();
    eprintln!("A04 A/A control: median difference {aa:.3} ms");
    assert!(
        !compare || aa < 1.0,
        "TOO NOISY TO JUDGE: A/A medians differ by {aa:.3} ms (≥ 1 ms) — not a pass"
    );

    for step in [
        vec![
            Kind::WrongPassword,
            Kind::CorruptedMsg1,
            Kind::ReplayedMsg1,
            Kind::SwappedSpakeA,
        ],
        vec![
            Kind::BadCertSignature,
            Kind::CertKeyMismatch,
            Kind::UntrustedKey,
        ],
    ] {
        let mut medians = Vec::new();
        for kind in step {
            let mut xs = measure(kind, n, &v, &replay).await;
            check_window(kind, &xs);
            medians.push((kind, median(&mut xs)));
        }
        for (ka, ma) in &medians {
            for (kb, mb) in &medians {
                assert!(
                    !compare || (ma - mb).abs() < 1.0,
                    "{ka:?} median {ma:.3} ms vs {kb:?} {mb:.3} ms: ≥ 1 ms apart"
                );
            }
        }
    }
}

#[test]
fn floor_deadline_is_arrival_plus_200_ms_and_flags_slow_work() {
    use tokio::time::Instant;
    let arrival = Instant::now();
    let (at, anomaly) = floor_deadline(arrival, arrival + Duration::from_millis(3));
    assert_eq!(at, arrival + AUTH_FAILURE_FLOOR);
    assert!(!anomaly);
    // Work just under the anomaly threshold: still hidden by the floor.
    let (at, anomaly) =
        floor_deadline(arrival, arrival + TIMING_ANOMALY - Duration::from_millis(1));
    assert_eq!(at, arrival + AUTH_FAILURE_FLOOR);
    assert!(!anomaly);
    // At the threshold the host must log an anomaly (the floor may stop
    // hiding the work).
    let (_, anomaly) = floor_deadline(arrival, arrival + TIMING_ANOMALY);
    assert!(anomaly);
    // Work longer than the floor: the close cannot go out before the
    // verdict exists.
    let late = arrival + Duration::from_millis(300);
    let (at, anomaly) = floor_deadline(arrival, late);
    assert_eq!(at, late);
    assert!(anomaly);
}

#[test]
fn floor_constants() {
    assert_eq!(AUTH_FAILURE_FLOOR, Duration::from_millis(200));
    assert_eq!(TIMING_ANOMALY, Duration::from_millis(150));
}
