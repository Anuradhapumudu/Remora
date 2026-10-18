//! phase3-criteria A10 over QUIC (tampering after Active fails closed),
//! A24 (slowloris: handshake not complete in 10 s ⇒ TIMEOUT), and the §2
//! logging rule: exactly one WARN `handshake_failed` per failure with the
//! precise reason, step, peer and attempt — and no secret (A28). Written
//! before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use remora_net::HostEvent;
use remora_session::CloseCode;
use remora_testkit::canary::{Canary, LogCapture, find_leaks};

fn click() -> remora_proto::messages::Input {
    use remora_proto::messages::{Input, MouseButton, input};
    Input {
        kind: Some(input::Kind::Button(MouseButton {
            button: 1,
            down: true,
            x: 0.5,
            y: 0.5,
        })),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a10_tampered_frame_after_active_closes_with_protocol_violation() {
    // A MITM cannot sit in the path of a working session (A14), so the
    // tampering is staged by a scripted viewer: it completes the handshake
    // honestly, is approved, sends one good input, then a tampered one.
    let (h, v) = (device("host"), device("viewer"));
    for edit in ["flip", "truncate", "duplicate-previous"] {
        let mut host = start_host(&h, vec![]).await;
        let nonce = host.server.issue_nonce(Duration::from_secs(300));
        let (_ep, conn, mut stream) = raw_connect(host.addr).await;
        let ex = remora_net::exporter(&conn).unwrap();
        let cfg = viewer_cfg(&v, password(&host.server.otp()));
        let (mut s, first) =
            remora_session::ViewerSession::start(cfg, nonce, ex, remora_session::Millis(0));
        let mut pending = first;
        loop {
            for a in std::mem::take(&mut pending) {
                if let remora_session::ViewerAction::Send(f) = a {
                    stream.send_frame(&f).await.unwrap();
                }
            }
            if s.state() == remora_session::State::Active {
                break;
            }
            if s.state() == remora_session::State::PendingApproval {
                if let Some(HostEvent::Prompt { id, sas, .. }) = host
                    .wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
                    .await
                {
                    host.server.approve(id, sas).unwrap();
                }
            }
            let f = stream.recv_frame().await.unwrap().unwrap();
            pending = s.on_frame(&f, remora_session::Millis(0), &mut rand_core::OsRng);
        }
        let Some(remora_session::ViewerAction::Send(good)) = s.send_input(click()) else {
            panic!("active viewer can send")
        };
        stream.send_frame(&good).await.unwrap();
        let bad = match edit {
            "flip" => {
                let Some(remora_session::ViewerAction::Send(mut f)) = s.send_input(click()) else {
                    panic!()
                };
                f[5] ^= 1;
                f
            }
            "truncate" => {
                let Some(remora_session::ViewerAction::Send(mut f)) = s.send_input(click()) else {
                    panic!()
                };
                f.pop();
                f
            }
            _ => good.clone(), // replayed: its Noise nonce is already used
        };
        stream.send_frame(&bad).await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .unwrap();
        assert_eq!(
            remora_net::close_code_of(&err),
            Some(CloseCode::ProtocolViolation),
            "{edit}"
        );
        let evs = host.drain(500).await;
        let delivered = evs
            .iter()
            .filter(|e| matches!(e, HostEvent::Deliver { .. }))
            .count();
        assert_eq!(delivered, 1, "{edit}: only the good input is processed");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a24_slowloris_is_closed_with_timeout_after_10_s() {
    let h = device("host");
    let mut host = start_host(&h, vec![]).await;
    let (_ep, conn, _stream) = raw_connect(host.addr).await;
    let started = tokio::time::Instant::now();
    let err = tokio::time::timeout(Duration::from_secs(15), conn.closed())
        .await
        .unwrap();
    let took = started.elapsed();
    assert_eq!(remora_net::close_code_of(&err), Some(CloseCode::Timeout));
    assert!(
        took >= Duration::from_millis(9_900) && took <= Duration::from_millis(11_000),
        "{took:?}"
    );
    let failed = host
        .wait_for(2, |e| matches!(e, HostEvent::Failed { .. }))
        .await;
    assert!(
        matches!(
            failed,
            Some(HostEvent::Failed {
                reason: remora_session::FailReason::Timeout,
                ..
            })
        ),
        "{failed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn logging_one_warn_per_failure_with_details_and_no_secrets() {
    let capture = LogCapture::start();
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![]).await;
    let otp = host.server.otp();
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let out = run_viewer(host.addr, viewer_cfg(&v, wrong(&otp)), nonce, |_, f| {
        Some(f)
    })
    .await;
    assert_eq!(out.host_close, Some(CloseCode::AuthFailed));
    host.wait_for(5, |e| matches!(e, HostEvent::Failed { .. }))
        .await
        .unwrap();
    let text = capture.text();
    let warns: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("handshake_failed"))
        .collect();
    assert_eq!(
        warns.len(),
        1,
        "exactly one handshake_failed event:\n{text}"
    );
    let w = warns[0];
    assert!(w.contains("WARN"), "{w}");
    for field in ["reason", "step", "peer", "attempt", "session_id", "elapsed"] {
        assert!(w.contains(field), "missing {field}: {w}");
    }
    assert!(w.contains("1/3"), "attempt n/3: {w}");
    let leaks = find_leaks(&text, &[Canary::new("otp", otp.reveal().to_owned())]);
    assert!(leaks.is_empty(), "{leaks:?}");
}
