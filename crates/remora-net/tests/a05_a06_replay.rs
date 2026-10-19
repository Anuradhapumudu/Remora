//! phase3-criteria A05 (replay of a recorded handshake on a new connection)
//! and A06 (reused connection-code nonce) over real QUIC. Written before
//! the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use prost::Message;
use remora_net::HostEvent;
use remora_proto::messages::ViewerHello;
use remora_session::{CloseCode, FailReason};

/// Records every frame a viewer sends in an honest, successful handshake.
async fn record_successful(v: &Device, host: &mut TestHost) -> Vec<Vec<u8>> {
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let out = run_viewer(
        host.addr,
        viewer_cfg(v, password(&host.server.otp())),
        nonce,
        |_, f| Some(f),
    )
    .await;
    assert!(
        host.wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
            .await
            .is_some()
    );
    out.sent
}

/// Sends `frames` blindly on a new connection; returns the host's close.
async fn replay(addr: std::net::SocketAddr, frames: &[Vec<u8>]) -> (Option<CloseCode>, usize) {
    let (_ep, conn, mut stream) = raw_connect(addr).await;
    let mut received = 0;
    for f in frames {
        if stream.send_frame(f).await.is_err() {
            break;
        }
        // Give the host time to answer before the next blind frame.
        if let Ok(Ok(Some(_))) =
            tokio::time::timeout(Duration::from_millis(300), stream.recv_frame()).await
        {
            received += 1;
        }
    }
    let err = tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .unwrap();
    (remora_net::close_code_of(&err), received)
}

#[tokio::test(flavor = "multi_thread")]
async fn a06_exact_replay_is_refused_at_the_hello_as_nonce_reused() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![]).await;
    let frames = record_successful(&v, &mut host).await;
    let (code, received) = replay(host.addr, &frames).await;
    assert_eq!(code, Some(CloseCode::AuthFailed));
    assert_eq!(received, 0, "refused before HostHello: nothing sent back");
    let failed = host
        .wait_for(5, |e| matches!(e, HostEvent::Failed { .. }))
        .await;
    assert!(
        matches!(
            failed,
            Some(HostEvent::Failed {
                reason: FailReason::NonceReused,
                ..
            })
        ),
        "{failed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a05_replay_with_a_fresh_nonce_fails_at_msg1_on_the_new_exporter() {
    // Even with a valid fresh nonce, the recorded SpakeA/msg1 belong to the
    // old QUIC session (old exporter) and the old SPAKE2 run: AUTH_FAILED
    // at Noise msg1. The host answers HostHello and SpakeB, then nothing.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![]).await;
    let mut frames = record_successful(&v, &mut host).await;
    let fresh = host.server.issue_nonce(Duration::from_secs(300));
    let mut vh = ViewerHello::decode(frames[0].as_slice()).unwrap();
    vh.nonce = fresh.to_vec();
    frames[0] = vh.encode_to_vec();
    let (code, received) = replay(host.addr, &frames[..3]).await;
    assert_eq!(code, Some(CloseCode::AuthFailed));
    assert_eq!(received, 2, "HostHello and SpakeB only");
    let failed = host.wait_for(5, |e| matches!(e, HostEvent::Failed { .. } if !matches!(e, HostEvent::Failed { reason: FailReason::NonceReused, .. }))).await;
    assert!(
        matches!(
            failed,
            Some(HostEvent::Failed {
                reason: FailReason::AuthFailed(_),
                ..
            })
        ),
        "{failed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a06_two_connections_with_one_issued_nonce_only_the_first_proceeds() {
    let (h, v) = (device("host"), device("viewer"));
    let host = start_host(&h, vec![]).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let otp = host.server.otp();
    let first = run_viewer(host.addr, viewer_cfg(&v, password(&otp)), nonce, |_, f| {
        Some(f)
    })
    .await;
    assert!(
        first
            .actions
            .iter()
            .any(|a| matches!(a, remora_session::ViewerAction::ShowSas { .. }))
    );
    let second = run_viewer(
        host.addr,
        viewer_cfg(&v, password(&host.server.otp())),
        nonce,
        |_, f| Some(f),
    )
    .await;
    assert_eq!(second.host_close, Some(CloseCode::AuthFailed));
    assert!(second.received.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a06_an_expired_nonce_is_refused() {
    let (h, v) = (device("host"), device("viewer"));
    let host = start_host(&h, vec![]).await;
    let nonce = host.server.issue_nonce(Duration::from_millis(1));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let out = run_viewer(
        host.addr,
        viewer_cfg(&v, password(&host.server.otp())),
        nonce,
        |_, f| Some(f),
    )
    .await;
    assert_eq!(out.host_close, Some(CloseCode::AuthFailed));
    assert!(out.received.is_empty());
}
