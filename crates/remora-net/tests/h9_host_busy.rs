//! H9 over real QUIC on 127.0.0.1 (phase4.5-criteria §4; owner 2026-10-25):
//! while a session is Active a second viewer is refused as "host busy"
//! before the handshake, with its own close code; the host reports every
//! refused attempt; no prompt appears and the password is not touched, so it
//! still works once the session ends.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use remora_net::{HostEvent, ViewerEvent, connect};
use remora_session::CloseCode;

/// Waits (≤ `secs`) for the viewer's end: `Closed` with the host's code, or
/// `None` if nothing ended it.
async fn closed_by_host(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<ViewerEvent>,
    secs: u64,
) -> Option<Option<CloseCode>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            rx.recv(),
        )
        .await
        {
            Ok(Some(ViewerEvent::Closed { remote, .. })) => return Some(remote),
            Ok(Some(ViewerEvent::ShowSas { .. })) => panic!("a busy host ran the handshake"),
            Ok(Some(_)) => continue,
            _ => return None,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn h9_second_viewer_is_refused_busy_and_the_password_survives() {
    let (h, a, b) = (device("host"), device("viewer a"), device("viewer b"));
    let mut host = start_host(&h, vec![]).await;

    // Viewer A: an active session.
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let (client_a, _a_events) = connect(
        host.addr,
        viewer_cfg(&a, password(&host.server.otp())),
        nonce,
    )
    .await
    .unwrap();
    let Some(HostEvent::Prompt { id, sas, .. }) = host
        .wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
        .await
    else {
        panic!("no prompt for A")
    };
    host.server.approve(id, sas).unwrap();
    assert!(
        host.wait_for(5, |e| *e == HostEvent::Active { id })
            .await
            .is_some()
    );

    // The password now on the host screen (A used the first one, INV15).
    let otp = host.server.otp();
    for attempt in 1..=3 {
        let nonce = host.server.issue_nonce(Duration::from_secs(300));
        let ended = match connect(host.addr, viewer_cfg(&b, password(&otp)), nonce).await {
            Ok((_client, mut ev)) => closed_by_host(&mut ev, 5).await,
            // Refused so early that opening the stream already failed.
            Err(e) => panic!("attempt {attempt}: connect failed without a close code: {e}"),
        };
        assert_eq!(ended, Some(Some(CloseCode::HostBusy)), "attempt {attempt}");
        let got = host
            .wait_for(5, |e| matches!(e, HostEvent::RefusedBusy { .. }))
            .await;
        assert!(
            matches!(got, Some(HostEvent::RefusedBusy { peer }) if peer.ip().is_loopback()),
            "attempt {attempt}: {got:?}"
        );
    }
    // No prompt, no failure, no password change for any of them.
    let others = host.drain(300).await;
    assert!(
        !others.iter().any(|e| matches!(
            e,
            HostEvent::Prompt { .. }
                | HostEvent::Failed { .. }
                | HostEvent::OtpRotated
                | HostEvent::OtpUsed { .. }
        )),
        "{others:?}"
    );
    assert_eq!(host.server.otp().reveal(), otp.reveal());

    // A leaves: B gets in with the same password.
    client_a.disconnect();
    assert!(
        host.wait_for(5, |e| matches!(e, HostEvent::Closed { .. }))
            .await
            .is_some()
    );
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let (_client_b, _b_events) = connect(host.addr, viewer_cfg(&b, password(&otp)), nonce)
        .await
        .unwrap();
    assert!(
        host.wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
            .await
            .is_some(),
        "the password was not spent by the refused attempts"
    );
}
