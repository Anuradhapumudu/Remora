//! Connection liveness over real QUIC (owner walkthrough, 2026-10-21).
//!
//! The owner's trusted-mode session ended by itself about 30 s after
//! `SESSION ACTIVE`: nothing was sent (Phase 3 has no video), quinn's
//! default is a 30 s idle timeout with no keepalive, so QUIC declared the
//! healthy connection dead. The host then printed `session ended (Normal)`
//! and the viewer `connection closed (None)` - a lie and a shrug.
//!
//! These tests idle for longer than [`IDLE_TIMEOUT`] in real time (~35 s
//! each; they run in parallel). Written before the fix: on the code before
//! it, the first two fail with the session gone and the third with
//! `Closed { Normal }` instead of `Lost`.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use remora_net::{HostEvent, IDLE_TIMEOUT, KEEP_ALIVE, ViewerEvent, connect};
use remora_session::ViewerMode;

async fn viewer_wait(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<ViewerEvent>,
    wait: Duration,
    mut pred: impl FnMut(&ViewerEvent) -> bool,
) -> Option<ViewerEvent> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            rx.recv(),
        )
        .await
        {
            Ok(Some(e)) if pred(&e) => return Some(e),
            Ok(Some(_)) => continue,
            _ => return None,
        }
    }
}

fn ended(e: &ViewerEvent) -> bool {
    matches!(e, ViewerEvent::Closed { .. } | ViewerEvent::Lost)
}

fn key_input() -> remora_proto::messages::Input {
    use remora_proto::messages::{Input, Key, input};
    Input {
        kind: Some(input::Kind::Key(Key {
            usb_hid_usage: 4,
            down: true,
        })),
    }
}

/// Longer than the idle timeout, with margin for a slow CI machine.
fn past_idle() -> Duration {
    IDLE_TIMEOUT + Duration::from_secs(5)
}

#[test]
fn keepalive_is_well_inside_the_idle_timeout() {
    // quinn: "Must be set lower than the idle_timeout of both peers to be
    // effective". A third leaves room for two lost PINGs.
    assert!(
        KEEP_ALIVE * 3 <= IDLE_TIMEOUT,
        "{KEEP_ALIVE:?} vs {IDLE_TIMEOUT:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_active_session_outlives_the_idle_timeout() {
    // The walkthrough failure itself: active, then nothing to say.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![v.key.public()]).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let mode = ViewerMode::Trusted {
        pinned: h.key.public(),
    };
    let (client, mut vev) = connect(host.addr, viewer_cfg(&v, mode), nonce)
        .await
        .unwrap();
    let Some(HostEvent::Prompt { id, sas, .. }) = host
        .wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
        .await
    else {
        panic!("no prompt")
    };
    host.server.approve(id, sas).unwrap();
    assert!(
        viewer_wait(&mut vev, Duration::from_secs(5), |e| *e
            == ViewerEvent::Active)
        .await
        .is_some()
    );
    let gone = viewer_wait(&mut vev, past_idle(), ended).await;
    assert_eq!(gone, None, "the viewer lost a healthy, silent session");
    let host_ended: Vec<_> = host
        .drain(100)
        .await
        .into_iter()
        .filter(|e| matches!(e, HostEvent::Closed { .. } | HostEvent::Lost { .. }))
        .collect();
    assert!(host_ended.is_empty(), "the host ended it: {host_ended:?}");
    // Still alive in fact, not just quiet: input gets through.
    client.send_input(key_input());
    assert!(
        host.wait_for(
            5,
            |e| matches!(e, HostEvent::Deliver { id: i, .. } if *i == id)
        )
        .await
        .is_some(),
        "input did not reach the host after the idle period"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prompt_can_wait_longer_than_the_idle_timeout() {
    // The prompt is allowed PROMPT_TIMEOUT_MS (60 s) for the host user to
    // decide; a silent transport must not cut that to 30 s.
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![]).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let (_client, mut vev) = connect(
        host.addr,
        viewer_cfg(&v, password(&host.server.otp())),
        nonce,
    )
    .await
    .unwrap();
    let Some(HostEvent::Prompt { id, sas, .. }) = host
        .wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
        .await
    else {
        panic!("no prompt")
    };
    let gone = viewer_wait(&mut vev, past_idle(), ended).await;
    assert_eq!(gone, None, "the connection died while the prompt was open");
    host.server.approve(id, sas).unwrap();
    assert!(
        viewer_wait(&mut vev, Duration::from_secs(5), |e| *e
            == ViewerEvent::Active)
        .await
        .is_some(),
        "approving after a long wait did not activate the session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_network_that_goes_silent_is_reported_as_lost_not_as_a_normal_close() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![v.key.public()]).await;
    let relay = Relay::start(host.addr).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let mode = ViewerMode::Trusted {
        pinned: h.key.public(),
    };
    let (_client, mut vev) = connect(relay.addr, viewer_cfg(&v, mode), nonce)
        .await
        .unwrap();
    let Some(HostEvent::Prompt { id, sas, .. }) = host
        .wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
        .await
    else {
        panic!("no prompt")
    };
    host.server.approve(id, sas).unwrap();
    assert!(
        viewer_wait(&mut vev, Duration::from_secs(5), |e| *e
            == ViewerEvent::Active)
        .await
        .is_some()
    );
    relay.cut();
    let secs = past_idle().as_secs();
    let host_end = host
        .wait_for(secs, |e| {
            matches!(e, HostEvent::Closed { .. } | HostEvent::Lost { .. })
        })
        .await;
    assert_eq!(host_end, Some(HostEvent::Lost { id }), "host side");
    let viewer_end = viewer_wait(&mut vev, Duration::from_secs(5), ended).await;
    assert_eq!(viewer_end, Some(ViewerEvent::Lost), "viewer side");
}
