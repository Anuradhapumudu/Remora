//! phase4.7-criteria C3 and C7 over real QUIC on loopback:
//!
//! * **C3** - a viewer the host remembers connects in trusted mode (no
//!   password) but is still prompted: it is not Active until the person
//!   approves, and a denial refuses it.
//! * **C7** - forgetting takes effect for the next connection: the same
//!   viewer in trusted mode then gets AUTH_FAILED. (A password and the
//!   host's approval still work for it, like for anyone.)
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use remora_net::HostEvent;
use remora_session::{CloseCode, ViewerMode};

fn trusted(h: &Device) -> ViewerMode {
    ViewerMode::Trusted {
        pinned: h.key.public(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn c3_a_remembered_viewer_skips_the_password_but_still_waits_for_approval() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![]).await;
    host.server.set_trusted(vec![v.key.public()]);
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let addr = host.addr;
    let cfg = viewer_cfg(&v, trusted(&h));
    let viewer = tokio::spawn(async move { run_viewer(addr, cfg, nonce, |_, f| Some(f)).await });
    let prompt = host
        .wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
        .await;
    let Some(HostEvent::Prompt { id, viewer_key, .. }) = prompt else {
        panic!("a remembered viewer is still prompted: {prompt:?}")
    };
    assert_eq!(viewer_key, v.key.public());
    // Nothing is Active while the prompt is open.
    let early = host.drain(1500).await;
    assert!(
        !early.iter().any(|e| matches!(e, HostEvent::Active { .. })),
        "Active without approval: {early:?}"
    );
    host.server.deny(id);
    let out = viewer.await.unwrap();
    assert!(!out.reached_active());
    assert_eq!(out.host_close, Some(CloseCode::Rejected));
}

#[tokio::test(flavor = "multi_thread")]
async fn c7_a_forgotten_viewer_is_refused_in_trusted_mode_at_once() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![]).await;
    host.server.set_trusted(vec![v.key.public()]);
    host.server.set_trusted(vec![]); // forgotten
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let out = run_viewer(host.addr, viewer_cfg(&v, trusted(&h)), nonce, |_, f| {
        Some(f)
    })
    .await;
    assert!(!out.reached_active());
    assert_eq!(out.host_close, Some(CloseCode::AuthFailed));
    assert!(
        host.wait_for(1, |e| matches!(e, HostEvent::Prompt { .. }))
            .await
            .is_none(),
        "no prompt for a refused viewer"
    );
}
