//! M7 over real QUIC: the viewer's keyframe request reaches the host as
//! `HostEvent::ForceKeyframe` (which the host app turns into a forced
//! keyframe from its encoder), and the session continues.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use remora_net::{HostEvent, ViewerEvent, connect};
use remora_session::ViewerMode;

#[tokio::test(flavor = "multi_thread")]
async fn m7_a_viewer_keyframe_request_reaches_the_host() {
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
    // Approval forces the first keyframe for the new viewer.
    assert!(
        host.wait_for(5, |e| matches!(e, HostEvent::ForceKeyframe))
            .await
            .is_some()
    );
    loop {
        match tokio::time::timeout(Duration::from_secs(5), vev.recv()).await {
            Ok(Some(ViewerEvent::Active)) => break,
            Ok(Some(_)) => {}
            other => panic!("viewer never became active: {other:?}"),
        }
    }
    client.request_keyframe();
    assert!(
        host.wait_for(5, |e| matches!(e, HostEvent::ForceKeyframe))
            .await
            .is_some(),
        "the request did not reach the host"
    );
    // Still connected: stats answer.
    assert!(client.media_stats().await.is_some());
}
