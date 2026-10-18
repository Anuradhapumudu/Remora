//! phase3-criteria A14 (QUIC-layer MITM that terminates TLS on both sides,
//! even with the right password), A08 (downgrade by editing the hellos) and
//! A09 over QUIC (bit flips in flight). Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use prost::Message;
use remora_net::HostEvent;
use remora_proto::messages::{HostHello, Mode, ViewerHello};
use remora_session::{CloseCode, FailReason, Step};

#[tokio::test(flavor = "multi_thread")]
async fn a14_pass_through_mitm_with_the_right_password_fails_at_msg1() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![]).await;
    let mitm = start_mitm(host.addr, pass()).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let out = run_viewer(
        mitm.addr,
        viewer_cfg(&v, password(&host.server.otp())),
        nonce,
        |_, f| Some(f),
    )
    .await;
    assert_eq!(
        out.host_close,
        Some(CloseCode::AuthFailed),
        "relayed AUTH_FAILED"
    );
    assert!(!out.reached_active());
    assert!(
        !out.actions
            .iter()
            .any(|a| matches!(a, remora_session::ViewerAction::ShowSas { .. }))
    );
    let failed = host
        .wait_for(5, |e| matches!(e, HostEvent::Failed { .. }))
        .await;
    assert!(
        matches!(
            failed,
            Some(HostEvent::Failed {
                step: Step::NoiseMsg1,
                reason: FailReason::AuthFailed(_),
                ..
            })
        ),
        "{failed:?}"
    );
    assert!(
        host.wait_for(1, |e| matches!(e, HostEvent::Prompt { .. }))
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a14_mitm_also_fails_in_trusted_mode() {
    let (h, v) = (device("host"), device("viewer"));
    let host = start_host(&h, vec![v.key.public()]).await;
    let mitm = start_mitm(host.addr, pass()).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let mode = remora_session::ViewerMode::Trusted {
        pinned: h.key.public(),
    };
    let out = run_viewer(mitm.addr, viewer_cfg(&v, mode), nonce, |_, f| Some(f)).await;
    assert!(!out.reached_active());
    assert!(
        !out.actions
            .iter()
            .any(|a| matches!(a, remora_session::ViewerAction::ShowSas { .. }))
    );
}

fn edit_viewer_hello(edit: fn(&mut ViewerHello)) -> Tap {
    Arc::new(Mutex::new(move |d: Dir, i: usize, f: Vec<u8>| {
        if d == Dir::ViewerToHost && i == 0 {
            let mut vh = ViewerHello::decode(f.as_slice()).unwrap();
            edit(&mut vh);
            vec![vh.encode_to_vec()]
        } else {
            vec![f]
        }
    }))
}

#[tokio::test(flavor = "multi_thread")]
async fn a08_edited_viewer_hello_fails_even_through_a_relaying_mitm() {
    // NOTE: through a MITM the exporters differ anyway; these runs show the
    // edit never yields a session. The hello-binding itself (without a
    // QUIC MITM) is proven in remora-crypto (a08_tampered_hello_changes_the_prologue).
    let (h, v) = (device("host"), device("viewer"));
    for edit in [
        (|vh: &mut ViewerHello| vh.versions = vec![1, 2]) as fn(&mut ViewerHello),
        |vh: &mut ViewerHello| vh.mode = Mode::Trusted as i32,
    ] {
        let host = start_host(&h, vec![v.key.public()]).await;
        let mitm = start_mitm(host.addr, edit_viewer_hello(edit)).await;
        let nonce = host.server.issue_nonce(Duration::from_secs(300));
        let out = run_viewer(
            mitm.addr,
            viewer_cfg(&v, password(&host.server.otp())),
            nonce,
            |_, f| Some(f),
        )
        .await;
        assert!(!out.reached_active());
        assert!(
            !out.actions
                .iter()
                .any(|a| matches!(a, remora_session::ViewerAction::ShowSas { .. }))
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a08_genuine_unknown_version_is_version_unsupported() {
    let h = device("host");
    let host = start_host(&h, vec![]).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let (_ep, conn, mut stream) = raw_connect(host.addr).await;
    let vh = ViewerHello {
        versions: vec![7],
        mode: Mode::Password as i32,
        nonce: nonce.to_vec(),
    };
    stream.send_frame(&vh.encode_to_vec()).await.unwrap();
    let err = tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .unwrap();
    assert_eq!(
        remora_net::close_code_of(&err),
        Some(CloseCode::VersionUnsupported)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a08_edited_host_hello_is_caught_by_the_viewer() {
    // The MITM rewrites the host's device ID in HostHello: the viewer that
    // asked for the real host's ID aborts (and in any case the exporter
    // and hello binding fail the handshake).
    let (h, v) = (device("host"), device("viewer"));
    let host = start_host(&h, vec![]).await;
    let tap: Tap = Arc::new(Mutex::new(|d: Dir, i: usize, f: Vec<u8>| {
        if d == Dir::HostToViewer && i == 0 {
            let mut hh = HostHello::decode(f.as_slice()).unwrap();
            hh.host_device_id[0] ^= 1;
            vec![hh.encode_to_vec()]
        } else {
            vec![f]
        }
    }));
    let mitm = start_mitm(host.addr, tap).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let want = remora_crypto::identity::DeviceId::of(&h.key.public());
    let mode = remora_session::ViewerMode::Password {
        otp: host.server.otp(),
        expect: Some(want),
    };
    let out = run_viewer(mitm.addr, viewer_cfg(&v, mode), nonce, |_, f| Some(f)).await;
    assert!(!out.reached_active());
    assert!(out.actions.iter().any(|a| matches!(
        a,
        remora_session::ViewerAction::Failed {
            reason: FailReason::IdentityMismatch,
            ..
        }
    )));
}

#[tokio::test(flavor = "multi_thread")]
async fn a09_a_bit_flip_in_any_handshake_message_in_flight_never_yields_a_session() {
    // One flip in each viewer -> host handshake message over real QUIC (the
    // exhaustive per-bit runs are in remora-crypto and remora-session).
    // There is no MITM here: the viewer flips its own outgoing frame, so
    // the exporter matches and only the flip can cause the failure.
    let (h, v) = (device("host"), device("viewer"));
    for index in 0..4usize {
        let mut host = start_host(&h, vec![]).await;
        let nonce = host.server.issue_nonce(Duration::from_secs(300));
        let out = run_viewer(
            host.addr,
            viewer_cfg(&v, password(&host.server.otp())),
            nonce,
            |i, mut f| {
                if i == index {
                    let at = f.len() / 2;
                    f[at] ^= 0x04;
                }
                Some(f)
            },
        )
        .await;
        assert!(out.host_close.is_some(), "msg {index}: host must close");
        assert!(!out.reached_active());
        assert!(
            host.wait_for(1, |e| matches!(e, HostEvent::Prompt { .. }))
                .await
                .is_none(),
            "msg {index}: no prompt"
        );
    }
}
