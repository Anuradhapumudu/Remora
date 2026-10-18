//! phase3-criteria F1 over real QUIC on 127.0.0.1, plus the wire format of
//! closes (§2: fixed code table, EMPTY reason phrase). Written before the
//! implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use remora_net::{HostEvent, ViewerEvent, close_code_of, connect, to_varint};
use remora_session::{AppMessage, CloseCode, ViewerMode};

async fn viewer_wait(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<ViewerEvent>,
    secs: u64,
    mut pred: impl FnMut(&ViewerEvent) -> bool,
) -> Option<ViewerEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
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

#[tokio::test(flavor = "multi_thread")]
async fn f1_password_mode_end_to_end_over_quic() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![]).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let (client, mut vev) = connect(
        host.addr,
        viewer_cfg(&v, password(&host.server.otp())),
        nonce,
    )
    .await
    .unwrap();
    let Some(HostEvent::Prompt {
        id,
        sas,
        viewer_name,
        ..
    }) = host
        .wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
        .await
    else {
        panic!("no prompt")
    };
    assert_eq!(viewer_name, "viewer");
    let Some(ViewerEvent::ShowSas {
        sas: vsas,
        host: hcert,
    }) = viewer_wait(&mut vev, 5, |e| matches!(e, ViewerEvent::ShowSas { .. })).await
    else {
        panic!("viewer showed no SAS")
    };
    assert_eq!(vsas, sas, "both screens show the same code");
    assert_eq!(hcert.identity(), &h.key.public());
    host.server.approve(id, sas).unwrap();
    assert!(
        host.wait_for(5, |e| *e == HostEvent::Active { id })
            .await
            .is_some()
    );
    assert!(
        viewer_wait(&mut vev, 5, |e| *e == ViewerEvent::Active)
            .await
            .is_some()
    );
    client.send_input(common_input());
    let got = host
        .wait_for(5, |e| matches!(e, HostEvent::Deliver { .. }))
        .await;
    assert_eq!(
        got,
        Some(HostEvent::Deliver {
            id,
            msg: AppMessage::Input(common_input())
        })
    );
    client.disconnect();
    assert!(
        host.wait_for(
            5,
            |e| matches!(e, HostEvent::Closed { id: i, code: CloseCode::Normal } if *i == id)
        )
        .await
        .is_some()
    );
}

fn common_input() -> remora_proto::messages::Input {
    use remora_proto::messages::{Input, Key, input};
    Input {
        kind: Some(input::Kind::Key(Key {
            usb_hid_usage: 4,
            down: true,
        })),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn f1_trusted_mode_end_to_end_over_quic() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![v.key.public()]).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let mode = ViewerMode::Trusted {
        pinned: h.key.public(),
    };
    let (_client, mut vev) = connect(host.addr, viewer_cfg(&v, mode), nonce)
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
        viewer_wait(&mut vev, 5, |e| *e == ViewerEvent::Active)
            .await
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn f1_deny_closes_with_rejected() {
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
    let Some(HostEvent::Prompt { id, .. }) = host
        .wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
        .await
    else {
        panic!("no prompt")
    };
    host.server.deny(id);
    let closed = viewer_wait(&mut vev, 5, |e| matches!(e, ViewerEvent::Closed { .. })).await;
    assert!(
        matches!(
            closed,
            Some(ViewerEvent::Closed {
                remote: Some(CloseCode::Rejected),
                ..
            }) | Some(ViewerEvent::Closed {
                local: Some(CloseCode::Rejected),
                ..
            })
        ),
        "{closed:?}"
    );
}

#[test]
fn close_code_table_on_the_wire() {
    for (code, wire) in [
        (CloseCode::Normal, 0x00u32),
        (CloseCode::AuthFailed, 0x10),
        (CloseCode::ProtocolViolation, 0x11),
        (CloseCode::VersionUnsupported, 0x12),
        (CloseCode::Rejected, 0x13),
        (CloseCode::Timeout, 0x14),
        (CloseCode::RateLimited, 0x15),
    ] {
        assert_eq!(to_varint(code), quinn::VarInt::from_u32(wire), "{code:?}");
        let err = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(wire),
            reason: bytes::Bytes::new(),
        });
        assert_eq!(close_code_of(&err), Some(code));
    }
    let unknown = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
        error_code: quinn::VarInt::from_u32(0x99),
        reason: bytes::Bytes::new(),
    });
    assert_eq!(close_code_of(&unknown), None);
    assert_eq!(close_code_of(&quinn::ConnectionError::TimedOut), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a04_bytes_auth_failed_close_has_an_empty_reason_phrase() {
    let (h, v) = (device("host"), device("viewer"));
    let host = start_host(&h, vec![]).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    // A wrong password; inspect the raw close frame.
    let (_ep, conn, mut stream) = raw_connect(host.addr).await;
    let ex = remora_net::exporter(&conn).unwrap();
    let (mut s, first) = remora_session::ViewerSession::start(
        viewer_cfg(&v, wrong(&host.server.otp())),
        nonce,
        ex,
        remora_session::Millis(0),
    );
    let mut pending = first;
    let err = loop {
        for a in std::mem::take(&mut pending) {
            if let remora_session::ViewerAction::Send(f) = a {
                stream.send_frame(&f).await.unwrap();
            }
        }
        tokio::select! {
            f = stream.recv_frame() => match f {
                Ok(Some(frame)) => pending = s.on_frame(&frame, remora_session::Millis(0), &mut rand_core::OsRng),
                _ => break conn.closed().await,
            },
            e = conn.closed() => break e,
        }
    };
    match err {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(c.error_code, quinn::VarInt::from_u32(0x10));
            assert!(
                c.reason.is_empty(),
                "reason phrase must be empty, got {:?}",
                c.reason
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_the_host_server_closes_its_connections() {
    // Mutation-gate finding: the accept loop holds its own endpoint handle,
    // so without an explicit close on drop, live sessions would outlive
    // the server object (the "session active" indicator would be gone
    // while the session is not).
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
    host.server.approve(id, sas).unwrap();
    assert!(
        viewer_wait(&mut vev, 5, |e| *e == ViewerEvent::Active)
            .await
            .is_some()
    );
    drop(host);
    let closed = viewer_wait(&mut vev, 3, |e| matches!(e, ViewerEvent::Closed { .. })).await;
    assert!(
        matches!(
            closed,
            Some(ViewerEvent::Closed {
                remote: Some(CloseCode::Normal),
                ..
            })
        ),
        "{closed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_output_names_the_type_and_holds_no_secrets() {
    let h = device("host");
    let host = start_host(&h, vec![]).await;
    let otp = host.server.otp();
    let shown = format!("{:?}", host.server);
    assert!(shown.starts_with("HostServer"), "{shown}");
    assert!(!shown.contains(otp.reveal()));
    let (_ep, conn, stream) = raw_connect(host.addr).await;
    assert!(format!("{stream:?}").starts_with("FramedStream"));
    let (tx, rx) = stream.split();
    assert!(format!("{tx:?}").starts_with("FrameSender"));
    assert!(format!("{rx:?}").starts_with("FrameReceiver"));
    drop(conn);
}

#[tokio::test(flavor = "multi_thread")]
async fn host_disconnect_ends_an_active_session_over_quic() {
    // CI mutation-gate finding: HostServer::disconnect was exercised only by
    // the CLI tests in remora-app, which the remora-net job does not run.
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
    host.server.approve(id, sas).unwrap();
    assert!(
        viewer_wait(&mut vev, 5, |e| *e == ViewerEvent::Active)
            .await
            .is_some()
    );
    host.server.disconnect(id);
    assert!(
        host.wait_for(5, |e| *e
            == HostEvent::Closed {
                id,
                code: CloseCode::Normal
            })
        .await
        .is_some()
    );
    let closed = viewer_wait(&mut vev, 5, |e| matches!(e, ViewerEvent::Closed { .. })).await;
    assert!(
        matches!(
            closed,
            Some(ViewerEvent::Closed {
                remote: Some(CloseCode::Normal),
                ..
            })
        ),
        "{closed:?}"
    );
}
