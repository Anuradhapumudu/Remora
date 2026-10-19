//! phase3-criteria A28 over the whole stack: run real sessions over QUIC
//! with EVERY log level captured (TRACE, including quinn's and rustls's own
//! logs) and search all of it for planted secrets - the one-time password
//! and both devices' identity and Noise secret keys - in raw, hex and
//! base64 form (remora-testkit canary scanner).
//!
//! Single-threaded runtime on purpose: LogCapture is a thread-local
//! subscriber, so every task must run on this test's thread.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use rand_core::OsRng;
use remora_crypto::identity::DeviceKeys;
use remora_net::{HostEvent, HostServer, ViewerEvent, connect};
use remora_session::{HostConfig, Identity, ViewerConfig, ViewerMode};
use remora_testkit::canary::{Canary, LogCapture, find_leaks};

/// A device built from DeviceKeys, keeping the secret bytes as canaries.
fn keyed(
    name: &str,
) -> (
    Arc<Identity>,
    remora_crypto::identity::IdentityPublic,
    Vec<Canary>,
) {
    let keys = DeviceKeys::generate(&mut OsRng);
    let enc = keys.encode();
    let canaries = vec![
        Canary::new("identity secret", enc[8..40].to_vec()),
        Canary::new("noise secret", enc[40..72].to_vec()),
    ];
    let cert = keys.cert(name, 1).unwrap();
    let public = keys.identity.public();
    (
        Arc::new(Identity {
            noise: keys.noise,
            cert,
        }),
        public,
        canaries,
    )
}

async fn wait_viewer(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<ViewerEvent>,
    pred: impl Fn(&ViewerEvent) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(e) = rx.recv().await {
            if pred(&e) {
                return;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a28_no_secret_in_any_log_line_at_trace_level() {
    let capture = LogCapture::start();
    let (host_id, host_pub, mut canaries) = keyed("canary host");
    let (viewer_id, _, viewer_canaries) = keyed("canary viewer");
    canaries.extend(viewer_canaries);
    let (server, mut events) = HostServer::bind(
        loopback(),
        HostConfig {
            identity: host_id,
            password_enabled: true,
            trusted: vec![],
        },
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();

    // 1. A successful session: handshake, approve, input, disconnect.
    let otp = server.otp();
    canaries.push(Canary::new("one-time password", otp.reveal().to_owned()));
    let nonce = server.issue_nonce(Duration::from_secs(300));
    let cfg = ViewerConfig {
        identity: viewer_id.clone(),
        mode: ViewerMode::Password {
            otp: otp.clone(),
            expect: None,
        },
    };
    let (client, mut vev) = connect(addr, cfg, nonce).await.unwrap();
    let (id, sas) = loop {
        if let Some(HostEvent::Prompt { id, sas, .. }) = events.recv().await {
            break (id, sas);
        }
    };
    server.approve(id, sas).unwrap();
    wait_viewer(&mut vev, |e| *e == ViewerEvent::Active).await;
    use remora_proto::messages::{Input, Key, input};
    client.send_input(Input {
        kind: Some(input::Kind::Key(Key {
            usb_hid_usage: 4,
            down: true,
        })),
    });
    client.disconnect();
    wait_viewer(&mut vev, |e| matches!(e, ViewerEvent::Closed { .. })).await;

    // 2. A wrong password (the NEW password is a canary too).
    let otp2 = server.otp();
    canaries.push(Canary::new(
        "second one-time password",
        otp2.reveal().to_owned(),
    ));
    let right: u32 = otp2.reveal().parse().unwrap();
    let wrong =
        remora_crypto::secret::Otp::parse(&format!("{:06}", (right + 1) % 1_000_000)).unwrap();
    let nonce = server.issue_nonce(Duration::from_secs(300));
    let cfg = ViewerConfig {
        identity: viewer_id.clone(),
        mode: ViewerMode::Password {
            otp: wrong,
            expect: None,
        },
    };
    let (_c2, mut v2) = connect(addr, cfg, nonce).await.unwrap();
    wait_viewer(&mut v2, |e| matches!(e, ViewerEvent::Closed { .. })).await;

    // 3. Trusted mode with an unknown viewer key.
    let nonce = server.issue_nonce(Duration::from_secs(300));
    let cfg = ViewerConfig {
        identity: viewer_id,
        mode: ViewerMode::Trusted { pinned: host_pub },
    };
    let (_c3, mut v3) = connect(addr, cfg, nonce).await.unwrap();
    wait_viewer(&mut v3, |e| matches!(e, ViewerEvent::Closed { .. })).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let text = capture.text();
    assert!(
        text.lines().count() > 50,
        "TRACE capture looks empty ({} lines)",
        text.lines().count()
    );
    assert!(
        text.contains("handshake_failed"),
        "the failures were logged"
    );
    let leaks = find_leaks(&text, &canaries);
    assert!(leaks.is_empty(), "secrets in logs: {leaks:?}");
    eprintln!(
        "A28: {} log lines at TRACE scanned for {} canaries: no leak",
        text.lines().count(),
        canaries.len()
    );
}
