//! phase4.6-criteria L7 (INV2): mouse and keyboard input never travel
//! unencrypted. A real viewer session over QUIC on loopback is approved,
//! then sends every input kind carrying a random canary (key usage,
//! coordinates, scroll amounts). Every frame the viewer hands to the
//! stream is recorded *before* QUIC's own encryption, so a missing Noise
//! seal would show: the plaintext of each input (any 8-byte window of its
//! encoded envelope) and the canary must appear in none of them, while
//! the host must still receive each input intact (so the test cannot pass
//! by sending nothing).
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use prost::Message;
use rand_core::{OsRng, RngCore};
use remora_net::HostEvent;
use remora_proto::messages::{
    Envelope, Input, Key, MouseButton, PointerMove, Scroll, envelope, input,
};
use remora_session::{AppMessage, Millis, State, ViewerAction, ViewerSession};

const WINDOW: usize = 8;

/// Inputs whose encodings contain random values (the canary).
fn inputs() -> Vec<Input> {
    let mut r = [0u8; 12];
    OsRng.fill_bytes(&mut r);
    // Random but valid: coordinates in (0, 1), a key from the table.
    let unit = |b: [u8; 4]| (u32::from_le_bytes(b) % 1_000_000) as f32 / 1_000_000.0;
    let x = unit([r[0], r[1], r[2], r[3]]);
    let y = unit([r[4], r[5], r[6], r[7]]);
    let usage = 0x04 + u32::from(r[8] % 26); // A..Z
    let k = |kind| Input { kind: Some(kind) };
    vec![
        k(input::Kind::Move(PointerMove { x, y })),
        k(input::Kind::Button(MouseButton {
            button: 1,
            down: true,
            x,
            y,
        })),
        k(input::Kind::Key(Key {
            usb_hid_usage: usage,
            down: true,
        })),
        k(input::Kind::Scroll(Scroll {
            dx: f32::from(r[9]) - 128.0,
            dy: f32::from(r[10]) + 0.5,
            precise: true,
        })),
    ]
}

/// Every WINDOW-byte window of `plain` that appears anywhere in `sent`.
fn leaked(plain: &[u8], sent: &[Vec<u8>]) -> Option<usize> {
    plain
        .windows(WINDOW)
        .position(|w| sent.iter().any(|f| f.windows(WINDOW).any(|g| g == w)))
}

/// Runs the session; `seal` lets a plant replace what is sent for inputs.
async fn run(seal: bool) -> (Vec<Vec<u8>>, Vec<Input>, Vec<Input>) {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = start_host(&h, vec![]).await;
    let nonce = host.server.issue_nonce(Duration::from_secs(300));
    let (_ep, conn, mut stream) = raw_connect(host.addr).await;
    let ex = remora_net::exporter(&conn).unwrap();
    let cfg = viewer_cfg(&v, password(&host.server.otp()));
    let (mut s, first) = ViewerSession::start(cfg, nonce, ex, Millis(0));
    let mut sent: Vec<Vec<u8>> = Vec::new();
    let mut pending = first;
    loop {
        for a in std::mem::take(&mut pending) {
            if let ViewerAction::Send(f) = a {
                stream.send_frame(&f).await.unwrap();
                sent.push(f);
            }
        }
        if s.state() == State::Active {
            break;
        }
        if s.state() == State::PendingApproval
            && let Some(HostEvent::Prompt { id, sas, .. }) = host
                .wait_for(5, |e| matches!(e, HostEvent::Prompt { .. }))
                .await
        {
            host.server.approve(id, sas).unwrap();
        }
        let f = stream.recv_frame().await.unwrap().unwrap();
        pending = s.on_frame(&f, Millis(0), &mut OsRng);
    }
    let want = inputs();
    for i in &want {
        let frame = if seal {
            let Some(ViewerAction::Send(f)) = s.send_input(i.clone()) else {
                panic!("an Active viewer can send input")
            };
            f
        } else {
            // PLANT: the envelope as plaintext, no Noise seal.
            Envelope {
                msg: Some(envelope::Msg::Input(i.clone())),
            }
            .encode_to_vec()
        };
        stream.send_frame(&frame).await.unwrap();
        sent.push(frame);
    }
    let got = host
        .drain(1000)
        .await
        .into_iter()
        .filter_map(|e| match e {
            HostEvent::Deliver {
                msg: AppMessage::Input(i),
                ..
            } => Some(i),
            _ => None,
        })
        .collect();
    (sent, want, got)
}

#[tokio::test(flavor = "multi_thread")]
async fn l7_input_is_sealed_on_the_stream_and_still_arrives() {
    let (sent, want, got) = run(true).await;
    for i in &want {
        let plain = Envelope {
            msg: Some(envelope::Msg::Input(i.clone())),
        }
        .encode_to_vec();
        assert!(plain.len() >= WINDOW, "canary long enough to find");
        assert_eq!(
            leaked(&plain, &sent),
            None,
            "plaintext of {i:?} found in a frame handed to QUIC"
        );
    }
    assert_eq!(got, want, "the host received every input intact");
}

/// The plant the test above must catch, kept as a test so it is seen
/// failing on every run: unsealed input is visible and never delivered.
#[tokio::test(flavor = "multi_thread")]
async fn l7_plant_unsealed_input_would_be_seen() {
    let (sent, want, got) = run(false).await;
    let plain = Envelope {
        msg: Some(envelope::Msg::Input(want[0].clone())),
    }
    .encode_to_vec();
    assert!(leaked(&plain, &sent).is_some(), "the scan finds plaintext");
    assert!(got.is_empty(), "the host refuses it (it cannot open it)");
}
