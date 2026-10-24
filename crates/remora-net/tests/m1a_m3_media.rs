//! Media over real QUIC (phase4-criteria §5, step 4).
//!
//! * **M1a** - INV2 on *our* layer: every payload handed to quinn is
//!   recorded (feature `test-tap`) while the host streams frames carrying
//!   a random canary. No canary and no 16-byte window of any frame may
//!   appear in any payload, every payload must parse as a sealed datagram,
//!   and the viewer must open every one of them. QUIC encrypts too, so a
//!   capture of the wire alone could not see a missing seal (M1b, step 7,
//!   checks the wire).
//!
//!   The frames are synthetic stand-ins for encoded video (random bytes
//!   with the canary inside): the seal does not depend on the codec, and
//!   the canary is then guaranteed to be in the plaintext. The VideoToolbox
//!   pipeline repeats this check end to end in step 7 (M1b, N1).
//! * **M3** - a host that sends datagrams before the handshake finished:
//!   the viewer closes, and nothing reaches the decoder.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use rand_core::{OsRng, RngCore};
use remora_crypto::media::MediaReceiver;
use remora_crypto::secret::MediaKey;
use remora_net::{HostEvent, ViewerEvent, connect};
use remora_proto::datagram::DatagramHeader;
use remora_proto::limits::{VIDEO_DATAGRAM_TARGET, VIDEO_FRAGMENT_DATA};
use remora_session::{FailReason, ViewerMode, Violation};
use tokio::sync::mpsc::UnboundedReceiver;

const FRAMES: usize = 600; // 10 s at 60 fps
const WINDOW: usize = 16;

fn window(b: &[u8]) -> u128 {
    u128::from_be_bytes(b.try_into().unwrap())
}

/// Every 16-byte window of every frame, sorted (for binary search).
fn windows_of(frames: &[Vec<u8>]) -> Vec<u128> {
    let mut w: Vec<u128> = frames
        .iter()
        .flat_map(|f| f.windows(WINDOW).map(window))
        .collect();
    w.sort_unstable();
    w.dedup();
    w
}

/// The frame, and offset in it, of a payload window that is frame content.
fn leak(payload: &[u8], frame_windows: &[u128], frames: &[Vec<u8>]) -> Option<(usize, usize)> {
    for pw in payload.windows(WINDOW) {
        if frame_windows.binary_search(&window(pw)).is_ok() {
            for (i, f) in frames.iter().enumerate() {
                if let Some(at) = f.windows(WINDOW).position(|fw| fw == pw) {
                    return Some((i, at));
                }
            }
        }
    }
    None
}

async fn viewer_frames(
    rx: &mut UnboundedReceiver<ViewerEvent>,
    want: usize,
    wait: Duration,
) -> Vec<remora_proto::video::VideoFrame> {
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    while got.len() < want {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(ViewerEvent::Video(f))) => got.push(f),
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    got
}

#[tokio::test(flavor = "multi_thread")]
async fn m1a_every_media_payload_handed_to_quic_is_sealed() {
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
    let mut tap = host.server.tap_datagrams();
    host.server.approve(id, sas).unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), vev.recv()).await {
            Ok(Some(ViewerEvent::Active)) => break,
            Ok(Some(_)) => {}
            other => panic!("viewer never became active: {other:?}"),
        }
    }

    // A random canary, as if it were a row of the screen.
    let mut canary = [0u8; 32];
    OsRng.fill_bytes(&mut canary);
    let mut frames = Vec::with_capacity(FRAMES);
    let mut fragments = 0;
    let mut ticker = tokio::time::interval(Duration::from_micros(16_667));
    for i in 0..FRAMES {
        let len = 100 + (OsRng.next_u32() as usize % 4000);
        let mut f = vec![0u8; len];
        OsRng.fill_bytes(&mut f);
        let at = OsRng.next_u32() as usize % (len - canary.len());
        f[at..at + canary.len()].copy_from_slice(&canary);
        ticker.tick().await;
        host.server
            .send_video(i % 60 == 0, i as u64 * 16_667, &f)
            .unwrap();
        fragments += len.div_ceil(VIDEO_FRAGMENT_DATA);
        frames.push(f);
    }

    let received = viewer_frames(&mut vev, FRAMES, Duration::from_secs(10)).await;
    let mut payloads = Vec::new();
    while let Ok(p) = tap.try_recv() {
        payloads.push(p);
    }

    // Every fragment went to quinn.
    assert_eq!(payloads.len(), fragments, "payloads handed to quinn");

    // No plaintext: not the canary, not any 16-byte window of any frame.
    let frame_windows = windows_of(&frames);
    for (n, p) in payloads.iter().enumerate() {
        if let Some((frame, at)) = leak(p, &frame_windows, &frames) {
            panic!("payload {n} carries plaintext of frame {frame} at byte {at}");
        }
        assert!(
            !p.windows(canary.len()).any(|w| w == canary),
            "payload {n} carries the canary"
        );
        // Shape: header ‖ ciphertext ‖ tag, within the size target.
        assert!(
            p.len() <= VIDEO_DATAGRAM_TARGET,
            "payload {n}: {} bytes",
            p.len()
        );
        DatagramHeader::parse(p).unwrap_or_else(|e| panic!("payload {n}: {e}"));
    }
    // ...and it opens only with the session's key: not with another key...
    let mut stranger = MediaReceiver::new();
    stranger.add_key(0, MediaKey::generate(&mut OsRng)).unwrap();
    assert!(payloads.iter().all(|p| stranger.open(p).is_err()));
    // ...but every one did open on the viewer, and every frame arrived
    // intact, in order.
    let stats = client.media_stats().await.unwrap();
    assert_eq!(stats.opened, payloads.len() as u64, "{stats:?}");
    assert_eq!(stats.dropped(), 0, "{stats:?}");
    assert_eq!(received.len(), FRAMES, "{stats:?}");
    for (i, (got, sent)) in received.iter().zip(&frames).enumerate() {
        assert_eq!(got.frame_id as usize, i);
        assert!(got.data == *sent, "frame {i} differs");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn m3_datagrams_before_the_handshake_finished_never_reach_the_decoder() {
    // A hostile "host" that sends media-looking datagrams at once.
    let ep = quinn::Endpoint::server(remora_net::server_config().unwrap(), loopback()).unwrap();
    let addr = ep.local_addr().unwrap();
    let fake = tokio::spawn(async move {
        let conn = ep.accept().await.unwrap().await.unwrap();
        // The viewer's hello opens stream 0; answer it only with datagrams.
        let _stream = conn.accept_bi().await.unwrap();
        for i in 0..5u8 {
            let mut d = vec![0u8; 200];
            d[0] = 1; // a video fragment
            d[4..12].copy_from_slice(&u64::from(i).to_be_bytes());
            conn.send_datagram(bytes::Bytes::from(d)).unwrap();
        }
        conn.closed().await
    });
    let v = device("viewer");
    let mode = ViewerMode::Password {
        otp: remora_crypto::secret::Otp::parse("123456").unwrap(),
        expect: None,
    };
    let (_client, mut vev) = connect(addr, viewer_cfg(&v, mode), [7; 16]).await.unwrap();
    let mut events = Vec::new();
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_secs(5), vev.recv()).await {
        let end = matches!(e, ViewerEvent::Closed { .. } | ViewerEvent::Lost);
        events.push(e);
        if end {
            break;
        }
    }
    assert!(
        !events.iter().any(|e| matches!(e, ViewerEvent::Video(_))),
        "{events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            ViewerEvent::Failed {
                reason: FailReason::ProtocolViolation(Violation::DatagramBeforeActive),
                ..
            }
        )),
        "{events:?}"
    );
    let _ = fake.await;
}
