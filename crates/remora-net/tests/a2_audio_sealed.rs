//! phase4.8-criteria A2 (INV2 for sound): every audio payload handed to
//! quinn is sealed. 200 packets (4 s of 20 ms audio) carrying a random
//! canary go out; no payload contains the canary or any 16-byte window of
//! a packet's Opus bytes, none opens with another key, and every packet
//! arrives intact and in order (so the test cannot pass by sending
//! nothing). Same method as M1a for video.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::time::Duration;

use common::*;
use rand_core::{OsRng, RngCore};
use remora_crypto::media::MediaReceiver;
use remora_crypto::secret::MediaKey;
use remora_net::{HostEvent, ViewerEvent, connect};
use remora_proto::audio::AudioPacket;
use remora_session::ViewerMode;

const PACKETS: u32 = 200;

#[tokio::test(flavor = "multi_thread")]
async fn a2_audio_is_sealed_on_the_wire_and_arrives_intact() {
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
    let mut canary = [0u8; 24];
    OsRng.fill_bytes(&mut canary);
    let mut sent = Vec::new();
    for seq in 0..PACKETS {
        let mut data = vec![0u8; 320];
        OsRng.fill_bytes(&mut data);
        data[100..124].copy_from_slice(&canary);
        let p = AudioPacket {
            seq,
            capture_ts_us: u64::from(seq) * 20_000,
            data,
        };
        host.server.send_audio(&p);
        sent.push(p);
        if seq % 20 == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await; // paced, not a burst
        }
    }
    let mut got = Vec::new();
    while got.len() < sent.len() {
        match tokio::time::timeout(Duration::from_secs(5), vev.recv()).await {
            Ok(Some(ViewerEvent::Audio(p))) => got.push(p),
            Ok(Some(_)) => {}
            other => panic!("audio stopped after {} packets: {other:?}", got.len()),
        }
    }
    let mut payloads = Vec::new();
    while let Ok(p) = tap.try_recv() {
        payloads.push(p);
    }
    assert_eq!(
        payloads.len(),
        sent.len(),
        "one datagram per packet to quinn"
    );
    // Every 16-byte window of every packet's Opus bytes (a set: fast).
    let plain: std::collections::HashSet<&[u8]> =
        sent.iter().flat_map(|s| s.data.windows(16)).collect();
    for (n, p) in payloads.iter().enumerate() {
        assert!(
            !p.windows(canary.len()).any(|w| w == canary),
            "payload {n} carries the canary"
        );
        assert!(
            !p.windows(16).any(|w| plain.contains(w)),
            "payload {n} carries plaintext Opus bytes"
        );
    }
    let mut stranger = MediaReceiver::new();
    stranger.add_key(0, MediaKey::generate(&mut OsRng)).unwrap();
    assert!(payloads.iter().all(|p| stranger.open(p).is_err()));
    assert_eq!(got, sent, "every packet intact and in order");
    let stats = client.media_stats().await.unwrap();
    assert_eq!(stats.audio_packets, u64::from(PACKETS), "{stats:?}");
}
