//! The real media path end to end, through a recording UDP relay
//! (phase4-criteria §5 M1b, M4; §6 N1). One test, in its own binary: it
//! captures every `tracing` event of the whole process.
//!
//! Host: `HostServer` with frames from the hardware encoder; each source
//! frame carries its number (P7 barcode), a 32-byte random **canary** in
//! its pixels and a band of fresh random pixels (so the encoded stream is
//! large and real). Viewer: `connect` through the relay; the frames it
//! receives are decoded afterwards with `VtDecoder`.
//!
//! * **M1b** — no 16-byte window of any encoded frame, and no canary,
//!   in any UDP payload either way; byte entropy over all payloads
//!   ≥ 7.99 bits/byte (≥ 1 MB). The checker is shown to work on a
//!   recorded payload with a frame window spliced in.
//! * **M4** — halfway through, the relay re-sends recorded host→viewer
//!   packets: recent ones and the oldest ones. No frame is delivered
//!   twice and the drawn numbers never repeat or go backwards (P7).
//!   QUIC drops a re-sent UDP packet itself (packet numbers are never
//!   reused), so our media replay window (M5, sans-IO) is the second line.
//! * **N1** — every log line at TRACE level, from every crate (quinn and
//!   rustls included), holds no window of any encoded frame and no canary,
//!   raw, hex or as a byte list.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use remora_codec::h264::SizeLimit;
use remora_codec::{EncoderConfig, EncoderEvent, SyntheticSource, VtDecoder, VtEncoder, barcode};
use remora_crypto::identity::IdentityKeypair;
use remora_crypto::noise::NoiseStaticKeypair;
use remora_net::{HostEvent, HostServer, ViewerEvent, connect};
use remora_proto::video::VideoFrame;
use remora_session::{HostConfig, Identity, ViewerConfig, ViewerMode};
use remora_testkit::canary::{Canary, LogCapture, Windows16, find_leaks};
use tokio::net::UdpSocket;

const FRAMES: u64 = 600; // 10 s at 60 fps
const REPLAY_AT: u64 = 300;
const W: u32 = 1280;
const H: u32 = 720;

fn device(name: &str) -> (IdentityKeypair, Arc<Identity>) {
    let key = IdentityKeypair::generate(&mut OsRng);
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let noise = NoiseStaticKeypair::from_secret(secret);
    let cert = key.sign_cert(noise.public(), name, 1_760_000_000).unwrap();
    (key, Arc::new(Identity { noise, cert }))
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    ToHost,
    ToViewer,
}

type Recording = Arc<Mutex<Vec<(Dir, Vec<u8>)>>>;

/// Forwards UDP between one viewer and the host and records every
/// payload. QUIC is end-to-end encrypted through it.
struct Relay {
    addr: SocketAddr,
    front: Arc<UdpSocket>,
    viewer: Arc<Mutex<Option<SocketAddr>>>,
    recorded: Recording,
}

impl Relay {
    async fn start(upstream: SocketAddr) -> Relay {
        let front = Arc::new(UdpSocket::bind(loopback()).await.unwrap());
        let back = Arc::new(UdpSocket::bind(loopback()).await.unwrap());
        back.connect(upstream).await.unwrap();
        let addr = front.local_addr().unwrap();
        let viewer: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
        let recorded: Recording = Arc::default();
        let (f, b, v, r) = (
            front.clone(),
            back.clone(),
            viewer.clone(),
            recorded.clone(),
        );
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok((n, from)) = f.recv_from(&mut buf).await {
                *v.lock().unwrap() = Some(from);
                r.lock().unwrap().push((Dir::ToHost, buf[..n].to_vec()));
                let _ = b.send(&buf[..n]).await;
            }
        });
        let (f, v, r) = (front.clone(), viewer.clone(), recorded.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok(n) = back.recv(&mut buf).await {
                r.lock().unwrap().push((Dir::ToViewer, buf[..n].to_vec()));
                let to = *v.lock().unwrap();
                if let Some(to) = to {
                    let _ = f.send_to(&buf[..n], to).await;
                }
            }
        });
        Relay {
            addr,
            front,
            viewer,
            recorded,
        }
    }

    /// Sends recorded host→viewer packets to the viewer again (M4).
    async fn replay_to_viewer(&self, packets: &[Vec<u8>]) {
        let to = self.viewer.lock().unwrap().unwrap();
        for p in packets {
            self.front.send_to(p, to).await.unwrap();
        }
    }

    fn to_viewer(&self) -> Vec<Vec<u8>> {
        let r = self.recorded.lock().unwrap();
        r.iter()
            .filter(|(d, _)| *d == Dir::ToViewer)
            .map(|(_, p)| p.clone())
            .collect()
    }
}

/// Shannon entropy in bits per byte.
fn entropy(data: &[Vec<u8>]) -> (f64, usize) {
    let mut counts = [0u64; 256];
    let mut total = 0usize;
    for p in data {
        for &b in p {
            counts[b as usize] += 1;
        }
        total += p.len();
    }
    let n = total as f64;
    let h = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum();
    (h, total)
}

fn xorshift(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

#[test]
fn m1b_m4_n1_a_real_stream_through_a_recording_relay() {
    let logs = LogCapture::global();
    let mut canary = [0u8; 32];
    OsRng.fill_bytes(&mut canary);
    let encoded: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (recorded, received) = rt.block_on(async {
        let (host_key, host_id) = device("wire host");
        let (viewer_key, viewer_id) = device("wire viewer");
        let (server, mut hev) = HostServer::bind(
            loopback(),
            HostConfig {
                identity: host_id,
                password_enabled: true,
                trusted: vec![viewer_key.public()],
            },
        )
        .await
        .unwrap();
        let server = Arc::new(server);
        let relay = Relay::start(server.local_addr().unwrap()).await;
        let nonce = server.issue_nonce(Duration::from_secs(300));
        let config = ViewerConfig {
            identity: viewer_id,
            mode: ViewerMode::Trusted {
                pinned: host_key.public(),
            },
        };
        let (client, mut vev) = connect(relay.addr, config, nonce).await.unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(10), hev.recv()).await {
                Ok(Some(HostEvent::Prompt { id, sas, .. })) => {
                    server.approve(id, sas).unwrap();
                    break;
                }
                Ok(Some(_)) => {}
                other => panic!("no prompt: {other:?}"),
            }
        }
        loop {
            match tokio::time::timeout(Duration::from_secs(10), vev.recv()).await {
                Ok(Some(ViewerEvent::Active)) => break,
                Ok(Some(_)) => {}
                other => panic!("viewer never active: {other:?}"),
            }
        }

        // The viewer's frames, as they arrive.
        let received: Arc<Mutex<Vec<VideoFrame>>> = Arc::default();
        let got = received.clone();
        tokio::spawn(async move {
            while let Some(ev) = vev.recv().await {
                if let ViewerEvent::Video(f) = ev {
                    got.lock().unwrap().push(f);
                }
            }
        });

        // The host: encoder → send_video, on the encoder's thread.
        let (srv, enc_out) = (server.clone(), encoded.clone());
        let sink = Box::new(move |ev: EncoderEvent| {
            if let EncoderEvent::Frame(f) = ev {
                srv.send_video(f.keyframe, f.seq * 16_667, &f.data).unwrap();
                enc_out.lock().unwrap().push(f.data);
            }
        });
        let cfg = EncoderConfig {
            width: W,
            height: H,
            ..EncoderConfig::default()
        };
        let source = std::thread::spawn(move || {
            let mut enc = VtEncoder::new(cfg, sink).unwrap();
            let mut src = SyntheticSource::new(W, H).unwrap();
            let mut x = OsRng.next_u64() | 1;
            for i in 0..FRAMES {
                let img = src
                    .next_frame_with(|luma, stride, width, rows| {
                        // Rows 100..164: fresh noise; rows 200..208: canary.
                        for row in 100..164 {
                            for px in &mut luma[row * stride..row * stride + width] {
                                *px = xorshift(&mut x) as u8;
                            }
                        }
                        for row in 200..208 {
                            luma[row * stride..row * stride + 32].copy_from_slice(&canary);
                        }
                        barcode::stamp(luma, stride, width, rows, i as u32)
                    })
                    .unwrap();
                enc.encode(&img, Duration::from_micros(i * 16_667), false)
                    .unwrap();
                std::thread::sleep(Duration::from_micros(16_667));
            }
            enc.flush().unwrap();
        });

        // M4: halfway, re-send the oldest and the most recent packets.
        while encoded.lock().unwrap().len() < REPLAY_AT as usize {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let sent = relay.to_viewer();
        let mut replay: Vec<Vec<u8>> = sent.iter().take(100).cloned().collect();
        replay.extend(sent.iter().rev().take(50).cloned());
        relay.replay_to_viewer(&replay).await;

        tokio::task::spawn_blocking(move || source.join().unwrap())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        client.disconnect();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let recorded = relay.recorded.lock().unwrap().clone();
        let received = received.lock().unwrap().clone();
        (recorded, received)
    });
    let encoded = encoded.lock().unwrap().clone();
    assert_eq!(encoded.len() as u64, FRAMES, "encoded frames");

    let mut content = Windows16::new();
    for f in &encoded {
        content.add(f);
    }
    content.add(&canary);

    // ---- M1b: the wire.
    let payloads: Vec<Vec<u8>> = recorded.iter().map(|(_, p)| p.clone()).collect();
    for (n, p) in payloads.iter().enumerate() {
        assert!(
            content.find_in_bytes(p).is_none(),
            "UDP payload {n} carries frame content"
        );
    }
    // The checker works: a payload with 16 bytes of a frame spliced in.
    let mut planted = payloads.iter().max_by_key(|p| p.len()).unwrap().clone();
    planted[20..36].copy_from_slice(&encoded[5][40..56]);
    assert_eq!(content.find_in_bytes(&planted), Some(20));
    let (h, total) = entropy(&payloads);
    assert!(total >= 1 << 20, "only {total} bytes on the wire");
    assert!(h >= 7.99, "entropy {h:.4} bits/byte over {total} bytes");

    // ---- M4: nothing twice, nothing backwards.
    let mut ids: Vec<u32> = received.iter().map(|f| f.frame_id).collect();
    let n = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), n, "a frame was delivered twice");
    assert!(
        n as u64 >= FRAMES * 9 / 10,
        "only {n} of {FRAMES} frames arrived"
    );
    let mut dec = VtDecoder::new(SizeLimit::default());
    let mut drawn = Vec::new();
    for f in &received {
        if let Ok(p) = dec.decode(f.frame_id, &f.data) {
            let number = p
                .with_nv12(|nv12| {
                    let (y, stride) = nv12.y();
                    barcode::read_luma(y, stride, W as usize, H as usize)
                })
                .unwrap();
            drawn.push(number.expect("a drawn frame's barcode is readable"));
        }
    }
    assert!(
        drawn.windows(2).all(|w| w[0] < w[1]),
        "drawn numbers repeat or go backwards"
    );
    assert!(
        drawn.len() as u64 >= FRAMES * 9 / 10,
        "only {} drawn",
        drawn.len()
    );

    // ---- N1: the logs.
    let text = logs.text();
    assert!(
        text.lines().filter(|l| l.contains("TRACE")).count() > 100,
        "trace-level capture is not working"
    );
    if let Some(line) = content.find_in_text(&text) {
        panic!("a log line carries frame content: {line}");
    }
    let leaks = find_leaks(&text, &[Canary::new("pixel canary", canary.to_vec())]);
    assert!(leaks.is_empty(), "{leaks:?}");
    println!(
        "M1b: {} payloads, {total} bytes, entropy {h:.4}; M4: {n} frames received, {} drawn, \
         {} packets re-sent; N1: {} log lines",
        payloads.len(),
        drawn.len(),
        150,
        text.lines().count()
    );
}
