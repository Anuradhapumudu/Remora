//! Shared harness for remora-net's attack tests: devices, a host server, a
//! scripted viewer with a tamper hook, and a QUIC-layer MITM proxy.
#![allow(dead_code, unreachable_pub)] // each test binary uses a subset
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand_core::OsRng;
use remora_crypto::identity::IdentityKeypair;
use remora_crypto::noise::NoiseStaticKeypair;
use remora_crypto::secret::Otp;
use remora_net::{FramedStream, HostEvent, HostServer, client_config, close_code_of, exporter};
use remora_session::{
    CloseCode, HostConfig, Identity, Millis, ViewerAction, ViewerConfig, ViewerMode, ViewerSession,
};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

pub struct Device {
    pub key: IdentityKeypair,
    pub identity: Arc<Identity>,
    /// The Noise secret, so a test can present the same Noise key under a
    /// different (bad) cert.
    pub noise_secret: [u8; 32],
}

pub fn device(name: &str) -> Device {
    let key = IdentityKeypair::generate(&mut OsRng);
    let mut noise_secret = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut noise_secret);
    let noise = NoiseStaticKeypair::from_secret(noise_secret);
    let cert = key.sign_cert(noise.public(), name, 1_760_000_000).unwrap();
    Device {
        key,
        identity: Arc::new(Identity { noise, cert }),
        noise_secret,
    }
}

pub fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

pub struct TestHost {
    pub server: HostServer,
    pub events: mpsc::UnboundedReceiver<HostEvent>,
    pub addr: SocketAddr,
}

pub async fn start_host(
    host: &Device,
    trusted: Vec<remora_crypto::identity::IdentityPublic>,
) -> TestHost {
    let (server, events) = HostServer::bind(
        loopback(),
        HostConfig {
            identity: host.identity.clone(),
            password_enabled: true,
            trusted,
        },
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    TestHost {
        server,
        events,
        addr,
    }
}

impl TestHost {
    /// Waits (≤ `secs`) for the first event matching `pred`.
    pub async fn wait_for(
        &mut self,
        secs: u64,
        mut pred: impl FnMut(&HostEvent) -> bool,
    ) -> Option<HostEvent> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match timeout(left, self.events.recv()).await {
                Ok(Some(e)) if pred(&e) => return Some(e),
                Ok(Some(_)) => continue,
                _ => return None,
            }
        }
    }

    /// Every event received within `ms`.
    pub async fn drain(&mut self, ms: u64) -> Vec<HostEvent> {
        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_millis(ms);
        while let Ok(Some(e)) = timeout(
            deadline.saturating_duration_since(Instant::now()),
            self.events.recv(),
        )
        .await
        {
            out.push(e);
        }
        out
    }
}

pub fn viewer_cfg(viewer: &Device, mode: ViewerMode) -> ViewerConfig {
    ViewerConfig {
        identity: viewer.identity.clone(),
        mode,
    }
}

pub fn password(otp: &Otp) -> ViewerMode {
    ViewerMode::Password {
        otp: otp.clone(),
        expect: None,
    }
}

pub fn wrong(otp: &Otp) -> ViewerMode {
    let right: u32 = otp.reveal().parse().unwrap();
    ViewerMode::Password {
        otp: Otp::parse(&format!("{:06}", (right + 1) % 1_000_000)).unwrap(),
        expect: None,
    }
}

/// A raw QUIC client connection with stream 0 open.
pub async fn raw_connect(addr: SocketAddr) -> (quinn::Endpoint, quinn::Connection, FramedStream) {
    let mut ep = quinn::Endpoint::client(loopback()).unwrap();
    ep.set_default_client_config(client_config().unwrap());
    let conn = ep
        .connect(addr, remora_net::SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    let (send, recv) = conn.open_bi().await.unwrap();
    (ep, conn, FramedStream::new(send, recv))
}

/// What a scripted viewer run observed.
#[derive(Debug)]
pub struct Outcome {
    /// Frames actually sent (after tampering).
    pub sent: Vec<Vec<u8>>,
    /// Frames received.
    pub received: Vec<Vec<u8>>,
    /// Every action of the viewer state machine.
    pub actions: Vec<ViewerAction>,
    /// The code the host closed with, if it closed.
    pub host_close: Option<CloseCode>,
    /// Time from sending the LAST frame to observing the host's close.
    pub close_after_last_send: Option<Duration>,
}

impl Outcome {
    pub fn reached_active(&self) -> bool {
        self.actions.contains(&ViewerAction::Active)
    }
}

/// Runs a viewer over a raw connection. `tamper(index, frame)` may replace
/// or drop (`None`) each outgoing frame. Stops when the host closes, the
/// viewer closes, or after `stop_after_sends` frames were sent (then waits
/// up to 3 s for the host's verdict).
pub async fn run_viewer(
    addr: SocketAddr,
    cfg: ViewerConfig,
    nonce: [u8; 16],
    mut tamper: impl FnMut(usize, Vec<u8>) -> Option<Vec<u8>>,
) -> Outcome {
    let (_ep, conn, mut stream) = raw_connect(addr).await;
    let ex = exporter(&conn).unwrap();
    let (mut viewer, first) = ViewerSession::start(cfg, nonce, ex, Millis(0));
    let mut out = Outcome {
        sent: Vec::new(),
        received: Vec::new(),
        actions: Vec::new(),
        host_close: None,
        close_after_last_send: None,
    };
    let mut last_send = Instant::now();
    let mut pending: Vec<ViewerAction> = first;
    loop {
        for a in std::mem::take(&mut pending) {
            if let ViewerAction::Send(f) = &a {
                let idx = out.sent.len();
                if let Some(f2) = tamper(idx, f.clone()) {
                    if stream.send_frame(&f2).await.is_ok() {
                        last_send = Instant::now();
                        out.sent.push(f2);
                    }
                } else {
                    out.sent.push(Vec::new()); // marks a dropped frame
                }
            }
            out.actions.push(a);
        }
        if out
            .actions
            .iter()
            .any(|a| matches!(a, ViewerAction::Close(_)))
        {
            break;
        }
        tokio::select! {
            f = stream.recv_frame() => match f {
                Ok(Some(frame)) => {
                    out.received.push(frame.clone());
                    pending = viewer.on_frame(&frame, Millis(0), &mut OsRng);
                }
                _ => {
                    let err = conn.closed().await;
                    out.host_close = close_code_of(&err);
                    out.close_after_last_send = Some(last_send.elapsed());
                    break;
                }
            },
            err = conn.closed() => {
                out.host_close = close_code_of(&err);
                out.close_after_last_send = Some(last_send.elapsed());
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(15)) => break,
        }
    }
    out
}

/// Which way a frame travels through the MITM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    ViewerToHost,
    HostToViewer,
}

/// Frames seen by the MITM, in order.
pub type Transcript = Arc<Mutex<Vec<(Dir, Vec<u8>)>>>;

pub type Tap = Arc<Mutex<dyn FnMut(Dir, usize, Vec<u8>) -> Vec<Vec<u8>> + Send>>;

/// A QUIC-layer man in the middle: terminates TLS towards the viewer (as a
/// server with its own throw-away certificate) and towards the host (as a
/// client), relaying stream-0 frames through `tap`, and relaying close codes.
pub struct Mitm {
    pub addr: SocketAddr,
    pub transcript: Transcript,
    _ep: quinn::Endpoint,
}

pub async fn start_mitm(target: SocketAddr, tap: Tap) -> Mitm {
    let ep = quinn::Endpoint::server(remora_net::server_config().unwrap(), loopback()).unwrap();
    let addr = ep.local_addr().unwrap();
    let transcript: Transcript = Arc::new(Mutex::new(Vec::new()));
    let ep2 = ep.clone();
    let t2 = transcript.clone();
    tokio::spawn(async move {
        while let Some(incoming) = ep2.accept().await {
            let tap = tap.clone();
            let transcript = t2.clone();
            tokio::spawn(async move {
                let Ok(v_conn) = incoming.await else { return };
                let Ok((v_send, v_recv)) = v_conn.accept_bi().await else {
                    return;
                };
                let mut v = FramedStream::new(v_send, v_recv);
                let (_h_ep, h_conn, mut h) = raw_connect(target).await;
                let (mut n_v2h, mut n_h2v) = (0usize, 0usize);
                loop {
                    tokio::select! {
                        f = v.recv_frame() => match f {
                            Ok(Some(frame)) => {
                                transcript.lock().unwrap().push((Dir::ViewerToHost, frame.clone()));
                                let outs = (tap.lock().unwrap())(Dir::ViewerToHost, n_v2h, frame);
                                n_v2h += 1;
                                for o in outs { let _ = h.send_frame(&o).await; }
                            }
                            _ => break,
                        },
                        f = h.recv_frame() => match f {
                            Ok(Some(frame)) => {
                                transcript.lock().unwrap().push((Dir::HostToViewer, frame.clone()));
                                let outs = (tap.lock().unwrap())(Dir::HostToViewer, n_h2v, frame);
                                n_h2v += 1;
                                for o in outs { let _ = v.send_frame(&o).await; }
                            }
                            _ => break,
                        },
                    }
                }
                // Relay whoever closed first, code included.
                tokio::select! {
                    e = h_conn.closed() => {
                        if let Some(c) = close_code_of(&e) { remora_net::close(&v_conn, c); }
                    }
                    e = v_conn.closed() => {
                        if let Some(c) = close_code_of(&e) { remora_net::close(&h_conn, c); }
                    }
                }
            });
        }
    });
    Mitm {
        addr,
        transcript,
        _ep: ep,
    }
}

/// A tap that passes everything through unchanged.
pub fn pass() -> Tap {
    Arc::new(Mutex::new(|_d: Dir, _i: usize, f: Vec<u8>| vec![f]))
}

pub fn median(xs: &mut [f64]) -> f64 {
    remora_testkit::stats::median(xs).unwrap()
}

/// A UDP relay between one viewer and `upstream`, with a switch that makes
/// it drop everything in both directions - a network that goes silent
/// without closing anything (Wi-Fi gone, a machine asleep). QUIC is
/// end-to-end encrypted through it; it only forwards or drops datagrams.
pub struct Relay {
    pub addr: SocketAddr,
    cut: Arc<std::sync::atomic::AtomicBool>,
}

impl Relay {
    pub async fn start(upstream: SocketAddr) -> Relay {
        use std::sync::atomic::Ordering;
        let front = Arc::new(tokio::net::UdpSocket::bind(loopback()).await.unwrap());
        let back = Arc::new(tokio::net::UdpSocket::bind(loopback()).await.unwrap());
        back.connect(upstream).await.unwrap();
        let addr = front.local_addr().unwrap();
        let cut = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let (f, b, c, k) = (front.clone(), back.clone(), client.clone(), cut.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok((n, from)) = f.recv_from(&mut buf).await {
                *c.lock().unwrap() = Some(from);
                if !k.load(Ordering::SeqCst) {
                    let _ = b.send(&buf[..n]).await;
                }
            }
        });
        let (f, b, k) = (front, back, cut.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok(n) = b.recv(&mut buf).await {
                let to = *client.lock().unwrap();
                if let (Some(to), false) = (to, k.load(Ordering::SeqCst)) {
                    let _ = f.send_to(&buf[..n], to).await;
                }
            }
        });
        Relay { addr, cut }
    }

    /// From now on, nothing gets through in either direction.
    pub fn cut(&self) {
        self.cut.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
