//! The host's async driver: accepts QUIC connections, feeds stream-0
//! frames and datagrams to the sans-IO [`remora_session::Host`], performs
//! its actions, and applies the [`crate::AUTH_FAILURE_FLOOR`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use remora_crypto::identity::IdentityPublic;
use remora_crypto::sas::Sas;
use remora_crypto::secret::Otp;
use remora_session::{
    AppMessage, ApproveError, CloseCode, FailReason, Host, HostAction, HostConfig, Millis,
    SendVideoError, SessionId, Step,
};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::media::MediaPath;
use crate::wire::{FrameSender, is_lost};
use crate::{FramedStream, NetError, TICK, close, exporter, floor_deadline, server_config};

/// What the host UI / CLI is told.
#[derive(Debug, Clone, PartialEq)]
pub enum HostEvent {
    /// Show the accept prompt.
    Prompt {
        /// Session.
        id: SessionId,
        /// Safety code to show.
        sas: Sas,
        /// Viewer's device name (untrusted).
        viewer_name: String,
        /// Viewer's identity key.
        viewer_key: IdentityPublic,
    },
    /// Withdraw the prompt for `id`.
    PromptClosed {
        /// Session.
        id: SessionId,
    },
    /// The session is active: show the indicator.
    Active {
        /// Session.
        id: SessionId,
    },
    /// An application message (Active only).
    Deliver {
        /// Session.
        id: SessionId,
        /// The message.
        msg: AppMessage,
    },
    /// A handshake failed (also logged as one WARN `handshake_failed`).
    Failed {
        /// Session.
        id: SessionId,
        /// Precise local reason.
        reason: FailReason,
        /// Where.
        step: Step,
        /// Password attempt number, if counted.
        attempt: Option<u32>,
        /// Peer address.
        peer: SocketAddr,
    },
    /// Three failures: a new password is in effect (show it).
    OtpRotated,
    /// Capture resumed after an interruption: encode the next frame as a
    /// keyframe.
    ForceKeyframe,
    /// The password was used: a new one is in effect (INV15).
    OtpUsed {
        /// Session that used it.
        id: SessionId,
    },
    /// The connection for `id` was closed with `code`.
    Closed {
        /// Session.
        id: SessionId,
        /// Code sent to the peer.
        code: CloseCode,
    },
    /// The connection for `id` died without a close from either side: the
    /// viewer went silent for [`crate::IDLE_TIMEOUT`] (network gone, viewer
    /// machine asleep or crashed) or reset it. The session is over; this is
    /// reported instead of [`HostEvent::Closed`], never as an orderly close.
    Lost {
        /// Session.
        id: SessionId,
    },
}

/// What the per-connection writer task does, in order.
enum Out {
    Frame(Vec<u8>),
    /// Close with `code`, not before `not_before` (the A04 floor).
    Close(CloseCode, Option<Instant>),
}

/// One live connection.
struct Conn {
    out: mpsc::UnboundedSender<Out>,
    peer: SocketAddr,
    accepted: Instant,
    /// For media datagrams, which bypass the ordered writer: a late frame
    /// is worth nothing, so they go out at once.
    quic: quinn::Connection,
}

struct Shared {
    host: Mutex<Host>,
    conns: Mutex<HashMap<SessionId, Conn>>,
    events: mpsc::UnboundedSender<HostEvent>,
    start: Instant,
    media: MediaPath,
}

/// A running host endpoint.
pub struct HostServer {
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for HostServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostServer").finish_non_exhaustive()
    }
}

impl HostServer {
    /// Binds a QUIC endpoint on `addr` and starts accepting connections.
    pub async fn bind(
        addr: SocketAddr,
        config: HostConfig,
    ) -> Result<(HostServer, mpsc::UnboundedReceiver<HostEvent>), NetError> {
        let endpoint = quinn::Endpoint::server(server_config()?, addr)?;
        let (events, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            host: Mutex::new(Host::new(config, &mut OsRng)),
            conns: Mutex::new(HashMap::new()),
            events,
            start: Instant::now(),
            media: MediaPath::default(),
        });
        tokio::spawn(accept_loop(endpoint.clone(), shared.clone()));
        tokio::spawn(tick_loop(Arc::downgrade(&shared)));
        Ok((HostServer { endpoint, shared }, rx))
    }

    /// The bound address.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// The current one-time password (show it on the host's screen).
    pub fn otp(&self) -> Otp {
        lock(&self.shared.host).otp().clone()
    }

    /// Issues a connection-code nonce valid for `ttl` (A06).
    pub fn issue_nonce(&self, ttl: Duration) -> [u8; 16] {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let expires = self.shared.now().plus(ttl_ms);
        lock(&self.shared.host).issue_nonce(nonce, expires);
        nonce
    }

    /// Accept on the prompt for `id` showing `sas`.
    pub fn approve(&self, id: SessionId, sas: Sas) -> Result<(), ApproveError> {
        let now = self.shared.now();
        let actions = lock(&self.shared.host).approve(id, sas, now)?;
        self.shared.apply(actions, None);
        Ok(())
    }

    /// Deny the prompt for `id`.
    pub fn deny(&self, id: SessionId) {
        let actions = lock(&self.shared.host).deny(id);
        self.shared.apply(actions, None);
    }

    /// Screen capture changed state (phase4-criteria §7); see
    /// [`remora_session::Host::capture_changed`].
    pub fn capture_changed(&self, status: remora_session::CaptureStatus) {
        let now = self.shared.now();
        let actions = lock(&self.shared.host).capture_changed(status, now);
        self.shared.apply(actions, None);
    }

    /// While the captured display is removed: how long until the host
    /// gives up waiting (roadmap D-29); `None` otherwise.
    pub fn pause_remaining(&self) -> Option<Duration> {
        let now = self.shared.now();
        lock(&self.shared.host)
            .pause_remaining(now)
            .map(|ms| Duration::from_millis(u64::from(ms)))
    }

    /// Sends one encoded video frame to every active session; see
    /// [`remora_session::Host::send_video`].
    pub fn send_video(
        &self,
        keyframe: bool,
        capture_ts_us: u64,
        data: &[u8],
    ) -> Result<(), SendVideoError> {
        let now = self.shared.now();
        let actions =
            lock(&self.shared.host).send_video(keyframe, capture_ts_us, data, now, &mut OsRng)?;
        self.shared.apply(actions, None);
        Ok(())
    }

    /// Every media datagram payload handed to quinn from now on
    /// (phase4-criteria M1a; feature `test-tap`, tests only).
    #[cfg(feature = "test-tap")]
    pub fn tap_datagrams(&self) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self
            .shared
            .media
            .tap
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(tx);
        rx
    }

    /// Disconnect session `id` (any state).
    pub fn disconnect(&self, id: SessionId) {
        let actions = lock(&self.shared.host).disconnect(id);
        self.shared.apply(actions, None);
    }

    /// Stops accepting and closes every connection.
    pub fn shutdown(&self) {
        self.endpoint
            .close(crate::to_varint(CloseCode::Normal), b"");
    }
}

impl Drop for HostServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Shared {
    fn now(&self) -> Millis {
        Millis(u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    /// Performs the actions of a session whose connection died (see
    /// [`is_lost`]): nothing can be sent any more, and the end is reported
    /// as [`HostEvent::Lost`] - not as the orderly close the session layer
    /// chose for it (walkthrough 2026-10-21: it used to print "Normal").
    fn lost(&self, actions: Vec<HostAction>) {
        let mut rest = Vec::new();
        for action in actions {
            match action {
                HostAction::Send { .. } | HostAction::Media { .. } => {}
                HostAction::Close { id, .. } => {
                    let _ = self.events.send(HostEvent::Lost { id });
                }
                other => rest.push(other),
            }
        }
        self.apply(rest, None);
    }

    /// Performs the session's actions. `arrival` is when the frame that
    /// produced them arrived: an `AUTH_FAILED` close is then held back
    /// until the floor (A04).
    fn apply(&self, actions: Vec<HostAction>, arrival: Option<Instant>) {
        let decided = Instant::now();
        let conns = lock(&self.conns);
        for action in actions {
            match action {
                HostAction::Send { id, frame } => {
                    if let Some(c) = conns.get(&id) {
                        let _ = c.out.send(Out::Frame(frame));
                    }
                }
                HostAction::Media { id, datagram } => {
                    if let Some(c) = conns.get(&id) {
                        self.media.send(&c.quic, datagram);
                    }
                }
                HostAction::Close { id, code } => {
                    let not_before = match (code, arrival) {
                        (CloseCode::AuthFailed, Some(arrival)) => {
                            let (at, anomaly) = floor_deadline(arrival, decided);
                            if anomaly {
                                tracing::warn!(
                                    session_id = id.0,
                                    work_ms = decided.saturating_duration_since(arrival).as_millis()
                                        as u64,
                                    "timing_anomaly"
                                );
                            }
                            Some(at)
                        }
                        _ => None,
                    };
                    if let Some(c) = conns.get(&id) {
                        let _ = c.out.send(Out::Close(code, not_before));
                    }
                    let _ = self.events.send(HostEvent::Closed { id, code });
                }
                HostAction::Prompt {
                    id,
                    sas,
                    viewer_name,
                    viewer_key,
                } => {
                    let _ = self.events.send(HostEvent::Prompt {
                        id,
                        sas,
                        viewer_name,
                        viewer_key,
                    });
                }
                HostAction::PromptClosed { id } => {
                    let _ = self.events.send(HostEvent::PromptClosed { id });
                }
                HostAction::Active { id } => {
                    let _ = self.events.send(HostEvent::Active { id });
                }
                HostAction::Deliver { id, msg } => {
                    let _ = self.events.send(HostEvent::Deliver { id, msg });
                }
                HostAction::Failed {
                    id,
                    reason,
                    step,
                    attempt,
                } => {
                    let (peer, elapsed) = conns
                        .get(&id)
                        .map(|c| (c.peer, c.accepted.elapsed()))
                        .unwrap_or((SocketAddr::from(([0, 0, 0, 0], 0)), Duration::ZERO));
                    let attempt_text = attempt
                        .map(|n| format!("{n}/{}", remora_session::limiter::ATTEMPTS_PER_OTP))
                        .unwrap_or_else(|| "-".to_owned());
                    // Exactly one WARN per failure (phase3-criteria §2):
                    // precise locally, generic on the wire. No secrets here.
                    tracing::warn!(
                        reason = %reason,
                        step = ?step,
                        peer = %peer,
                        attempt = %attempt_text,
                        session_id = id.0,
                        elapsed_ms = elapsed.as_millis() as u64,
                        "handshake_failed"
                    );
                    let _ = self.events.send(HostEvent::Failed {
                        id,
                        reason,
                        step,
                        attempt,
                        peer,
                    });
                }
                HostAction::OtpRotated { .. } => {
                    let _ = self.events.send(HostEvent::OtpRotated);
                }
                HostAction::OtpUsed { id } => {
                    let _ = self.events.send(HostEvent::OtpUsed { id });
                }
                HostAction::ForceKeyframe => {
                    let _ = self.events.send(HostEvent::ForceKeyframe);
                }
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock must not take the host down with it:
    // the data is still consistent at every unlock point.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn accept_loop(endpoint: quinn::Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(run_connection(incoming, shared.clone()));
    }
}

/// Advances every session's clock (handshake and prompt deadlines).
async fn tick_loop(shared: std::sync::Weak<Shared>) {
    let mut interval = tokio::time::interval(TICK);
    loop {
        interval.tick().await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let now = shared.now();
        let actions = lock(&shared.host).tick(now);
        shared.apply(actions, None);
    }
}

async fn run_connection(incoming: quinn::Incoming, shared: Arc<Shared>) {
    let Ok(conn) = incoming.await else {
        return;
    };
    let peer = conn.remote_address();
    let Ok(exporter) = exporter(&conn) else {
        close(&conn, CloseCode::ProtocolViolation);
        return;
    };
    let admitted =
        lock(&shared.host).accept_connection(peer.ip(), exporter, shared.now(), &mut OsRng);
    let id = match admitted {
        Ok(id) => id,
        Err(_) => {
            // Refused before any crypto (A03).
            close(&conn, CloseCode::RateLimited);
            return;
        }
    };
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    lock(&shared.conns).insert(
        id,
        Conn {
            out: out_tx,
            peer,
            accepted: Instant::now(),
            quic: conn.clone(),
        },
    );
    let mut out_rx = out_rx;
    let reader = async {
        // Until the viewer opens stream 0 there is nothing to write to, but
        // the session may still decide to close (slowloris: the 10 s
        // handshake deadline, A24) - so wait for either.
        let opened = tokio::select! {
            s = conn.accept_bi() => s.ok(),
            item = out_rx.recv() => {
                if let Some(Out::Close(code, not_before)) = item {
                    if let Some(at) = not_before {
                        tokio::time::sleep_until(at).await;
                    }
                    close(&conn, code);
                }
                None
            }
        };
        let Some((send, recv)) = opened else {
            return;
        };
        let (tx, mut stream) = FramedStream::new(send, recv).split();
        tokio::spawn(writer(conn.clone(), tx, out_rx));
        loop {
            tokio::select! {
                frame = stream.recv_frame() => match frame {
                    Ok(Some(frame)) => {
                        let arrival = Instant::now();
                        let actions = lock(&shared.host).on_frame(id, &frame, shared.now(), &mut OsRng);
                        shared.apply(actions, Some(arrival));
                    }
                    Ok(None) => break,
                    Err(NetError::Framing(_)) => {
                        // Oversized or malformed length prefix (A26).
                        let actions = lock(&shared.host).framing_error(id);
                        shared.apply(actions, None);
                        break;
                    }
                    // The connection went away: handled after the loop.
                    Err(_) => break,
                },
                dgram = conn.read_datagram() => match dgram {
                    Ok(d) => {
                        let actions = lock(&shared.host).on_datagram(id, &d);
                        shared.apply(actions, None);
                    }
                    Err(_) => break,
                },
            }
        }
    };
    reader.await;
    let err = conn.closed().await;
    // The connection is gone: end the session (frees its slot) and forget it.
    let actions = lock(&shared.host).disconnect(id);
    if is_lost(&err) {
        shared.lost(actions);
    } else {
        shared.apply(actions, None);
    }
    lock(&shared.host).forget(id);
    lock(&shared.conns).remove(&id);
}

/// Writes frames in order; a close waits for the floor, then closes.
async fn writer(
    conn: quinn::Connection,
    mut send: FrameSender,
    mut rx: mpsc::UnboundedReceiver<Out>,
) {
    while let Some(item) = rx.recv().await {
        match item {
            Out::Frame(frame) => {
                if send.send_frame(&frame).await.is_err() {
                    return;
                }
            }
            Out::Close(code, not_before) => {
                if let Some(at) = not_before {
                    tokio::time::sleep_until(at).await;
                }
                close(&conn, code);
                return;
            }
        }
    }
}
