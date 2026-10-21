//! The viewer's async driver for one connection.

use std::net::SocketAddr;

use rand_core::OsRng;
use remora_crypto::identity::IdentityCert;
use remora_crypto::sas::Sas;
use remora_session::{
    CloseCode, FailReason, MediaStats, Millis, Step, ViewerAction, ViewerConfig, ViewerSession,
};
use std::time::Duration;
use tokio::sync::mpsc;

use tokio::time::Instant;

use crate::wire::is_lost;
use crate::{
    FramedStream, NetError, SERVER_NAME, TICK, client_config, close, close_code_of, exporter,
};

/// What the viewer UI / CLI is told.
#[derive(Debug, Clone, PartialEq)]
pub enum ViewerEvent {
    /// Show the safety code.
    ShowSas {
        /// The code.
        sas: Sas,
        /// The host's verified identity.
        host: IdentityCert,
    },
    /// The host approved.
    Active,
    /// A complete video frame from the host, for the decoder.
    Video(remora_proto::video::VideoFrame),
    /// The host's capture paused (session stays active).
    StreamPaused(remora_session::PauseReason),
    /// The stream resumed.
    StreamResumed,
    /// The session failed locally.
    Failed {
        /// Reason.
        reason: FailReason,
        /// Where.
        step: Step,
    },
    /// The connection ended. `remote` is the code the host closed with, if
    /// it closed first.
    Closed {
        /// Code we sent, if we closed.
        local: Option<CloseCode>,
        /// Code the host sent, if it closed.
        remote: Option<CloseCode>,
    },
    /// The connection died without a close from either side: the host went
    /// silent for [`crate::IDLE_TIMEOUT`] or reset it.
    Lost,
}

/// Handle to a running viewer connection.
#[derive(Debug)]
pub struct ViewerClient {
    pub(crate) commands: mpsc::UnboundedSender<ViewerCommand>,
}

#[derive(Debug)]
pub(crate) enum ViewerCommand {
    Input(remora_proto::messages::Input),
    Stats(tokio::sync::oneshot::Sender<MediaStats>),
    Disconnect,
}

/// Connects to a host at `addr` and runs the viewer side of the handshake.
pub async fn connect(
    addr: SocketAddr,
    config: ViewerConfig,
    nonce: [u8; 16],
) -> Result<(ViewerClient, mpsc::UnboundedReceiver<ViewerEvent>), NetError> {
    let local: SocketAddr = if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = quinn::Endpoint::client(local)?;
    endpoint.set_default_client_config(client_config()?);
    let conn = endpoint.connect(addr, SERVER_NAME)?.await?;
    let ex = exporter(&conn)?;
    let (send, recv) = conn.open_bi().await?;
    let stream = FramedStream::new(send, recv);
    let start = Instant::now();
    let (session, first) = ViewerSession::start(config, nonce, ex, Millis(0));
    let (events, rx) = mpsc::unbounded_channel();
    let (commands, cmd_rx) = mpsc::unbounded_channel();
    tokio::spawn(drive(
        endpoint, conn, stream, session, first, events, cmd_rx, start,
    ));
    Ok((ViewerClient { commands }, rx))
}

/// How the connection ended, when the host (or the network) ended it.
fn ended(err: &quinn::ConnectionError) -> ViewerEvent {
    if is_lost(err) {
        ViewerEvent::Lost
    } else {
        ViewerEvent::Closed {
            local: None,
            remote: close_code_of(err),
        }
    }
}

fn now(start: Instant) -> Millis {
    Millis(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    stream: FramedStream,
    mut session: ViewerSession,
    first: Vec<ViewerAction>,
    events: mpsc::UnboundedSender<ViewerEvent>,
    mut commands: mpsc::UnboundedReceiver<ViewerCommand>,
    start: Instant,
) {
    let (mut tx, mut rx) = stream.split();
    let mut tick = tokio::time::interval(TICK);
    let mut pending = first;
    loop {
        // Perform the session's actions in order.
        for action in std::mem::take(&mut pending) {
            match action {
                ViewerAction::Send(frame) => {
                    let _ = tx.send_frame(&frame).await;
                }
                ViewerAction::Close(code) => {
                    if code == CloseCode::Normal {
                        // Orderly: give the Goodbye time to arrive (closing
                        // at once discards unsent stream data); the host
                        // closes as soon as it has it.
                        let _ = tokio::time::timeout(Duration::from_secs(1), conn.closed()).await;
                    }
                    close(&conn, code);
                    let _ = events.send(ViewerEvent::Closed {
                        local: Some(code),
                        remote: None,
                    });
                    return;
                }
                ViewerAction::ShowSas { sas, host } => {
                    let _ = events.send(ViewerEvent::ShowSas { sas, host });
                }
                ViewerAction::Active => {
                    let _ = events.send(ViewerEvent::Active);
                }
                ViewerAction::Video(frame) => {
                    let _ = events.send(ViewerEvent::Video(frame));
                }
                ViewerAction::StreamPaused(reason) => {
                    let _ = events.send(ViewerEvent::StreamPaused(reason));
                }
                ViewerAction::StreamResumed => {
                    let _ = events.send(ViewerEvent::StreamResumed);
                }
                ViewerAction::Failed { reason, step } => {
                    let _ = events.send(ViewerEvent::Failed { reason, step });
                }
            }
        }
        tokio::select! {
            frame = rx.recv_frame() => match frame {
                Ok(Some(frame)) => pending = session.on_frame(&frame, now(start), &mut OsRng),
                _ => {
                    let err = conn.closed().await;
                    let _ = events.send(ended(&err));
                    return;
                }
            },
            dgram = conn.read_datagram() => match dgram {
                Ok(d) => pending = session.on_datagram(&d, now(start)),
                Err(err) => {
                    let _ = events.send(ended(&err));
                    return;
                }
            },
            cmd = commands.recv() => match cmd {
                Some(ViewerCommand::Input(input)) => pending = session.send_input(input).into_iter().collect(),
                Some(ViewerCommand::Stats(reply)) => {
                    let _ = reply.send(session.media_stats());
                }
                Some(ViewerCommand::Disconnect) | None => pending = session.disconnect(),
            },
            _ = tick.tick() => pending = session.tick(now(start)),
        }
    }
}

impl ViewerClient {
    /// Sends an input event (dropped unless the session is Active).
    pub fn send_input(&self, input: remora_proto::messages::Input) {
        let _ = self.commands.send(ViewerCommand::Input(input));
    }

    /// What happened to the media datagrams received so far (`None` once
    /// the connection is gone).
    pub async fn media_stats(&self) -> Option<MediaStats> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.commands.send(ViewerCommand::Stats(tx)).ok()?;
        rx.await.ok()
    }

    /// Ends the session.
    pub fn disconnect(&self) {
        let _ = self.commands.send(ViewerCommand::Disconnect);
    }
}
