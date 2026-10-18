//! Remora networking (Phase 3 scope): QUIC over a single UDP socket with
//! quinn, the TLS exporter that binds QUIC into the Noise prologue, the
//! stream-0 frame transport, wire close codes, and the async drivers that
//! run the sans-IO [`remora_session`] state machines.
//!
//! * TLS inside QUIC is **untrusted plumbing** (architecture.md D1): each
//!   endpoint uses a throw-away self-signed certificate and the client
//!   accepts any certificate. Peers authenticate with SPAKE2 + Noise, and
//!   the TLS exporter in the Noise prologue makes a QUIC-layer MITM fail
//!   (A14).
//! * Every authentication failure is closed with `AUTH_FAILED`, an empty
//!   reason phrase, and **no earlier than [`AUTH_FAILURE_FLOOR`] after the
//!   failing message arrived** (A04), so which check failed cannot be read
//!   from the timing.
//!
//! STUN / ICE / hole punching come in Phase 5; on loopback none is needed.

#![forbid(unsafe_code)]

mod host;
mod tls;
mod viewer;
mod wire;

use std::time::Duration;

pub use host::{HostEvent, HostServer};
pub use tls::{ALPN, SERVER_NAME, client_config, server_config};
pub use viewer::{ViewerClient, ViewerEvent, connect};
pub use wire::{
    FrameReceiver, FrameSender, FramedStream, close, close_code_of, exporter, to_varint,
};

/// Minimum time between a failing message's arrival and the host's
/// `AUTH_FAILED` close (phase3-criteria §3.1a).
pub const AUTH_FAILURE_FLOOR: Duration = Duration::from_millis(200);
/// If the work before a failure verdict takes longer than this, the floor
/// may stop hiding it: the host logs a timing anomaly.
pub const TIMING_ANOMALY: Duration = Duration::from_millis(150);
/// How often the host advances its sessions' clocks (deadlines).
pub const TICK: Duration = Duration::from_millis(50);

/// Network errors.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// TLS / QUIC configuration could not be built.
    #[error("configuration: {0}")]
    Config(String),
    /// The QUIC connection failed or was closed.
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Connecting failed.
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// Socket error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A frame violated the framing rules (length prefix, size).
    #[error("framing: {0}")]
    Framing(#[from] remora_proto::frame::FrameError),
    /// Stream write failed.
    #[error("write: {0}")]
    Write(#[from] quinn::WriteError),
    /// Stream read failed.
    #[error("read: {0}")]
    Read(#[from] quinn::ReadError),
    /// The TLS exporter could not be derived.
    #[error("TLS exporter unavailable")]
    Exporter,
}

/// The pure part of the timing floor: when may the close for a failure that
/// was decided at `decided`, for a message that arrived at `arrival`, be
/// sent? Also says whether the work took longer than [`TIMING_ANOMALY`].
pub fn floor_deadline(
    arrival: tokio::time::Instant,
    decided: tokio::time::Instant,
) -> (tokio::time::Instant, bool) {
    let deadline = (arrival + AUTH_FAILURE_FLOOR).max(decided);
    let anomaly = decided.saturating_duration_since(arrival) >= TIMING_ANOMALY;
    (deadline, anomaly)
}
