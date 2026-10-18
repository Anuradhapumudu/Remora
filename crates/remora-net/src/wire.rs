//! Stream-0 framing, the TLS exporter, and close codes.

use remora_crypto::keyschedule::EXPORTER_LABEL;
use remora_crypto::secret::Exporter;
use std::collections::VecDeque;

use remora_proto::frame::{FrameDecoder, encode_frame};
use remora_session::CloseCode;

use crate::NetError;

/// The 32-byte TLS exporter (label `EXPORTER-remora/1`, empty context).
pub fn exporter(conn: &quinn::Connection) -> Result<Exporter, NetError> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, b"")
        .map_err(|_| NetError::Exporter)?;
    Ok(Exporter::from_bytes(out))
}

/// The QUIC application error code for `code`.
pub fn to_varint(code: CloseCode) -> quinn::VarInt {
    quinn::VarInt::from_u32(u32::from(code as u16))
}

/// Closes `conn` with `code` and an **empty** reason phrase.
pub fn close(conn: &quinn::Connection, code: CloseCode) {
    conn.close(to_varint(code), b"");
}

/// The close code the peer used, if `err` is an application close with a
/// code from our table.
pub fn close_code_of(err: &quinn::ConnectionError) -> Option<CloseCode> {
    let quinn::ConnectionError::ApplicationClosed(c) = err else {
        return None;
    };
    [
        CloseCode::Normal,
        CloseCode::AuthFailed,
        CloseCode::ProtocolViolation,
        CloseCode::VersionUnsupported,
        CloseCode::Rejected,
        CloseCode::Timeout,
        CloseCode::RateLimited,
    ]
    .into_iter()
    .find(|&code| to_varint(code) == c.error_code)
}

/// Stream 0: `u16` big-endian length prefix, then the frame.
pub struct FramedStream {
    tx: FrameSender,
    rx: FrameReceiver,
}

/// The sending half of stream 0.
pub struct FrameSender {
    send: quinn::SendStream,
}

/// The receiving half of stream 0. The decoder refuses an oversized prefix
/// before buffering (remora-proto, A26).
pub struct FrameReceiver {
    recv: quinn::RecvStream,
    decoder: FrameDecoder,
    ready: VecDeque<Vec<u8>>,
}

impl std::fmt::Debug for FramedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedStream").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FrameSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameSender").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FrameReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameReceiver").finish_non_exhaustive()
    }
}

impl FramedStream {
    /// Wraps a bidirectional stream.
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            tx: FrameSender { send },
            rx: FrameReceiver {
                recv,
                decoder: FrameDecoder::new(remora_proto::limits::NOISE_FRAME_MAX),
                ready: VecDeque::new(),
            },
        }
    }

    /// Sends one frame.
    pub async fn send_frame(&mut self, frame: &[u8]) -> Result<(), NetError> {
        self.tx.send_frame(frame).await
    }

    /// Receives the next whole frame; `None` when the peer finished the
    /// stream.
    pub async fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        self.rx.recv_frame().await
    }

    /// Splits into independently usable halves.
    pub fn split(self) -> (FrameSender, FrameReceiver) {
        (self.tx, self.rx)
    }
}

impl FrameSender {
    /// Sends one frame.
    pub async fn send_frame(&mut self, frame: &[u8]) -> Result<(), NetError> {
        let bytes = encode_frame(frame, remora_proto::limits::NOISE_FRAME_MAX)?;
        self.send.write_all(&bytes).await?;
        Ok(())
    }
}

impl FrameReceiver {
    /// Receives the next whole frame; `None` when the peer finished.
    pub async fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        let mut buf = [0u8; 4096];
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            match self.recv.read(&mut buf).await? {
                Some(n) => self.ready.extend(self.decoder.push(&buf[..n])?),
                None => return Ok(None),
            }
        }
    }
}
