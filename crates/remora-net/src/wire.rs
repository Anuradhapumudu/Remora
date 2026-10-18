//! Stream-0 framing, the TLS exporter, and close codes.

use remora_crypto::keyschedule::EXPORTER_LABEL;
use remora_crypto::secret::Exporter;
use remora_proto::frame::FrameDecoder;
use remora_session::CloseCode;

use crate::NetError;

/// The 32-byte TLS exporter (label `EXPORTER-remora/1`, empty context).
pub fn exporter(conn: &quinn::Connection) -> Result<Exporter, NetError> {
    let _ = (conn, EXPORTER_LABEL);
    todo!()
}

/// The QUIC application error code for `code`.
pub fn to_varint(code: CloseCode) -> quinn::VarInt {
    let _ = code;
    todo!()
}

/// Closes `conn` with `code` and an **empty** reason phrase.
pub fn close(conn: &quinn::Connection, code: CloseCode) {
    let _ = (conn, code);
    todo!()
}

/// The close code the peer used, if `err` is an application close with a
/// code from our table.
pub fn close_code_of(err: &quinn::ConnectionError) -> Option<CloseCode> {
    let _ = err;
    todo!()
}

/// Stream 0: `u16` big-endian length prefix, then the frame.
pub struct FramedStream {
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
    pub(crate) decoder: FrameDecoder,
    pub(crate) ready: std::collections::VecDeque<Vec<u8>>,
}

impl std::fmt::Debug for FramedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedStream").finish_non_exhaustive()
    }
}

impl FramedStream {
    /// Wraps a bidirectional stream.
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv,
            decoder: FrameDecoder::new(remora_proto::limits::NOISE_FRAME_MAX),
            ready: std::collections::VecDeque::new(),
        }
    }

    /// Sends one frame.
    pub async fn send_frame(&mut self, frame: &[u8]) -> Result<(), NetError> {
        let _ = frame;
        todo!()
    }

    /// Receives the next whole frame; `None` when the peer finished the
    /// stream.
    pub async fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        todo!()
    }
}
