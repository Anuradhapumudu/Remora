//! Length-prefixed framing on QUIC stream 0 (protocol.md §4): `u16` big-endian
//! length (1..=max) followed by that many bytes.

/// Framing errors. After any error the decoder is poisoned (fail closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The length prefix exceeds the limit for this stream state.
    #[error("frame of {len} bytes exceeds the {max}-byte limit")]
    TooLarge {
        /// Claimed length.
        len: usize,
        /// Allowed maximum.
        max: usize,
    },
    /// A zero-length frame.
    #[error("empty frame")]
    Empty,
    /// The decoder already failed; the stream must be closed.
    #[error("frame decoder poisoned by an earlier error")]
    Poisoned,
}

/// Encodes one frame. `payload` must be 1..=`max` bytes.
pub fn encode_frame(payload: &[u8], max: usize) -> Result<Vec<u8>, FrameError> {
    let _ = (payload, max);
    todo!("phase 3 step 2: implement after the tests")
}

/// Incremental decoder. Buffers at most one partial frame (≤ 2 + `max` bytes),
/// whatever the caller pushes.
#[derive(Debug)]
pub struct FrameDecoder {
    max: usize,
    partial: Vec<u8>,
    poisoned: bool,
}

impl FrameDecoder {
    /// A decoder accepting frames of 1..=`max` bytes. Allocates nothing yet.
    pub fn new(max: usize) -> Self {
        Self {
            max,
            partial: Vec::new(),
            poisoned: false,
        }
    }

    /// Feeds bytes; returns every complete frame. Rejects an oversized length
    /// prefix as soon as its two bytes arrive, before buffering the body.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        let _ = (bytes, self.max, &self.partial, self.poisoned);
        todo!("phase 3 step 2: implement after the tests")
    }
}
