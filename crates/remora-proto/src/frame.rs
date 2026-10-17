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
    let len = payload.len();
    if len == 0 {
        return Err(FrameError::Empty);
    }
    let prefix = u16::try_from(len)
        .ok()
        .filter(|_| len <= max)
        .ok_or(FrameError::TooLarge { len, max })?;
    let mut out = Vec::with_capacity(2 + len);
    out.extend_from_slice(&prefix.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
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
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }
        let mut frames = Vec::new();
        let mut input = bytes;
        while !input.is_empty() {
            // Fast path: a whole frame is available in the input — copy it once.
            if self.partial.is_empty()
                && let [hi, lo, rest @ ..] = input
            {
                let len = self.check_len(u16::from_be_bytes([*hi, *lo]))?;
                if let Some((body, tail)) = rest.split_at_checked(len) {
                    frames.push(body.to_vec());
                    input = tail;
                    continue;
                }
            }
            // Slow path: accumulate a partial frame (never more than 2 + max bytes).
            if self.partial.len() < 2 {
                self.partial.push(input[0]);
                input = &input[1..];
                if let [hi, lo] = self.partial[..] {
                    let len = self.check_len(u16::from_be_bytes([hi, lo]))?;
                    self.partial.reserve_exact(len);
                }
                continue;
            }
            let len = usize::from(u16::from_be_bytes([self.partial[0], self.partial[1]]));
            let missing = len - (self.partial.len() - 2);
            let (chunk, tail) = input.split_at(missing.min(input.len()));
            self.partial.extend_from_slice(chunk);
            input = tail;
            if self.partial.len() - 2 == len {
                frames.push(self.partial.split_off(2));
                self.partial.clear();
            }
        }
        Ok(frames)
    }

    /// Validates a length prefix; poisons the decoder on failure.
    fn check_len(&mut self, len: u16) -> Result<usize, FrameError> {
        let len = usize::from(len);
        let err = if len == 0 {
            FrameError::Empty
        } else if len > self.max {
            FrameError::TooLarge { len, max: self.max }
        } else {
            return Ok(len);
        };
        self.poisoned = true;
        self.partial = Vec::new();
        Err(err)
    }
}
