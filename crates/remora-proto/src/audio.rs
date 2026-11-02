//! The audio datagram body (phase4.8-criteria A3; protocol.md §6).
//!
//! An audio datagram has the common clear header (kind `0x04`, sealed with
//! the session's media key like video) and this body, encrypted:
//!
//! ```text
//!  0..4   u32  seq            packet number, +1 per 20 ms
//!  4..12  u64  capture_ts_us  shared-clock time of the first sample (sync)
//! 12..    Opus packet         1..=MAX_OPUS_BYTES bytes
//! ```
//!
//! One packet per datagram (no fragments). Limits are checked before
//! anything is kept; the Opus bytes are handed to the decoder only after
//! this parse succeeded. Fuzzed: `audio_packet`.

/// Bytes before the Opus data.
pub const AUDIO_BODY_HEADER_LEN: usize = 12;
/// Largest Opus packet accepted. A 20 ms stereo packet at 256 kbit/s is
/// 640 bytes; this leaves room and keeps the datagram under
/// [`crate::limits::VIDEO_DATAGRAM_TARGET`].
pub const MAX_OPUS_BYTES: usize = 1000;

/// One audio packet.
#[derive(Clone, PartialEq, Eq)]
pub struct AudioPacket {
    /// Packet number.
    pub seq: u32,
    /// Shared-clock time of its first sample, microseconds.
    pub capture_ts_us: u64,
    /// The Opus packet.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for AudioPacket {
    // Never the sound itself (INV9, A4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AudioPacket")
            .field("seq", &self.seq)
            .field("capture_ts_us", &self.capture_ts_us)
            .field("bytes", &self.data.len())
            .finish()
    }
}

/// Why an audio body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AudioError {
    /// Shorter than its header.
    #[error("audio packet too short")]
    TooShort,
    /// No Opus data.
    #[error("audio packet has no data")]
    Empty,
    /// More than [`MAX_OPUS_BYTES`].
    #[error("audio packet too long")]
    TooLong,
}

impl AudioPacket {
    /// Reads a decrypted audio body.
    pub fn parse(body: &[u8]) -> Result<Self, AudioError> {
        let Some((head, data)) = body.split_at_checked(AUDIO_BODY_HEADER_LEN) else {
            return Err(AudioError::TooShort);
        };
        if data.is_empty() {
            return Err(AudioError::Empty);
        }
        if data.len() > MAX_OPUS_BYTES {
            return Err(AudioError::TooLong);
        }
        let mut seq = [0u8; 4];
        seq.copy_from_slice(&head[..4]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&head[4..]);
        Ok(Self {
            seq: u32::from_be_bytes(seq),
            capture_ts_us: u64::from_be_bytes(ts),
            data: data.to_vec(),
        })
    }

    /// The body to seal.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(AUDIO_BODY_HEADER_LEN + self.data.len());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.capture_ts_us.to_be_bytes());
        b.extend_from_slice(&self.data);
        b
    }
}
