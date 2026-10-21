//! Remora video codecs: hardware-first encoders with a software fallback.
//!
//! Low-latency configuration everywhere: no B-frames (no reordering), no
//! lookahead, real-time rate control, keyframes only on request (plus an
//! optional interval). Output is an H.264 Annex B byte stream, so it can be
//! written straight to a `.h264` file or packetized for the network.

// `unsafe_code` is denied workspace-wide. Only the OS FFI modules under
// `src/sys/` may opt in with `#[allow(unsafe_code)]`, and every unsafe block
// needs a `// SAFETY:` comment (architecture.md §4).

use std::time::{Duration, Instant};

pub mod bitstream;
pub mod h264;
mod sys;

#[cfg(target_os = "macos")]
pub use sys::macos::{
    DecodedFrame, EncoderInfo, Probe444, PropertyReport, SyntheticSource, VtDecoder, VtEncoder,
    list_encoders, probe_444, supported_properties,
};

/// Video codecs Remora can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    /// H.264 / AVC.
    H264,
    /// H.265 / HEVC.
    Hevc,
}

/// H.264 profile. All of them are used without B-frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H264Profile {
    /// Most compatible (software decoders, old hardware); no CABAC, so ~10–15 % larger.
    ConstrainedBaseline,
    /// High profile without B-frames: better compression, needs a High-capable decoder.
    ConstrainedHigh,
}

/// Encoder settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Expected frame rate (rate-control hint).
    pub fps: u32,
    /// Target average bitrate in bits per second.
    pub bitrate_bps: u32,
    /// H.264 profile.
    pub profile: H264Profile,
    /// Force a keyframe every N frames; `0` = only the first frame and on request.
    pub keyframe_interval: u32,
    /// Enable long-term reference frames (loss recovery without keyframes).
    pub enable_ltr: bool,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_bps: 8_000_000,
            profile: H264Profile::ConstrainedBaseline,
            keyframe_interval: 0,
            enable_ltr: false,
        }
    }
}

/// A value for a named encoder property (see `VtEncoder::with_codec`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TuneValue {
    /// Boolean property.
    Bool(bool),
    /// Integer property.
    Int(i64),
    /// Floating-point property.
    Float(f64),
}

impl std::str::FromStr for TuneValue {
    type Err = String;
    /// Parses `true`/`false`, an integer, or a float.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "true" => Ok(Self::Bool(true)),
            "false" => Ok(Self::Bool(false)),
            _ => s
                .parse::<i64>()
                .map(Self::Int)
                .or_else(|_| s.parse::<f64>().map(Self::Float))
                .map_err(|_| format!("not a bool or number: {s}")),
        }
    }
}

/// One compressed frame.
pub struct EncodedFrame {
    /// Sequence number returned by `encode`.
    pub seq: u64,
    /// True for an IDR frame (decodable on its own; carries SPS/PPS).
    pub keyframe: bool,
    /// Annex B byte stream for this frame.
    pub data: Vec<u8>,
    /// When `encode` was called for this frame.
    pub submitted: Instant,
    /// When the encoder delivered it.
    pub completed: Instant,
}

impl EncodedFrame {
    /// Encode latency: submit → output (criterion C2).
    pub fn latency(&self) -> Duration {
        self.completed.saturating_duration_since(self.submitted)
    }
}

impl std::fmt::Debug for EncodedFrame {
    // Omits the payload: it is (compressed) screen content (threat model INV9).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodedFrame")
            .field("seq", &self.seq)
            .field("keyframe", &self.keyframe)
            .field("bytes", &self.data.len())
            .field("latency", &self.latency())
            .finish()
    }
}

/// What an encoder reports, delivered on the encoder's own thread.
#[derive(Debug)]
pub enum EncoderEvent {
    /// A compressed frame.
    Frame(EncodedFrame),
    /// The encoder dropped frame `seq` (e.g. real-time deadline missed).
    Dropped {
        /// Sequence number of the dropped frame.
        seq: u64,
    },
    /// Encoding frame `seq` failed.
    Error {
        /// Sequence number of the failed frame.
        seq: u64,
        /// What went wrong.
        error: CodecError,
    },
}

/// Receives encoder events. Must return quickly (it runs on the encoder's thread).
pub type EncoderSink = Box<dyn FnMut(EncoderEvent) + Send + 'static>;

/// Codec failures.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// An OS codec call failed.
    #[error("{api} failed with OSStatus {status}")]
    Os {
        /// Which call failed.
        api: &'static str,
        /// The OS status code.
        status: i32,
    },
    /// The encoder produced data we couldn't parse.
    #[error("malformed bitstream: {0}")]
    Bitstream(&'static str),
    /// Not available on this machine / OS.
    #[error("not supported: {0}")]
    Unsupported(&'static str),
}

/// Why a frame produced no picture. **Every** case means the decoder needs
/// a keyframe before it can show anything correct again, so the viewer
/// asks the host for one (phase4-criteria M7).
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// Refused before decoding (malformed, too large, or waiting for a
    /// keyframe): no byte of it reached the decoder.
    #[error("refused: {0}")]
    Refused(h264::Refusal),
    /// The decoder could not be configured with the keyframe's SPS/PPS.
    #[error("decoder configuration failed: {0}")]
    Configure(CodecError),
    /// The decoder reported an error for this frame.
    #[error("decode failed: {0}")]
    Decode(CodecError),
    /// The decoder returned no picture, or one larger than the SPS said.
    #[error("decoder returned no usable picture")]
    NoPicture,
}

/// What a decoder did with the frames it was given.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeStats {
    /// Frames decoded to a picture.
    pub decoded: u64,
    /// Frames refused before decoding ([`DecodeError::Refused`]).
    pub refused: u64,
    /// Frames the decoder failed on (configure, decode, no picture).
    pub failed: u64,
    /// Decoder sessions created (one per accepted change of SPS/PPS).
    pub sessions_created: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tune_values() {
        assert_eq!("true".parse::<TuneValue>(), Ok(TuneValue::Bool(true)));
        assert_eq!("4".parse::<TuneValue>(), Ok(TuneValue::Int(4)));
        assert_eq!("0.004".parse::<TuneValue>(), Ok(TuneValue::Float(0.004)));
        assert!("fast".parse::<TuneValue>().is_err());
    }

    #[test]
    fn debug_never_prints_payload() {
        let now = Instant::now();
        let f = EncodedFrame {
            seq: 7,
            keyframe: true,
            data: vec![0xAB; 32],
            submitted: now,
            completed: now + Duration::from_millis(3),
        };
        let s = format!("{f:?}");
        assert!(s.contains("bytes: 32"));
        assert!(!s.contains("171")); // 0xAB in decimal
        assert_eq!(f.latency(), Duration::from_millis(3));
    }
}
