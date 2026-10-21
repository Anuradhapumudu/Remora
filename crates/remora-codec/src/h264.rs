//! Checks an H.264 frame received from the network **before** any of it
//! reaches the decoder (phase4-criteria M7). Pure Rust, no FFI.
//!
//! The host is authenticated, but a compromised or buggy host is still an
//! attacker against the viewer's decoder (threat model: the decoder is
//! attack surface; whether VideoToolbox decodes out of process is
//! unverified, C12, so we assume it runs in ours). So the viewer accepts
//! only the small subset of H.264 that Remora's own encoder produces:
//!
//! * an Annex B byte stream (start codes), at most [`MAX_NALS_PER_FRAME`]
//!   NAL units, none empty, forbidden bit clear;
//! * NAL unit types 1 (slice), 5 (IDR slice), 6 (SEI), 7 (SPS), 8 (PPS),
//!   9 (access unit delimiter); anything else (extensions, SVC, MVC,
//!   data partitioning) is refused;
//! * a keyframe (IDR) carries exactly one SPS and one PPS; any other frame
//!   carries none (so the size can only change at a keyframe, where it is
//!   checked);
//! * the SPS declares 8-bit 4:2:0 in Baseline, Main or High profile, and a
//!   picture no larger than the viewer's [`SizeLimit`] (≤ 7680 × 4320) -
//!   checked here, before the decoder is configured with it.

use crate::bitstream::{Bits, unescape_rbsp};

/// Largest picture any viewer accepts (protocol.md §7).
pub const MAX_WIDTH: u32 = 7680;
/// Largest picture any viewer accepts (protocol.md §7).
pub const MAX_HEIGHT: u32 = 4320;
/// Largest SPS or PPS NAL unit accepted, in bytes. Ours are < 32 bytes;
/// the decoder copies parameter sets into its configuration.
pub const MAX_PARAMETER_SET: usize = 256;
/// Most NAL units in one frame (our encoder sends at most a few: SPS,
/// PPS, SEI, one slice per thread).
pub const MAX_NALS_PER_FRAME: usize = 256;

/// The largest picture this viewer will decode: what it would announce as
/// `max_width × max_height` (protocol.md §5 `Capabilities`; not yet sent,
/// roadmap D-31), never above [`MAX_WIDTH`] × [`MAX_HEIGHT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeLimit {
    max_width: u32,
    max_height: u32,
}

impl SizeLimit {
    /// A limit of `max_width × max_height`, clamped to
    /// [`MAX_WIDTH`] × [`MAX_HEIGHT`].
    pub fn new(max_width: u32, max_height: u32) -> Self {
        let _ = (max_width, max_height);
        Self::default() // RED: not yet
    }

    /// Widest picture accepted.
    pub fn max_width(&self) -> u32 {
        self.max_width
    }

    /// Tallest picture accepted.
    pub fn max_height(&self) -> u32 {
        self.max_height
    }
}

impl Default for SizeLimit {
    /// [`MAX_WIDTH`] × [`MAX_HEIGHT`].
    fn default() -> Self {
        Self {
            max_width: MAX_WIDTH,
            max_height: MAX_HEIGHT,
        }
    }
}

/// What a sequence parameter set declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpsInfo {
    /// `profile_idc` (66 Baseline, 77 Main, 100 High).
    pub profile_idc: u8,
    /// `level_idc`.
    pub level_idc: u8,
    /// `seq_parameter_set_id`.
    pub sps_id: u32,
    /// Displayed width (after cropping), pixels.
    pub width: u32,
    /// Displayed height (after cropping), pixels.
    pub height: u32,
    /// Decoded width (whole macroblocks), pixels: what the decoder allocates.
    pub coded_width: u32,
    /// Decoded height (whole macroblocks), pixels.
    pub coded_height: u32,
}

/// Why a frame was refused. Never carries frame bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    /// The frame does not start with a start code.
    #[error("no start code")]
    NoStartCode,
    /// A NAL unit with no bytes.
    #[error("empty NAL unit")]
    EmptyNal,
    /// `forbidden_zero_bit` set.
    #[error("forbidden bit set")]
    ForbiddenBit,
    /// A NAL unit type Remora never sends.
    #[error("NAL unit type {0} not accepted")]
    NalType(u8),
    /// More than [`MAX_NALS_PER_FRAME`] NAL units.
    #[error("too many NAL units")]
    TooManyNals,
    /// A parameter set longer than [`MAX_PARAMETER_SET`].
    #[error("parameter set too large")]
    ParameterSetTooLarge,
    /// A second SPS or PPS in one frame.
    #[error("repeated parameter set")]
    RepeatedParameterSet,
    /// A keyframe without its SPS and PPS.
    #[error("keyframe without SPS and PPS")]
    KeyframeWithoutParameterSets,
    /// SPS or PPS outside a keyframe.
    #[error("parameter sets outside a keyframe")]
    ParameterSetsOutsideKeyframe,
    /// Both IDR and non-IDR slices, or no slice at all.
    #[error("bad slice mix")]
    Slices,
    /// The SPS is malformed or uses a feature Remora does not accept.
    #[error("SPS refused: {0}")]
    Sps(&'static str),
    /// The PPS is malformed or names another SPS.
    #[error("PPS refused: {0}")]
    Pps(&'static str),
    /// The picture is larger than the viewer's [`SizeLimit`].
    #[error("picture {width}x{height} larger than the limit")]
    TooLarge {
        /// Declared width (coded, i.e. before cropping, if that is larger).
        width: u64,
        /// Declared height (coded, if that is larger).
        height: u64,
    },
}

/// One checked frame: borrowed slices of the input, nothing copied yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H264Frame<'a> {
    /// Contains an IDR slice (decodable on its own).
    pub keyframe: bool,
    /// The SPS NAL unit (keyframes only) and what it declares.
    pub sps: Option<(&'a [u8], SpsInfo)>,
    /// The PPS NAL unit (keyframes only).
    pub pps: Option<&'a [u8]>,
    /// Every other NAL unit (slices, SEI, delimiters), in order.
    pub nals: Vec<&'a [u8]>,
}

impl H264Frame<'_> {
    /// The non-parameter-set NAL units with 4-byte big-endian length
    /// prefixes, as VideoToolbox decodes them (AVCC).
    pub fn to_avcc(&self) -> Vec<u8> {
        Vec::new() // RED: not yet
    }
}

/// Splits an Annex B frame into NAL units and checks it against the rules
/// in the module documentation and `limit`.
pub fn parse_frame(annexb: &[u8], limit: SizeLimit) -> Result<H264Frame<'_>, StreamError> {
    let _ = (annexb, limit);
    Err(StreamError::NoStartCode) // RED: not yet
}

/// Reads an SPS NAL unit (starting at its header byte) far enough to know
/// the picture size; refuses what Remora's encoder never produces.
pub fn parse_sps(nal: &[u8]) -> Result<SpsInfo, StreamError> {
    let _ = nal;
    let _ = (unescape_rbsp(&[]), Bits::new(&[]).se());
    Err(StreamError::Sps("RED: not yet"))
}

/// A frame the gate let through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted<'a> {
    /// The checked frame.
    pub frame: H264Frame<'a>,
    /// The parameter sets differ from the decoder's current ones (or there
    /// is no decoder yet): (re)create it from `frame.sps` / `frame.pps`
    /// before decoding.
    pub reconfigure: bool,
}

/// Why the gate refused a frame. Either way the viewer needs a keyframe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The frame broke a rule.
    #[error("malformed: {0}")]
    Malformed(StreamError),
    /// Not a keyframe, and the decoder has nothing valid to predict from
    /// (start of stream, or after a refused frame or decode error).
    #[error("waiting for a keyframe")]
    WaitingForKeyframe,
}

/// Stream state in front of the decoder: which parameter sets are in use,
/// and whether the next frame must be a keyframe.
#[derive(Debug)]
pub struct DecodeGate {
    limit: SizeLimit,
    current: Option<(Vec<u8>, Vec<u8>)>,
    waiting_for_keyframe: bool,
}

impl DecodeGate {
    /// A gate that waits for the first keyframe.
    pub fn new(limit: SizeLimit) -> Self {
        Self {
            limit,
            current: None,
            waiting_for_keyframe: true,
        }
    }

    /// Checks one frame. A refused frame also makes the gate wait for the
    /// next keyframe (the decoder's reference pictures are now stale).
    pub fn admit<'a>(&mut self, annexb: &'a [u8]) -> Result<Admitted<'a>, Refusal> {
        let _ = (
            annexb,
            &self.limit,
            &self.current,
            self.waiting_for_keyframe,
        );
        Err(Refusal::WaitingForKeyframe) // RED: not yet
    }

    /// The decoder failed on an admitted frame: wait for a keyframe.
    pub fn decode_failed(&mut self) {
        // RED: not yet
    }

    /// The decoder could not be (re)configured with the last keyframe's
    /// parameter sets: forget them, so the next keyframe reconfigures.
    pub fn configure_failed(&mut self) {
        // RED: not yet
    }

    /// True until a keyframe is admitted, and again after any refusal or
    /// decode error.
    pub fn waiting_for_keyframe(&self) -> bool {
        self.waiting_for_keyframe
    }
}
