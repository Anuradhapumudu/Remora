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
        Self {
            max_width: max_width.min(MAX_WIDTH),
            max_height: max_height.min(MAX_HEIGHT),
        }
    }

    /// Refuses a picture whose displayed or coded size is over the limit.
    /// The coded size may exceed the displayed one by the macroblock
    /// padding only (to a multiple of 16 wide, 32 tall: field coding).
    fn check(
        &self,
        width: u64,
        height: u64,
        coded_width: u64,
        coded_height: u64,
    ) -> Result<(), StreamError> {
        let (w, h) = (u64::from(self.max_width), u64::from(self.max_height));
        if width > w
            || height > h
            || coded_width > w.next_multiple_of(16)
            || coded_height > h.next_multiple_of(32)
        {
            return Err(StreamError::TooLarge {
                width: coded_width.max(width),
                height: coded_height.max(height),
            });
        }
        Ok(())
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
        let mut out = Vec::with_capacity(self.nals.iter().map(|n| 4 + n.len()).sum());
        for nal in &self.nals {
            // A NAL unit is part of one reassembled frame (≤ 8 MiB), so its
            // length always fits.
            let len = u32::try_from(nal.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(nal);
        }
        out
    }
}

/// Splits an Annex B frame into NAL units and checks it against the rules
/// in the module documentation and `limit`.
pub fn parse_frame(annexb: &[u8], limit: SizeLimit) -> Result<H264Frame<'_>, StreamError> {
    let mut sps = None;
    let mut pps = None;
    let mut nals = Vec::new();
    let (mut idr, mut non_idr) = (false, false);
    for nal in split_annexb(annexb)? {
        let header = nal[0];
        if header & 0x80 != 0 {
            return Err(StreamError::ForbiddenBit);
        }
        match header & 0x1f {
            t @ (7 | 8) => {
                if nal.len() > MAX_PARAMETER_SET {
                    return Err(StreamError::ParameterSetTooLarge);
                }
                let slot = if t == 7 { &mut sps } else { &mut pps };
                if slot.replace(nal).is_some() {
                    return Err(StreamError::RepeatedParameterSet);
                }
            }
            1 => {
                non_idr = true;
                nals.push(nal);
            }
            5 => {
                idr = true;
                nals.push(nal);
            }
            6 | 9 => nals.push(nal),
            t => return Err(StreamError::NalType(t)),
        }
    }
    // Exactly one kind of slice: an IDR frame or a predicted one.
    if idr == non_idr {
        return Err(StreamError::Slices);
    }
    if !idr {
        if sps.is_some() || pps.is_some() {
            return Err(StreamError::ParameterSetsOutsideKeyframe);
        }
        return Ok(H264Frame {
            keyframe: false,
            sps: None,
            pps: None,
            nals,
        });
    }
    let (Some(sps), Some(pps)) = (sps, pps) else {
        return Err(StreamError::KeyframeWithoutParameterSets);
    };
    let info = parse_sps(sps)?;
    if parse_pps(pps)? != info.sps_id {
        return Err(StreamError::Pps("names another SPS"));
    }
    limit.check(
        u64::from(info.width),
        u64::from(info.height),
        u64::from(info.coded_width),
        u64::from(info.coded_height),
    )?;
    Ok(H264Frame {
        keyframe: true,
        sps: Some((sps, info)),
        pps: Some(pps),
        nals,
    })
}

/// The NAL units of an Annex B frame: each follows a `00 00 01` start code
/// (with any number of leading zero bytes before the first, and trailing
/// zero bytes after each, both allowed by H.264 Annex B).
fn split_annexb(data: &[u8]) -> Result<Vec<&[u8]>, StreamError> {
    let starts: Vec<usize> = data
        .windows(3)
        .enumerate()
        .filter(|(_, w)| *w == [0, 0, 1])
        .map(|(i, _)| i)
        .take(MAX_NALS_PER_FRAME + 1)
        .collect();
    match starts.first() {
        Some(&first) if data[..first].iter().all(|&b| b == 0) => {}
        _ => return Err(StreamError::NoStartCode),
    }
    if starts.len() > MAX_NALS_PER_FRAME {
        return Err(StreamError::TooManyNals);
    }
    let mut nals = Vec::with_capacity(starts.len());
    for (i, &at) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(data.len());
        let nal = &data[at + 3..end];
        let trimmed = nal.len() - nal.iter().rev().take_while(|&&b| b == 0).count();
        if trimmed == 0 {
            return Err(StreamError::EmptyNal);
        }
        nals.push(&nal[..trimmed]);
    }
    Ok(nals)
}

/// `seq_parameter_set_id` named by a PPS NAL unit (its header is type 8).
fn parse_pps(nal: &[u8]) -> Result<u32, StreamError> {
    let rbsp = unescape_rbsp(nal.get(1..).unwrap_or_default());
    let mut r = Bits::new(&rbsp);
    let pps_id = r.ue().ok_or(StreamError::Pps("truncated"))?;
    let sps_id = r.ue().ok_or(StreamError::Pps("truncated"))?;
    if pps_id > 255 {
        return Err(StreamError::Pps("pps_id over 255"));
    }
    Ok(sps_id)
}

/// Reads an SPS NAL unit (starting at its header byte) far enough to know
/// the picture size; refuses what Remora's encoder never produces.
pub fn parse_sps(nal: &[u8]) -> Result<SpsInfo, StreamError> {
    if nal.len() > MAX_PARAMETER_SET {
        return Err(StreamError::ParameterSetTooLarge);
    }
    match nal.split_first() {
        Some((&header, body)) if header & 0x1f == 7 => {
            read_sps(&mut Bits::new(&unescape_rbsp(body))).ok_or(StreamError::Sps("truncated"))?
        }
        _ => Err(StreamError::Sps("not an SPS")),
    }
}

/// ITU-T H.264 §7.3.2.1.1, up to the VUI flag. The outer `None` means the
/// bits ran out (or an Exp-Golomb code was too long); the inner error is a
/// value Remora does not accept.
fn read_sps(r: &mut Bits<'_>) -> Option<Result<SpsInfo, StreamError>> {
    let refuse = |why| Some(Err(StreamError::Sps(why)));
    let profile_idc = r.bits(8)? as u8;
    r.skip(8)?; // constraint_set flags, reserved
    let level_idc = r.bits(8)? as u8;
    let sps_id = r.ue()?;
    if sps_id > 31 {
        return refuse("sps_id over 31");
    }
    match profile_idc {
        66 | 77 => {}
        100 => {
            if r.ue()? != 1 {
                return refuse("chroma format is not 4:2:0");
            }
            if r.ue()? != 0 || r.ue()? != 0 {
                return refuse("bit depth is not 8");
            }
            r.skip(1)?; // qpprime_y_zero_transform_bypass_flag
            if r.bit()? == 1 {
                for i in 0..8 {
                    if r.bit()? == 1 && !skip_scaling_list(r, if i < 6 { 16 } else { 64 })? {
                        return refuse("scaling list delta out of range");
                    }
                }
            }
        }
        _ => return refuse("profile is not Baseline, Main or High"),
    }
    if r.ue()? > 12 {
        return refuse("log2_max_frame_num over 16");
    }
    match r.ue()? {
        0 => {
            if r.ue()? > 12 {
                return refuse("log2_max_pic_order_cnt_lsb over 16");
            }
        }
        1 => {
            r.skip(1)?; // delta_pic_order_always_zero_flag
            r.se()?; // offset_for_non_ref_pic
            r.se()?; // offset_for_top_to_bottom_field
            let cycle = r.ue()?;
            if cycle > 255 {
                return refuse("pic order cycle over 255");
            }
            for _ in 0..cycle {
                r.se()?;
            }
        }
        2 => {}
        _ => return refuse("pic_order_cnt_type over 2"),
    }
    if r.ue()? > 16 {
        return refuse("max_num_ref_frames over 16");
    }
    r.skip(1)?; // gaps_in_frame_num_value_allowed_flag
    let width_mbs = u64::from(r.ue()?) + 1;
    let height_map_units = u64::from(r.ue()?) + 1;
    let frame_mbs_only = r.bit()? == 1;
    if !frame_mbs_only {
        r.skip(1)?; // mb_adaptive_frame_field_flag
    }
    r.skip(1)?; // direct_8x8_inference_flag
    let mut crop = [0u64; 4]; // left, right, top, bottom
    if r.bit()? == 1 {
        for c in &mut crop {
            *c = u64::from(r.ue()?);
        }
    }
    if r.bit()? == 0 {
        // No VUI: what follows must be exactly rbsp_trailing_bits (a 1,
        // then zeros), so a cut-short SPS is not read as complete.
        if r.bit()? != 1 {
            return refuse("trailing bits");
        }
        while let Some(b) = r.bit() {
            if b != 0 {
                return refuse("data after the trailing bits");
            }
        }
    }
    // 4:2:0: a crop unit is 2 columns, and 2 rows per frame row (4 when
    // field coded) (H.264 §7.4.2.1.1, CropUnitX/Y).
    let rows_per_unit = if frame_mbs_only { 1 } else { 2 };
    let coded_width = width_mbs * 16;
    let coded_height = height_map_units * 16 * rows_per_unit;
    let width = coded_width
        .checked_sub(2 * (crop[0] + crop[1]))
        .filter(|&w| w > 0);
    let height = coded_height
        .checked_sub(2 * rows_per_unit * (crop[2] + crop[3]))
        .filter(|&h| h > 0);
    let (Some(width), Some(height)) = (width, height) else {
        return refuse("cropped to nothing");
    };
    // Over 8K for every viewer; this also keeps every size within u32.
    if let Err(e) = SizeLimit::default().check(width, height, coded_width, coded_height) {
        return Some(Err(e));
    }
    let px = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
    Some(Ok(SpsInfo {
        profile_idc,
        level_idc,
        sps_id,
        width: px(width),
        height: px(height),
        coded_width: px(coded_width),
        coded_height: px(coded_height),
    }))
}

/// Skips one `scaling_list()` (H.264 §7.3.2.1.1.1). `Some(false)`: a delta
/// outside -128..=127.
fn skip_scaling_list(r: &mut Bits<'_>, size: usize) -> Option<bool> {
    let (mut last, mut next) = (8i64, 8i64);
    for _ in 0..size {
        if next != 0 {
            let delta = r.se()?;
            if !(-128..=127).contains(&delta) {
                return Some(false);
            }
            // (last + delta + 256) % 256 in the standard; rem_euclid is
            // never negative, so the + 256 is not needed.
            next = (last + delta).rem_euclid(256);
        }
        if next != 0 {
            last = next;
        }
    }
    Some(true)
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
        let frame = match parse_frame(annexb, self.limit) {
            Ok(f) => f,
            Err(e) => {
                self.waiting_for_keyframe = true;
                return Err(Refusal::Malformed(e));
            }
        };
        let (Some((sps, _)), Some(pps)) = (frame.sps, frame.pps) else {
            // Not a keyframe (parse_frame: a keyframe always has both).
            if self.waiting_for_keyframe {
                return Err(Refusal::WaitingForKeyframe);
            }
            return Ok(Admitted {
                frame,
                reconfigure: false,
            });
        };
        let same = self
            .current
            .as_ref()
            .is_some_and(|(s, p)| s.as_slice() == sps && p.as_slice() == pps);
        if !same {
            self.current = Some((sps.to_vec(), pps.to_vec()));
        }
        self.waiting_for_keyframe = false;
        Ok(Admitted {
            frame,
            reconfigure: !same,
        })
    }

    /// The decoder failed on an admitted frame: wait for a keyframe.
    pub fn decode_failed(&mut self) {
        self.waiting_for_keyframe = true;
    }

    /// The decoder could not be (re)configured with the last keyframe's
    /// parameter sets: forget them, so the next keyframe reconfigures.
    pub fn configure_failed(&mut self) {
        self.current = None;
        self.waiting_for_keyframe = true;
    }

    /// True until a keyframe is admitted, and again after any refusal or
    /// decode error.
    pub fn waiting_for_keyframe(&self) -> bool {
        self.waiting_for_keyframe
    }
}
