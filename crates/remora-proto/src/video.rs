//! Video frames as media datagrams (protocol.md §6, §7; phase4-criteria
//! step 3).
//!
//! The host cuts each encoded frame into fragments that fit one datagram
//! ([`packetize`]); the viewer puts them back together ([`Reassembler`]).
//!
//! The reassembler receives bytes from an *authenticated* host (only
//! datagrams that opened under the media key get here), which can still be
//! malicious: every limit is checked **before** storing or allocating
//! (M6). The latency policy is "never wait": when a newer frame completes,
//! older incomplete ones are abandoned, and each delivered frame says
//! whether it directly follows the previous one, so the viewer knows when
//! it must ask for a keyframe.
//!
//! Plaintext fragment body (inside the AEAD):
//!
//! ```text
//! 0..4    u32 frame_id       strictly increasing per stream
//! 4..6    u16 frag_index     < frag_count
//! 6..8    u16 frag_count     1..=8192
//! 8..10   u16 fec_group      0 = no FEC (Phase 4 sends no FEC; roadmap D-27)
//! 10..18  u64 capture_ts_us  host clock, the frame's display time
//! 18..    data               ≥ 1 byte
//! ```

use std::collections::VecDeque;

use crate::datagram::{FLAG_KEYFRAME, FLAG_LAST};
use crate::limits::{
    FRAGMENT_HEADER_LEN, FRAME_MAX, MAX_FRAGMENTS, MAX_OPEN_FRAMES, REASSEMBLY_BYTES_MAX,
};

/// The plaintext header of one fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    /// Which frame.
    pub frame_id: u32,
    /// Position within the frame.
    pub frag_index: u16,
    /// Fragments in the frame.
    pub frag_count: u16,
    /// FEC group (0 = none).
    pub fec_group: u16,
    /// Capture time on the host clock, microseconds.
    pub capture_ts_us: u64,
}

/// Why a fragment body is malformed (the datagram is dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FragmentError {
    /// Shorter than the header plus one data byte.
    #[error("fragment too short")]
    TooShort,
    /// `frag_count` is 0 or above [`MAX_FRAGMENTS`].
    #[error("fragment count {0} out of range")]
    BadCount(u16),
    /// `frag_index >= frag_count`.
    #[error("fragment index {index} not below count {count}")]
    BadIndex {
        /// Index given.
        index: u16,
        /// Count given.
        count: u16,
    },
    /// `fec_group` set although no FEC is in use (Phase 4).
    #[error("FEC group set but FEC is not supported yet")]
    UnsupportedFec,
    /// The last-fragment flag disagrees with the index.
    #[error("last-fragment flag does not match the index")]
    BadLastFlag,
}

impl FragmentHeader {
    /// The plaintext body: header then `data`.
    pub fn encode_with(&self, data: &[u8]) -> Vec<u8> {
        let _ = data;
        todo!("phase 4 step 3: written test-first")
    }

    /// Parses a plaintext body (after the AEAD opened it).
    pub fn parse(body: &[u8]) -> Result<(Self, &[u8]), FragmentError> {
        let _ = body;
        todo!("phase 4 step 3: written test-first")
    }
}

/// One fragment ready to seal: the clear-header flags and the plaintext body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// [`FLAG_KEYFRAME`] / [`FLAG_LAST`] for the clear header.
    pub flags: u8,
    /// Plaintext body ([`FragmentHeader`] + data).
    pub body: Vec<u8>,
}

/// Why a frame cannot be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketizeError {
    /// Empty frame.
    #[error("empty frame")]
    Empty,
    /// Larger than [`FRAME_MAX`] or than [`MAX_FRAGMENTS`] fragments.
    #[error("frame of {0} bytes is too large to send")]
    TooLarge(usize),
    /// `max_data` is 0.
    #[error("no room for data in a datagram")]
    NoRoom,
}

/// Cuts `data` (one encoded frame) into fragments of at most `max_data`
/// data bytes each.
pub fn packetize(
    frame_id: u32,
    capture_ts_us: u64,
    keyframe: bool,
    data: &[u8],
    max_data: usize,
) -> Result<Vec<Fragment>, PacketizeError> {
    let _ = (frame_id, capture_ts_us, keyframe, data, max_data);
    todo!("phase 4 step 3: written test-first")
}

/// A reassembled frame.
#[derive(Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// Frame identifier.
    pub frame_id: u32,
    /// A keyframe (decodable on its own).
    pub keyframe: bool,
    /// Host capture time, microseconds.
    pub capture_ts_us: u64,
    /// `true` if this is the frame right after the previously delivered one;
    /// `false` after a gap (a P-frame after a gap needs a keyframe first).
    pub follows_previous: bool,
    /// The encoded frame.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for VideoFrame {
    // Never prints the payload: it is (compressed) screen content (INV9).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VideoFrame")
            .field("frame_id", &self.frame_id)
            .field("keyframe", &self.keyframe)
            .field("capture_ts_us", &self.capture_ts_us)
            .field("follows_previous", &self.follows_previous)
            .field("bytes", &self.data.len())
            .finish()
    }
}

/// Why a frame was given up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// A newer frame completed first ("never wait").
    Superseded,
    /// More than [`MAX_OPEN_FRAMES`] frames open; this was the oldest.
    TooManyOpen,
    /// The reassembly byte budget was exceeded; this was the oldest.
    OverBudget,
    /// Larger than [`FRAME_MAX`].
    TooLarge,
    /// Fragments of one frame disagreed (count, keyframe flag or time).
    Inconsistent,
}

/// What the reassembler reports for one pushed fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyEvent {
    /// A complete frame.
    Frame(VideoFrame),
    /// Frame `frame_id` was given up.
    Dropped {
        /// Which frame.
        frame_id: u32,
        /// Why.
        reason: DropReason,
    },
    /// The fragment itself was malformed and ignored.
    Rejected(FragmentError),
    /// A fragment of a frame that was already delivered or given up.
    Late {
        /// Which frame.
        frame_id: u32,
    },
}

/// Puts video frames back together, within the protocol's limits.
#[derive(Debug, Default)]
pub struct Reassembler {
    _private: (),
}

impl Reassembler {
    /// An empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes one opened video-fragment datagram: its clear-header `flags`
    /// and plaintext `body`.
    pub fn push(&mut self, flags: u8, body: &[u8]) -> Vec<ReassemblyEvent> {
        let _ = (flags, body);
        todo!("phase 4 step 3: written test-first")
    }

    /// Bytes currently held for incomplete frames.
    pub fn bytes_in_flight(&self) -> usize {
        todo!("phase 4 step 3: written test-first")
    }

    /// Frames currently incomplete.
    pub fn open_frames(&self) -> usize {
        todo!("phase 4 step 3: written test-first")
    }
}

#[allow(dead_code)]
const _USES: (
    usize,
    usize,
    usize,
    usize,
    usize,
    u8,
    u8,
    Option<VecDeque<u8>>,
) = (
    FRAGMENT_HEADER_LEN,
    FRAME_MAX,
    MAX_FRAGMENTS,
    MAX_OPEN_FRAMES,
    REASSEMBLY_BYTES_MAX,
    FLAG_KEYFRAME,
    FLAG_LAST,
    None,
);
