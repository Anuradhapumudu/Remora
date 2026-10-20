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

use std::collections::{BTreeMap, VecDeque};

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
        let mut b = Vec::with_capacity(FRAGMENT_HEADER_LEN + data.len());
        b.extend_from_slice(&self.frame_id.to_be_bytes());
        b.extend_from_slice(&self.frag_index.to_be_bytes());
        b.extend_from_slice(&self.frag_count.to_be_bytes());
        b.extend_from_slice(&self.fec_group.to_be_bytes());
        b.extend_from_slice(&self.capture_ts_us.to_be_bytes());
        b.extend_from_slice(data);
        b
    }

    /// Parses a plaintext body (after the AEAD opened it).
    pub fn parse(body: &[u8]) -> Result<(Self, &[u8]), FragmentError> {
        // At least one data byte: an empty fragment carries nothing and
        // would only cost bookkeeping.
        if body.len() <= FRAGMENT_HEADER_LEN {
            return Err(FragmentError::TooShort);
        }
        let (head, data) = body.split_at(FRAGMENT_HEADER_LEN);
        let be16 = |i: usize| u16::from_be_bytes([head[i], head[i + 1]]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&head[10..18]);
        let h = Self {
            frame_id: u32::from_be_bytes([head[0], head[1], head[2], head[3]]),
            frag_index: be16(4),
            frag_count: be16(6),
            fec_group: be16(8),
            capture_ts_us: u64::from_be_bytes(ts),
        };
        if h.frag_count == 0 || usize::from(h.frag_count) > MAX_FRAGMENTS {
            return Err(FragmentError::BadCount(h.frag_count));
        }
        if h.frag_index >= h.frag_count {
            return Err(FragmentError::BadIndex {
                index: h.frag_index,
                count: h.frag_count,
            });
        }
        if h.fec_group != 0 {
            return Err(FragmentError::UnsupportedFec);
        }
        Ok((h, data))
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
    if data.is_empty() {
        return Err(PacketizeError::Empty);
    }
    if max_data == 0 {
        return Err(PacketizeError::NoRoom);
    }
    let count = data.len().div_ceil(max_data);
    if data.len() > FRAME_MAX || count > MAX_FRAGMENTS {
        return Err(PacketizeError::TooLarge(data.len()));
    }
    let frag_count = u16::try_from(count).map_err(|_| PacketizeError::TooLarge(data.len()))?;
    let key = if keyframe { FLAG_KEYFRAME } else { 0 };
    Ok(data
        .chunks(max_data)
        .zip(0u16..)
        .map(|(chunk, frag_index)| Fragment {
            flags: key
                | if frag_index + 1 == frag_count {
                    FLAG_LAST
                } else {
                    0
                },
            body: FragmentHeader {
                frame_id,
                frag_index,
                frag_count,
                fec_group: 0,
                capture_ts_us,
            }
            .encode_with(chunk),
        })
        .collect())
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

/// A frame still missing fragments.
#[derive(Debug)]
struct Partial {
    frame_id: u32,
    frag_count: u16,
    keyframe: bool,
    capture_ts_us: u64,
    /// Fragments received, by index. One allocation per stored fragment,
    /// made only after every limit was checked.
    parts: BTreeMap<u16, Vec<u8>>,
    bytes: usize,
}

/// Frame IDs given up recently, remembered so that their stray fragments are
/// "late" instead of starting a new partial frame.
const REMEMBER_DROPPED: usize = 64;

/// Puts video frames back together, within the protocol's limits.
#[derive(Debug, Default)]
pub struct Reassembler {
    /// Incomplete frames, oldest (first fragment seen) first.
    open: VecDeque<Partial>,
    bytes_in_flight: usize,
    /// Highest frame delivered: anything at or below it is late.
    floor: Option<u32>,
    /// Frames given up above the floor.
    dropped: VecDeque<u32>,
}

impl Reassembler {
    /// An empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes one opened video-fragment datagram: its clear-header `flags`
    /// and plaintext `body`.
    pub fn push(&mut self, flags: u8, body: &[u8]) -> Vec<ReassemblyEvent> {
        let mut out = Vec::new();
        let (h, data) = match FragmentHeader::parse(body) {
            Ok(x) => x,
            Err(e) => {
                out.push(ReassemblyEvent::Rejected(e));
                return out;
            }
        };
        if (flags & FLAG_LAST != 0) != (h.frag_index + 1 == h.frag_count) {
            out.push(ReassemblyEvent::Rejected(FragmentError::BadLastFlag));
            return out;
        }
        if self.floor.is_some_and(|f| h.frame_id <= f) || self.dropped.contains(&h.frame_id) {
            out.push(ReassemblyEvent::Late {
                frame_id: h.frame_id,
            });
            return out;
        }
        let keyframe = flags & FLAG_KEYFRAME != 0;

        // Find or open this frame's partial; opening may evict the oldest.
        let pos = match self.open.iter().position(|p| p.frame_id == h.frame_id) {
            Some(pos) => pos,
            None => {
                if self.open.len() >= MAX_OPEN_FRAMES {
                    self.drop_at(0, DropReason::TooManyOpen, &mut out);
                }
                self.open.push_back(Partial {
                    frame_id: h.frame_id,
                    frag_count: h.frag_count,
                    keyframe,
                    capture_ts_us: h.capture_ts_us,
                    parts: BTreeMap::new(),
                    bytes: 0,
                });
                self.open.len() - 1
            }
        };

        let p = &self.open[pos];
        if p.frag_count != h.frag_count
            || p.keyframe != keyframe
            || p.capture_ts_us != h.capture_ts_us
        {
            self.drop_at(pos, DropReason::Inconsistent, &mut out);
            return out;
        }
        if p.parts.contains_key(&h.frag_index) {
            return out; // duplicate: keep the first copy
        }
        if p.bytes + data.len() > FRAME_MAX {
            self.drop_at(pos, DropReason::TooLarge, &mut out);
            return out;
        }
        // The total budget: evict the oldest OTHER frames until this fits
        // (this frame alone is at most FRAME_MAX, well under the budget).
        let id = h.frame_id;
        while self.bytes_in_flight + data.len() > REASSEMBLY_BYTES_MAX {
            let Some(victim) = self.open.iter().position(|p| p.frame_id != id) else {
                break;
            };
            self.drop_at(victim, DropReason::OverBudget, &mut out);
        }
        let Some(pos) = self.open.iter().position(|p| p.frame_id == id) else {
            return out;
        };

        let p = &mut self.open[pos];
        p.parts.insert(h.frag_index, data.to_vec());
        p.bytes += data.len();
        self.bytes_in_flight += data.len();
        if p.parts.len() < usize::from(p.frag_count) {
            return out;
        }

        // Complete: deliver, and abandon every older incomplete frame.
        let Some(p) = self.open.remove(pos) else {
            return out;
        };
        self.bytes_in_flight -= p.bytes;
        self.abandon_older(p.frame_id, &mut out);
        let follows_previous = self
            .floor
            .is_some_and(|f| p.frame_id.checked_sub(1) == Some(f));
        // `dropped` is not pruned here: IDs at or below the floor are late
        // anyway, and the list is bounded (REMEMBER_DROPPED).
        self.floor = Some(p.frame_id);
        let mut data = Vec::with_capacity(p.bytes);
        for part in p.parts.values() {
            data.extend_from_slice(part);
        }
        out.push(ReassemblyEvent::Frame(VideoFrame {
            frame_id: p.frame_id,
            keyframe: p.keyframe,
            capture_ts_us: p.capture_ts_us,
            follows_previous,
            data,
        }));
        out
    }

    /// "Never wait": abandons every open frame older than `completed`.
    /// (Its own function with a single comparison, so mutation testing can
    /// name it exactly: open frame IDs are unique and `completed` already
    /// left `open`, so `<` and `<=` are equivalent here.)
    fn abandon_older(&mut self, completed: u32, out: &mut Vec<ReassemblyEvent>) {
        let (older, newer): (VecDeque<Partial>, VecDeque<Partial>) = std::mem::take(&mut self.open)
            .into_iter()
            .partition(|p| p.frame_id < completed);
        self.open = newer;
        for p in older {
            self.release(p, DropReason::Superseded, out);
        }
    }

    /// Gives up the partial at `pos`.
    fn drop_at(&mut self, pos: usize, reason: DropReason, out: &mut Vec<ReassemblyEvent>) {
        if let Some(p) = self.open.remove(pos) {
            self.release(p, reason, out);
        }
    }

    /// Releases a given-up partial's bytes and remembers its ID.
    fn release(&mut self, p: Partial, reason: DropReason, out: &mut Vec<ReassemblyEvent>) {
        self.bytes_in_flight -= p.bytes;
        if self.dropped.len() >= REMEMBER_DROPPED {
            self.dropped.pop_front();
        }
        self.dropped.push_back(p.frame_id);
        out.push(ReassemblyEvent::Dropped {
            frame_id: p.frame_id,
            reason,
        });
    }

    /// Bytes currently held for incomplete frames.
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    /// Frames currently incomplete.
    pub fn open_frames(&self) -> usize {
        self.open.len()
    }
}
