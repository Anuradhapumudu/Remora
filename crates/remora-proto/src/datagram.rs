//! Clear (authenticated, not encrypted) media-datagram header, protocol.md §6.
//!
//! ```text
//! 0      u8   kind        1 video fragment, 2 FEC repair, 3 pointer motion
//! 1      u8   flags       bit0 keyframe, bit1 last fragment, bit2 refinement; others 0
//! 2..4   u16  key_id
//! 4..12  u64  counter
//! 12..14 u16  stream_id
//! 14     u8   layer_id
//! 15     u8   reserved = 0
//! ```
//! Followed by the encrypted body including its 16-byte AEAD tag.

/// Datagram kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramKind {
    /// A fragment of an encoded video frame.
    VideoFragment,
    /// A forward-error-correction repair packet.
    FecRepair,
    /// Absolute pointer position (latest wins).
    PointerMotion,
}

/// Bits of `flags` that have a meaning; all others must be zero.
pub const KNOWN_FLAGS: u8 = 0b0000_0111;

/// The parsed clear header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramHeader {
    /// What the datagram carries.
    pub kind: DatagramKind,
    /// Flag bits (only [`KNOWN_FLAGS`] may be set).
    pub flags: u8,
    /// Which announced sender key encrypted it.
    pub key_id: u16,
    /// Per-key packet counter (AEAD nonce, replay window).
    pub counter: u64,
    /// Media stream (monitor / future simulcast stream).
    pub stream_id: u16,
    /// Simulcast layer.
    pub layer_id: u8,
}

/// Header errors (the datagram is dropped, not the session).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DatagramError {
    /// Shorter than header + AEAD tag.
    #[error("datagram too short")]
    TooShort,
    /// Longer than [`crate::limits::DATAGRAM_MAX`].
    #[error("datagram too long")]
    TooLong,
    /// Unknown kind byte.
    #[error("unknown datagram kind {0}")]
    UnknownKind(u8),
    /// Undefined flag bits set.
    #[error("undefined flag bits set")]
    UnknownFlags,
    /// Reserved byte not zero.
    #[error("reserved byte not zero")]
    Reserved,
}

impl DatagramHeader {
    /// Parses a datagram; returns the header and the encrypted body (incl. tag).
    pub fn parse(datagram: &[u8]) -> Result<(Self, &[u8]), DatagramError> {
        use crate::limits::{AEAD_TAG_LEN, DATAGRAM_HEADER_LEN, DATAGRAM_MAX};
        if datagram.len() > DATAGRAM_MAX {
            return Err(DatagramError::TooLong);
        }
        if datagram.len() < DATAGRAM_HEADER_LEN + AEAD_TAG_LEN {
            return Err(DatagramError::TooShort);
        }
        let (head, body) = datagram.split_at(DATAGRAM_HEADER_LEN);
        let [
            kind,
            flags,
            k0,
            k1,
            c0,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            c7,
            s0,
            s1,
            layer_id,
            reserved,
        ] = <[u8; DATAGRAM_HEADER_LEN]>::try_from(head).map_err(|_| DatagramError::TooShort)?;
        let kind = match kind {
            1 => DatagramKind::VideoFragment,
            2 => DatagramKind::FecRepair,
            3 => DatagramKind::PointerMotion,
            other => return Err(DatagramError::UnknownKind(other)),
        };
        if flags & !KNOWN_FLAGS != 0 {
            return Err(DatagramError::UnknownFlags);
        }
        if reserved != 0 {
            return Err(DatagramError::Reserved);
        }
        let header = Self {
            kind,
            flags,
            key_id: u16::from_be_bytes([k0, k1]),
            counter: u64::from_be_bytes([c0, c1, c2, c3, c4, c5, c6, c7]),
            stream_id: u16::from_be_bytes([s0, s1]),
            layer_id,
        };
        Ok((header, body))
    }

    /// The 16 header bytes (used as AEAD associated data).
    pub fn encode(&self) -> [u8; crate::limits::DATAGRAM_HEADER_LEN] {
        let kind = match self.kind {
            DatagramKind::VideoFragment => 1,
            DatagramKind::FecRepair => 2,
            DatagramKind::PointerMotion => 3,
        };
        let [k0, k1] = self.key_id.to_be_bytes();
        let [c0, c1, c2, c3, c4, c5, c6, c7] = self.counter.to_be_bytes();
        let [s0, s1] = self.stream_id.to_be_bytes();
        [
            kind,
            self.flags,
            k0,
            k1,
            c0,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            c7,
            s0,
            s1,
            self.layer_id,
            0,
        ]
    }
}
