//! Media datagram encryption (protocol.md §6; phase3-criteria A11–A13).
//!
//! * ChaCha20-Poly1305, one key per sender, announced over the Noise channel.
//! * Nonce = 4 zero bytes ‖ `counter` (u64 big-endian). The counter is in the
//!   clear header and the whole 16-byte header is the AEAD's associated data,
//!   so it cannot be changed without failing the tag.
//! * **Nonce reuse is impossible by construction (A13):** a [`MediaSender`]
//!   owns its counter, only ever increments it, and refuses to send once
//!   [`MAX_PACKETS_PER_KEY`] packets used the key — the caller must rotate to
//!   a new key with a new `key_id`. A receiver refuses a second key under a
//!   `key_id` it has seen before.
//! * **Replay window:** [`REPLAY_WINDOW`] counters per key, WireGuard-style
//!   sliding bitmap. A counter is marked as seen only **after** its tag
//!   verified, so forged packets cannot burn real counters.
//!
//! Time-based rotation (1 hour) is the session's job.

use std::collections::{HashMap, HashSet};

use remora_proto::datagram::{DatagramError, DatagramHeader};

use crate::secret::MediaKey;

/// Packets per key before the sender refuses (2³²); rotation is forced.
pub const MAX_PACKETS_PER_KEY: u64 = 1 << 32;
/// Replay-window width in packets.
pub const REPLAY_WINDOW: u64 = 4096;
/// Keys a receiver holds at once (current + one being rotated in, with room).
pub const MAX_LIVE_KEYS: usize = 4;

/// Sender-side errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MediaError {
    /// This key has sent [`MAX_PACKETS_PER_KEY`] packets; rotate.
    #[error("media key exhausted; rotate")]
    KeyExhausted,
    /// Body too large for one datagram.
    #[error("media body too large")]
    BodyTooLarge,
    /// Receiver: this `key_id` was used before.
    #[error("media key id {0} already used")]
    KeyIdReused(u16),
    /// Receiver: already holding [`MAX_LIVE_KEYS`] keys.
    #[error("too many live media keys")]
    TooManyKeys,
}

/// Why a received datagram was dropped (the session continues).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MediaDrop {
    /// Clear header invalid.
    #[error("bad header: {0}")]
    Header(DatagramError),
    /// No live key with this `key_id`.
    #[error("unknown key id")]
    UnknownKey,
    /// Counter already accepted.
    #[error("replayed counter")]
    Replay,
    /// Counter older than the window.
    #[error("counter too old")]
    TooOld,
    /// Tag did not verify (header, ciphertext or tag modified, or wrong key).
    #[error("authentication failed")]
    Auth,
}

/// Encrypts datagrams under one key.
pub struct MediaSender {
    pub(crate) key_id: u16,
    pub(crate) key: MediaKey,
    pub(crate) next_counter: u64,
}

impl std::fmt::Debug for MediaSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaSender")
            .field("key_id", &self.key_id)
            .field("next_counter", &self.next_counter)
            .finish_non_exhaustive()
    }
}

impl MediaSender {
    /// A sender for a freshly generated, freshly announced key.
    pub fn new(key_id: u16, key: MediaKey) -> Self {
        Self {
            key_id,
            key,
            next_counter: 0,
        }
    }

    /// Packets sent so far with this key.
    pub fn packets_sent(&self) -> u64 {
        self.next_counter
    }

    /// Encrypts one datagram. `header.key_id` and `header.counter` are
    /// **overwritten** with this sender's values; the caller cannot choose
    /// the counter.
    pub fn seal(&mut self, header: DatagramHeader, body: &[u8]) -> Result<Vec<u8>, MediaError> {
        let _ = (header, body);
        todo!()
    }
}

/// Sliding replay window for one key.
#[derive(Debug, Clone)]
pub(crate) struct ReplayWindow {
    pub(crate) highest: Option<u64>,
    pub(crate) bitmap: [u64; (REPLAY_WINDOW / 64) as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            bitmap: [0; (REPLAY_WINDOW / 64) as usize],
        }
    }
}

/// Decrypts datagrams from one peer.
#[derive(Default)]
pub struct MediaReceiver {
    pub(crate) keys: HashMap<u16, (MediaKey, ReplayWindow)>,
    pub(crate) used_ids: HashSet<u16>,
    pub(crate) dropped: u64,
}

impl std::fmt::Debug for MediaReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaReceiver")
            .field("live_keys", &self.keys.len())
            .field("dropped", &self.dropped)
            .finish_non_exhaustive()
    }
}

impl MediaReceiver {
    /// No keys yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs an announced key. A `key_id` can be installed only once per
    /// session (A13).
    pub fn add_key(&mut self, key_id: u16, key: MediaKey) -> Result<(), MediaError> {
        let _ = (key_id, key);
        todo!()
    }

    /// Forgets a rotated-out key (its `key_id` stays used).
    pub fn remove_key(&mut self, key_id: u16) {
        let _ = key_id;
        todo!()
    }

    /// Parses, authenticates and replay-checks one datagram.
    pub fn open(&mut self, datagram: &[u8]) -> Result<(DatagramHeader, Vec<u8>), MediaDrop> {
        let _ = datagram;
        todo!()
    }

    /// Datagrams dropped so far (any [`MediaDrop`]).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    //! A13 at the counter limit: needs a sender part-way through its key's
    //! life, which only crate code can construct (no public setter exists —
    //! that is the point).
    use super::*;
    use remora_proto::datagram::DatagramKind;

    fn header() -> DatagramHeader {
        DatagramHeader {
            kind: DatagramKind::VideoFragment,
            flags: 0,
            key_id: 0,
            counter: 0,
            stream_id: 0,
            layer_id: 0,
        }
    }

    #[test]
    fn a13_sender_refuses_after_2_pow_32_packets() {
        let mut s = MediaSender {
            key_id: 1,
            key: MediaKey([3; 32]),
            next_counter: MAX_PACKETS_PER_KEY - 2,
        };
        assert!(s.seal(header(), b"a").is_ok());
        assert!(
            s.seal(header(), b"b").is_ok(),
            "counter 2^32 - 1 is the last"
        );
        assert_eq!(s.packets_sent(), MAX_PACKETS_PER_KEY);
        assert_eq!(s.seal(header(), b"c"), Err(MediaError::KeyExhausted));
        assert_eq!(
            s.seal(header(), b"d"),
            Err(MediaError::KeyExhausted),
            "stays refused"
        );
        assert_eq!(
            s.packets_sent(),
            MAX_PACKETS_PER_KEY,
            "a refusal does not advance the counter"
        );
    }

    #[test]
    fn a13_the_last_counter_decrypts() {
        let mut s = MediaSender {
            key_id: 1,
            key: MediaKey([3; 32]),
            next_counter: MAX_PACKETS_PER_KEY - 1,
        };
        let d = s.seal(header(), b"last").unwrap();
        let mut r = MediaReceiver::new();
        r.add_key(1, MediaKey([3; 32])).unwrap();
        let (h, body) = r.open(&d).unwrap();
        assert_eq!(h.counter, MAX_PACKETS_PER_KEY - 1);
        assert_eq!(body, b"last");
    }
}
