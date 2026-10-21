//! Media datagrams inside a session (protocol.md §6; phase4-criteria step 4).
//!
//! * **Host** ([`MediaOut`], one per session): a fresh random key per
//!   session, announced over the Noise channel, and the **next** key
//!   announced at the same time, so a rotation never waits for an
//!   announcement to arrive. A key is replaced after [`KEY_LIFETIME_MS`] or
//!   after [`MAX_PACKETS_PER_KEY`] packets, whichever comes first.
//! * **Viewer** ([`MediaIn`]): installs announced keys (ids strictly
//!   increasing), opens datagrams, keeps an old key for [`KEY_GRACE_MS`]
//!   after the first packet under a newer key opened (late, reordered
//!   packets), and reassembles video frames. Every datagram that is not
//!   used is counted in [`MediaStats`], never silently lost.
//!
//! Only datagrams that opened under an announced key reach the
//! reassembler, and only reassembled frames leave this module (INV2).

use rand_core::{CryptoRng, RngCore};
use remora_crypto::media::{
    MAX_LIVE_KEYS, MAX_PACKETS_PER_KEY, MediaDrop, MediaError, MediaReceiver, MediaSender,
    SealedDatagram,
};
use remora_crypto::secret::MediaKey;
use remora_proto::datagram::{DatagramHeader, DatagramKind};
use remora_proto::messages::MediaKeyAnnounce;
use remora_proto::video::{Reassembler, ReassemblyEvent, VideoFrame};

use crate::Millis;
use crate::fail::Violation;

/// A media key is replaced after this long (protocol.md §6: 1 hour).
pub const KEY_LIFETIME_MS: u64 = 3_600_000;
/// How long a replaced key still opens packets, counted from the first
/// packet that opened under a newer key (protocol.md §6).
pub const KEY_GRACE_MS: u64 = 2_000;
/// Keyframe requests are answered at most this often (phase4-criteria
/// M7): a viewer asks only once per interval, and the host forces at most
/// one keyframe per interval for all viewers together, so a hostile viewer
/// cannot turn the stream into keyframes only.
pub const KEYFRAME_REQUEST_INTERVAL_MS: u64 = 500;
/// The one video stream of Phase 4 (`stream_id`, `layer_id` 0).
pub const VIDEO_STREAM: u16 = 0;

/// The host's media keys for one session.
pub(crate) struct MediaOut {
    sender: MediaSender,
    next: (u16, MediaKey),
    /// When the current key sent its first packet.
    since: Option<Millis>,
    /// Announcements not yet sent (taken by the session).
    unannounced: Vec<MediaKeyAnnounce>,
}

fn announcement(key_id: u16, key: &MediaKey) -> MediaKeyAnnounce {
    MediaKeyAnnounce {
        key_id: u32::from(key_id),
        key: key.expose_for_announce().to_vec(),
    }
}

impl MediaOut {
    /// Keys 0 (current) and 1 (next), both to be announced.
    pub(crate) fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let current = MediaKey::generate(rng);
        let next = MediaKey::generate(rng);
        let unannounced = vec![announcement(0, &current), announcement(1, &next)];
        Self {
            sender: MediaSender::new(0, current),
            next: (1, next),
            since: None,
            unannounced,
        }
    }

    /// Announcements to send now, in order.
    pub(crate) fn take_announcements(&mut self) -> Vec<MediaKeyAnnounce> {
        std::mem::take(&mut self.unannounced)
    }

    /// Seals one datagram, first switching to the next key if the current
    /// one has sent `rotate_after` packets or is [`KEY_LIFETIME_MS`] old.
    pub(crate) fn seal<R: RngCore + CryptoRng>(
        &mut self,
        header: DatagramHeader,
        body: &[u8],
        rotate_after: u64,
        now: Millis,
        rng: &mut R,
    ) -> Result<SealedDatagram, MediaError> {
        let since = *self.since.get_or_insert(now);
        let rotate_after = rotate_after.clamp(1, MAX_PACKETS_PER_KEY);
        if self.sender.packets_sent() >= rotate_after
            || now.0.saturating_sub(since.0) >= KEY_LIFETIME_MS
        {
            self.rotate(now, rng)?;
        }
        self.sender.seal(header, body)
    }

    /// Starts using the announced next key and announces a new next one.
    fn rotate<R: RngCore + CryptoRng>(
        &mut self,
        now: Millis,
        rng: &mut R,
    ) -> Result<(), MediaError> {
        // 65 535 rotations: an hour each would take 7 years.
        let new_id = self.next.0.checked_add(1).ok_or(MediaError::KeyExhausted)?;
        let new_key = MediaKey::generate(rng);
        self.unannounced.push(announcement(new_id, &new_key));
        let (id, key) = std::mem::replace(&mut self.next, (new_id, new_key));
        self.sender = MediaSender::new(id, key);
        self.since = Some(now);
        Ok(())
    }
}

/// What happened to the media datagrams a viewer received.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MediaStats {
    /// Opened (authentic, fresh).
    pub opened: u64,
    /// Arrived before the session was `Active` (dropped unread).
    pub before_active: u64,
    /// Clear header invalid (too short, too long, bad kind/flags/reserved).
    pub bad_header: u64,
    /// No live key with this `key_id` (never announced, or retired).
    pub unknown_key: u64,
    /// Counter already seen (replay).
    pub replayed: u64,
    /// Counter older than the replay window.
    pub too_old: u64,
    /// Tag did not verify (tampered or forged).
    pub auth_failed: u64,
    /// Opened, but not video on stream 0 (FEC repair, pointer motion,
    /// another stream: none is used in Phase 4).
    pub ignored: u64,
    /// Opened video fragments the reassembler refused as malformed.
    pub bad_fragments: u64,
    /// Fragments of frames already delivered or given up.
    pub late_fragments: u64,
    /// Frames delivered.
    pub frames: u64,
    /// Frames given up (incomplete when a newer one completed, limits).
    pub frames_dropped: u64,
}

impl MediaStats {
    /// Datagrams dropped before reaching the reassembler.
    pub fn dropped(&self) -> u64 {
        self.before_active
            + self.bad_header
            + self.unknown_key
            + self.replayed
            + self.too_old
            + self.auth_failed
    }

    fn count(&mut self, drop: MediaDrop) {
        let n = match drop {
            MediaDrop::Header(_) => &mut self.bad_header,
            MediaDrop::UnknownKey => &mut self.unknown_key,
            MediaDrop::Replay => &mut self.replayed,
            MediaDrop::TooOld => &mut self.too_old,
            MediaDrop::Auth => &mut self.auth_failed,
        };
        *n += 1;
    }
}

/// The viewer's media keys, reassembler and counters.
#[derive(Debug, Default)]
pub(crate) struct MediaIn {
    rx: MediaReceiver,
    /// Installed key ids and, once superseded, when they are forgotten.
    live: Vec<(u16, Option<Millis>)>,
    last_announced: Option<u16>,
    newest_used: Option<u16>,
    reassembler: Reassembler,
    pub(crate) stats: MediaStats,
}

impl MediaIn {
    /// Installs an announced key. Ids must strictly increase: a repeated or
    /// older id is a protocol violation (it would reuse a nonce space).
    pub(crate) fn announce(&mut self, k: &MediaKeyAnnounce) -> Result<(), Violation> {
        let id = u16::try_from(k.key_id).map_err(|_| Violation::MediaKey("key id out of range"))?;
        if self.last_announced.is_some_and(|last| id <= last) {
            return Err(Violation::MediaKey("key id not increasing"));
        }
        let bytes: [u8; 32] = k
            .key
            .as_slice()
            .try_into()
            .map_err(|_| Violation::MediaKey("key length"))?;
        if self.live.len() >= MAX_LIVE_KEYS {
            // Make room by forgetting the oldest superseded key early; a
            // host rotating faster than the grace period only loses its
            // own late packets.
            let oldest = self
                .live
                .iter()
                .filter(|(_, retire)| retire.is_some())
                .map(|&(id, _)| id)
                .min()
                .ok_or(Violation::MediaKey("too many live keys"))?;
            self.forget(oldest);
        }
        self.rx
            .add_key(id, MediaKey::from_bytes(bytes))
            .map_err(|_| Violation::MediaKey("key rejected"))?;
        self.live.push((id, None));
        self.last_announced = Some(id);
        Ok(())
    }

    /// Opens one datagram; returns the frames it completed.
    pub(crate) fn datagram(&mut self, datagram: &[u8], now: Millis) -> Vec<VideoFrame> {
        let mut frames = Vec::new();
        let (header, body) = match self.rx.open(datagram) {
            Ok(x) => x,
            Err(drop) => {
                self.stats.count(drop);
                return frames;
            }
        };
        self.stats.opened += 1;
        if self.newest_used.is_none_or(|n| header.key_id > n) {
            self.newest_used = Some(header.key_id);
            let retire_at = now.plus(KEY_GRACE_MS);
            for (id, retire) in &mut self.live {
                if *id < header.key_id && retire.is_none() {
                    *retire = Some(retire_at);
                }
            }
        }
        if header.kind != DatagramKind::VideoFragment
            || header.stream_id != VIDEO_STREAM
            || header.layer_id != 0
        {
            self.stats.ignored += 1;
            return frames;
        }
        for event in self.reassembler.push(header.flags, &body) {
            match event {
                ReassemblyEvent::Frame(f) => {
                    self.stats.frames += 1;
                    frames.push(f);
                }
                ReassemblyEvent::Dropped { .. } => self.stats.frames_dropped += 1,
                ReassemblyEvent::Rejected(_) => self.stats.bad_fragments += 1,
                ReassemblyEvent::Late { .. } => self.stats.late_fragments += 1,
            }
        }
        frames
    }

    /// Forgets superseded keys whose grace period is over.
    pub(crate) fn tick(&mut self, now: Millis) {
        let expired: Vec<u16> = self
            .live
            .iter()
            .filter(|(_, retire)| retire.is_some_and(|at| now >= at))
            .map(|&(id, _)| id)
            .collect();
        for id in expired {
            self.forget(id);
        }
    }

    fn forget(&mut self, id: u16) {
        self.rx.remove_key(id);
        self.live.retain(|&(k, _)| k != id);
    }
}

/// The clear header of a video fragment on stream 0 (`key_id` and
/// `counter` are filled in by the sender).
pub(crate) fn video_header(flags: u8) -> DatagramHeader {
    DatagramHeader {
        kind: DatagramKind::VideoFragment,
        flags,
        key_id: 0,
        counter: 0,
        stream_id: VIDEO_STREAM,
        layer_id: 0,
    }
}
