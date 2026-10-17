//! In-process message links with a scriptable man-in-the-middle.
//!
//! A [`Link`] connects a viewer endpoint and a host endpoint. Every message
//! passes through a [`Tap`] that may deliver it unchanged, modify it, drop it,
//! duplicate it or inject extra messages — the attacker's position on the
//! network. Every original message is recorded in a [`Transcript`] so a test
//! can replay or mutate it later. Messages are opaque bytes: the link knows
//! nothing about the protocol, so it can't accidentally "help" it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

/// Direction of a message on the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dir {
    /// Viewer (initiator) → host (responder).
    ToHost,
    /// Host → viewer.
    ToViewer,
}

/// One message as originally sent, before the tap acted on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Which way it travelled.
    pub dir: Dir,
    /// Index among messages in the same direction (0-based).
    pub index: usize,
    /// The bytes as sent.
    pub bytes: Vec<u8>,
}

/// Everything sent on a link, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transcript {
    /// All records in send order.
    pub records: Vec<Record>,
}

impl Transcript {
    /// The messages sent in one direction, in order.
    pub fn messages(&self, dir: Dir) -> Vec<Vec<u8>> {
        self.records
            .iter()
            .filter(|r| r.dir == dir)
            .map(|r| r.bytes.clone())
            .collect()
    }

    /// Every (record position, bit) pair — for exhaustive single-bit-flip tests.
    pub fn bit_positions(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.records
            .iter()
            .enumerate()
            .flat_map(|(i, r)| (0..r.bytes.len() * 8).map(move |b| (i, b)))
    }
}

/// The attacker in the middle: decides what is delivered for each message.
pub trait Tap: Send {
    /// Called for every message. Return the messages to deliver to the other
    /// side, in order: `vec![msg]` = forward, `vec![]` = drop, two entries =
    /// duplicate or inject.
    fn on_message(&mut self, dir: Dir, index: usize, msg: Vec<u8>) -> Vec<Vec<u8>>;
}

impl<F> Tap for F
where
    F: FnMut(Dir, usize, Vec<u8>) -> Vec<Vec<u8>> + Send,
{
    fn on_message(&mut self, dir: Dir, index: usize, msg: Vec<u8>) -> Vec<Vec<u8>> {
        self(dir, index, msg)
    }
}

/// Ready-made taps.
pub mod taps {
    use super::Dir;

    /// Forwards everything unchanged (an honest network).
    pub fn pass() -> impl FnMut(Dir, usize, Vec<u8>) -> Vec<Vec<u8>> + Send {
        |_, _, m| vec![m]
    }

    /// Flips `bit` (0 = least significant bit of byte 0) of message `index` in `dir`.
    /// A bit beyond the message length leaves it unchanged (the test should not
    /// generate those; [`super::Transcript::bit_positions`] never does).
    pub fn flip_bit(
        dir: Dir,
        index: usize,
        bit: usize,
    ) -> impl FnMut(Dir, usize, Vec<u8>) -> Vec<Vec<u8>> + Send {
        move |d, i, mut m| {
            if d == dir
                && i == index
                && let Some(byte) = m.get_mut(bit / 8)
            {
                *byte ^= 1 << (bit % 8);
            }
            vec![m]
        }
    }

    /// Drops message `index` in `dir`.
    pub fn drop(dir: Dir, index: usize) -> impl FnMut(Dir, usize, Vec<u8>) -> Vec<Vec<u8>> + Send {
        move |d, i, m| {
            if d == dir && i == index {
                vec![]
            } else {
                vec![m]
            }
        }
    }

    /// Delivers message `index` in `dir` twice.
    pub fn duplicate(
        dir: Dir,
        index: usize,
    ) -> impl FnMut(Dir, usize, Vec<u8>) -> Vec<Vec<u8>> + Send {
        move |d, i, m| {
            if d == dir && i == index {
                vec![m.clone(), m]
            } else {
                vec![m]
            }
        }
    }

    /// Truncates message `index` in `dir` to `len` bytes.
    pub fn truncate(
        dir: Dir,
        index: usize,
        len: usize,
    ) -> impl FnMut(Dir, usize, Vec<u8>) -> Vec<Vec<u8>> + Send {
        move |d, i, mut m| {
            if d == dir && i == index {
                m.truncate(len);
            }
            vec![m]
        }
    }

    /// Replaces message `index` in `dir` with `bytes`.
    pub fn replace(
        dir: Dir,
        index: usize,
        bytes: Vec<u8>,
    ) -> impl FnMut(Dir, usize, Vec<u8>) -> Vec<Vec<u8>> + Send {
        move |d, i, m| {
            if d == dir && i == index {
                vec![bytes.clone()]
            } else {
                vec![m]
            }
        }
    }

    /// Holds message `index` in `dir` and delivers it after the next message in
    /// the same direction (swaps their order).
    pub fn swap_with_next(
        dir: Dir,
        index: usize,
    ) -> impl FnMut(Dir, usize, Vec<u8>) -> Vec<Vec<u8>> + Send {
        let mut held: Option<Vec<u8>> = None;
        move |d, i, m| {
            if d != dir {
                return vec![m];
            }
            if i == index {
                held = Some(m);
                vec![]
            } else if i == index + 1 {
                held.take()
                    .map_or_else(|| vec![m.clone()], |h| vec![m.clone(), h])
            } else {
                vec![m]
            }
        }
    }
}

struct Shared {
    tap: Box<dyn Tap>,
    transcript: Transcript,
    counts: [usize; 2],
    to_host: VecDeque<Vec<u8>>,
    to_viewer: VecDeque<Vec<u8>>,
}

/// One side of a [`Link`].
#[derive(Clone)]
pub struct Endpoint {
    side: Dir, // direction of messages this endpoint SENDS
    shared: Arc<Mutex<Shared>>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("sends", &self.side)
            .finish()
    }
}

impl Endpoint {
    fn lock(&self) -> std::sync::MutexGuard<'_, Shared> {
        // A panic in another test thread must not hide this test's result.
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends a message; the tap decides what the other side receives.
    pub fn send(&self, msg: Vec<u8>) {
        let mut s = self.lock();
        let slot = match self.side {
            Dir::ToHost => 0,
            Dir::ToViewer => 1,
        };
        let index = s.counts[slot];
        s.counts[slot] += 1;
        s.transcript.records.push(Record {
            dir: self.side,
            index,
            bytes: msg.clone(),
        });
        let delivered = s.tap.on_message(self.side, index, msg);
        let queue = match self.side {
            Dir::ToHost => &mut s.to_host,
            Dir::ToViewer => &mut s.to_viewer,
        };
        queue.extend(delivered);
    }

    /// Receives the next delivered message, if any.
    pub fn recv(&self) -> Option<Vec<u8>> {
        let mut s = self.lock();
        match self.side {
            Dir::ToHost => s.to_viewer.pop_front(),
            Dir::ToViewer => s.to_host.pop_front(),
        }
    }
}

/// A viewer↔host message link with a man-in-the-middle tap.
pub struct Link {
    /// The viewer's end.
    pub viewer: Endpoint,
    /// The host's end.
    pub host: Endpoint,
    shared: Arc<Mutex<Shared>>,
}

impl Link {
    /// Creates a link whose traffic passes through `tap`.
    pub fn new(tap: impl Tap + 'static) -> Self {
        let shared = Arc::new(Mutex::new(Shared {
            tap: Box::new(tap),
            transcript: Transcript::default(),
            counts: [0, 0],
            to_host: VecDeque::new(),
            to_viewer: VecDeque::new(),
        }));
        Self {
            viewer: Endpoint {
                side: Dir::ToHost,
                shared: Arc::clone(&shared),
            },
            host: Endpoint {
                side: Dir::ToViewer,
                shared: Arc::clone(&shared),
            },
            shared,
        }
    }

    /// An honest link.
    pub fn honest() -> Self {
        Self::new(taps::pass())
    }

    /// Everything sent so far (before the tap acted).
    pub fn transcript(&self) -> Transcript {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .transcript
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_link_delivers_in_order_both_ways() {
        let l = Link::honest();
        l.viewer.send(vec![1]);
        l.viewer.send(vec![2]);
        l.host.send(vec![9]);
        assert_eq!(l.host.recv(), Some(vec![1]));
        assert_eq!(l.host.recv(), Some(vec![2]));
        assert_eq!(l.host.recv(), None);
        assert_eq!(l.viewer.recv(), Some(vec![9]));
    }

    #[test]
    fn transcript_records_originals_not_tampered_copies() {
        let l = Link::new(taps::flip_bit(Dir::ToHost, 0, 0));
        l.viewer.send(vec![0b1010]);
        assert_eq!(l.host.recv(), Some(vec![0b1011]));
        let t = l.transcript();
        assert_eq!(t.messages(Dir::ToHost), vec![vec![0b1010]]);
    }

    #[test]
    fn taps_drop_duplicate_truncate_replace_swap() {
        let l = Link::new(taps::drop(Dir::ToHost, 1));
        for m in [vec![1], vec![2], vec![3]] {
            l.viewer.send(m);
        }
        assert_eq!(
            (l.host.recv(), l.host.recv(), l.host.recv()),
            (Some(vec![1]), Some(vec![3]), None)
        );

        let l = Link::new(taps::duplicate(Dir::ToViewer, 0));
        l.host.send(vec![7]);
        assert_eq!(
            (l.viewer.recv(), l.viewer.recv()),
            (Some(vec![7]), Some(vec![7]))
        );

        let l = Link::new(taps::truncate(Dir::ToHost, 0, 1));
        l.viewer.send(vec![1, 2, 3]);
        assert_eq!(l.host.recv(), Some(vec![1]));

        let l = Link::new(taps::replace(Dir::ToHost, 0, vec![42]));
        l.viewer.send(vec![1]);
        assert_eq!(l.host.recv(), Some(vec![42]));

        let l = Link::new(taps::swap_with_next(Dir::ToHost, 0));
        l.viewer.send(vec![1]);
        assert_eq!(l.host.recv(), None, "held back");
        l.viewer.send(vec![2]);
        assert_eq!(
            (l.host.recv(), l.host.recv()),
            (Some(vec![2]), Some(vec![1]))
        );
    }

    #[test]
    fn bit_positions_cover_every_bit_exactly_once() {
        let l = Link::honest();
        l.viewer.send(vec![0; 2]);
        l.host.send(vec![0; 1]);
        let t = l.transcript();
        let all: Vec<_> = t.bit_positions().collect();
        assert_eq!(all.len(), 24);
        assert_eq!(all.first(), Some(&(0, 0)));
        assert_eq!(all.last(), Some(&(1, 7)));
    }
}
