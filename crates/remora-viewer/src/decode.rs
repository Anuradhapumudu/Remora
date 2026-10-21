//! Decoding the received video (phase4-criteria steps 5 and 6).
//!
//! Frames go to the decoder's own thread through a queue of
//! [`QUEUE`] frames. When the decoder falls behind, new frames are dropped
//! here rather than queued without bound; the decoder sees the gap in
//! frame ids and waits for a keyframe. Every frame the decoder cannot use
//! (refused, failed, after a gap) makes the viewer ask the host for a
//! keyframe; the session sends at most one request per 500 ms. Decoded
//! pictures go to `show` (the window) in decode order.
//!
//! macOS decodes with VideoToolbox. Other systems have no decoder yet
//! (Phase 6.5): frames are counted and dropped.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

use remora_net::ViewerClient;
use remora_proto::video::VideoFrame;

/// Frames waiting for the decoder at most (≈ 67 ms at 60 fps).
const QUEUE: usize = 4;

/// A decoded picture on its way to the window.
#[cfg(target_os = "macos")]
pub(crate) struct Picture {
    pub(crate) frame: remora_codec::DecodedFrame,
    /// How long the decoder took for it.
    pub(crate) decode: std::time::Duration,
}

/// Receives decoded pictures (on the decode thread).
#[cfg(target_os = "macos")]
pub(crate) type Show = Box<dyn FnMut(Picture) + Send>;
#[cfg(not(target_os = "macos"))]
pub(crate) type Show = ();

/// What happened to the frames handed to [`Decoder::offer`], so far.
/// Shared with the window, which shows it once per second (R3).
#[derive(Debug, Default)]
pub(crate) struct Counters {
    /// Decoded to a picture.
    pub(crate) decoded: AtomicU64,
    /// Refused before the decoder (malformed, too large, after a gap).
    pub(crate) refused: AtomicU64,
    /// The decoder failed on them.
    pub(crate) failed: AtomicU64,
    /// Dropped because the decoder was busy (or there is none).
    pub(crate) dropped: AtomicU64,
    /// Decoded but not shown: the window still had [`MAX_UNSHOWN`]
    /// pictures to draw (latest wins; the decoder's chain is unaffected).
    pub(crate) not_shown: AtomicU64,
    /// Pictures handed to the window and not yet drawn.
    pub(crate) unshown: AtomicU64,
}

/// Pictures on their way to the window at most: more would only add
/// latency (and hold decoder surfaces), so newer ones are dropped.
pub(crate) const MAX_UNSHOWN: u64 = 2;

impl Counters {
    /// `(decoded, refused, failed, dropped + not shown)` now.
    pub(crate) fn get(&self) -> (u64, u64, u64, u64) {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        (
            g(&self.decoded),
            g(&self.refused),
            g(&self.failed),
            g(&self.dropped) + g(&self.not_shown),
        )
    }

    /// The window has dealt with one picture. Only the window thread
    /// decrements, so the check and the subtraction cannot race to
    /// below zero.
    pub(crate) fn shown(&self) {
        if self.unshown.load(Ordering::Relaxed) > 0 {
            self.unshown.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn bump(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

pub(crate) struct Decoder {
    tx: Option<SyncSender<VideoFrame>>,
    worker: Option<JoinHandle<()>>,
    counters: Arc<Counters>,
}

impl Decoder {
    /// Starts the decoder thread; it asks for keyframes through `client`
    /// and hands pictures to `show`.
    pub(crate) fn start(client: ViewerClient, show: Show) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel::<VideoFrame>(QUEUE);
        let counters = Arc::new(Counters::default());
        let shared = Arc::clone(&counters);
        let worker = std::thread::Builder::new()
            .name("remora-decode".into())
            .spawn(move || run(rx, client, show, &shared))?;
        Ok(Self {
            tx: Some(tx),
            worker: Some(worker),
            counters,
        })
    }

    /// The live counters.
    pub(crate) fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.counters)
    }

    /// Hands a frame to the decoder, or drops it if the decoder is busy.
    pub(crate) fn offer(&mut self, frame: VideoFrame) {
        let Some(tx) = &self.tx else {
            bump(&self.counters.dropped);
            return;
        };
        match tx.try_send(frame) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => bump(&self.counters.dropped),
            Err(TrySendError::Disconnected(_)) => {
                bump(&self.counters.dropped);
                self.tx = None;
            }
        }
    }

    /// Stops the decoder thread; returns the final counts.
    pub(crate) fn finish(mut self) -> (u64, u64, u64, u64) {
        self.tx = None; // ends the thread's loop
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
        self.counters.get()
    }
}

#[cfg(target_os = "macos")]
fn run(
    rx: std::sync::mpsc::Receiver<VideoFrame>,
    client: ViewerClient,
    mut show: Show,
    counters: &Counters,
) {
    use remora_codec::h264::SizeLimit;
    use remora_codec::{DecodeError, VtDecoder};

    let mut decoder = VtDecoder::new(SizeLimit::default());
    for frame in rx {
        let started = std::time::Instant::now();
        match decoder.decode(frame.frame_id, &frame.data) {
            Ok(picture) => {
                bump(&counters.decoded);
                if counters.unshown.load(Ordering::Relaxed) >= MAX_UNSHOWN {
                    bump(&counters.not_shown);
                    continue;
                }
                bump(&counters.unshown);
                show(Picture {
                    frame: picture,
                    decode: started.elapsed(),
                });
            }
            Err(e) => {
                bump(match e {
                    DecodeError::Refused(_) => &counters.refused,
                    _ => &counters.failed,
                });
                client.request_keyframe();
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn run(
    rx: std::sync::mpsc::Receiver<VideoFrame>,
    client: ViewerClient,
    show: Show,
    counters: &Counters,
) {
    let _ = (client, show);
    for _ in rx {
        bump(&counters.dropped);
    }
}
