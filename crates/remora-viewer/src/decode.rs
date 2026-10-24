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
    /// Shared-clock times in µs (P1/P2, `connect --timing`): the frame's
    /// display time at the host, its arrival here, decoding done.
    pub(crate) capture_us: u64,
    pub(crate) received_us: u64,
    pub(crate) decoded_us: u64,
}

/// Now on the shared monotonic clock in µs (0 where there is none).
pub(crate) fn now_us() -> u64 {
    remora_app::clock::monotonic_ns().map_or(0, |n| n / 1000)
}

/// Receives decoded pictures (on the decode thread); `None` = no window
/// (`connect --no-window`): pictures are decoded, counted and released.
#[cfg(target_os = "macos")]
pub(crate) type Show = Option<Box<dyn FnMut(Picture) + Send>>;
/// No decoder, so no pictures (a named type rather than `()`, which
/// clippy's `unit_arg` rejects as an argument).
#[cfg(not(target_os = "macos"))]
pub(crate) struct Show;

/// What happened to the frames handed to [`Decoder::offer`], so far.
/// Shared with the window, which shows it once per second (R3).
#[derive(Debug, Default)]
pub(crate) struct Counters {
    /// Decoded to a picture.
    pub(crate) decoded: AtomicU64,
    /// Refused before the decoder: malformed or too large.
    pub(crate) refused: AtomicU64,
    /// Not decodable yet: before the first keyframe, or after a gap or an
    /// error until the next one. Normal for a moment at the start of a
    /// session (frames encoded before the host's keyframe for this viewer).
    pub(crate) waiting: AtomicU64,
    /// The decoder failed on them.
    pub(crate) failed: AtomicU64,
    /// Dropped because the decoder was busy (or there is none).
    pub(crate) dropped: AtomicU64,
    /// Decoded but not shown: the window still had `MAX_UNSHOWN`
    /// pictures to draw (latest wins; the decoder's chain is unaffected).
    pub(crate) not_shown: AtomicU64,
    /// Pictures handed to the window and not yet drawn.
    #[cfg(target_os = "macos")]
    pub(crate) unshown: AtomicU64,
}

/// Pictures on their way to the window at most: more would only add
/// latency (and hold decoder surfaces), so newer ones are dropped.
#[cfg(target_os = "macos")]
pub(crate) const MAX_UNSHOWN: u64 = 2;

/// The counters at one moment.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Totals {
    pub(crate) decoded: u64,
    pub(crate) refused: u64,
    pub(crate) waiting: u64,
    pub(crate) failed: u64,
    /// Dropped before the decoder plus decoded but not shown.
    pub(crate) dropped: u64,
}

impl Counters {
    /// The counters now.
    pub(crate) fn get(&self) -> Totals {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Totals {
            decoded: g(&self.decoded),
            refused: g(&self.refused),
            waiting: g(&self.waiting),
            failed: g(&self.failed),
            dropped: g(&self.dropped) + g(&self.not_shown),
        }
    }

    /// The window has dealt with one picture. Only the window thread
    /// decrements, so the check and the subtraction cannot race to
    /// below zero.
    #[cfg(target_os = "macos")]
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
    tx: Option<SyncSender<(VideoFrame, u64)>>,
    worker: Option<JoinHandle<()>>,
    counters: Arc<Counters>,
}

impl Decoder {
    /// Starts the decoder thread; it asks for keyframes through `client`
    /// and hands pictures to `show`.
    pub(crate) fn start(client: ViewerClient, show: Show) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel::<(VideoFrame, u64)>(QUEUE);
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
        match tx.try_send((frame, now_us())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => bump(&self.counters.dropped),
            Err(TrySendError::Disconnected(_)) => {
                bump(&self.counters.dropped);
                self.tx = None;
            }
        }
    }

    /// Stops the decoder thread; returns the final counts.
    pub(crate) fn finish(mut self) -> Totals {
        self.tx = None; // ends the thread's loop
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
        self.counters.get()
    }
}

#[cfg(target_os = "macos")]
fn run(
    rx: std::sync::mpsc::Receiver<(VideoFrame, u64)>,
    client: ViewerClient,
    mut show: Show,
    counters: &Counters,
) {
    use remora_codec::VtDecoder;
    use remora_codec::h264::SizeLimit;

    let mut decoder = VtDecoder::new(SizeLimit::default());
    for (frame, received_us) in rx {
        let started = std::time::Instant::now();
        match decoder.decode(frame.frame_id, &frame.data) {
            Ok(picture) => {
                bump(&counters.decoded);
                let Some(show) = show.as_mut() else {
                    continue; // no window: the picture is released here
                };
                if counters.unshown.load(Ordering::Relaxed) >= MAX_UNSHOWN {
                    bump(&counters.not_shown);
                    continue;
                }
                bump(&counters.unshown);
                show(Picture {
                    frame: picture,
                    decode: started.elapsed(),
                    capture_us: frame.capture_ts_us,
                    received_us,
                    decoded_us: now_us(),
                });
            }
            Err(e) => {
                bump(counter_for(counters, &e));
                client.request_keyframe();
            }
        }
    }
}

/// The counter a decode error goes to: "refused" means the host sent
/// something malformed; "waiting" is normal for a moment (module docs).
#[cfg(target_os = "macos")]
fn counter_for<'a>(c: &'a Counters, e: &remora_codec::DecodeError) -> &'a AtomicU64 {
    use remora_codec::DecodeError;
    use remora_codec::h264::Refusal;
    match e {
        DecodeError::Refused(Refusal::WaitingForKeyframe) => &c.waiting,
        DecodeError::Refused(Refusal::Malformed(_)) => &c.refused,
        DecodeError::Configure(_) | DecodeError::Decode(_) | DecodeError::NoPicture => &c.failed,
    }
}

#[cfg(not(target_os = "macos"))]
fn run(
    rx: std::sync::mpsc::Receiver<(VideoFrame, u64)>,
    client: ViewerClient,
    show: Show,
    counters: &Counters,
) {
    let _ = (client, show);
    for _ in rx {
        bump(&counters.dropped);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use remora_codec::DecodeError;
    use remora_codec::h264::{Refusal, StreamError};

    use super::*;

    #[test]
    fn decode_errors_are_counted_where_they_belong() {
        let c = Counters::default();
        let is = |e: DecodeError, want: &AtomicU64| std::ptr::eq(counter_for(&c, &e), want);
        assert!(is(
            DecodeError::Refused(Refusal::WaitingForKeyframe),
            &c.waiting
        ));
        assert!(is(
            DecodeError::Refused(Refusal::Malformed(StreamError::NoStartCode)),
            &c.refused
        ));
        assert!(is(DecodeError::NoPicture, &c.failed));
    }
}
