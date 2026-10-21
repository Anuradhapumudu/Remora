//! Decoding the received video (phase4-criteria step 5).
//!
//! Frames go to the decoder's own thread through a queue of
//! [`QUEUE`] frames. When the decoder falls behind, new frames are dropped
//! here rather than queued without bound; the decoder sees the gap in
//! frame ids and waits for a keyframe. Every frame the decoder cannot use
//! (refused, failed, after a gap) makes the viewer ask the host for a
//! keyframe; the session sends at most one request per 500 ms.
//!
//! macOS decodes with VideoToolbox. Other systems have no decoder yet
//! (Phase 6.5): frames are counted and dropped.

use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

use remora_net::ViewerClient;
use remora_proto::video::VideoFrame;

/// Frames waiting for the decoder at most (≈ 67 ms at 60 fps).
const QUEUE: usize = 4;

/// What happened to the frames handed to [`Decoder::offer`].
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Summary {
    /// Decoded to a picture.
    pub(crate) decoded: u64,
    /// Refused before the decoder (malformed, too large, after a gap).
    pub(crate) refused: u64,
    /// The decoder failed on them.
    pub(crate) failed: u64,
    /// Dropped because the decoder was busy (or there is none).
    pub(crate) dropped: u64,
}

pub(crate) struct Decoder {
    tx: Option<SyncSender<VideoFrame>>,
    worker: Option<JoinHandle<Summary>>,
    dropped: u64,
}

impl Decoder {
    /// Starts the decoder thread; it asks for keyframes through `client`.
    pub(crate) fn start(client: ViewerClient) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel::<VideoFrame>(QUEUE);
        let worker = std::thread::Builder::new()
            .name("remora-decode".into())
            .spawn(move || run(rx, client))?;
        Ok(Self {
            tx: Some(tx),
            worker: Some(worker),
            dropped: 0,
        })
    }

    /// Hands a frame to the decoder, or drops it if the decoder is busy.
    pub(crate) fn offer(&mut self, frame: VideoFrame) {
        let Some(tx) = &self.tx else {
            self.dropped += 1;
            return;
        };
        match tx.try_send(frame) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => self.dropped += 1,
            Err(TrySendError::Disconnected(_)) => {
                self.dropped += 1;
                self.tx = None;
            }
        }
    }

    /// Stops the decoder thread and returns what happened.
    pub(crate) fn finish(mut self) -> Summary {
        self.tx = None; // ends the thread's loop
        let mut s = self
            .worker
            .take()
            .and_then(|w| w.join().ok())
            .unwrap_or_default();
        s.dropped += self.dropped;
        s
    }
}

#[cfg(target_os = "macos")]
fn run(rx: std::sync::mpsc::Receiver<VideoFrame>, client: ViewerClient) -> Summary {
    use remora_codec::VtDecoder;
    use remora_codec::h264::SizeLimit;

    let mut decoder = VtDecoder::new(SizeLimit::default());
    for frame in rx {
        match decoder.decode(frame.frame_id, &frame.data) {
            // Phase 4 step 6 draws the picture; until then it is released.
            Ok(_picture) => {}
            Err(_) => client.request_keyframe(),
        }
    }
    let s = decoder.stats();
    Summary {
        decoded: s.decoded,
        refused: s.refused,
        failed: s.failed,
        dropped: 0,
    }
}

#[cfg(not(target_os = "macos"))]
fn run(rx: std::sync::mpsc::Receiver<VideoFrame>, client: ViewerClient) -> Summary {
    let _ = client;
    Summary {
        dropped: rx.iter().count() as u64,
        ..Summary::default()
    }
}
