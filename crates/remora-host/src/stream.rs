//! Streaming the screen to approved viewers (phase4-criteria step 7).
//!
//! Capture (on the backend's thread) → hardware encoder → [`VideoOut`]
//! (the host server, which seals each frame per session). Three rules:
//!
//! * **Keyframes when needed, never on a timer.** The first frame, the
//!   first frame after capture resumes (T2), and the next frame after a
//!   viewer asks for one ([`Streamer::force_keyframe`]) or after the encoder
//!   failed. A keyframe is several times larger than a normal frame, so
//!   sending them only on demand keeps bandwidth and latency down.
//! * **The capture time travels with the frame.** Each frame carries the
//!   compositor's display time on the shared monotonic clock
//!   ([`remora_app::clock`]), so the viewer can measure end-to-end latency
//!   (P1) against the same clock.
//! * **Capture state goes to the session layer**, which tells the viewer
//!   (StreamPaused / StreamResumed) and ends sessions when capture stops.
//!
//! Nothing here logs frame content (INV9): only counts and states.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Context;
use remora_capture::{CaptureEvent, InterruptReason, ScreenCapture};
// The macOS test pattern (SyntheticCapture) only.
#[cfg(target_os = "macos")]
use remora_capture::{CaptureError, CapturedFrame, EventSink, FrameStatus};
#[cfg(target_os = "macos")]
use remora_codec::SyntheticSource;
use remora_codec::{EncoderConfig, EncoderEvent};

/// The encoder for this OS: the Mac's hardware encoder (VideoToolbox), or
/// openh264 in software on Linux (phase 4.6). Same calls on both.
#[cfg(target_os = "macos")]
type VideoEncoder = remora_codec::VtEncoder;
#[cfg(target_os = "linux")]
type VideoEncoder = remora_codec::OpenH264Encoder;
use remora_session::{CaptureStatus, PauseReason};

/// Where encoded frames and capture state go: the host server, or a
/// recorder in tests.
pub(crate) trait VideoOut: Send + Sync + 'static {
    /// One encoded frame (Annex B) with its display time in microseconds
    /// on the shared monotonic clock.
    fn video(&self, keyframe: bool, capture_ts_us: u64, data: &[u8]);
    /// Capture paused, resumed or stopped.
    fn capture(&self, status: CaptureStatus);
    /// A captured frame with new content goes to the encoder (P3 counts
    /// these: the first point where Remora sees a frame the screen made).
    fn captured(&self, capture_ts_us: u64);
    /// A captured frame never became an encoded frame. Every captured
    /// frame ends as exactly one [`video`](Self::video) or one of these.
    fn not_encoded(&self, capture_ts_us: u64, why: NotEncoded);
}

/// Why a captured frame was not encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotEncoded {
    /// The encoder skipped it (e.g. it missed its real-time deadline).
    Dropped,
    /// The encoder refused or failed it.
    Failed,
}

/// Display times of the frames inside the encoder, by encoder sequence
/// number modulo this. The encoder holds a few frames at most (it runs in
/// real time, without B-frames), far fewer than 64.
const IN_FLIGHT: usize = 64;

/// One captured picture as this OS's encoder takes it.
#[cfg(target_os = "macos")]
type Image = remora_capture::PixelBufferRef;
#[cfg(target_os = "linux")]
type Image = remora_capture::CpuImage;

/// Linux: a keyframe asked for while the screen is still is made from the
/// last picture after this long without a new one (LP4). GNOME sends a
/// picture only when something changes, so without this a viewer that
/// lost a frame on a still screen stayed stale until the next change
/// (owner's laptop, 2026-11-02: "waiting" 479 over one session).
#[cfg(target_os = "linux")]
const REPEAT_AFTER: Duration = Duration::from_millis(40);

/// What the capture thread and the encoder thread share.
struct Shared {
    out: Arc<dyn VideoOut>,
    /// The next frame must be a keyframe.
    force: AtomicBool,
    /// `capture_ts_us` per encoder sequence number (see [`IN_FLIGHT`]).
    display_us: [AtomicU64; IN_FLIGHT],
    /// Calls to `encode` so far: the encoder numbers frames 0, 1, 2, ... by
    /// them (failed calls included), so a frame's slot is known before the
    /// call and the encoder thread can never read it too early. Only
    /// changed with the encoder locked.
    calls: AtomicU64,
    /// Linux: the last picture and when it was encoded (for LP4 repeats).
    #[cfg(target_os = "linux")]
    last: Mutex<Option<(Arc<Image>, Instant)>>,
    /// Linux: tells the repeat thread to finish.
    #[cfg(target_os = "linux")]
    stopping: AtomicBool,
}

/// Encodes one picture shown at `shown` (a keyframe if one is due).
fn submit(s: &Shared, enc: &Mutex<VideoEncoder>, image: &Image, shown: Instant, started: Instant) {
    let shown_us = display_us(shown);
    s.out.captured(shown_us);
    let pts = shown.saturating_duration_since(started);
    let sent = enc.lock().map(|mut e| {
        let call = s.calls.fetch_add(1, Ordering::Relaxed);
        s.display_us[call as usize % IN_FLIGHT].store(shown_us, Ordering::Relaxed);
        let keyframe = s.force.swap(false, Ordering::Relaxed);
        e.encode(image, pts, keyframe)
    });
    if !matches!(sent, Ok(Ok(_))) {
        s.force.store(true, Ordering::Relaxed);
        s.out.not_encoded(shown_us, NotEncoded::Failed);
    }
}

/// A running capture → encode → send pipeline.
pub(crate) struct Streamer {
    capture: Box<dyn ScreenCapture>,
    encoder: Arc<Mutex<VideoEncoder>>,
    shared: Arc<Shared>,
    /// Linux: re-encodes the last picture as a keyframe when one is asked
    /// for on a still screen (LP4).
    #[cfg(target_os = "linux")]
    repeat: Option<JoinHandle<()>>,
}

impl Streamer {
    /// Starts `capture` and an encoder of its output size (default
    /// bitrate; tuning it is part of the latency measurements, P1).
    pub(crate) fn start(
        mut capture: Box<dyn ScreenCapture>,
        out: Arc<dyn VideoOut>,
    ) -> anyhow::Result<Self> {
        let (width, height) = capture.output_size();
        let shared = Arc::new(Shared {
            out,
            // Not needed for the first frame: VideoToolbox always starts
            // with an IDR (test `the_first_frame_is_a_keyframe_…` passes
            // without forcing it, checked by removing a forced first frame).
            force: AtomicBool::new(false),
            display_us: std::array::from_fn(|_| AtomicU64::new(0)),
            calls: AtomicU64::new(0),
            #[cfg(target_os = "linux")]
            last: Mutex::new(None),
            #[cfg(target_os = "linux")]
            stopping: AtomicBool::new(false),
        });
        let s = Arc::clone(&shared);
        let encoder = VideoEncoder::new(
            EncoderConfig {
                width,
                height,
                // The default keyframe_interval, 0, means keyframes only
                // when asked for (module docs).
                ..EncoderConfig::default()
            },
            Box::new(move |ev| match ev {
                EncoderEvent::Frame(f) => {
                    let slot = &s.display_us[f.seq as usize % IN_FLIGHT];
                    s.out
                        .video(f.keyframe, slot.load(Ordering::Relaxed), &f.data);
                }
                // A frame the encoder skipped is never referenced by later
                // ones, so the stream stays decodable.
                EncoderEvent::Dropped { seq } => {
                    let slot = &s.display_us[seq as usize % IN_FLIGHT];
                    s.out
                        .not_encoded(slot.load(Ordering::Relaxed), NotEncoded::Dropped);
                }
                // A failed frame may leave the encoder's references in an
                // unknown state: start again from a keyframe.
                EncoderEvent::Error { seq, .. } => {
                    s.force.store(true, Ordering::Relaxed);
                    let slot = &s.display_us[seq as usize % IN_FLIGHT];
                    s.out
                        .not_encoded(slot.load(Ordering::Relaxed), NotEncoded::Failed);
                }
            }),
        )
        .context("video encoder")?;
        let encoder = Arc::new(Mutex::new(encoder));
        let (enc, s) = (Arc::clone(&encoder), Arc::clone(&shared));
        let started = Instant::now();
        #[cfg(target_os = "linux")]
        let repeat = {
            let (enc, s) = (Arc::clone(&encoder), Arc::clone(&shared));
            Some(
                std::thread::Builder::new()
                    .name("remora-repeat".into())
                    .spawn(move || repeat_when_still(&s, &enc, started))
                    .context("starting the keyframe repeat thread")?,
            )
        };
        capture
            .start(Box::new(move |ev| match ev {
                #[cfg(target_os = "macos")]
                CaptureEvent::Frame(f) => {
                    let Some(image) = f.image.as_ref() else {
                        return; // nothing changed on screen: nothing to send
                    };
                    submit(&s, &enc, image, f.display_time(), started);
                }
                #[cfg(target_os = "linux")]
                CaptureEvent::Frame(mut f) => {
                    let Some(image) = f.image.take().map(Arc::new) else {
                        return; // nothing changed on screen: nothing to send
                    };
                    submit(&s, &enc, &image, f.display_time(), started);
                    if let Ok(mut last) = s.last.lock() {
                        *last = Some((image, Instant::now()));
                    }
                }
                CaptureEvent::Interrupted(reason) => s
                    .out
                    .capture(CaptureStatus::Interrupted(pause_reason(reason))),
                CaptureEvent::Resumed => {
                    // The viewer's decoder has nothing current: T2.
                    s.force.store(true, Ordering::Relaxed);
                    s.out.capture(CaptureStatus::Running);
                }
                CaptureEvent::Stopped(e) => {
                    // An OS error message, never screen content.
                    eprintln!("capture stopped: {e}");
                    s.out.capture(CaptureStatus::Stopped);
                }
            }))
            .context("starting screen capture")?;
        Ok(Self {
            capture,
            encoder,
            shared,
            #[cfg(target_os = "linux")]
            repeat,
        })
    }

    /// The next frame is encoded as a keyframe (a viewer asked for one).
    pub(crate) fn force_keyframe(&self) {
        self.shared.force.store(true, Ordering::Relaxed);
    }

    /// Stops capture and delivers every frame already submitted.
    pub(crate) fn stop(mut self) {
        if let Err(e) = self.capture.stop() {
            eprintln!("stopping capture: {e}");
        }
        #[cfg(target_os = "linux")]
        {
            self.shared.stopping.store(true, Ordering::Relaxed);
            if let Some(t) = self.repeat.take() {
                let _ = t.join();
            }
        }
        if let Ok(mut e) = self.encoder.lock()
            && let Err(err) = e.flush()
        {
            eprintln!("flushing the encoder: {err}");
        }
    }
}

/// Linux (LP4): while a keyframe is due and no new picture has come for
/// [`REPEAT_AFTER`], encode the last picture again, as that keyframe. Its
/// display time is now: it shows the screen as it still is.
#[cfg(target_os = "linux")]
fn repeat_when_still(s: &Shared, enc: &Mutex<VideoEncoder>, started: Instant) {
    while !s.stopping.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(10));
        if !s.force.load(Ordering::Relaxed) {
            continue;
        }
        let image = match s.last.lock() {
            Ok(mut last) => match last.as_mut() {
                Some((image, at)) if at.elapsed() >= REPEAT_AFTER => {
                    *at = Instant::now();
                    Arc::clone(image)
                }
                _ => continue,
            },
            Err(_) => return,
        };
        submit(s, enc, &image, Instant::now(), started);
    }
}

/// `shown` in microseconds on the shared monotonic clock (0 if this OS
/// has none yet; the viewer then reports no latency).
fn display_us(shown: Instant) -> u64 {
    remora_app::clock::monotonic_ns()
        .map(|now| {
            let ago = u64::try_from(shown.elapsed().as_nanos()).unwrap_or(u64::MAX);
            now.saturating_sub(ago) / 1000
        })
        .unwrap_or(0)
}

fn pause_reason(r: InterruptReason) -> PauseReason {
    match r {
        InterruptReason::DisplayAsleep => PauseReason::DisplayAsleep,
        InterruptReason::AccessLost => PauseReason::AccessLost,
        InterruptReason::Other => PauseReason::Other,
        InterruptReason::DisplayUnavailable { remaining } => PauseReason::DisplayUnavailable {
            remaining_ms: u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX),
        },
    }
}

/// A test pattern instead of the screen (macOS: the pattern is drawn by
/// VideoToolbox's pixel buffers): frames numbered by a barcode
/// strip (`SyntheticSource::next_frame_marked`) at a fixed rate. Needs no
/// Screen Recording permission, so CI can stream end to end; everything
/// after the source (encoder, sealing, network) is the real path.
#[cfg(target_os = "macos")]
pub(crate) struct SyntheticCapture {
    width: u32,
    height: u32,
    fps: u32,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[cfg(target_os = "macos")]
impl SyntheticCapture {
    /// `width × height` (even) at `fps` frames per second.
    pub(crate) fn new(width: u32, height: u32, fps: u32) -> Self {
        Self {
            width: width & !1,
            height: height & !1,
            fps: fps.max(1),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
        }
    }
}

#[cfg(target_os = "macos")]
impl ScreenCapture for SyntheticCapture {
    fn start(&mut self, mut sink: EventSink) -> Result<(), CaptureError> {
        if self.thread.is_some() {
            return Err(CaptureError::InvalidState("already running"));
        }
        let os = |e: remora_codec::CodecError| CaptureError::Os {
            api: "synthetic source",
            code: 0, // not an OS error
            message: e.to_string(),
        };
        let mut src = SyntheticSource::new(self.width, self.height).map_err(os)?;
        let (stop, period) = (Arc::clone(&self.stop), Duration::from_secs(1) / self.fps);
        self.stop.store(false, Ordering::Relaxed);
        let thread = std::thread::Builder::new()
            .name("remora-synthetic".into())
            .spawn(move || {
                let mut next = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    match src.next_frame_marked() {
                        Ok((number, image)) => sink(CaptureEvent::Frame(CapturedFrame {
                            seq: u64::from(number),
                            status: FrameStatus::Complete,
                            arrival: Instant::now(),
                            delivery_ns: Some(0),
                            dirty_rects: Vec::new(),
                            image: Some(image),
                        })),
                        Err(e) => {
                            sink(CaptureEvent::Stopped(os(e)));
                            return;
                        }
                    }
                    next += period;
                    std::thread::sleep(next.saturating_duration_since(Instant::now()));
                }
            })
            .map_err(|e| CaptureError::Os {
                api: "spawn",
                code: e.raw_os_error().map_or(0, i64::from),
                message: e.to_string(),
            })?;
        self.thread = Some(thread);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), CaptureError> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            t.join()
                .map_err(|_| CaptureError::InvalidState("synthetic source panicked"))?;
        }
        Ok(())
    }

    fn output_size(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

// The tests drive the macOS pipeline (pixel buffers from SyntheticSource);
// the Linux pipeline is checked end to end on the laptop (phase 4.6 step 6).
#[cfg(all(test, target_os = "macos"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // test code

    use std::sync::mpsc;

    use remora_capture::{FrameStatus, InterruptReason};
    use remora_codec::SyntheticSource;
    use remora_session::PauseReason;

    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    enum Rec {
        /// `sent_us`: the shared clock when the frame reached us.
        Video {
            keyframe: bool,
            ts_us: u64,
            sent_us: u64,
        },
        Capture(CaptureStatus),
    }

    #[derive(Default)]
    struct Recorder(Mutex<Vec<Rec>>, Mutex<Vec<u64>>, Mutex<Vec<u64>>);

    impl VideoOut for Recorder {
        fn video(&self, keyframe: bool, capture_ts_us: u64, data: &[u8]) {
            assert!(!data.is_empty());
            self.0.lock().unwrap().push(Rec::Video {
                keyframe,
                ts_us: capture_ts_us,
                sent_us: remora_app::clock::monotonic_ns().unwrap() / 1000,
            });
        }
        fn capture(&self, status: CaptureStatus) {
            self.0.lock().unwrap().push(Rec::Capture(status));
        }
        fn captured(&self, capture_ts_us: u64) {
            self.1.lock().unwrap().push(capture_ts_us);
        }
        fn not_encoded(&self, capture_ts_us: u64, _why: NotEncoded) {
            self.2.lock().unwrap().push(capture_ts_us);
        }
    }

    impl Recorder {
        fn all(&self) -> Vec<Rec> {
            self.0.lock().unwrap().clone()
        }
        fn videos(&self) -> usize {
            self.all()
                .iter()
                .filter(|r| matches!(r, Rec::Video { .. }))
                .count()
        }
        /// Waits (≤ 5 s) until `n` frames arrived.
        fn wait_videos(&self, n: usize) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.videos() < n {
                assert!(Instant::now() < deadline, "only {:?}", self.all());
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    enum Step {
        Frames(u32),
        Interrupt,
        Resume,
        Stop,
        /// Wait for the test to say go.
        Wait(mpsc::Receiver<()>),
    }

    /// The script's frames reach the backend this long after the
    /// compositor displayed them.
    const DISPLAYED_BEFORE_NS: i64 = 50_000_000;

    const W: u32 = 640;
    const H: u32 = 360;

    /// A capture backend that plays a script on its own thread, as the
    /// real backend calls its sink on its own thread.
    struct Scripted {
        script: Option<Vec<Step>>,
        thread: Option<JoinHandle<()>>,
    }

    impl Scripted {
        fn new(script: Vec<Step>) -> Box<Self> {
            Box::new(Self {
                script: Some(script),
                thread: None,
            })
        }
    }

    impl ScreenCapture for Scripted {
        fn start(&mut self, mut sink: EventSink) -> Result<(), CaptureError> {
            let script = self.script.take().unwrap();
            self.thread = Some(std::thread::spawn(move || {
                let mut src = SyntheticSource::new(W, H).unwrap();
                let mut seq = 0;
                for step in script {
                    match step {
                        Step::Frames(n) => {
                            for _ in 0..n {
                                sink(CaptureEvent::Frame(CapturedFrame {
                                    seq,
                                    status: FrameStatus::Complete,
                                    arrival: Instant::now(),
                                    delivery_ns: Some(DISPLAYED_BEFORE_NS),
                                    dirty_rects: Vec::new(),
                                    image: Some(src.next_frame().unwrap()),
                                }));
                                seq += 1;
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        }
                        Step::Interrupt => {
                            sink(CaptureEvent::Interrupted(InterruptReason::DisplayAsleep))
                        }
                        Step::Resume => sink(CaptureEvent::Resumed),
                        Step::Stop => sink(CaptureEvent::Stopped(CaptureError::PermissionDenied)),
                        Step::Wait(rx) => rx.recv().unwrap(),
                    }
                }
            }));
            Ok(())
        }

        fn stop(&mut self) -> Result<(), CaptureError> {
            if let Some(t) = self.thread.take() {
                t.join().unwrap();
            }
            Ok(())
        }

        fn output_size(&self) -> (u32, u32) {
            (W, H)
        }
    }

    fn run(script: Vec<Step>) -> (Arc<Recorder>, Streamer) {
        let rec = Arc::new(Recorder::default());
        let out: Arc<dyn VideoOut> = rec.clone();
        let s = Streamer::start(Scripted::new(script), out).unwrap();
        (rec, s)
    }

    fn keyframes(recs: &[Rec]) -> Vec<bool> {
        recs.iter()
            .filter_map(|r| match r {
                Rec::Video { keyframe, .. } => Some(*keyframe),
                Rec::Capture(_) => None,
            })
            .collect()
    }

    #[test]
    fn the_first_frame_is_a_keyframe_and_no_other_is_on_a_timer() {
        let (rec, s) = run(vec![Step::Frames(40)]);
        rec.wait_videos(40);
        s.stop();
        let k = keyframes(&rec.all());
        assert_eq!(k.len(), 40);
        assert!(k[0], "first frame");
        assert!(k[1..].iter().all(|k| !k), "no keyframe after it: {k:?}");
    }

    #[test]
    fn frames_carry_their_display_time_on_the_shared_clock() {
        let (rec, s) = run(vec![Step::Frames(10)]);
        rec.wait_videos(10);
        s.stop();
        let ts: Vec<(u64, u64)> = rec
            .all()
            .iter()
            .filter_map(|r| match r {
                Rec::Video { ts_us, sent_us, .. } => Some((*ts_us, *sent_us)),
                Rec::Capture(_) => None,
            })
            .collect();
        // Displayed 50 ms before the backend got it, so at least 50 ms
        // before it was sent; and not long before (encoding is fast).
        for (t, sent) in &ts {
            let age = sent - t;
            assert!(
                (50_000..1_000_000).contains(&age),
                "display time {age} µs before sending"
            );
        }
        assert!(ts.windows(2).all(|w| w[0].0 < w[1].0), "increasing: {ts:?}");
    }

    /// T2's open item: "the first frame after resume is a keyframe".
    #[test]
    fn after_capture_resumes_the_first_frame_is_a_keyframe() {
        // The encoder delivers on its own thread: wait until the 20
        // frames are out before interrupting, or one could be recorded
        // after the pause (seen on GitHub's VM).
        let (go, wait) = mpsc::channel();
        let (rec, s) = run(vec![
            Step::Frames(20),
            Step::Wait(wait),
            Step::Interrupt,
            Step::Resume,
            Step::Frames(5),
        ]);
        rec.wait_videos(20);
        go.send(()).unwrap();
        rec.wait_videos(25);
        s.stop();
        let all = rec.all();
        let paused = Rec::Capture(CaptureStatus::Interrupted(PauseReason::DisplayAsleep));
        let at = all.iter().position(|r| *r == paused).expect("paused");
        assert_eq!(all[at + 1], Rec::Capture(CaptureStatus::Running));
        let k = keyframes(&all[at + 2..]);
        assert_eq!(k.len(), 5);
        assert!(k[0], "first frame after resume: {k:?}");
        assert!(!keyframes(&all[..at])[1..].iter().any(|k| *k));
    }

    #[test]
    fn a_keyframe_request_makes_the_next_frame_a_keyframe() {
        let (go, wait) = mpsc::channel();
        let (rec, s) = run(vec![Step::Frames(10), Step::Wait(wait), Step::Frames(5)]);
        rec.wait_videos(10);
        s.force_keyframe();
        go.send(()).unwrap();
        rec.wait_videos(15);
        s.stop();
        let k = keyframes(&rec.all());
        assert!(!k[1..10].iter().any(|k| *k), "{k:?}");
        assert!(k[10], "the frame after the request: {k:?}");
        assert!(!k[11..].iter().any(|k| *k), "only that one: {k:?}");
    }

    #[test]
    fn stopped_capture_is_reported() {
        let (rec, s) = run(vec![Step::Frames(3), Step::Stop]);
        rec.wait_videos(3);
        s.stop();
        // Frames still in the encoder may arrive after it; order is free.
        assert!(
            rec.all().contains(&Rec::Capture(CaptureStatus::Stopped)),
            "{:?}",
            rec.all()
        );
    }

    #[test]
    fn the_synthetic_source_streams_at_its_rate_until_stopped() {
        let rec = Arc::new(Recorder::default());
        let out: Arc<dyn VideoOut> = rec.clone();
        // The strip is 704 pixels wide: 640 × 360 would not hold it.
        let cap = Box::new(SyntheticCapture::new(1281, 721, 120));
        assert_eq!(cap.output_size(), (1280, 720), "even sizes");
        let s = Streamer::start(cap, out).unwrap();
        rec.wait_videos(1);
        let first = Instant::now();
        let at_first = rec.videos();
        std::thread::sleep(Duration::from_millis(500));
        let made = rec.videos() - at_first;
        s.stop();
        // 120 fps for 0.5 s: about 60, never a free-running source.
        let secs = first.elapsed().as_secs_f64();
        assert!((40..=80).contains(&made), "{made} frames in {secs:.2} s");
        assert!(keyframes(&rec.all())[0]);
        // Stopped means stopped.
        let stopped = rec.videos();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(rec.videos(), stopped, "frames after stop()");
    }

    /// D-29: the time left survives the trip from the capture to the
    /// session in milliseconds; an absurd one saturates (the session then
    /// clamps it to the protocol's bound).
    #[test]
    fn d29_display_unavailable_keeps_its_time_left() {
        let r = |remaining| pause_reason(InterruptReason::DisplayUnavailable { remaining });
        assert_eq!(
            r(Duration::from_secs(120)),
            PauseReason::DisplayUnavailable {
                remaining_ms: 120_000
            }
        );
        assert_eq!(
            r(Duration::from_secs(u64::MAX)),
            PauseReason::DisplayUnavailable {
                remaining_ms: u32::MAX
            }
        );
    }

    /// P3's count: every captured frame is reported once, and ends as
    /// exactly one sent frame or one "not encoded" (so frames lost between
    /// capture and network show up in the timing log).
    #[test]
    fn p3_every_captured_frame_is_accounted_for() {
        let (rec, s) = run(vec![Step::Frames(40)]);
        rec.wait_videos(40);
        s.stop();
        let captured = rec.1.lock().unwrap().clone();
        let mut ends: Vec<u64> = rec
            .all()
            .iter()
            .filter_map(|r| match r {
                Rec::Video { ts_us, .. } => Some(*ts_us),
                Rec::Capture(_) => None,
            })
            .chain(rec.2.lock().unwrap().iter().copied())
            .collect();
        let mut want = captured.clone();
        assert_eq!(captured.len(), 40);
        want.sort_unstable();
        ends.sort_unstable();
        assert_eq!(ends, want);
    }
}

/// LP4 on Linux, with openh264 and a fake screen (no desktop needed).
#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use std::sync::mpsc;

    use remora_capture::{CaptureError, CapturedFrame, CpuImage, EventSink, FrameStatus};
    use remora_session::CaptureStatus;

    use super::*;

    /// Sends three pictures, then nothing: a still screen.
    struct StillScreen;

    impl ScreenCapture for StillScreen {
        fn start(&mut self, mut sink: EventSink) -> Result<(), CaptureError> {
            for seq in 0..3u8 {
                // Almost the same picture each time (a whole new picture
                // is a "scene change" to openh264, which then sends IDRs).
                let mut px = vec![100; 64 * 36 * 4];
                px[usize::from(seq) * 4] = 200;
                sink(CaptureEvent::Frame(CapturedFrame {
                    seq: u64::from(seq),
                    status: FrameStatus::Complete,
                    arrival: Instant::now(),
                    delivery_ns: None,
                    dirty_rects: Vec::new(),
                    image: CpuImage::new(64, 36, px),
                }));
            }
            Ok(())
        }
        fn stop(&mut self) -> Result<(), CaptureError> {
            Ok(())
        }
        fn output_size(&self) -> (u32, u32) {
            (64, 36)
        }
    }

    struct Frames(Mutex<mpsc::Sender<bool>>);

    impl VideoOut for Frames {
        fn video(&self, keyframe: bool, _: u64, _: &[u8]) {
            if let Ok(tx) = self.0.lock() {
                let _ = tx.send(keyframe);
            }
        }
        fn capture(&self, _: CaptureStatus) {}
        fn captured(&self, _: u64) {}
        fn not_encoded(&self, _: u64, _: NotEncoded) {}
    }

    #[test]
    fn lp4_a_keyframe_asked_for_on_a_still_screen_comes_from_the_last_picture() {
        let (tx, rx) = mpsc::channel();
        let s = Streamer::start(Box::new(StillScreen), Arc::new(Frames(Mutex::new(tx))))
            .expect("start");
        let first: Vec<bool> = rx.iter().take(3).collect();
        assert_eq!(first, [true, false, false], "first picture is a keyframe");
        // Still screen: nothing more unless asked.
        assert!(rx.recv_timeout(Duration::from_millis(150)).is_err());
        let asked = Instant::now();
        s.force_keyframe();
        let k = rx
            .recv_timeout(Duration::from_millis(300))
            .expect("a keyframe within 300 ms on a still screen");
        assert!(k, "the repeat is a keyframe");
        assert!(asked.elapsed() < Duration::from_millis(200), "LP4 budget");
        // Asked once, sent once.
        assert!(rx.recv_timeout(Duration::from_millis(150)).is_err());
        s.stop();
    }
}
