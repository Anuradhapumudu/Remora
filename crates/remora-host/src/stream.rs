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
#![allow(dead_code, unused_imports)] // RED stubs (step 7); removed in GREEN

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use remora_capture::{CaptureError, CaptureEvent, CapturedFrame, EventSink, ScreenCapture};
use remora_codec::VtEncoder;
use remora_session::CaptureStatus;

/// Where encoded frames and capture state go: the host server, or a
/// recorder in tests.
pub(crate) trait VideoOut: Send + Sync + 'static {
    /// One encoded frame (Annex B) with its display time in microseconds
    /// on the shared monotonic clock.
    fn video(&self, keyframe: bool, capture_ts_us: u64, data: &[u8]);
    /// Capture paused, resumed or stopped.
    fn capture(&self, status: CaptureStatus);
}

/// A running capture → encode → send pipeline.
pub(crate) struct Streamer {
    capture: Box<dyn ScreenCapture>,
    encoder: Option<Arc<Mutex<VtEncoder>>>,
    force: Arc<AtomicBool>,
}

impl Streamer {
    /// Starts `capture` and an encoder of its output size at `bitrate_bps`.
    pub(crate) fn start(
        capture: Box<dyn ScreenCapture>,
        bitrate_bps: u32,
        out: Arc<dyn VideoOut>,
    ) -> anyhow::Result<Self> {
        let _ = (bitrate_bps, out);
        Ok(Self {
            capture,
            encoder: None,
            force: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The next frame is encoded as a keyframe (a viewer asked for one).
    pub(crate) fn force_keyframe(&self) {}

    /// Stops capture and delivers every frame already submitted.
    pub(crate) fn stop(mut self) {
        let _ = self.capture.stop();
        let _ = (&self.encoder, &self.force);
    }
}

/// A test pattern instead of the screen: frames numbered by a barcode
/// strip (`SyntheticSource::next_frame_marked`) at a fixed rate. Needs no
/// Screen Recording permission, so CI can stream end to end; everything
/// after the source (encoder, sealing, network) is the real path.
pub(crate) struct SyntheticCapture {
    width: u32,
    height: u32,
    fps: u32,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

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

impl ScreenCapture for SyntheticCapture {
    fn start(&mut self, sink: EventSink) -> Result<(), CaptureError> {
        let _ = (sink, self.fps, &self.stop, &mut self.thread);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }

    fn output_size(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // test code

    use std::sync::mpsc;

    use remora_capture::{FrameStatus, InterruptReason};
    use remora_codec::SyntheticSource;
    use remora_session::PauseReason;

    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    enum Rec {
        Video { keyframe: bool, ts_us: u64 },
        Capture(CaptureStatus),
    }

    #[derive(Default)]
    struct Recorder(Mutex<Vec<Rec>>);

    impl VideoOut for Recorder {
        fn video(&self, keyframe: bool, capture_ts_us: u64, data: &[u8]) {
            assert!(!data.is_empty());
            self.0.lock().unwrap().push(Rec::Video {
                keyframe,
                ts_us: capture_ts_us,
            });
        }
        fn capture(&self, status: CaptureStatus) {
            self.0.lock().unwrap().push(Rec::Capture(status));
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
                                    delivery_ns: Some(2_000_000),
                                    dirty_rects: Vec::new(),
                                    image: Some(src.next_frame().unwrap()),
                                }));
                                seq += 1;
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        }
                        Step::Interrupt => sink(CaptureEvent::Interrupted(
                            InterruptReason::DisplayUnavailable,
                        )),
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
        let s = Streamer::start(Scripted::new(script), 2_000_000, out).unwrap();
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
        let before = remora_app::clock::monotonic_ns().unwrap() / 1000;
        let (rec, s) = run(vec![Step::Frames(10)]);
        rec.wait_videos(10);
        s.stop();
        let after = remora_app::clock::monotonic_ns().unwrap() / 1000;
        let ts: Vec<u64> = rec
            .all()
            .iter()
            .filter_map(|r| match r {
                Rec::Video { ts_us, .. } => Some(*ts_us),
                Rec::Capture(_) => None,
            })
            .collect();
        // Displayed 2 ms before arrival (the script's delivery_ns).
        for t in &ts {
            assert!(
                (before.saturating_sub(2_000)..=after).contains(t),
                "{t} not in {before}..={after}"
            );
        }
        assert!(ts.windows(2).all(|w| w[0] < w[1]), "increasing: {ts:?}");
    }

    /// T2's open item: "the first frame after resume is a keyframe".
    #[test]
    fn after_capture_resumes_the_first_frame_is_a_keyframe() {
        let (rec, s) = run(vec![
            Step::Frames(20),
            Step::Interrupt,
            Step::Resume,
            Step::Frames(5),
        ]);
        rec.wait_videos(25);
        s.stop();
        let all = rec.all();
        let paused = Rec::Capture(CaptureStatus::Interrupted(PauseReason::DisplayUnavailable));
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
    fn the_synthetic_source_streams_numbered_frames() {
        let rec = Arc::new(Recorder::default());
        let out: Arc<dyn VideoOut> = rec.clone();
        let cap = Box::new(SyntheticCapture::new(W, H, 120));
        let s = Streamer::start(cap, 2_000_000, out).unwrap();
        rec.wait_videos(20);
        s.stop();
        assert!(keyframes(&rec.all())[0]);
    }
}
