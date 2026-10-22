//! Remora screen capture: a [`ScreenCapture`] trait with per-OS backends.
//!
//! The backend pushes [`CaptureEvent`]s into a caller-supplied sink on its own
//! thread. Frames are never queued here: if the consumer is slow, the OS drops
//! frames rather than building latency (architecture.md §3).
//!
//! OS code lives in `src/sys/<os>.rs`; nothing outside it touches FFI.

// `unsafe_code` is denied workspace-wide. Only the OS FFI modules under
// `src/sys/` may opt in with `#[allow(unsafe_code)]`, and every unsafe block
// needs a `// SAFETY:` comment (architecture.md §4).

use std::time::{Duration, Instant};

mod sys;

#[cfg(target_os = "macos")]
pub use sys::macos::{MacScreenCapture, PixelBufferRef};

/// What to capture and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Output width in pixels (even). The display is scaled to this width.
    pub width: u32,
    /// Output height in pixels (even), or `0` to keep the display's aspect ratio.
    pub height: u32,
    /// Upper bound on delivered frames per second.
    pub max_fps: u32,
    /// Draw the cursor into the frames. Remora sends the cursor separately, so
    /// this is normally `false`.
    pub show_cursor: bool,
    /// Number of surfaces the OS may have in flight (ScreenCaptureKit: 3..=8).
    pub queue_depth: u32,
    /// How long an interrupted capture waits for a **removed** display to
    /// come back before it stops ([`DISPLAY_GONE_LIMIT`]; shorter in tests).
    pub display_gone_limit: Duration,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 0,
            max_fps: 60,
            show_cursor: false,
            queue_depth: 3,
            display_gone_limit: DISPLAY_GONE_LIMIT,
        }
    }
}

/// How long capture waits for a removed display to come back, then stops
/// with [`CaptureError::DisplayRemoved`] (roadmap D-29, architecture D38:
/// a loose cable or a dock reconnect, not days later).
pub const DISPLAY_GONE_LIMIT: Duration = Duration::from_secs(120);

/// Times how long the captured display has been **missing** while an
/// interrupted capture retries (D-29). Missing means not in the OS's list
/// of displays: a removed display. A display that is listed but asleep
/// (lid closed, display sleep) does not count — that wait is ended by the
/// session's liveness check when the Mac itself sleeps (D37), or never
/// while the Mac is awake and someone may wake the display.
#[derive(Debug, Clone, Copy)]
pub struct GoneTimer {
    limit: Duration,
    since: Option<Instant>,
}

impl GoneTimer {
    /// A timer that expires after the display was missing for `limit`.
    pub fn new(limit: Duration) -> Self {
        Self { limit, since: None }
    }

    /// One retry's observation at `now`: is the display listed? Returns
    /// `true` once it has been missing for the limit: capture must stop.
    pub fn expired(&mut self, listed: bool, now: Instant) -> bool {
        if listed {
            self.since = None;
            return false;
        }
        let since = *self.since.get_or_insert(now);
        now.saturating_duration_since(since) >= self.limit
    }
}

/// Output size for a `display_w × display_h` display captured at `cfg`:
/// keeps the aspect ratio when `cfg.height == 0`, never upscales, and rounds
/// both sides down to even numbers (4:2:0 chroma needs even dimensions).
pub fn output_size(cfg: &CaptureConfig, display_w: u32, display_h: u32) -> (u32, u32) {
    let even = |v: u32| (v & !1).max(2);
    let w = cfg.width.min(display_w).max(2);
    let h = if cfg.height == 0 {
        // u64 avoids overflow for large displays; rounding to nearest.
        ((u64::from(w) * u64::from(display_h) + u64::from(display_w) / 2) / u64::from(display_w))
            as u32
    } else {
        cfg.height.min(display_h)
    };
    (even(w), even(h))
}

/// Why the OS delivered a callback (ScreenCaptureKit's `SCFrameStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameStatus {
    /// New content: the frame carries an image.
    Complete,
    /// Nothing changed since the previous frame; no image.
    Idle,
    /// The display produced a blank frame.
    Blank,
    /// Capture is suspended (e.g. display asleep).
    Suspended,
    /// First callback after start.
    Started,
    /// Capture stopped.
    Stopped,
    /// A value this build doesn't know.
    Unknown(i64),
}

/// An axis-aligned rectangle in output pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    /// Left edge.
    pub x: f64,
    /// Top edge.
    pub y: f64,
    /// Width.
    pub w: f64,
    /// Height.
    pub h: f64,
}

/// One callback from the capture backend.
pub struct CapturedFrame {
    /// Callback counter since start (includes idle callbacks).
    pub seq: u64,
    /// Why this callback happened.
    pub status: FrameStatus,
    /// When our handler received it.
    pub arrival: Instant,
    /// `arrival − display time` in nanoseconds, where the display time is the OS
    /// compositor's timestamp for this content. **Negative** if the frame reached
    /// us before that time; `None` if the OS gave no timestamp.
    pub delivery_ns: Option<i64>,
    /// Regions that changed since the previous frame (empty if unknown).
    pub dirty_rects: Vec<Rect>,
    /// The image, present for [`FrameStatus::Complete`] frames.
    #[cfg(target_os = "macos")]
    pub image: Option<PixelBufferRef>,
}

impl CapturedFrame {
    /// The compositor's display time as an `Instant` (falls back to `arrival`).
    /// Use it as the frame's presentation timestamp.
    pub fn display_time(&self) -> Instant {
        match self.delivery_ns {
            Some(ns) if ns >= 0 => self
                .arrival
                .checked_sub(Duration::from_nanos(ns.unsigned_abs()))
                .unwrap_or(self.arrival),
            Some(ns) => self.arrival + Duration::from_nanos(ns.unsigned_abs()),
            None => self.arrival,
        }
    }
}

impl std::fmt::Debug for CapturedFrame {
    // Deliberately omits pixel data (threat model INV9: never log screen content).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedFrame")
            .field("seq", &self.seq)
            .field("status", &self.status)
            .field("delivery_ns", &self.delivery_ns)
            .field("dirty_rects", &self.dirty_rects.len())
            .finish_non_exhaustive()
    }
}

/// Why capture paused (OS-neutral; each backend maps its own errors here,
/// so nothing above the trait needs to know the OS — architecture D17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterruptReason {
    /// The display is asleep, closed or gone.
    DisplayUnavailable,
    /// The OS took the capture surface away (Windows: ACCESS_LOST).
    AccessLost,
    /// Another interruption the backend expects to recover from.
    Other,
}

/// Something the capture backend reports.
#[derive(Debug)]
pub enum CaptureEvent {
    /// A frame callback.
    Frame(CapturedFrame),
    /// Capture paused but is expected to come back: the backend keeps
    /// retrying on its own and sends [`CaptureEvent::Resumed`] when frames
    /// flow again.
    Interrupted(InterruptReason),
    /// Frames flow again after [`CaptureEvent::Interrupted`]. The next
    /// encoded frame must be a keyframe.
    Resumed,
    /// Capture will not come back without user action (permission revoked,
    /// the user stopped it from the system UI, …).
    Stopped(CaptureError),
}

/// Receives capture events on the backend's thread. Must return quickly.
pub type EventSink = Box<dyn FnMut(CaptureEvent) + Send + 'static>;

/// Capture failures.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// The user hasn't granted screen-recording permission.
    #[error(
        "screen recording permission denied — enable it in System Settings → Privacy & Security"
    )]
    PermissionDenied,
    /// No display to capture.
    #[error("no display found")]
    NoDisplay,
    /// The captured display was removed and did not come back in time
    /// ([`DISPLAY_GONE_LIMIT`]). Capture never moves to another display.
    #[error("the captured display was removed and did not come back")]
    DisplayRemoved,
    /// The capture is already running / not running.
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
    /// An error from the operating system.
    #[error("{api} failed: {message} (code {code})")]
    Os {
        /// Which OS call failed.
        api: &'static str,
        /// OS error code.
        code: i64,
        /// OS error description.
        message: String,
    },
    /// The OS didn't answer in time.
    #[error("{0} timed out")]
    Timeout(&'static str),
    /// Not implemented on this OS yet.
    #[error("screen capture is not supported on this platform yet")]
    Unsupported,
}

/// A source of screen frames.
pub trait ScreenCapture: Send {
    /// Starts capturing; events go to `sink` until [`stop`](Self::stop).
    fn start(&mut self, sink: EventSink) -> Result<(), CaptureError>;
    /// Stops capturing and waits until no more events will be delivered.
    fn stop(&mut self) -> Result<(), CaptureError>;
    /// The output frame size actually in use.
    fn output_size(&self) -> (u32, u32);
}

#[cfg(test)]
mod tests {
    /// D-29: missing for the limit (and only then) stops capture; the
    /// display coming back resets the wait.
    #[test]
    fn d29_a_missing_display_is_waited_for_then_given_up() {
        let t0 = Instant::now();
        let s = |secs: u64| t0 + Duration::from_secs(secs);
        let mut t = GoneTimer::new(Duration::from_secs(120));
        assert!(!t.expired(true, s(0)), "listed: nothing to time");
        assert!(!t.expired(false, s(10)), "missing from 10 s");
        assert!(!t.expired(false, s(129)), "119 s missing");
        assert!(t.expired(false, s(130)), "120 s missing: give up");
        // Back in time: the wait starts again from the next absence.
        let mut t = GoneTimer::new(Duration::from_secs(120));
        assert!(!t.expired(false, s(0)));
        assert!(!t.expired(true, s(100)), "back after 100 s");
        assert!(!t.expired(false, s(200)), "missing again from 200 s");
        assert!(!t.expired(false, s(319)));
        assert!(t.expired(false, s(320)));
    }

    #[test]
    fn d29_a_listed_but_sleeping_display_never_expires() {
        let t0 = Instant::now();
        let mut t = GoneTimer::new(Duration::from_secs(120));
        for h in 0..24 {
            assert!(!t.expired(true, t0 + Duration::from_secs(h * 3600)));
        }
        assert_eq!(
            CaptureConfig::default().display_gone_limit,
            DISPLAY_GONE_LIMIT
        );
        assert_eq!(DISPLAY_GONE_LIMIT, Duration::from_secs(120));
    }

    /// N4 (phase4-criteria §6, INV9): a captured frame's `Debug` names
    /// exactly these fields — the image is never among them.
    #[test]
    fn n4_captured_frame_debug_never_shows_the_image() {
        let f = CapturedFrame {
            seq: 3,
            status: FrameStatus::Complete,
            arrival: Instant::now(),
            delivery_ns: Some(5),
            dirty_rects: vec![Rect {
                x: 1.0,
                y: 2.0,
                w: 3.0,
                h: 4.0,
            }],
            #[cfg(target_os = "macos")]
            image: None,
        };
        assert_eq!(
            format!("{f:?}"),
            "CapturedFrame { seq: 3, status: Complete, delivery_ns: Some(5), dirty_rects: 1, .. }"
        );
    }

    use super::*;

    fn cfg(width: u32, height: u32) -> CaptureConfig {
        CaptureConfig {
            width,
            height,
            ..CaptureConfig::default()
        }
    }

    #[test]
    fn keeps_aspect_ratio_of_macbook_air_panel() {
        // 2560×1664 at 1920 wide → 1248 (exact).
        assert_eq!(output_size(&cfg(1920, 0), 2560, 1664), (1920, 1248));
    }

    #[test]
    fn never_upscales_and_stays_even() {
        assert_eq!(output_size(&cfg(4000, 0), 1366, 768), (1366, 768));
        assert_eq!(output_size(&cfg(1001, 0), 1920, 1080), (1000, 562));
        assert_eq!(output_size(&cfg(1920, 1081), 1920, 1080), (1920, 1080));
    }

    #[test]
    fn tiny_or_degenerate_sizes_stay_valid() {
        assert_eq!(output_size(&cfg(0, 0), 1920, 1080), (2, 2));
        assert_eq!(output_size(&cfg(1, 1), 1, 1), (2, 2));
    }
}
