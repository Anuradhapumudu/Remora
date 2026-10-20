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
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 0,
            max_fps: 60,
            show_cursor: false,
            queue_depth: 3,
        }
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
