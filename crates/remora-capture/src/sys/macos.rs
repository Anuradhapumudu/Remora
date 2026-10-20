//! macOS backend: ScreenCaptureKit (`SCStream`), the current, non-deprecated API
//! on macOS 13–27 (see docs/phase2-criteria.md Q3).
//!
//! Flow: `SCShareableContent` → pick display → `SCContentFilter(display:)` +
//! `SCStreamConfiguration` → `SCStream` with an `SCStreamOutput` handler on a
//! private serial dispatch queue. The handler does the minimum per frame: read
//! the frame-info attachments, retain the `CVPixelBuffer`, call the sink.

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::{DispatchQoS, DispatchQueue, DispatchQueueAttr, DispatchRetained};
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{AllocAnyThread, DefinedClass, define_class, msg_send};
use objc2_core_foundation::{CFArray, CFDictionary, CFNumber, CFRetained, CFType, CGRect};
use objc2_core_graphics::{
    CGDisplayCopyDisplayMode, CGDisplayMode, CGMainDisplayID, CGPreflightScreenCaptureAccess,
    CGRectMakeWithDictionaryRepresentation, CGRequestScreenCaptureAccess,
};
use objc2_core_media::{CMSampleBuffer, CMTime};
use objc2_core_video::{
    CVGetCurrentHostTime, CVGetHostClockFrequency, CVPixelBuffer, CVPixelBufferGetHeight,
    CVPixelBufferGetWidth, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
};
use objc2_foundation::{NSArray, NSError, NSObject, NSObjectProtocol};
use objc2_screen_capture_kit::{
    SCCaptureResolutionType, SCContentFilter, SCDisplay, SCShareableContent, SCStream,
    SCStreamConfiguration, SCStreamDelegate, SCStreamErrorCode, SCStreamFrameInfoDirtyRects,
    SCStreamFrameInfoDisplayTime, SCStreamFrameInfoStatus, SCStreamOutput, SCStreamOutputType,
};

use crate::{
    CaptureConfig, CaptureError, CaptureEvent, CapturedFrame, EventSink, FrameStatus,
    InterruptReason, Rect, ScreenCapture, output_size,
};

/// How long we wait for ScreenCaptureKit's asynchronous calls.
const OS_TIMEOUT: Duration = Duration::from_secs(10);
/// `SCStreamErrorUserDeclined`: the user denied screen-recording permission.
const SC_ERROR_USER_DECLINED: i64 = SCStreamErrorCode::UserDeclined.0 as i64;

/// What a stream-stop error means (phase4-criteria §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopKind {
    /// Retry until the stream starts again.
    Interrupted(InterruptReason),
    /// Give up: [`CaptureEvent::Stopped`].
    Fatal,
}

/// Classifies an `SCStream` stop error code (objc2-screen-capture-kit 0.3.2
/// `SCError.rs` names):
///
/// * `NoCaptureSource` (−3815): display asleep, lid closed, display removed —
///   all three **measured** in Phase 2 (phase2-criteria Q4).
/// * `SystemStoppedStream` (−3821): **unverified**, never observed; treated as
///   recoverable because a wrong retry costs a paused stream while a wrong
///   give-up kills the session.
/// * Anything else (user declined, user stopped from the menu bar, …): fatal.
fn classify_stop(code: i64) -> StopKind {
    let _ = code;
    todo!("phase 4 step 2: written test-first")
}

/// A retained, IOSurface-backed `CVPixelBuffer` holding one captured frame (NV12).
/// Cloning adds a reference; it never copies pixels.
#[derive(Clone)]
pub struct PixelBufferRef(CFRetained<CVPixelBuffer>);

// SAFETY: CVPixelBuffer is a CoreFoundation object: retain/release are atomic, and
// ScreenCaptureKit hands out immutable IOSurface-backed buffers that may be read
// from any thread. This handle never mutates the buffer.
unsafe impl Send for PixelBufferRef {}

impl PixelBufferRef {
    /// Wraps a retained buffer (e.g. a synthetic test frame from a pixel buffer pool).
    pub fn from_retained(buffer: CFRetained<CVPixelBuffer>) -> Self {
        Self(buffer)
    }
    /// The underlying CoreVideo buffer (for the VideoToolbox encoder).
    pub fn as_cv(&self) -> &CVPixelBuffer {
        &self.0
    }
    /// Width in pixels.
    pub fn width(&self) -> u32 {
        u32::try_from(CVPixelBufferGetWidth(&self.0)).unwrap_or(u32::MAX)
    }
    /// Height in pixels.
    pub fn height(&self) -> u32 {
        u32::try_from(CVPixelBufferGetHeight(&self.0)).unwrap_or(u32::MAX)
    }
}

/// Converts mach host-time ticks (the clock ScreenCaptureKit timestamps use) to durations.
#[derive(Clone, Copy)]
struct HostClock {
    nanos_per_tick: f64,
}

impl HostClock {
    fn new() -> Self {
        // Ticks per second (24 MHz on Apple Silicon). Guard against a nonsense value.
        let freq = CVGetHostClockFrequency();
        let nanos_per_tick = if freq.is_finite() && freq > 0.0 {
            1e9 / freq
        } else {
            1.0
        };
        Self { nanos_per_tick }
    }
    fn signed_nanos(self, ticks: i128) -> i64 {
        // `as` saturates for out-of-range floats, so absurd inputs can't wrap.
        (ticks as f64 * self.nanos_per_tick) as i64
    }
}

/// State shared between the stream handler (dispatch-queue thread) and the owner.
struct HandlerIvars {
    sink: Mutex<Option<EventSink>>,
    seq: AtomicU64,
    clock: HostClock,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements and `StreamHandler` does
    // not implement `Drop` (its ivars are dropped by objc2).
    #[unsafe(super(NSObject))]
    #[name = "RemoraStreamHandler"]
    #[ivars = HandlerIvars]
    struct StreamHandler;

    unsafe impl NSObjectProtocol for StreamHandler {}

    unsafe impl SCStreamOutput for StreamHandler {
        #[unsafe(method(stream:didOutputSampleBuffer:ofType:))]
        fn stream_did_output_sample_buffer(
            &self,
            _stream: &SCStream,
            sample_buffer: &CMSampleBuffer,
            kind: SCStreamOutputType,
        ) {
            self.on_sample(sample_buffer, kind);
        }
    }

    unsafe impl SCStreamDelegate for StreamHandler {
        #[unsafe(method(stream:didStopWithError:))]
        fn stream_did_stop(&self, _stream: &SCStream, error: &NSError) {
            let err = ns_error_to_capture("SCStream", error);
            self.emit(CaptureEvent::Stopped(err));
        }
    }
);

impl StreamHandler {
    fn new(sink: EventSink) -> Retained<Self> {
        let this = Self::alloc().set_ivars(HandlerIvars {
            sink: Mutex::new(Some(sink)),
            seq: AtomicU64::new(0),
            clock: HostClock::new(),
        });
        // SAFETY: calling NSObject's designated initializer on a freshly allocated object.
        unsafe { msg_send![super(this), init] }
    }

    fn emit(&self, event: CaptureEvent) {
        // A poisoned lock means a sink panicked earlier; drop events rather than panic again.
        if let Ok(mut guard) = self.ivars().sink.lock()
            && let Some(sink) = guard.as_mut()
        {
            sink(event);
        }
    }

    /// Detaches the sink: after this returns, no further events are delivered.
    fn detach(&self) {
        if let Ok(mut guard) = self.ivars().sink.lock() {
            guard.take();
        }
    }

    /// Hot path: called on our serial dispatch queue for every frame callback.
    fn on_sample(&self, sample_buffer: &CMSampleBuffer, kind: SCStreamOutputType) {
        // Timestamp first, before any other work, so delivery latency is accurate.
        let arrival_ticks = CVGetCurrentHostTime();
        let arrival = Instant::now();
        if kind != SCStreamOutputType::Screen {
            return;
        }
        let ivars = self.ivars();
        let seq = ivars.seq.fetch_add(1, Ordering::Relaxed);
        let info = read_frame_info(sample_buffer);

        // Signed: the display time can be later than our arrival.
        let delivery_ns = info.display_ticks.map(|t| {
            ivars
                .clock
                .signed_nanos(i128::from(arrival_ticks) - i128::from(t))
        });
        let image = if info.status == FrameStatus::Complete {
            // SAFETY: `sample_buffer` is a valid CMSampleBuffer for the duration of
            // this callback; `image_buffer` returns a +1 retained reference.
            unsafe { sample_buffer.image_buffer() }.map(PixelBufferRef)
        } else {
            None
        };
        self.emit(CaptureEvent::Frame(CapturedFrame {
            seq,
            status: info.status,
            arrival,
            delivery_ns,
            dirty_rects: info.dirty_rects,
            image,
        }));
    }
}

struct FrameInfo {
    status: FrameStatus,
    display_ticks: Option<u64>,
    dirty_rects: Vec<Rect>,
}

/// Reads ScreenCaptureKit's per-frame info dictionary. Every value is type-checked
/// before use, so an unexpected type yields "unknown" instead of undefined behaviour.
fn read_frame_info(sample_buffer: &CMSampleBuffer) -> FrameInfo {
    let mut info = FrameInfo {
        status: FrameStatus::Unknown(-1),
        display_ticks: None,
        dirty_rects: Vec::new(),
    };
    // SAFETY: valid sample buffer for the callback's duration; `false` = don't create.
    let Some(attachments) = (unsafe { sample_buffer.sample_attachments_array(false) }) else {
        return info;
    };
    if attachments.count() < 1 {
        return info;
    }
    // SAFETY: index 0 < count; the array (and so the element) stays alive while
    // `attachments` is in scope.
    let Some(dict) = (unsafe { cf_ref(attachments.value_at_index(0)) })
        .and_then(|v| v.downcast_ref::<CFDictionary>())
    else {
        return info;
    };

    // SAFETY: the three statics are Apple-provided constant NSStrings, toll-free
    // bridged to CFString, valid for the whole process lifetime.
    let (status_key, time_key, dirty_key) = unsafe {
        (
            SCStreamFrameInfoStatus,
            SCStreamFrameInfoDisplayTime,
            SCStreamFrameInfoDirtyRects,
        )
    };

    if let Some(n) = dict_get::<CFNumber>(dict, status_key) {
        info.status = match n.as_i64() {
            Some(0) => FrameStatus::Complete,
            Some(1) => FrameStatus::Idle,
            Some(2) => FrameStatus::Blank,
            Some(3) => FrameStatus::Suspended,
            Some(4) => FrameStatus::Started,
            Some(5) => FrameStatus::Stopped,
            Some(other) => FrameStatus::Unknown(other),
            None => FrameStatus::Unknown(-1),
        };
    }
    if let Some(n) = dict_get::<CFNumber>(dict, time_key) {
        info.display_ticks = n.as_i64().and_then(|t| u64::try_from(t).ok());
    }
    if let Some(rects) = dict_get::<CFArray>(dict, dirty_key) {
        let count = usize::try_from(rects.count()).unwrap_or(0);
        info.dirty_rects.reserve_exact(count);
        for i in 0..rects.count() {
            // SAFETY: i < count; element lives as long as `rects`.
            let Some(rd) = (unsafe { cf_ref(rects.value_at_index(i)) })
                .and_then(|v| v.downcast_ref::<CFDictionary>())
            else {
                continue;
            };
            let mut r = CGRect::default();
            // SAFETY: `rd` is a valid CFDictionary and `r` a valid out pointer.
            if unsafe { CGRectMakeWithDictionaryRepresentation(Some(rd), &mut r) } {
                info.dirty_rects.push(Rect {
                    x: r.origin.x,
                    y: r.origin.y,
                    w: r.size.width,
                    h: r.size.height,
                });
            }
        }
    }
    info
}

/// Borrows a CF object from a raw pointer returned by a CF "Get" function.
///
/// # Safety
/// `ptr` must be null or point to a live CF object that outlives the returned reference.
unsafe fn cf_ref<'a>(ptr: *const c_void) -> Option<&'a CFType> {
    // SAFETY: guaranteed by the caller.
    NonNull::new(ptr.cast_mut().cast::<CFType>()).map(|p| unsafe { p.as_ref() })
}

/// Type-checked dictionary lookup with an NSString key (toll-free bridged to CFString).
fn dict_get<'a, T: objc2_core_foundation::ConcreteType>(
    dict: &'a CFDictionary,
    key: &objc2_foundation::NSString,
) -> Option<&'a T> {
    let key_ptr: *const c_void = (key as *const objc2_foundation::NSString).cast();
    // SAFETY: `dict` is a valid CFDictionary; the key is a valid CFString. The value
    // is owned by the dictionary and lives as long as `dict`.
    unsafe { cf_ref(dict.value(key_ptr)) }.and_then(|v| v.downcast_ref::<T>())
}

fn ns_error_to_capture(api: &'static str, err: &NSError) -> CaptureError {
    let code = err.code() as i64;
    if code == SC_ERROR_USER_DECLINED {
        return CaptureError::PermissionDenied;
    }
    CaptureError::Os {
        api,
        code,
        message: err.localizedDescription().to_string(),
    }
}

/// Moves a value across threads for one hand-off from a completion block.
struct SendOnce<T>(T);
// SAFETY: used only to pass ScreenCaptureKit result objects (immutable snapshots:
// `SCShareableContent`) or `NSError`s from the completion-handler thread to the
// thread waiting on the channel; the sender never touches the value afterwards.
unsafe impl<T> Send for SendOnce<T> {}

fn shareable_content() -> Result<Retained<SCShareableContent>, CaptureError> {
    let (tx, rx) =
        mpsc::sync_channel::<SendOnce<Result<Retained<SCShareableContent>, CaptureError>>>(1);
    let block = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: ScreenCaptureKit passes valid (possibly null) object pointers that
            // are alive for the duration of the block; `retain` takes our own reference.
            let result = match unsafe { (Retained::retain(content), Retained::retain(error)) } {
                (Some(c), _) => Ok(c),
                (None, Some(e)) => Err(ns_error_to_capture("SCShareableContent", &e)),
                (None, None) => Err(CaptureError::NoDisplay),
            };
            let _ = tx.try_send(SendOnce(result));
        },
    );
    // SAFETY: `block` matches the documented completion-handler signature.
    unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&block) };
    rx.recv_timeout(OS_TIMEOUT)
        .map_err(|_| CaptureError::Timeout("SCShareableContent"))?
        .0
}

/// Waits for a `(NSError?) -> ()` completion handler.
fn wait_completion(
    api: &'static str,
    call: impl FnOnce(&block2::DynBlock<dyn Fn(*mut NSError)>),
) -> Result<(), CaptureError> {
    let (tx, rx) = mpsc::sync_channel::<SendOnce<Option<Retained<NSError>>>>(1);
    let block = RcBlock::new(move |error: *mut NSError| {
        // SAFETY: valid (possibly null) NSError pointer for the block's duration.
        let _ = tx.try_send(SendOnce(unsafe { Retained::retain(error) }));
    });
    call(&block);
    match rx
        .recv_timeout(OS_TIMEOUT)
        .map_err(|_| CaptureError::Timeout(api))?
        .0
    {
        None => Ok(()),
        Some(e) => Err(ns_error_to_capture(api, &e)),
    }
}

/// All displays ScreenCaptureKit can capture. Requests permission (system
/// prompt, once) and fails with `PermissionDenied` if it isn't granted.
fn shareable_displays() -> Result<Retained<NSArray<SCDisplay>>, CaptureError> {
    if !CGPreflightScreenCaptureAccess() {
        // Shows the system prompt (once) and adds this app to the Screen
        // Recording list; the grant only takes effect for a new process.
        CGRequestScreenCaptureAccess();
        return Err(CaptureError::PermissionDenied);
    }
    // SAFETY: property getter on a valid object.
    Ok(unsafe { shareable_content()?.displays() })
}

/// Pixel size of a display's current mode (not its size in points).
fn display_pixel_size(display: &SCDisplay) -> (u32, u32) {
    // SAFETY: plain property getters on a valid SCDisplay.
    let id = unsafe { display.displayID() };
    let mode = CGDisplayCopyDisplayMode(id);
    let (w, h) = (
        CGDisplayMode::pixel_width(mode.as_deref()),
        CGDisplayMode::pixel_height(mode.as_deref()),
    );
    if w > 0 && h > 0 {
        (
            u32::try_from(w).unwrap_or(u32::MAX),
            u32::try_from(h).unwrap_or(u32::MAX),
        )
    } else {
        // SAFETY: plain property getters (points, used only as a fallback).
        let (w, h) = unsafe { (display.width(), display.height()) };
        (
            u32::try_from(w).unwrap_or(u32::MAX),
            u32::try_from(h).unwrap_or(u32::MAX),
        )
    }
}

/// ScreenCaptureKit capture of one display.
pub struct MacScreenCapture {
    cfg: CaptureConfig,
    size: (u32, u32),
    display: Retained<SCDisplay>,
    running: Option<Running>,
}

struct Running {
    stream: Retained<SCStream>,
    handler: Retained<StreamHandler>,
    // Keeps the queue alive while the stream may still dispatch to it.
    _queue: DispatchRetained<DispatchQueue>,
}

// SAFETY: `MacScreenCapture` is only used through `&mut self`, so calls into
// SCStream are serialized. ScreenCaptureKit objects may be messaged from any
// thread (Apple's own samples drive SCStream from Swift concurrency tasks); the
// handler's shared state is behind a Mutex/atomics.
unsafe impl Send for MacScreenCapture {}

impl MacScreenCapture {
    /// Prepares capture of the main display. Fails fast if permission is missing.
    pub fn main_display(cfg: CaptureConfig) -> Result<Self, CaptureError> {
        Self::display(cfg, None)
    }

    /// Prepares capture of display `id` (a `CGDirectDisplayID`), or the main
    /// display when `None`.
    pub fn display(cfg: CaptureConfig, id: Option<u32>) -> Result<Self, CaptureError> {
        let displays = shareable_displays()?;
        let wanted = id.unwrap_or_else(|| CGMainDisplayID());
        let display = displays
            .iter()
            // SAFETY: property getter on a valid SCDisplay.
            .find(|d| unsafe { d.displayID() } == wanted)
            .or_else(|| {
                if id.is_none() {
                    displays.firstObject()
                } else {
                    None
                }
            })
            .ok_or(CaptureError::NoDisplay)?;
        let (pw, ph) = display_pixel_size(&display);
        Ok(Self {
            size: output_size(&cfg, pw, ph),
            cfg,
            display,
            running: None,
        })
    }

    /// Lists capturable displays: `(id, width_px, height_px, is_main)`.
    pub fn list_displays() -> Result<Vec<(u32, u32, u32, bool)>, CaptureError> {
        let main_id = CGMainDisplayID();
        Ok(shareable_displays()?
            .iter()
            .map(|d| {
                // SAFETY: property getter on a valid SCDisplay.
                let id = unsafe { d.displayID() };
                let (w, h) = display_pixel_size(&d);
                (id, w, h, id == main_id)
            })
            .collect())
    }

    /// The display's native size in pixels.
    pub fn display_pixel_size(&self) -> (u32, u32) {
        display_pixel_size(&self.display)
    }

    fn configuration(&self) -> Retained<SCStreamConfiguration> {
        let fps = i32::try_from(self.cfg.max_fps.clamp(1, 240)).unwrap_or(60);
        // SAFETY: freshly created configuration object; setters take plain values.
        unsafe {
            let c = SCStreamConfiguration::new();
            c.setWidth(self.size.0 as usize);
            c.setHeight(self.size.1 as usize);
            c.setPixelFormat(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange);
            // Interval of 1/(fps+1), not 1/fps: with exactly 1/fps, display timing
            // jitter makes ScreenCaptureKit skip frames that arrive a hair early
            // (measured: 57.2 instead of 60 fps). The display's own refresh rate still
            // caps delivery, and on faster displays every other frame still fits.
            c.setMinimumFrameInterval(CMTime::new(1, fps + 1));
            c.setQueueDepth(self.cfg.queue_depth.clamp(3, 8) as isize);
            c.setShowsCursor(self.cfg.show_cursor);
            // Capture at full pixel resolution, then scale (sharper text).
            c.setCaptureResolution(SCCaptureResolutionType::Best);
            c
        }
    }
}

impl ScreenCapture for MacScreenCapture {
    fn start(&mut self, sink: EventSink) -> Result<(), CaptureError> {
        if self.running.is_some() {
            return Err(CaptureError::InvalidState("already running"));
        }
        let config = self.configuration();
        // SAFETY: valid display; empty exclusion array.
        let filter = unsafe {
            SCContentFilter::initWithDisplay_excludingWindows(
                SCContentFilter::alloc(),
                &self.display,
                &NSArray::new(),
            )
        };
        let handler = StreamHandler::new(sink);
        let delegate = ProtocolObject::<dyn SCStreamDelegate>::from_ref(&*handler);
        // SAFETY: valid filter/config; the delegate is retained by us for the
        // stream's lifetime (`Running::handler`).
        let stream = unsafe {
            SCStream::initWithFilter_configuration_delegate(
                SCStream::alloc(),
                &filter,
                &config,
                Some(delegate),
            )
        };
        // Frames are latency-critical: user-interactive QoS. The QoS must be part of
        // the queue's attributes at creation — libdispatch traps if a queue's
        // properties are changed after it is active.
        let attr = DispatchQueueAttr::with_qos_class(
            DispatchQueueAttr::SERIAL,
            DispatchQoS::UserInteractive,
            0,
        );
        let queue = DispatchQueue::new("dev.remora.capture", Some(&attr));
        let output = ProtocolObject::<dyn SCStreamOutput>::from_ref(&*handler);
        // SAFETY: valid stream, output and queue; all retained in `Running`.
        unsafe {
            stream.addStreamOutput_type_sampleHandlerQueue_error(
                output,
                SCStreamOutputType::Screen,
                Some(&queue),
            )
        }
        .map_err(|e| ns_error_to_capture("SCStream.addStreamOutput", &e))?;
        // SAFETY: the block matches the completion-handler signature.
        wait_completion("SCStream.startCapture", |b| unsafe {
            stream.startCaptureWithCompletionHandler(Some(b))
        })
        .inspect_err(|_| handler.detach())?;
        self.running = Some(Running {
            stream,
            handler,
            _queue: queue,
        });
        Ok(())
    }

    fn stop(&mut self) -> Result<(), CaptureError> {
        let Some(running) = self.running.take() else {
            return Err(CaptureError::InvalidState("not running"));
        };
        // SAFETY: the block matches the completion-handler signature.
        let result = wait_completion("SCStream.stopCapture", |b| unsafe {
            running.stream.stopCaptureWithCompletionHandler(Some(b))
        });
        running.handler.detach();
        result
    }

    fn output_size(&self) -> (u32, u32) {
        self.size
    }
}

impl Drop for MacScreenCapture {
    fn drop(&mut self) {
        if self.running.is_some() {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod stop_tests {
    use super::*;

    #[test]
    fn display_gone_is_an_interruption_and_permission_loss_is_fatal() {
        assert_eq!(
            classify_stop(-3815),
            StopKind::Interrupted(InterruptReason::DisplayUnavailable)
        );
        assert_eq!(
            classify_stop(-3821),
            StopKind::Interrupted(InterruptReason::Other)
        );
        for fatal in [-3801, -3802, -3817, 0, 1, i64::MIN] {
            assert_eq!(classify_stop(fatal), StopKind::Fatal, "{fatal}");
        }
        // The names we rely on still mean the numbers Phase 2 measured.
        assert_eq!(SCStreamErrorCode::NoCaptureSource.0, -3815);
        assert_eq!(SCStreamErrorCode::SystemStoppedStream.0, -3821);
    }
}
