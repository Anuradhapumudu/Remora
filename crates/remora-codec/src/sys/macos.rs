//! macOS backend: VideoToolbox hardware encoder and decoder.
//!
//! Configuration follows Apple's documented recipe for "ultra-low-latency
//! conferencing and cloud gaming" (VTCompressionProperties.h, SDK 27):
//! `EnableLowLatencyRateControl`, `RealTime`, `ExpectedFrameRate`,
//! `PrioritizeEncodingSpeedOverQuality`; plus no frame reordering (no B-frames).

use std::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use objc2_core_foundation::{
    CFArray, CFBoolean, CFDictionary, CFNumber, CFRetained, CFString, CFType,
};
use objc2_core_media::{
    CMBlockBuffer, CMFormatDescription, CMSampleBuffer, CMTime, CMVideoCodecType,
    CMVideoFormatDescriptionCreateFromH264ParameterSets,
    CMVideoFormatDescriptionGetH264ParameterSetAtIndex,
    CMVideoFormatDescriptionGetHEVCParameterSetAtIndex, kCMBlockBufferAssureMemoryNowFlag,
    kCMSampleAttachmentKey_NotSync, kCMTimeInvalid, kCMVideoCodecType_H264, kCMVideoCodecType_HEVC,
};
use objc2_core_video::{
    CVImageBuffer, CVPixelBuffer, CVPixelBufferCreate, CVPixelBufferGetBaseAddressOfPlane,
    CVPixelBufferGetBytesPerRowOfPlane, CVPixelBufferGetHeightOfPlane, CVPixelBufferGetWidth,
    CVPixelBufferLockBaseAddress, CVPixelBufferLockFlags, CVPixelBufferPool,
    CVPixelBufferUnlockBaseAddress, kCVPixelBufferHeightKey, kCVPixelBufferIOSurfacePropertiesKey,
    kCVPixelBufferPixelFormatTypeKey, kCVPixelBufferWidthKey,
    kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
    kCVPixelFormatType_444YpCbCr8BiPlanarVideoRange,
};
use objc2_video_toolbox::{
    VTCompressionSession, VTCopyVideoEncoderList, VTDecodeFrameFlags, VTDecodeInfoFlags,
    VTDecompressionOutputCallbackRecord, VTDecompressionSession, VTEncodeInfoFlags,
    VTSessionCopySupportedPropertyDictionary, VTSessionSetProperty,
    kVTCompressionPropertyKey_AllowFrameReordering, kVTCompressionPropertyKey_AverageBitRate,
    kVTCompressionPropertyKey_EnableLTR, kVTCompressionPropertyKey_ExpectedFrameRate,
    kVTCompressionPropertyKey_MaxKeyFrameInterval,
    kVTCompressionPropertyKey_PrioritizeEncodingSpeedOverQuality,
    kVTCompressionPropertyKey_ProfileLevel, kVTCompressionPropertyKey_RealTime,
    kVTDecompressionPropertyKey_RealTime, kVTEncodeFrameOptionKey_ForceKeyFrame,
    kVTProfileLevel_H264_ConstrainedBaseline_AutoLevel,
    kVTProfileLevel_H264_ConstrainedHigh_AutoLevel, kVTProfileLevel_HEVC_Main_AutoLevel,
    kVTPropertySupportedValueListKey, kVTVideoEncoderList_CodecType,
    kVTVideoEncoderList_DisplayName, kVTVideoEncoderList_EncoderID,
    kVTVideoEncoderList_IsHardwareAccelerated,
    kVTVideoEncoderSpecification_EnableLowLatencyRateControl,
    kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder,
};
use remora_capture::PixelBufferRef;

use crate::bitstream::{
    ProfileInfo, START_CODE, h264_sps_profile, hevc_sps_profile, length_prefixed_to_annexb,
};
use crate::h264::{DecodeGate, SizeLimit, SpsInfo};
use crate::{
    Codec, CodecError, DecodeError, DecodeStats, EncodedFrame, EncoderConfig, EncoderEvent,
    EncoderSink, H264Profile, TuneValue,
};

/// Submit timestamps are kept for this many in-flight frames (power of two).
const SUBMIT_RING: usize = 256;

fn os(api: &'static str, status: i32) -> Result<(), CodecError> {
    if status == 0 {
        Ok(())
    } else {
        Err(CodecError::Os { api, status })
    }
}

fn codec_type(codec: Codec) -> CMVideoCodecType {
    match codec {
        Codec::H264 => kCMVideoCodecType_H264,
        Codec::Hevc => kCMVideoCodecType_HEVC,
    }
}

/// State shared with VideoToolbox's output callback (passed as its refcon).
struct Shared {
    codec: Codec,
    base: Instant,
    submit_ns: [AtomicU64; SUBMIT_RING],
    sink: Mutex<EncoderSink>,
}

impl Shared {
    fn emit(&self, event: EncoderEvent) {
        if let Ok(mut sink) = self.sink.lock() {
            sink(event);
        }
    }
}

/// Hardware H.264/HEVC encoder backed by a `VTCompressionSession`.
pub struct VtEncoder {
    session: CFRetained<VTCompressionSession>,
    // Boxed so its address is stable: VideoToolbox holds a raw pointer to it
    // until the session is invalidated in `Drop`.
    shared: Box<Shared>,
    force_keyframe_props: CFRetained<CFDictionary<CFString, CFType>>,
    frame_duration: CMTime,
    keyframe_interval: u64,
    next_seq: u64,
    /// Which optional properties the encoder accepted / rejected.
    report: Vec<(String, bool)>,
}

// SAFETY: VTCompressionSession is thread-safe for encode/complete/invalidate
// (Apple documents encoding from capture callbacks on arbitrary queues). We
// only call it through `&mut self`, and `Shared` is Sync (Mutex + atomics).
unsafe impl Send for VtEncoder {}

/// Sets one session property; returns whether the encoder accepted it.
fn set_prop(session: &VTCompressionSession, key: &CFString, value: &CFType) -> bool {
    // SAFETY: valid session (a VTSession is a CFType), key and value.
    unsafe { VTSessionSetProperty(session, key, Some(value)) == 0 }
}

impl VtEncoder {
    /// Creates a hardware H.264 encoder (fails if no hardware encoder exists).
    pub fn new(cfg: EncoderConfig, sink: EncoderSink) -> Result<Self, CodecError> {
        Self::with_codec(Codec::H264, cfg, sink, &[])
    }

    /// Creates a hardware encoder for `codec`. `tuning` sets extra VideoToolbox
    /// session properties by name (developer experiments; each one's acceptance
    /// is recorded in [`property_report`](Self::property_report)).
    pub fn with_codec(
        codec: Codec,
        cfg: EncoderConfig,
        sink: EncoderSink,
        tuning: &[(String, TuneValue)],
    ) -> Result<Self, CodecError> {
        let shared = Box::new(Shared {
            codec,
            base: Instant::now(),
            submit_ns: std::array::from_fn(|_| AtomicU64::new(0)),
            sink: Mutex::new(sink),
        });
        let session = create_session(
            codec,
            cfg.width,
            cfg.height,
            None,
            true,
            Some((&*shared as *const Shared).cast_mut().cast()),
        )?;

        let fps = cfg.fps.clamp(1, 240);
        let mut report = Vec::new();
        // Required: real-time, no reordering. Failure here means we can't meet our design.
        let t: &CFType = CFBoolean::new(true);
        let f: &CFType = CFBoolean::new(false);
        // SAFETY: the key statics are Apple constants valid for the process lifetime.
        let (k_rt, k_reorder) = unsafe {
            (
                kVTCompressionPropertyKey_RealTime,
                kVTCompressionPropertyKey_AllowFrameReordering,
            )
        };
        if !set_prop(&session, k_rt, t) || !set_prop(&session, k_reorder, f) {
            return Err(CodecError::Unsupported(
                "real-time encoding without frame reordering",
            ));
        }
        // Recommended / optional: record acceptance for the report.
        // SAFETY: Apple constant keys/values valid for the process lifetime.
        let optional: [(&'static str, &CFString, CFRetained<CFType>); 5] = unsafe {
            [
                (
                    "ExpectedFrameRate",
                    kVTCompressionPropertyKey_ExpectedFrameRate,
                    CFNumber::new_i32(fps as i32).into(),
                ),
                (
                    "PrioritizeEncodingSpeedOverQuality",
                    kVTCompressionPropertyKey_PrioritizeEncodingSpeedOverQuality,
                    CFRetained::from(t),
                ),
                (
                    "AverageBitRate",
                    kVTCompressionPropertyKey_AverageBitRate,
                    CFNumber::new_i64(i64::from(cfg.bitrate_bps)).into(),
                ),
                (
                    "MaxKeyFrameInterval",
                    kVTCompressionPropertyKey_MaxKeyFrameInterval,
                    CFNumber::new_i32(if cfg.keyframe_interval == 0 {
                        i32::MAX
                    } else {
                        cfg.keyframe_interval.min(i32::MAX as u32) as i32
                    })
                    .into(),
                ),
                (
                    "ProfileLevel",
                    kVTCompressionPropertyKey_ProfileLevel,
                    CFRetained::from(match (codec, cfg.profile) {
                        (Codec::H264, H264Profile::ConstrainedBaseline) => {
                            kVTProfileLevel_H264_ConstrainedBaseline_AutoLevel
                        }
                        (Codec::H264, H264Profile::ConstrainedHigh) => {
                            kVTProfileLevel_H264_ConstrainedHigh_AutoLevel
                        }
                        // HEVC: Main (4:2:0, 8-bit); the H.264 profile choice doesn't apply.
                        (Codec::Hevc, _) => kVTProfileLevel_HEVC_Main_AutoLevel,
                    } as &CFType),
                ),
            ]
        };
        for (name, key, value) in &optional {
            report.push(((*name).to_owned(), set_prop(&session, key, value)));
        }
        if cfg.enable_ltr {
            // SAFETY: Apple constant key.
            report.push((
                "EnableLTR".to_owned(),
                set_prop(&session, unsafe { kVTCompressionPropertyKey_EnableLTR }, t),
            ));
        }
        for (name, value) in tuning {
            let v: CFRetained<CFType> = match *value {
                TuneValue::Bool(b) => CFRetained::from(CFBoolean::new(b) as &CFType),
                TuneValue::Int(i) => CFNumber::new_i64(i).into(),
                TuneValue::Float(x) => CFNumber::new_f64(x).into(),
            };
            report.push((
                name.clone(),
                set_prop(&session, &CFString::from_str(name), &v),
            ));
        }
        // SAFETY: valid session.
        os("VTCompressionSessionPrepareToEncodeFrames", unsafe {
            session.prepare_to_encode_frames()
        })?;

        // SAFETY: Apple constant key.
        let k_force = unsafe { kVTEncodeFrameOptionKey_ForceKeyFrame };
        let force_keyframe_props = CFDictionary::<CFString, CFType>::from_slices(&[k_force], &[t]);
        Ok(Self {
            session,
            shared,
            force_keyframe_props,
            // SAFETY: plain constructor.
            frame_duration: unsafe { CMTime::new(1, fps as i32) },
            keyframe_interval: u64::from(cfg.keyframe_interval),
            next_seq: 0,
            report,
        })
    }

    /// Optional properties and whether this encoder accepted each one.
    pub fn property_report(&self) -> &[(String, bool)] {
        &self.report
    }

    /// Submits a frame. Returns its sequence number; the result arrives via the sink.
    pub fn encode(
        &mut self,
        image: &PixelBufferRef,
        timestamp: Duration,
        force_keyframe: bool,
    ) -> Result<u64, CodecError> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let keyframe = force_keyframe
            || (self.keyframe_interval > 0 && seq.is_multiple_of(self.keyframe_interval));
        let submitted = self.shared.base.elapsed().as_nanos() as u64;
        self.shared.submit_ns[seq as usize % SUBMIT_RING].store(submitted, Ordering::Relaxed);
        let micros = i64::try_from(timestamp.as_micros()).unwrap_or(i64::MAX);
        let mut flags = VTEncodeInfoFlags(0);
        // SAFETY: valid session and pixel buffer; `seq` is smuggled through the
        // refcon pointer as an integer (never dereferenced); `flags` is a valid out pointer.
        let status = unsafe {
            self.session.encode_frame(
                image.as_cv(),
                CMTime::new(micros, 1_000_000),
                self.frame_duration,
                keyframe.then(|| self.force_keyframe_props.as_opaque()),
                seq as usize as *mut c_void,
                &mut flags,
            )
        };
        os("VTCompressionSessionEncodeFrame", status)?;
        Ok(seq)
    }

    /// Blocks until every submitted frame has been delivered to the sink.
    pub fn flush(&mut self) -> Result<(), CodecError> {
        // SAFETY: valid session; kCMTimeInvalid = complete all frames.
        os("VTCompressionSessionCompleteFrames", unsafe {
            self.session.complete_frames(kCMTimeInvalid)
        })
    }
}

impl Drop for VtEncoder {
    fn drop(&mut self) {
        // SAFETY: valid session. After `invalidate` returns, VideoToolbox makes no
        // further callbacks, so freeing `shared` afterwards (field drop) is sound.
        unsafe {
            let _ = self.session.complete_frames(kCMTimeInvalid);
            self.session.invalidate();
        }
    }
}

/// Creates a compression session. `refcon = None` creates a probe session with no callback.
fn create_session(
    codec: Codec,
    width: u32,
    height: u32,
    source_format: Option<u32>,
    low_latency: bool,
    refcon: Option<*mut c_void>,
) -> Result<CFRetained<VTCompressionSession>, CodecError> {
    let t: &CFType = CFBoolean::new(true);
    // SAFETY: Apple constant keys.
    let (k_ll, k_hw) = unsafe {
        (
            kVTVideoEncoderSpecification_EnableLowLatencyRateControl,
            kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder,
        )
    };
    let spec = if low_latency {
        CFDictionary::<CFString, CFType>::from_slices(&[k_ll, k_hw], &[t, t])
    } else {
        CFDictionary::<CFString, CFType>::from_slices(&[k_hw], &[t])
    };
    let source_attrs = source_format.map(|fmt| {
        // SAFETY: Apple constant key.
        let k_fmt = unsafe { kCVPixelBufferPixelFormatTypeKey };
        CFDictionary::<CFString, CFType>::from_slices(&[k_fmt], &[&*CFNumber::new_i32(fmt as i32)])
    });
    let mut out: *mut VTCompressionSession = ptr::null_mut();
    // SAFETY: all dictionaries are valid; the callback matches the documented
    // signature; `refcon` points to a `Shared` that outlives the session (see
    // `VtEncoder::drop`); `out` is a valid out pointer.
    let status = unsafe {
        VTCompressionSession::create(
            None,
            width as i32,
            height as i32,
            codec_type(codec),
            Some(spec.as_opaque()),
            source_attrs.as_deref().map(CFDictionary::as_opaque),
            None,
            refcon.map(|_| on_encoded as _),
            refcon.unwrap_or(ptr::null_mut()),
            NonNull::from(&mut out),
        )
    };
    os("VTCompressionSessionCreate", status)?;
    // SAFETY: on success VideoToolbox returned a +1 retained, non-null session.
    NonNull::new(out)
        .map(|p| unsafe { CFRetained::from_raw(p) })
        .ok_or(CodecError::Os {
            api: "VTCompressionSessionCreate",
            status: -1,
        })
}

/// VideoToolbox output callback (runs on a VideoToolbox thread).
unsafe extern "C-unwind" fn on_encoded(
    output_refcon: *mut c_void,
    source_refcon: *mut c_void,
    status: i32,
    flags: VTEncodeInfoFlags,
    sample: *mut CMSampleBuffer,
) {
    let completed = Instant::now();
    if output_refcon.is_null() {
        return;
    }
    // SAFETY: the refcon is the `Shared` we passed at creation; it outlives the session.
    let shared = unsafe { &*output_refcon.cast::<Shared>() };
    let seq = source_refcon as usize as u64;
    // Never let a panic unwind into VideoToolbox.
    let event = catch_unwind(AssertUnwindSafe(|| {
        if status != 0 {
            return EncoderEvent::Error {
                seq,
                error: CodecError::Os {
                    api: "VTCompressionOutputCallback",
                    status,
                },
            };
        }
        // SAFETY: VideoToolbox passes a valid sample buffer (or null) for the callback's duration.
        let Some(sample) = (unsafe { sample.as_ref() }) else {
            return EncoderEvent::Dropped { seq };
        };
        if flags.0 & VTEncodeInfoFlags::FrameDropped.0 != 0 {
            return EncoderEvent::Dropped { seq };
        }
        let submitted = shared.base
            + Duration::from_nanos(
                shared.submit_ns[seq as usize % SUBMIT_RING].load(Ordering::Relaxed),
            );
        match sample_to_annexb(shared.codec, sample) {
            Ok((keyframe, data)) => EncoderEvent::Frame(EncodedFrame {
                seq,
                keyframe,
                data,
                submitted,
                completed,
            }),
            Err(error) => EncoderEvent::Error { seq, error },
        }
    }));
    if let Ok(event) = event {
        shared.emit(event);
    }
}

/// Extracts one encoded frame as Annex B (with SPS/PPS[/VPS] prepended on keyframes).
fn sample_to_annexb(codec: Codec, sample: &CMSampleBuffer) -> Result<(bool, Vec<u8>), CodecError> {
    let keyframe = !is_not_sync(sample);
    // SAFETY: valid sample buffer.
    let format = unsafe { sample.format_description() }
        .ok_or(CodecError::Bitstream("no format description"))?;
    let (sets, nal_len) = parameter_sets(codec, &format, keyframe)?;
    // SAFETY: valid sample buffer.
    let block = unsafe { sample.data_buffer() }.ok_or(CodecError::Bitstream("no data buffer"))?;
    let mut out = Vec::new();
    for set in &sets {
        out.reserve(START_CODE.len() + set.len());
        out.extend_from_slice(&START_CODE);
        out.extend_from_slice(set);
    }
    with_block_bytes(&block, |bytes| {
        length_prefixed_to_annexb(bytes, nal_len, &mut out)
    })??;
    Ok((keyframe, out))
}

/// True if the sample's attachments mark it as a non-keyframe.
fn is_not_sync(sample: &CMSampleBuffer) -> bool {
    // SAFETY: valid sample buffer; `false` = don't create the array.
    let Some(arr) = (unsafe { sample.sample_attachments_array(false) }) else {
        return false;
    };
    // SAFETY: Apple constant key.
    let key = unsafe { kCMSampleAttachmentKey_NotSync };
    array_item::<CFDictionary>(&arr, 0)
        .and_then(|dict| dict_value(dict, key))
        .and_then(|v| v.downcast_ref::<CFBoolean>())
        .is_some_and(CFBoolean::as_bool)
}

/// Returns the parameter sets (only when `want_sets`) and the NAL length-prefix size.
fn parameter_sets(
    codec: Codec,
    format: &CMFormatDescription,
    want_sets: bool,
) -> Result<(Vec<Vec<u8>>, usize), CodecError> {
    let get = |i: usize, p: *mut *const u8, sz: *mut usize, count: *mut usize, nal: *mut c_int| {
        // SAFETY: valid format description; out pointers are valid or null (allowed).
        unsafe {
            match codec {
                Codec::H264 => {
                    CMVideoFormatDescriptionGetH264ParameterSetAtIndex(format, i, p, sz, count, nal)
                }
                Codec::Hevc => {
                    CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(format, i, p, sz, count, nal)
                }
            }
        }
    };
    let (mut count, mut nal_len): (usize, c_int) = (0, 0);
    os(
        "CMVideoFormatDescriptionGetParameterSetAtIndex",
        get(
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut count,
            &mut nal_len,
        ),
    )?;
    let nal_len =
        usize::try_from(nal_len).map_err(|_| CodecError::Bitstream("negative NAL length size"))?;
    let mut sets = Vec::new();
    if want_sets {
        sets.reserve_exact(count);
        for i in 0..count {
            let (mut p, mut sz): (*const u8, usize) = (ptr::null(), 0);
            os(
                "CMVideoFormatDescriptionGetParameterSetAtIndex",
                get(i, &mut p, &mut sz, ptr::null_mut(), ptr::null_mut()),
            )?;
            if p.is_null() {
                return Err(CodecError::Bitstream("null parameter set"));
            }
            // SAFETY: CoreMedia returned a pointer to `sz` bytes owned by `format`.
            sets.push(unsafe { std::slice::from_raw_parts(p, sz) }.to_vec());
        }
    }
    Ok((sets, nal_len))
}

/// Calls `f` with the block buffer's bytes, copying only if they aren't contiguous.
fn with_block_bytes<R>(block: &CMBlockBuffer, f: impl FnOnce(&[u8]) -> R) -> Result<R, CodecError> {
    let (mut at_offset, mut total): (usize, usize) = (0, 0);
    let mut data: *mut std::ffi::c_char = ptr::null_mut();
    // SAFETY: valid block buffer; out pointers valid.
    os("CMBlockBufferGetDataPointer", unsafe {
        block.data_pointer(0, &mut at_offset, &mut total, &mut data)
    })?;
    if !data.is_null() && at_offset == total {
        // SAFETY: CoreMedia guarantees `total` contiguous readable bytes at `data`
        // for the lifetime of `block`.
        return Ok(f(unsafe {
            std::slice::from_raw_parts(data.cast::<u8>(), total)
        }));
    }
    let mut buf = vec![0u8; total];
    if let Some(dst) = NonNull::new(buf.as_mut_ptr().cast::<c_void>()) {
        // SAFETY: `buf` has exactly `total` writable bytes.
        os("CMBlockBufferCopyDataBytes", unsafe {
            block.copy_data_bytes(0, total, dst)
        })?;
    }
    Ok(f(&buf))
}

// ───────────────────────── Synthetic frames (encoder-only benchmark) ─────────────────────────

/// Generates moving NV12 test frames from a pixel-buffer pool (no screen capture).
pub struct SyntheticSource {
    pool: CFRetained<CVPixelBufferPool>,
    frame: u64,
}

// SAFETY: the pool is a thread-safe CF object; only used through `&mut self`.
unsafe impl Send for SyntheticSource {}

fn pixel_buffer_attrs(
    width: u32,
    height: u32,
    format: u32,
) -> CFRetained<CFDictionary<CFString, CFType>> {
    // SAFETY: Apple constant keys.
    let (k_fmt, k_w, k_h, k_io) = unsafe {
        (
            kCVPixelBufferPixelFormatTypeKey,
            kCVPixelBufferWidthKey,
            kCVPixelBufferHeightKey,
            kCVPixelBufferIOSurfacePropertiesKey,
        )
    };
    let empty = CFDictionary::<CFString, CFType>::empty();
    CFDictionary::<CFString, CFType>::from_slices(
        &[k_fmt, k_w, k_h, k_io],
        &[
            &*CFNumber::new_i32(format as i32),
            &*CFNumber::new_i32(width as i32),
            &*CFNumber::new_i32(height as i32),
            empty.as_opaque(),
        ],
    )
}

impl SyntheticSource {
    /// Creates a source of `width × height` NV12 IOSurface-backed frames.
    pub fn new(width: u32, height: u32) -> Result<Self, CodecError> {
        let attrs = pixel_buffer_attrs(
            width,
            height,
            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
        );
        let mut out: *mut CVPixelBufferPool = ptr::null_mut();
        // SAFETY: valid attribute dictionary and out pointer.
        os("CVPixelBufferPoolCreate", unsafe {
            CVPixelBufferPool::create(None, None, Some(attrs.as_opaque()), NonNull::from(&mut out))
        })?;
        // SAFETY: on success the pool is a +1 retained, non-null object.
        let pool = NonNull::new(out)
            .map(|p| unsafe { CFRetained::from_raw(p) })
            .ok_or(CodecError::Os {
                api: "CVPixelBufferPoolCreate",
                status: -1,
            })?;
        Ok(Self { pool, frame: 0 })
    }

    /// Returns the next frame: a vertical bar sweeping across a gradient, so
    /// every frame differs (like a moving test pattern on screen).
    pub fn next_frame(&mut self) -> Result<PixelBufferRef, CodecError> {
        let mut out: *mut CVPixelBuffer = ptr::null_mut();
        // SAFETY: valid pool and out pointer. Buffers still used by the encoder
        // are not handed out again by the pool.
        os("CVPixelBufferPoolCreatePixelBuffer", unsafe {
            CVPixelBufferPool::create_pixel_buffer(None, &self.pool, NonNull::from(&mut out))
        })?;
        // SAFETY: +1 retained, non-null on success.
        let buf = NonNull::new(out)
            .map(|p| unsafe { CFRetained::from_raw(p) })
            .ok_or(CodecError::Os {
                api: "CVPixelBufferPoolCreatePixelBuffer",
                status: -1,
            })?;
        fill_pattern(&buf, self.frame)?;
        self.frame += 1;
        Ok(PixelBufferRef::from_retained(buf))
    }
}

/// Fills a bi-planar YCbCr buffer (4:2:0 or 4:4:4): luma gradient with a bright
/// bar that moves 16 px per frame; neutral chroma.
fn fill_pattern(buf: &CVPixelBuffer, frame: u64) -> Result<(), CodecError> {
    // SAFETY: valid buffer; flags 0 = read/write lock.
    os("CVPixelBufferLockBaseAddress", unsafe {
        CVPixelBufferLockBaseAddress(buf, CVPixelBufferLockFlags(0))
    })?;
    let width = CVPixelBufferGetWidth(buf);
    for plane in 0..2 {
        let base = CVPixelBufferGetBaseAddressOfPlane(buf, plane).cast::<u8>();
        let stride = CVPixelBufferGetBytesPerRowOfPlane(buf, plane);
        let rows = CVPixelBufferGetHeightOfPlane(buf, plane);
        if base.is_null() {
            continue;
        }
        // SAFETY: while locked, the plane is `stride * rows` writable bytes at `base`.
        let bytes = unsafe { std::slice::from_raw_parts_mut(base, stride * rows) };
        if plane == 0 {
            let bar = (frame as usize * 16) % width.max(1);
            for (y, row) in bytes.chunks_exact_mut(stride).enumerate() {
                let shade = (y % 256) as u8;
                row[..width.min(stride)].fill(shade);
                let end = (bar + 64).min(width).min(stride);
                row[bar.min(end)..end].fill(235);
            }
        } else {
            bytes.fill(128); // neutral chroma
        }
    }
    // SAFETY: matched with the lock above.
    unsafe { CVPixelBufferUnlockBaseAddress(buf, CVPixelBufferLockFlags(0)) };
    Ok(())
}

// ───────────────────────── Capability probes (Phase 2 Q1/Q2) ─────────────────────────

/// One installed video encoder.
#[derive(Debug, Clone)]
pub struct EncoderInfo {
    /// Human-readable name.
    pub display_name: String,
    /// Encoder ID string.
    pub encoder_id: String,
    /// Codec FourCC (e.g. "avc1", "hvc1").
    pub codec: String,
    /// Hardware-accelerated?
    pub hardware: bool,
}

fn fourcc(v: u32) -> String {
    v.to_be_bytes()
        .iter()
        .map(|&b| if b.is_ascii_graphic() { b as char } else { '?' })
        .collect()
}

fn dict_value<'a>(dict: &'a CFDictionary, key: &CFString) -> Option<&'a CFType> {
    // SAFETY: valid dictionary and key; value owned by `dict`.
    let v = unsafe { dict.value((key as *const CFString).cast()) };
    // SAFETY: non-null CF object owned by `dict`.
    NonNull::new(v.cast_mut().cast::<CFType>()).map(|p| unsafe { p.as_ref() })
}

/// Element `i` of a CF array, type-checked as `T`.
fn array_item<T: objc2_core_foundation::ConcreteType>(arr: &CFArray, i: isize) -> Option<&T> {
    if i < 0 || i >= arr.count() {
        return None;
    }
    // SAFETY: 0 <= i < count; the element is owned by `arr` and outlives the borrow.
    let v = unsafe { arr.value_at_index(i) };
    // SAFETY: non-null CF object owned by `arr`.
    NonNull::new(v.cast_mut().cast::<CFType>())
        .map(|p| unsafe { p.as_ref() })
        .and_then(|o| o.downcast_ref::<T>())
}

/// Lists every video encoder VideoToolbox knows about on this machine.
pub fn list_encoders() -> Result<Vec<EncoderInfo>, CodecError> {
    let mut out: *const CFArray = ptr::null();
    // SAFETY: no options; valid out pointer.
    os("VTCopyVideoEncoderList", unsafe {
        VTCopyVideoEncoderList(None, NonNull::from(&mut out))
    })?;
    // SAFETY: +1 retained array on success.
    let Some(list) = NonNull::new(out.cast_mut()).map(|p| unsafe { CFRetained::from_raw(p) })
    else {
        return Ok(Vec::new());
    };
    // SAFETY: Apple constant keys.
    let (k_name, k_id, k_codec, k_hw) = unsafe {
        (
            kVTVideoEncoderList_DisplayName,
            kVTVideoEncoderList_EncoderID,
            kVTVideoEncoderList_CodecType,
            kVTVideoEncoderList_IsHardwareAccelerated,
        )
    };
    let mut encoders = Vec::with_capacity(usize::try_from(list.count()).unwrap_or(0));
    for i in 0..list.count() {
        let Some(d) = array_item::<CFDictionary>(&list, i) else {
            continue;
        };
        let text = |k| {
            dict_value(d, k)
                .and_then(|v| v.downcast_ref::<CFString>())
                .map(ToString::to_string)
                .unwrap_or_default()
        };
        encoders.push(EncoderInfo {
            display_name: text(k_name),
            encoder_id: text(k_id),
            codec: dict_value(d, k_codec)
                .and_then(|v| v.downcast_ref::<CFNumber>())
                .and_then(CFNumber::as_i64)
                .map(|v| fourcc(v as u32))
                .unwrap_or_default(),
            hardware: dict_value(d, k_hw)
                .and_then(|v| v.downcast_ref::<CFBoolean>())
                .is_some_and(CFBoolean::as_bool),
        });
    }
    Ok(encoders)
}

/// The properties a hardware encoder session supports (Q2 evidence).
#[derive(Debug, Clone)]
pub struct PropertyReport {
    /// All supported property keys, sorted.
    pub keys: Vec<String>,
    /// Supported values of `ProfileLevel`, if the encoder lists them.
    pub profile_levels: Vec<String>,
}

/// Creates a probe session and dumps `VTSessionCopySupportedPropertyDictionary`.
pub fn supported_properties(codec: Codec, low_latency: bool) -> Result<PropertyReport, CodecError> {
    let session = create_session(codec, 1920, 1080, None, low_latency, None)?;
    let mut out: *const CFDictionary = ptr::null();
    // SAFETY: valid session; valid out pointer.
    os("VTSessionCopySupportedPropertyDictionary", unsafe {
        VTSessionCopySupportedPropertyDictionary(&session, NonNull::from(&mut out))
    })?;
    // SAFETY: +1 retained dictionary on success.
    let dict = NonNull::new(out.cast_mut())
        .map(|p| unsafe { CFRetained::from_raw(p) })
        .ok_or(CodecError::Bitstream("no property dictionary"))?;
    // SAFETY: reinterpreting an untyped CFDictionary as CFString → CFType; every
    // key VideoToolbox returns here is a CFString.
    let typed = unsafe { dict.cast_unchecked::<CFString, CFType>() };
    let (keys, values) = typed.to_vecs();
    let mut names: Vec<String> = keys.iter().map(ToString::to_string).collect();
    names.sort();
    let mut profile_levels = Vec::new();
    // SAFETY: Apple constant keys.
    let (k_profile, k_list) = unsafe {
        (
            kVTCompressionPropertyKey_ProfileLevel,
            kVTPropertySupportedValueListKey,
        )
    };
    if let Some(idx) = keys.iter().position(|k| **k == *k_profile)
        && let Some(info) = values[idx].downcast_ref::<CFDictionary>()
        && let Some(list) = dict_value(info, k_list).and_then(|v| v.downcast_ref::<CFArray>())
    {
        profile_levels.extend(
            (0..list.count())
                .filter_map(|i| array_item::<CFString>(list, i).map(ToString::to_string)),
        );
        profile_levels.sort();
    }
    // SAFETY: invalidate the probe session before releasing it.
    unsafe { session.invalidate() };
    Ok(PropertyReport {
        keys: names,
        profile_levels,
    })
}

/// Result of trying to encode a 4:4:4 frame (Q1 evidence).
#[derive(Debug, Clone)]
pub struct Probe444 {
    /// Could a session be created with a 4:4:4 source format?
    pub session_created: bool,
    /// Did encoding a 4:4:4 frame produce output?
    pub frame_encoded: bool,
    /// Profile found in the produced SPS, if any.
    pub sps_profile: Option<ProfileInfo>,
    /// The OS error, if any step failed.
    pub error: Option<String>,
}

/// Feeds one 4:4:4 (`444v`) frame to the hardware encoder and reports which
/// profile the resulting SPS declares. A 4:2:0 profile means the encoder
/// silently subsampled — i.e. no 4:4:4 encode.
pub fn probe_444(codec: Codec, low_latency: bool) -> Probe444 {
    let mut r = Probe444 {
        session_created: false,
        frame_encoded: false,
        sps_profile: None,
        error: None,
    };
    let (tx, rx) = std::sync::mpsc::sync_channel::<EncoderEvent>(4);
    let sink: EncoderSink = Box::new(move |e| {
        let _ = tx.try_send(e);
    });
    let shared = Box::new(Shared {
        codec,
        base: Instant::now(),
        submit_ns: std::array::from_fn(|_| AtomicU64::new(0)),
        sink: Mutex::new(sink),
    });
    let fmt = kCVPixelFormatType_444YpCbCr8BiPlanarVideoRange;
    let session = match create_session(
        codec,
        1280,
        720,
        Some(fmt),
        low_latency,
        Some((&*shared as *const Shared).cast_mut().cast()),
    ) {
        Ok(s) => s,
        Err(e) => {
            r.error = Some(e.to_string());
            return r;
        }
    };
    r.session_created = true;
    let attrs = pixel_buffer_attrs(1280, 720, fmt);
    let mut pb: *mut CVPixelBuffer = ptr::null_mut();
    // SAFETY: valid attributes and out pointer.
    let st = unsafe {
        CVPixelBufferCreate(
            None,
            1280,
            720,
            fmt,
            Some(attrs.as_opaque()),
            NonNull::from(&mut pb),
        )
    };
    // SAFETY: +1 retained on success.
    let Some(pb) = (st == 0)
        .then_some(())
        .and_then(|()| NonNull::new(pb))
        .map(|p| unsafe { CFRetained::from_raw(p) })
    else {
        r.error = Some(format!("CVPixelBufferCreate(444v) failed: {st}"));
        // SAFETY: valid session.
        unsafe { session.invalidate() };
        return r;
    };
    if let Err(e) = fill_pattern(&pb, 0) {
        r.error = Some(e.to_string());
    }
    // SAFETY: valid session, buffer; refcon 0 is an integer, never dereferenced.
    let st = unsafe {
        let st = session.encode_frame(
            &pb,
            CMTime::new(0, 30),
            kCMTimeInvalid,
            None,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        let _ = session.complete_frames(kCMTimeInvalid);
        st
    };
    if st != 0 {
        r.error = Some(format!(
            "VTCompressionSessionEncodeFrame(444v) failed: {st}"
        ));
    }
    while let Ok(ev) = rx.try_recv() {
        if let EncoderEvent::Frame(f) = ev {
            r.frame_encoded = true;
            r.sps_profile = first_sps_profile(codec, &f.data);
        } else if let EncoderEvent::Error { error, .. } = ev {
            r.error = Some(error.to_string());
        }
    }
    // SAFETY: invalidate before `shared` is dropped (no callbacks afterwards).
    unsafe { session.invalidate() };
    drop(shared);
    r
}

/// Finds the first SPS in an Annex B stream and reads its profile.
fn first_sps_profile(codec: Codec, annexb: &[u8]) -> Option<ProfileInfo> {
    annexb
        .windows(START_CODE.len())
        .enumerate()
        .filter(|(_, w)| *w == START_CODE)
        .find_map(|(i, _)| {
            let nal = &annexb[i + START_CODE.len()..];
            match codec {
                Codec::H264 => h264_sps_profile(nal),
                Codec::Hevc => hevc_sps_profile(nal),
            }
        })
}

// ───────────────────────── Decoder (Phase 4 step 5) ─────────────────────────

/// One decoded picture (NV12, IOSurface-backed). `Debug` prints its size
/// and id, never pixels (INV9).
pub struct DecodedFrame {
    /// The video frame it came from (`frame_id` on the wire).
    pub frame_id: u32,
    image: PixelBufferRef,
}

impl DecodedFrame {
    /// The picture.
    pub fn image(&self) -> &PixelBufferRef {
        &self.image
    }
}

impl std::fmt::Debug for DecodedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedFrame")
            .field("frame_id", &self.frame_id)
            .field("width", &self.image.width())
            .field("height", &self.image.height())
            .finish()
    }
}

/// Hardware H.264 decoder behind a [`DecodeGate`]: no frame reaches
/// VideoToolbox unless the gate admitted it, and the decoder is only ever
/// configured with parameter sets the gate checked (phase4-criteria M7).
///
/// Decoding is synchronous: VideoToolbox calls the output callback before
/// `VTDecompressionSessionDecodeFrame` returns when no asynchronous flag is
/// set (VTDecompressionSession.h, SDK 27). Run it on its own thread.
pub struct VtDecoder {
    gate: DecodeGate,
    stats: DecodeStats,
    session: Option<DecodeSession>,
    /// The id of the last frame offered to `decode`.
    last_frame_id: Option<u32>,
}

// SAFETY: a VTDecompressionSession may be used from any thread (it is a CF
// object, and decoding runs on the caller's thread); `VtDecoder` is only
// used through `&mut self`, and `DecodeOutput` is Sync (a Mutex).
unsafe impl Send for VtDecoder {}

impl VtDecoder {
    /// A decoder for pictures up to `limit`. Nothing is created until the
    /// first keyframe passes the gate.
    pub fn new(limit: SizeLimit) -> Self {
        Self {
            gate: DecodeGate::new(limit),
            stats: DecodeStats::default(),
            session: None,
            last_frame_id: None,
        }
    }

    /// Decodes one Annex B frame. On any error the viewer needs a keyframe.
    ///
    /// `frame_id` must follow the previous one: after a gap (a frame lost,
    /// given up, or not offered) a predicted frame would refer to a picture
    /// the decoder never saw, and VideoToolbox decodes it without an error
    /// (seen in `m7_a_missing_frame_waits_for_a_keyframe`). So a gap is
    /// treated like a decode error: nothing until the next keyframe.
    pub fn decode(&mut self, frame_id: u32, annexb: &[u8]) -> Result<DecodedFrame, DecodeError> {
        let previous = self.last_frame_id.replace(frame_id);
        if previous.is_some_and(|p| frame_id != p.wrapping_add(1)) {
            self.gate.decode_failed();
        }
        let admitted = match self.gate.admit(annexb) {
            Ok(a) => a,
            Err(r) => {
                self.stats.refused += 1;
                return Err(DecodeError::Refused(r));
            }
        };
        if admitted.reconfigure {
            // The old session goes first: never two decoders at once.
            self.session = None;
            let created = match (admitted.frame.sps, admitted.frame.pps) {
                (Some((sps, info)), Some(pps)) => DecodeSession::new(sps, pps, info),
                _ => Err(CodecError::Bitstream("keyframe without parameter sets")),
            };
            match created {
                Ok(s) => {
                    self.session = Some(s);
                    self.stats.sessions_created += 1;
                }
                Err(e) => return Err(self.failed(DecodeError::Configure(e))),
            }
        }
        let Some(session) = &self.session else {
            return Err(self.failed(DecodeError::NoPicture));
        };
        match session.decode(&admitted.frame.to_avcc()) {
            Ok(image) => {
                self.stats.decoded += 1;
                Ok(DecodedFrame { frame_id, image })
            }
            Err(e) => Err(self.failed(e)),
        }
    }

    /// Counts a failure, drops the decoder session and makes the gate wait
    /// for a keyframe that creates a new one. A failed session is never
    /// reused: its reference pictures are suspect, and some errors (e.g. an
    /// invalidated session) would repeat on every later frame.
    fn failed(&mut self, e: DecodeError) -> DecodeError {
        self.stats.failed += 1;
        self.session = None;
        self.gate.configure_failed();
        e
    }

    /// Counters.
    pub fn stats(&self) -> DecodeStats {
        self.stats
    }
}

/// The decoder's output for the frame being decoded (the callback's refcon).
#[derive(Default)]
struct DecodeOutput {
    slot: Mutex<Option<Result<CFRetained<CVPixelBuffer>, i32>>>,
}

/// One `VTDecompressionSession`, configured from checked parameter sets.
struct DecodeSession {
    session: CFRetained<VTDecompressionSession>,
    format: CFRetained<CMFormatDescription>,
    /// Pictures larger than this are not passed on (the SPS's coded size).
    max: (u32, u32),
    // Boxed so their addresses are stable: VideoToolbox holds pointers to
    // both until the session is invalidated in `Drop`. Whether it copies
    // the callback record is not documented (VTDecompressionSession.h), so
    // the record lives as long as the session.
    _record: Box<VTDecompressionOutputCallbackRecord>,
    output: Box<DecodeOutput>,
    /// The SPS and PPS the description was made from (see `new`).
    _parameter_sets: Box<(Vec<u8>, Vec<u8>)>,
}

impl DecodeSession {
    fn new(sps: &[u8], pps: &[u8], info: SpsInfo) -> Result<Self, CodecError> {
        // Our own copies, kept as long as the description: the header
        // (CMFormatDescription.h, SDK 27) does not say whether CoreMedia
        // copies the parameter sets or keeps pointing at them.
        let parameter_sets = Box::new((sps.to_vec(), pps.to_vec()));
        let mut sets = [
            NonNull::from(parameter_sets.0.as_slice()).cast::<u8>(),
            NonNull::from(parameter_sets.1.as_slice()).cast::<u8>(),
        ];
        let mut sizes = [sps.len(), pps.len()];
        let mut format: *const CMFormatDescription = ptr::null();
        // SAFETY: two parameter sets of the given sizes, which live as long
        // as the description (`parameter_sets`, a field); 4-byte NAL length
        // prefixes (our AVCC); valid out pointer.
        let status = unsafe {
            CMVideoFormatDescriptionCreateFromH264ParameterSets(
                None,
                2,
                NonNull::from(&mut sets).cast(),
                NonNull::from(&mut sizes).cast(),
                4,
                NonNull::from(&mut format),
            )
        };
        os(
            "CMVideoFormatDescriptionCreateFromH264ParameterSets",
            status,
        )?;
        // SAFETY: on success a +1 retained, non-null description.
        let format = NonNull::new(format.cast_mut())
            .map(|p| unsafe { CFRetained::from_raw(p) })
            .ok_or(CodecError::Os {
                api: "CMVideoFormatDescriptionCreateFromH264ParameterSets",
                status: -1,
            })?;
        let output = Box::new(DecodeOutput::default());
        let record = Box::new(VTDecompressionOutputCallbackRecord {
            decompressionOutputCallback: Some(on_decoded),
            decompressionOutputRefCon: (&*output as *const DecodeOutput).cast_mut().cast(),
        });
        // NV12 (what the viewer uploads, R2), IOSurface-backed.
        // SAFETY: Apple constant keys.
        let (k_fmt, k_io) = unsafe {
            (
                kCVPixelBufferPixelFormatTypeKey,
                kCVPixelBufferIOSurfacePropertiesKey,
            )
        };
        let empty = CFDictionary::<CFString, CFType>::empty();
        let attrs = CFDictionary::<CFString, CFType>::from_slices(
            &[k_fmt, k_io],
            &[
                &*CFNumber::new_i32(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange as i32),
                empty.as_opaque(),
            ],
        );
        let mut out: *mut VTDecompressionSession = ptr::null_mut();
        // SAFETY: valid description and attributes; the record and the
        // `DecodeOutput` it points to outlive the session (see `Drop`);
        // valid out pointer.
        let status = unsafe {
            VTDecompressionSession::create(
                None,
                &format,
                None,
                Some(attrs.as_opaque()),
                &*record,
                NonNull::from(&mut out),
            )
        };
        os("VTDecompressionSessionCreate", status)?;
        // SAFETY: on success a +1 retained, non-null session.
        let session = NonNull::new(out)
            .map(|p| unsafe { CFRetained::from_raw(p) })
            .ok_or(CodecError::Os {
                api: "VTDecompressionSessionCreate",
                status: -1,
            })?;
        // Optional: favour latency. Ignored if the decoder does not support it.
        let t: &CFType = CFBoolean::new(true);
        // SAFETY: valid session (a VTSession); Apple constant key.
        unsafe {
            let _ = VTSessionSetProperty(&session, kVTDecompressionPropertyKey_RealTime, Some(t));
        }
        Ok(Self {
            session,
            format,
            max: (info.coded_width, info.coded_height),
            _record: record,
            output,
            _parameter_sets: parameter_sets,
        })
    }

    /// Decodes one AVCC frame synchronously.
    fn decode(&self, avcc: &[u8]) -> Result<PixelBufferRef, DecodeError> {
        let os_err = |api, status| DecodeError::Decode(CodecError::Os { api, status });
        let len = avcc.len();
        let mut block: *mut CMBlockBuffer = ptr::null_mut();
        // SAFETY: CoreMedia allocates `len` bytes now (null memory block,
        // default allocator, AssureMemoryNow); valid out pointer.
        let st = unsafe {
            CMBlockBuffer::create_with_memory_block(
                None,
                ptr::null_mut(),
                len,
                None,
                ptr::null(),
                0,
                len,
                kCMBlockBufferAssureMemoryNowFlag,
                NonNull::from(&mut block),
            )
        };
        if st != 0 {
            return Err(os_err("CMBlockBufferCreateWithMemoryBlock", st));
        }
        // SAFETY: +1 retained, non-null on success.
        let block = NonNull::new(block)
            .map(|p| unsafe { CFRetained::from_raw(p) })
            .ok_or(os_err("CMBlockBufferCreateWithMemoryBlock", -1))?;
        let src = NonNull::new(avcc.as_ptr().cast_mut().cast::<c_void>())
            .ok_or(DecodeError::NoPicture)?;
        // SAFETY: `src` is `len` readable bytes; the block holds `len` bytes.
        let st = unsafe { CMBlockBuffer::replace_data_bytes(src, &block, 0, len) };
        if st != 0 {
            return Err(os_err("CMBlockBufferReplaceDataBytes", st));
        }
        let mut sample: *mut CMSampleBuffer = ptr::null_mut();
        // SAFETY: valid block and description; one sample of `len` bytes, no
        // timing (decode order = arrival order); valid out pointers.
        let st = unsafe {
            CMSampleBuffer::create_ready(
                None,
                Some(&block),
                Some(&self.format),
                1,
                0,
                ptr::null(),
                1,
                &len,
                NonNull::from(&mut sample),
            )
        };
        if st != 0 {
            return Err(os_err("CMSampleBufferCreateReady", st));
        }
        // SAFETY: +1 retained, non-null on success.
        let sample = NonNull::new(sample)
            .map(|p| unsafe { CFRetained::from_raw(p) })
            .ok_or(os_err("CMSampleBufferCreateReady", -1))?;
        if let Ok(mut slot) = self.output.slot.lock() {
            *slot = None;
        }
        let mut info = VTDecodeInfoFlags(0);
        // SAFETY: valid session and sample. No asynchronous flag: the output
        // callback runs before this returns (VTDecompressionSession.h).
        let st = unsafe {
            self.session
                .decode_frame(&sample, VTDecodeFrameFlags(0), ptr::null_mut(), &mut info)
        };
        if info.0 & VTDecodeInfoFlags::Asynchronous.0 != 0 {
            // Not expected without the flag; wait rather than read too early.
            // SAFETY: valid session.
            let _ = unsafe { self.session.wait_for_asynchronous_frames() };
        }
        if st != 0 {
            return Err(os_err("VTDecompressionSessionDecodeFrame", st));
        }
        let got = self.output.slot.lock().ok().and_then(|mut s| s.take());
        match got {
            Some(Ok(image)) => {
                let image = PixelBufferRef::from_retained(image);
                if image.width() > self.max.0 || image.height() > self.max.1 {
                    return Err(DecodeError::NoPicture);
                }
                Ok(image)
            }
            Some(Err(status)) => Err(os_err("VTDecompressionOutputCallback", status)),
            None => Err(DecodeError::NoPicture),
        }
    }
}

impl Drop for DecodeSession {
    fn drop(&mut self) {
        // SAFETY: valid session. After `invalidate` returns VideoToolbox
        // makes no further callbacks, so freeing the record and the output
        // afterwards (field drop) is sound.
        unsafe {
            let _ = self.session.wait_for_asynchronous_frames();
            self.session.invalidate();
        }
    }
}

/// VideoToolbox decoder output callback (runs before `decode_frame`
/// returns, on the decoding thread).
unsafe extern "C-unwind" fn on_decoded(
    output_refcon: *mut c_void,
    _source_refcon: *mut c_void,
    status: i32,
    flags: VTDecodeInfoFlags,
    image: *mut CVImageBuffer,
    _pts: CMTime,
    _duration: CMTime,
) {
    if output_refcon.is_null() {
        return;
    }
    // SAFETY: the refcon is the session's `DecodeOutput`, which outlives it.
    let output = unsafe { &*output_refcon.cast::<DecodeOutput>() };
    // Never let a panic unwind into VideoToolbox.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let result = if status != 0 {
            Err(status)
        } else if flags.0 & VTDecodeInfoFlags::FrameDropped.0 != 0 {
            Err(-1)
        } else {
            // SAFETY: VideoToolbox passes a valid image buffer (or null) for
            // the callback's duration; retaining keeps it alive after.
            NonNull::new(image)
                .map(|p| unsafe { CFRetained::retain(p) })
                .ok_or(-1)
        };
        if let Ok(mut slot) = output.slot.lock() {
            *slot = Some(result);
        }
    }));
}
