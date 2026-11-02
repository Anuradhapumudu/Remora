//! Linux: Cisco's openh264 in software (phase4.6-criteria §5).
//!
//! The owner's laptop has no hardware encoder usable without extra drivers;
//! spike S-L1b measured openh264 with these settings at 1080p: convert +
//! encode p50 10.7 ms, p95 13.6 ms, ~55 fps, 3.4 Mbit/s. The settings are
//! the spike's: screen-content real-time mode, low complexity, 8 threads,
//! no frame skipping, slices of ≤ 1200 bytes (so the threads have
//! independent work). Plus BT.709 video-range colour signalling, which is
//! what [`crate::yuv`] produces and the viewer assumes, and (unlike the
//! spike) Remora's bitrate with a QP cap, for readable text.
//!
//! Same shape as the macOS `VtEncoder`: `encode` returns a sequence number
//! and the result goes to the sink (here synchronously, on the caller's
//! thread). Keyframes only for the first frame and on request.

use std::time::{Duration, Instant};

use openh264::encoder::{
    BitRate, Complexity, Encoder, FrameRate, FrameType, QpRange, UsageType, VuiConfig,
};
use remora_capture::CpuImage;

use crate::{CodecError, EncodedFrame, EncoderConfig, EncoderEvent, EncoderSink};

/// Threads for the colour conversion and the encoder (S-L1b: 8 on the
/// owner's 16-thread laptop).
const THREADS: u16 = 8;

/// openh264's limit (its README: level 5.2).
const MAX_W: u32 = 3840;
const MAX_H: u32 = 2160;

/// A software H.264 encoder.
pub struct OpenH264Encoder {
    encoder: Encoder,
    sink: EncoderSink,
    next_seq: u64,
    keyframe_interval: u64,
}

impl std::fmt::Debug for OpenH264Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenH264Encoder")
            .field("next_seq", &self.next_seq)
            .finish_non_exhaustive()
    }
}

fn err(api: &'static str) -> impl Fn(openh264::Error) -> CodecError {
    // openh264's errors carry a native status; keep the API name only.
    move |_| CodecError::Os { api, status: -1 }
}

impl OpenH264Encoder {
    /// An encoder; `cfg.width × cfg.height` is a hint (openh264 adapts to
    /// each picture's size).
    pub fn new(cfg: EncoderConfig, sink: EncoderSink) -> Result<Self, CodecError> {
        let config = openh264::encoder::EncoderConfig::new()
            .usage_type(UsageType::ScreenContentRealTime)
            .complexity(Complexity::Low)
            .num_threads(THREADS)
            .max_frame_rate(FrameRate::from_hz(cfg.fps.max(1) as f32))
            .skip_frames(false)
            .max_slice_len(1200)
            // The crate's default target is 120 kbit/s (encoder.rs
            // `EncoderConfig::new`), far too little for a desktop: text
            // came out soft (owner, 2026-11-02, "can we improve the video
            // quality?"). Use Remora's bitrate (8 Mbit/s by default) and
            // never quantise coarser than QP 36, so text stays readable.
            .bitrate(BitRate::from_bps(cfg.bitrate_bps))
            .qp(QpRange::new(10, 36))
            .vui(VuiConfig::bt709());
        let encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)
            .map_err(err("openh264 WelsCreateSVCEncoder"))?;
        Ok(Self {
            encoder,
            sink,
            next_seq: 0,
            keyframe_interval: u64::from(cfg.keyframe_interval),
        })
    }

    /// Encodes one picture; the frame goes to the sink before this returns.
    /// `timestamp` is accepted for the same shape as macOS (openh264 does
    /// not need it in real-time mode).
    pub fn encode(
        &mut self,
        image: &CpuImage,
        _timestamp: Duration,
        force_keyframe: bool,
    ) -> Result<u64, CodecError> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let submitted = Instant::now();
        let (w, h) = (image.width(), image.height());
        if w > MAX_W || h > MAX_H {
            return Err(CodecError::Unsupported(
                "pictures larger than 3840x2160 (openh264's limit)",
            ));
        }
        let yuv = crate::yuv::bgrx_to_i420(
            image.bgrx(),
            w as usize * 4,
            w as usize,
            h as usize,
            usize::from(THREADS),
        )
        .ok_or(CodecError::Unsupported("pictures smaller than 2x2"))?;
        let keyframe_due = force_keyframe
            || seq == 0
            || (self.keyframe_interval > 0 && seq.is_multiple_of(self.keyframe_interval));
        if keyframe_due {
            self.encoder.force_intra_frame();
        }
        let (cw, ch) = (yuv.width / 2, yuv.height / 2);
        debug_assert_eq!(yuv.u.len(), cw * ch);
        let slices = openh264::formats::YUVSlices::new(
            (&yuv.y, &yuv.u, &yuv.v),
            (yuv.width, yuv.height),
            (yuv.width, cw, cw),
        );
        let bits = self
            .encoder
            .encode(&slices)
            .map_err(err("openh264 EncodeFrame"))?;
        let frame_type = bits.frame_type();
        let data = bits.to_vec();
        match frame_type {
            FrameType::Skip | FrameType::Invalid if data.is_empty() => {
                (self.sink)(EncoderEvent::Dropped { seq });
            }
            _ => (self.sink)(EncoderEvent::Frame(EncodedFrame {
                seq,
                keyframe: frame_type == FrameType::IDR,
                data,
                submitted,
                completed: Instant::now(),
            })),
        }
        Ok(seq)
    }

    /// Nothing is held back (each `encode` delivers its frame).
    pub fn flush(&mut self) -> Result<(), CodecError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn picture(w: u32, h: u32, shade: u8) -> CpuImage {
        let px = (0..w * h)
            .flat_map(|i| [shade, (i % 251) as u8, 255 - shade, 0])
            .collect();
        CpuImage::new(w, h, px).expect("sized")
    }

    /// (seq, keyframe, bytes) of each frame the sink received.
    type Log = Arc<Mutex<Vec<(u64, bool, usize)>>>;

    fn encoder() -> (OpenH264Encoder, Log) {
        let got = Arc::new(Mutex::new(Vec::new()));
        let g = Arc::clone(&got);
        let enc = OpenH264Encoder::new(
            EncoderConfig {
                width: 640,
                height: 360,
                ..EncoderConfig::default()
            },
            Box::new(move |ev| {
                if let EncoderEvent::Frame(f) = ev {
                    g.lock()
                        .expect("log")
                        .push((f.seq, f.keyframe, f.data.len()));
                }
            }),
        )
        .expect("openh264");
        (enc, got)
    }

    #[test]
    fn first_frame_and_requested_frames_are_keyframes_only() {
        let (mut enc, got) = encoder();
        for i in 0..6u8 {
            enc.encode(&picture(640, 360, i * 20), Duration::ZERO, i == 4)
                .expect("encoded");
        }
        let frames = got.lock().expect("log").clone();
        let keys: Vec<bool> = frames.iter().map(|f| f.1).collect();
        assert_eq!(keys, [true, false, false, false, true, false], "{frames:?}");
        assert!(frames.iter().all(|f| f.2 > 0), "every frame has data");
    }

    #[test]
    fn keyframes_parse_as_h264_with_parameter_sets() {
        let (mut enc, _) = encoder();
        let mut first = Vec::new();
        let sink_data = Arc::new(Mutex::new(Vec::new()));
        let s = Arc::clone(&sink_data);
        enc.sink = Box::new(move |ev| {
            if let EncoderEvent::Frame(f) = ev {
                s.lock().expect("log").push(f.data);
            }
        });
        enc.encode(&picture(640, 360, 9), Duration::ZERO, false)
            .expect("encoded");
        first.extend(sink_data.lock().expect("log")[0].iter().copied());
        // The same parser every received frame goes through (M7): the
        // viewer must accept what this encoder makes.
        let f = crate::h264::parse_frame(&first, crate::h264::SizeLimit::default())
            .expect("a valid Annex B keyframe");
        assert!(f.keyframe && f.pps.is_some());
        let (_, sps) = f.sps.expect("SPS on a keyframe");
        assert_eq!((sps.width, sps.height), (640, 360));
    }

    #[test]
    fn pictures_over_openh264s_limit_are_refused_not_crashed() {
        let (mut enc, _) = encoder();
        let r = enc.encode(&picture(3842, 2, 0), Duration::ZERO, false);
        assert!(matches!(r, Err(CodecError::Unsupported(_))), "{r:?}");
    }
}
