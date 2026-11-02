//! The host's sound (phase4.8-criteria A1, A4): what this computer plays,
//! Opus-encoded in 20 ms packets, sent to every Active session.
//!
//! [`Video`](crate::serve::Video) starts it when a session becomes Active
//! and drops it when the last one ends, so nothing is recorded while no
//! one is connected (A1). Sound is never logged or stored (A4, INV9).

/// Starts the host's sound; dropping what it returns stops it.
pub(crate) type SoundStarter =
    Box<dyn FnMut() -> anyhow::Result<Box<dyn std::any::Any + Send>> + Send>;

/// Mutes the host's speakers; `Ok(None)` when they were already muted.
/// Dropping what it returns restores them (A7).
#[cfg(any(target_os = "linux", test))]
pub(crate) type SpeakerMuter =
    Box<dyn FnMut() -> anyhow::Result<Option<Box<dyn std::any::Any + Send>>> + Send>;

/// A7 (`serve --mute-speakers`): `inner`, with the speakers silent while
/// it runs. Recording starts first, so a host that cannot record never
/// mutes; a mute that fails is said once and the session goes on with
/// the speakers playing. Dropped in field order: recording stops, then the
/// speakers come back.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn with_speakers_muted(mut inner: SoundStarter, mut mute: SpeakerMuter) -> SoundStarter {
    Box::new(move || {
        let recording = inner()?;
        let muted = match mute() {
            Ok(Some(m)) => {
                println!(
                    "speakers: silent while a viewer is connected (restored when the session ends)"
                );
                Some(m)
            }
            Ok(None) => None, // already muted by the person: left alone
            Err(e) => {
                println!("speakers: could not silence them ({e:#}) - they keep playing");
                None
            }
        };
        Ok(Box::new((recording, muted)) as Box<dyn std::any::Any + Send>)
    })
}

/// Cuts captured samples into 20 ms packets (phase4.8 A1; OS-neutral so
/// it is tested everywhere). PipeWire hands over buffers of any length
/// (~43 ms by default, S-A1): one may hold two frames, or half of one.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default)]
pub(crate) struct Framer {
    /// Interleaved samples not yet in a whole frame (always < one frame
    /// after [`Framer::push`]: no backlog can build up here).
    pending: Vec<f32>,
    seq: u32,
}

#[cfg(any(target_os = "linux", test))]
impl Framer {
    /// `samples` (interleaved stereo, 48 kHz) arrived at `now_us`; for
    /// each whole frame, `encode` it and `send` the packet. A frame the
    /// encoder refuses still uses up its sequence number, so the viewer
    /// sees the gap and conceals it.
    pub(crate) fn push(
        &mut self,
        samples: &[f32],
        now_us: u64,
        encode: &mut dyn FnMut(&[f32]) -> Option<Vec<u8>>,
        send: &mut dyn FnMut(remora_proto::audio::AudioPacket),
    ) {
        use remora_codec::audio::{CHANNELS, FRAME, RATE};
        const PER_FRAME: usize = FRAME * CHANNELS;
        self.pending.extend_from_slice(samples);
        let mut start = 0;
        while self.pending.len() - start >= PER_FRAME {
            // The newest sample was captured about `now`; this frame's
            // first one as many samples earlier as follow it.
            let after = ((self.pending.len() - start) / CHANNELS) as u64;
            let capture_ts_us = now_us.saturating_sub(after * 1_000_000 / u64::from(RATE));
            let seq = self.seq;
            self.seq = self.seq.wrapping_add(1);
            if let Some(data) = encode(&self.pending[start..start + PER_FRAME]) {
                send(remora_proto::audio::AudioPacket {
                    seq,
                    capture_ts_us,
                    data,
                });
            }
            start += PER_FRAME;
        }
        self.pending.drain(..start);
    }
}

/// Linux: PipeWire capture of the default output -> Opus -> the server.
#[cfg(target_os = "linux")]
pub(crate) fn starter(server: std::sync::Arc<remora_net::HostServer>) -> SoundStarter {
    use remora_codec::audio::{AudioEncoder, DEFAULT_BITRATE};
    Box::new(move || {
        let server = std::sync::Arc::clone(&server);
        let mut enc = AudioEncoder::new(DEFAULT_BITRATE)?;
        let mut framer = Framer::default();
        let capture = remora_capture::SoundCapture::start(Box::new(move |samples| {
            let now_us = remora_app::clock::monotonic_ns().map_or(0, |n| n / 1000);
            framer.push(
                samples,
                now_us,
                &mut |frame| enc.encode(frame).ok(),
                &mut |p| server.send_audio(&p),
            );
        }))?;
        Ok(Box::new(capture) as Box<dyn std::any::Any + Send>)
    })
}

#[cfg(test)]
mod framer_tests {
    use super::Framer;
    use remora_codec::audio::{CHANNELS, FRAME};
    use remora_proto::audio::AudioPacket;

    const PER: usize = FRAME * CHANNELS;

    /// Pushes `n` interleaved samples at `now_us`; returns (seq, ts, first
    /// sample) of each packet. The fake encoder puts the frame's first
    /// sample in the data, or refuses frames whose first sample is < 0.
    fn push(f: &mut Framer, samples: &[f32], now_us: u64) -> Vec<(u32, u64, f32)> {
        let mut out = Vec::new();
        f.push(
            samples,
            now_us,
            &mut |frame| (frame[0] >= 0.0).then(|| frame[0].to_le_bytes().to_vec()),
            &mut |p: AudioPacket| {
                let first = f32::from_le_bytes(p.data[..4].try_into().expect("4 bytes"));
                out.push((p.seq, p.capture_ts_us, first));
            },
        );
        out
    }

    fn ramp(from: usize, n: usize) -> Vec<f32> {
        (from..from + n).map(|i| (i / CHANNELS) as f32).collect()
    }

    #[test]
    fn whole_frames_go_out_in_order_with_their_own_capture_times() {
        let mut f = Framer::default();
        // 1.5 frames at t = 100 ms: one packet, its first sample 30 ms old.
        assert_eq!(
            push(&mut f, &ramp(0, PER + PER / 2), 100_000),
            vec![(0, 70_000, 0.0)]
        );
        // Half a frame more at 110 ms completes the second: captured at 90.
        assert_eq!(
            push(&mut f, &ramp(PER + PER / 2, PER / 2), 110_000),
            vec![(1, 90_000, FRAME as f32)]
        );
        // One PipeWire buffer holding three frames: 20 ms apart, oldest first.
        assert_eq!(
            push(&mut f, &ramp(2 * PER, 3 * PER), 200_000),
            vec![
                (2, 140_000, 2.0 * FRAME as f32),
                (3, 160_000, 3.0 * FRAME as f32),
                (4, 180_000, 4.0 * FRAME as f32)
            ]
        );
        assert!(f.pending.is_empty());
    }

    #[test]
    fn a_frame_the_encoder_refuses_leaves_a_gap_the_viewer_can_see() {
        let mut f = Framer::default();
        let mut bad = vec![-1.0; PER];
        bad.extend(ramp(PER, PER));
        let got = push(&mut f, &bad, 100_000);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].0, 1,
            "seq not advanced past the lost frame: no concealment"
        );
    }

    #[test]
    fn nothing_waits_longer_than_one_frame_and_seq_wraps() {
        let mut f = Framer {
            seq: u32::MAX,
            ..Framer::default()
        };
        for k in 0..10 {
            push(&mut f, &ramp(0, PER - 2), k);
            assert!(f.pending.len() < PER);
        }
        assert_eq!(f.seq, u32::MAX.wrapping_add(9), "9 frames out, wrapped");
    }
}
