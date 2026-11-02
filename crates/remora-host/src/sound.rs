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

/// Linux: PipeWire capture of the default output -> Opus -> the server.
#[cfg(target_os = "linux")]
pub(crate) fn starter(server: std::sync::Arc<remora_net::HostServer>) -> SoundStarter {
    use remora_codec::audio::{AudioEncoder, CHANNELS, DEFAULT_BITRATE, FRAME};
    use remora_proto::audio::AudioPacket;
    Box::new(move || {
        let server = std::sync::Arc::clone(&server);
        let mut enc = AudioEncoder::new(DEFAULT_BITRATE)?;
        let mut pending: Vec<f32> = Vec::with_capacity(4 * FRAME * CHANNELS);
        let mut seq: u32 = 0;
        let capture = remora_capture::SoundCapture::start(Box::new(move |samples| {
            pending.extend_from_slice(samples);
            while pending.len() >= FRAME * CHANNELS {
                let frame: Vec<f32> = pending.drain(..FRAME * CHANNELS).collect();
                let Ok(data) = enc.encode(&frame) else {
                    continue; // a frame lost to the encoder: the viewer conceals it
                };
                let now_us = remora_app::clock::monotonic_ns().map_or(0, |n| n / 1000);
                server.send_audio(&AudioPacket {
                    seq,
                    // The frame's first sample was captured ~20 ms ago.
                    capture_ts_us: now_us.saturating_sub(20_000),
                    data,
                });
                seq = seq.wrapping_add(1);
            }
            // Never let a slow consumer grow this without bound.
            if pending.len() > 50 * FRAME * CHANNELS {
                pending.clear();
            }
        }))?;
        Ok(Box::new(capture) as Box<dyn std::any::Any + Send>)
    })
}
