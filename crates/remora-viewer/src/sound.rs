//! Playing the host's sound on the Mac (phase4.8-criteria A6, AU1, AU2).
//!
//! * [`Jitter`] (pure, tested): decoded 48 kHz stereo frames in, the output
//!   device's samples out. It starts after [`START`] of sound (to ride out
//!   Wi-Fi jitter), never holds more than [`MAX_HELD`] (old sound is
//!   dropped, so delay cannot build up), conceals lost packets (the caller
//!   decodes concealment for each missing `seq`), and converts 48 kHz to
//!   the device's rate by linear interpolation. **Muted, it outputs silence**
//!   (A6) and keeps consuming, so unmuting does not play old sound.
//! * [`Sound`]: a thread with an Opus decoder and (macOS) a cpal output
//!   stream on the current output device (built-in speakers, Bluetooth
//!   earbuds, …). cpal holds the CoreAudio `unsafe`; this file has none.
//!   Elsewhere it says plainly that it does not play.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use remora_codec::audio::{CHANNELS, FRAME, RATE};
use remora_proto::audio::AudioPacket;

/// Sound waited for before playing starts (and after running dry).
pub(crate) const START: usize = 2 * FRAME; // 40 ms
/// Most sound held; older is dropped (bounds the delay: AU1).
pub(crate) const MAX_HELD: usize = 6 * FRAME; // 120 ms
/// Most packets concealed for one gap; a longer gap restarts cleanly.
pub(crate) const MAX_CONCEAL: u32 = 5;

/// The playout buffer between the decoder and the output device.
pub(crate) struct Jitter {
    /// Stereo frames at 48 kHz: (left, right).
    held: VecDeque<(f32, f32)>,
    playing: bool,
    /// Output samples per input sample (device rate / 48 kHz).
    step: f64,
    /// Fractional read position into `held` for rate conversion.
    pos: f64,
    /// Statistics: packets concealed, frames dropped for delay, dry runs.
    pub(crate) concealed: u64,
    pub(crate) dropped: u64,
    pub(crate) underruns: u64,
}

/// A4 (INV9): counts only, never the samples.
impl std::fmt::Debug for Jitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jitter")
            .field("held_frames", &self.held.len())
            .field("playing", &self.playing)
            .field("concealed", &self.concealed)
            .field("dropped", &self.dropped)
            .field("underruns", &self.underruns)
            .finish()
    }
}

impl Jitter {
    /// For an output device running at `device_rate` Hz.
    pub(crate) fn new(device_rate: u32) -> Self {
        Self {
            held: VecDeque::with_capacity(MAX_HELD + FRAME),
            playing: false,
            step: f64::from(RATE) / f64::from(device_rate.max(1)),
            pos: 0.0,
            concealed: 0,
            dropped: 0,
            underruns: 0,
        }
    }

    /// One decoded frame (interleaved stereo at 48 kHz).
    pub(crate) fn push(&mut self, pcm: &[f32]) {
        for [l, r] in pcm.as_chunks::<CHANNELS>().0 {
            self.held.push_back((*l, *r));
        }
        while self.held.len() > MAX_HELD {
            self.held.pop_front();
            self.dropped += 1;
        }
    }

    /// Fills `out` (interleaved, `channels` per frame) for the device.
    /// Silence before enough sound arrived, after running dry, and always
    /// when `muted` (A6) - muted, sound is still consumed.
    pub(crate) fn pull(&mut self, out: &mut [f32], channels: usize, muted: bool) {
        let channels = channels.max(1);
        if !self.playing && self.held.len() >= START {
            self.playing = true;
        }
        for frame in out.chunks_mut(channels) {
            let (l, r) = if self.playing {
                match self.next() {
                    Some(lr) => lr,
                    None => {
                        self.playing = false;
                        self.underruns += 1;
                        (0.0, 0.0)
                    }
                }
            } else {
                (0.0, 0.0)
            };
            let (l, r) = if muted { (0.0, 0.0) } else { (l, r) };
            match channels {
                1 => frame[0] = (l + r) / 2.0,
                _ => {
                    frame[0] = l;
                    frame[1] = r;
                    for extra in &mut frame[2..] {
                        *extra = 0.0;
                    }
                }
            }
        }
    }

    /// The next device sample, interpolated between 48 kHz samples.
    fn next(&mut self) -> Option<(f32, f32)> {
        let a = *self.held.front()?;
        let b = self.held.get(1).copied().unwrap_or(a);
        let t = self.pos as f32;
        let v = (a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t);
        self.pos += self.step;
        while self.pos >= 1.0 && !self.held.is_empty() {
            self.held.pop_front();
            self.pos -= 1.0;
        }
        Some(v)
    }

    /// Sound waiting, in 48 kHz frames.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held.len()
    }
}

/// Decodes packets in order, concealing gaps (AU2), into a [`Jitter`].
#[derive(Debug)]
pub(crate) struct Feeder {
    decoder: remora_codec::audio::AudioDecoder,
    next_seq: Option<u32>,
}

impl Feeder {
    pub(crate) fn new() -> Result<Self, remora_codec::audio::AudioCodecError> {
        Ok(Self {
            decoder: remora_codec::audio::AudioDecoder::new()?,
            next_seq: None,
        })
    }

    /// One packet (already checked by the protocol parser, A3).
    pub(crate) fn feed(&mut self, p: &AudioPacket, jitter: &mut Jitter) {
        if let Some(want) = self.next_seq {
            let missing = p.seq.wrapping_sub(want);
            if missing > u32::MAX / 2 {
                return; // older than the last played: late or reordered
            }
            if missing <= MAX_CONCEAL {
                for _ in 0..missing {
                    if let Ok(pcm) = self.decoder.conceal() {
                        jitter.push(&pcm);
                        jitter.concealed += 1;
                    }
                }
            }
        }
        if let Ok(pcm) = self.decoder.decode(&p.data) {
            jitter.push(&pcm);
        }
        self.next_seq = Some(p.seq.wrapping_add(1));
    }
}

/// A6: the viewer's mute, toggled by the window's local mute key
/// (Ctrl+Option+M, never sent to the host). One session per process.
pub(crate) static MUTED: AtomicBool = AtomicBool::new(false);

/// Flips [`MUTED`]; returns the new state.
pub(crate) fn toggle_mute() -> bool {
    !MUTED.fetch_xor(true, Ordering::Relaxed)
}

/// Packets waiting for the sound thread; more are dropped (never blocks
/// the network task).
const QUEUE: usize = 16;

/// The sound thread: owns the decoder and the output stream (cpal's
/// stream stays on the thread that made it). Dropping this ends it and
/// prints one `sound:` line of counts (INV9: never content).
#[derive(Debug)]
pub(crate) struct Sound {
    tx: Option<std::sync::mpsc::SyncSender<AudioPacket>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sound {
    /// Starts the thread; problems with the output device are printed once
    /// and the session goes on without sound.
    pub(crate) fn start() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<AudioPacket>(QUEUE);
        let thread = std::thread::Builder::new()
            .name("remora-sound".into())
            .spawn(move || {
                let mut out = match Output::start() {
                    Ok(o) => Some(o),
                    Err(e) => {
                        println!("sound: not playing ({e:#})");
                        None
                    }
                };
                let mut packets = 0u64;
                while let Ok(p) = rx.recv() {
                    packets += 1;
                    if let Some(o) = out.as_mut() {
                        o.play(&p);
                    }
                }
                if let Some((c, d, u)) = out.as_ref().and_then(Output::stats) {
                    println!(
                        "sound: {packets} packets, {c} concealed, {d} samples dropped for delay, {u} times ran dry"
                    );
                }
            })
            .ok();
        Self {
            tx: Some(tx),
            thread,
        }
    }

    /// One received packet (dropped if the thread is behind).
    pub(crate) fn offer(&self, p: AudioPacket) {
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(p);
        }
    }
}

impl Drop for Sound {
    fn drop(&mut self) {
        self.tx = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The output device side (macOS: CoreAudio through cpal).
struct Output {
    jitter: Arc<Mutex<Jitter>>,
    feeder: Feeder,
    #[cfg(target_os = "macos")]
    _stream: cpal::Stream,
}

impl Output {
    #[cfg(target_os = "macos")]
    fn start() -> anyhow::Result<Self> {
        use anyhow::Context;
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
        let device = cpal::default_host()
            .default_output_device()
            .context("no sound output device")?;
        let config = device.default_output_config()?.config();
        let channels = usize::from(config.channels);
        let jitter = Arc::new(Mutex::new(Jitter::new(config.sample_rate)));
        let j = Arc::clone(&jitter);
        let stream = device.build_output_stream(
            config,
            move |out: &mut [f32], _| match j.lock() {
                Ok(mut j) => j.pull(out, channels, MUTED.load(Ordering::Relaxed)),
                Err(_) => out.fill(0.0),
            },
            |e| eprintln!("sound output: {e}"),
            None,
        )?;
        stream.play()?;
        Ok(Self {
            jitter,
            feeder: Feeder::new()?,
            _stream: stream,
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn start() -> anyhow::Result<Self> {
        let _ = (Feeder::new, &MUTED);
        anyhow::bail!("sound playback is macOS-only for now")
    }

    fn play(&mut self, p: &AudioPacket) {
        if let Ok(mut j) = self.jitter.lock() {
            self.feeder.feed(p, &mut j);
        }
    }

    /// Counts (no sound content: INV9).
    fn stats(&self) -> Option<(u64, u64, u64)> {
        let j = self.jitter.lock().ok()?;
        Some((j.concealed, j.dropped, j.underruns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(v: f32) -> Vec<f32> {
        vec![v; FRAME * CHANNELS]
    }

    #[test]
    fn waits_for_start_then_plays_and_runs_dry_cleanly() {
        let mut j = Jitter::new(RATE);
        let mut out = vec![9.0; 2 * 100];
        j.push(&frame(0.5));
        j.pull(&mut out, 2, false);
        assert!(out.iter().all(|&s| s == 0.0), "played before START");
        j.push(&frame(0.5));
        j.pull(&mut out, 2, false);
        assert!(out.iter().all(|&s| (s - 0.5).abs() < 1e-6));
        let mut long = vec![9.0; 2 * 3 * FRAME];
        j.pull(&mut long, 2, false);
        assert_eq!(j.underruns, 1);
        assert_eq!(long[long.len() - 1], 0.0, "silence after running dry");
    }

    #[test]
    fn a6_muted_is_silent_and_still_consumes() {
        let mut j = Jitter::new(RATE);
        for _ in 0..3 {
            j.push(&frame(0.7));
        }
        let before = j.held();
        let mut out = vec![9.0; 2 * FRAME];
        j.pull(&mut out, 2, true);
        assert!(out.iter().all(|&s| s == 0.0), "sound while muted");
        assert!(j.held() < before, "muted must not let sound pile up");
    }

    #[test]
    fn a4_debug_shows_counts_never_samples() {
        let mut j = Jitter::new(RATE);
        j.push(&frame(0.123_456_7));
        let text = format!("{j:?}");
        assert!(!text.contains("0.123"), "samples in Debug: {text}");
        assert!(text.contains("held_frames: 960"), "{text}");
    }

    #[test]
    fn delay_is_bounded() {
        let mut j = Jitter::new(RATE);
        for _ in 0..50 {
            j.push(&frame(0.1));
        }
        assert_eq!(j.held(), MAX_HELD);
        assert!(j.dropped > 0);
    }

    #[test]
    fn rate_conversion_keeps_time() {
        // 44.1 kHz device: 20 ms of 48 kHz sound gives ~882 output frames.
        let mut j = Jitter::new(44_100);
        for _ in 0..3 {
            j.push(&frame(0.2));
        }
        let mut out = vec![0.0; 2 * 882];
        j.pull(&mut out, 2, false);
        let used = 3 * FRAME - j.held();
        assert!((958..=962).contains(&used), "{used} input frames for 20 ms");
    }

    #[test]
    fn mono_and_multichannel_devices_get_sensible_samples() {
        let mut j = Jitter::new(RATE);
        let lr: Vec<f32> = (0..2 * FRAME)
            .map(|i| if i % 2 == 0 { 0.2 } else { 0.4 })
            .collect();
        for _ in 0..2 {
            j.push(&lr);
        }
        let mut mono = vec![0.0; 10];
        j.pull(&mut mono, 1, false);
        assert!(mono.iter().all(|&s| (s - 0.3).abs() < 1e-6));
        let mut quad = vec![9.0; 4 * 10];
        j.pull(&mut quad, 4, false);
        assert!(quad.chunks(4).all(|f| f[2] == 0.0 && f[3] == 0.0));
    }

    #[test]
    fn gaps_are_concealed_and_late_packets_ignored() {
        use remora_codec::audio::{AudioEncoder, DEFAULT_BITRATE};
        let mut enc = AudioEncoder::new(DEFAULT_BITRATE).expect("enc");
        let mut pkt = |seq| AudioPacket {
            seq,
            capture_ts_us: 0,
            data: enc.encode(&frame(0.1)).expect("encode"),
        };
        let (p0, p3, p1) = (pkt(0), pkt(3), pkt(1));
        let mut f = Feeder::new().expect("feeder");
        let mut j = Jitter::new(RATE);
        f.feed(&p0, &mut j);
        f.feed(&p3, &mut j); // 1 and 2 lost
        assert_eq!(j.concealed, 2);
        assert_eq!(j.held(), 4 * FRAME);
        f.feed(&p1, &mut j); // arrives late: not played
        assert_eq!(j.held(), 4 * FRAME);
    }
}
