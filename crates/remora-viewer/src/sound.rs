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
/// Sound held for a whole second above this makes playback catch up
/// (live, 2026-11-03: the buffer filled to ~110 ms while the earbuds
/// started and never drained, since sound arrives as fast as it plays).
pub(crate) const TARGET: usize = 3 * FRAME; // 60 ms
/// Catching up plays this much faster (1 %: ~17 cents, not heard as a
/// pitch change); it stops once the buffer is back at [`START`].
pub(crate) const CATCH_UP: f64 = 1.01;

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
    /// Timing (`--timing`, AU1/AU3): 48 kHz frames pushed and consumed
    /// since the start, and where each packet's sound begins with its
    /// capture time on the host's clock (µs).
    pushed: u64,
    consumed: u64,
    marks: VecDeque<(u64, u64)>,
    /// Speaker time (viewer clock) minus capture time (host clock), µs,
    /// one per device callback while playing; taken by the stats line.
    pub(crate) ages: Vec<i64>,
    /// The output device's own delay (buffer + reported latency), µs.
    pub(crate) device_delay_us: u64,
    /// Catch-up: the device's rate, the least held in the current
    /// one-second window, output frames counted in it, and whether
    /// playback is running fast.
    device_rate: u32,
    window_min: usize,
    window_frames: u64,
    catching_up: bool,
    /// Times catch-up started (stats).
    pub(crate) catch_ups: u64,
    /// Output frames played since the sound (re)started after running
    /// dry; `None` once [`RESYNC_WINDOW`] has passed.
    since_dry: Option<u64>,
    /// Times a backlog was dropped right after a restart (stats).
    pub(crate) resyncs: u64,
}

/// Just after the sound (re)starts, a gap was already heard: a backlog
/// that arrives then (live, 2026-11-03: the buffer ran dry, then jumped to
/// ~110 ms in one burst) is dropped down to [`START`] at once rather than
/// drained at 1 % for seconds. Milliseconds of playback this applies for.
const RESYNC_WINDOW_MS: u64 = 500;

/// Most timing samples kept between two stats lines.
const MAX_AGES: usize = 4096;

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
            pushed: 0,
            consumed: 0,
            marks: VecDeque::new(),
            ages: Vec::new(),
            device_delay_us: 0,
            device_rate: device_rate.max(1),
            window_min: usize::MAX,
            window_frames: 0,
            catching_up: false,
            catch_ups: 0,
            since_dry: Some(0),
            resyncs: 0,
        }
    }

    /// One decoded frame (interleaved stereo at 48 kHz).
    #[cfg(test)]
    pub(crate) fn push(&mut self, pcm: &[f32]) {
        self.push_at(pcm, None);
    }

    /// One decoded frame whose first sample was captured at `capture_us`
    /// (host clock), when known.
    pub(crate) fn push_at(&mut self, pcm: &[f32], capture_us: Option<u64>) {
        if let Some(c) = capture_us {
            self.marks.push_back((self.pushed, c));
        }
        let frames = pcm.as_chunks::<CHANNELS>().0;
        for [l, r] in frames {
            self.held.push_back((*l, *r));
        }
        self.pushed += frames.len() as u64;
        while self.held.len() > MAX_HELD {
            self.held.pop_front();
            self.consumed += 1;
            self.dropped += 1;
        }
    }

    /// Capture time (host clock, µs) of the sound about to play.
    fn head_capture_us(&mut self) -> Option<u64> {
        while self.marks.len() >= 2 && self.marks[1].0 <= self.consumed {
            self.marks.pop_front();
        }
        let (start, c) = *self.marks.front()?;
        let into = self.consumed.checked_sub(start)?;
        Some(c + into * 1_000_000 / u64::from(RATE))
    }

    /// [`Self::pull`], and with `speaker_us` (when this buffer reaches the
    /// speaker, viewer clock) records one age for `--timing`.
    pub(crate) fn pull_timed(
        &mut self,
        out: &mut [f32],
        channels: usize,
        muted: bool,
        speaker_us: Option<u64>,
    ) {
        if !self.playing && self.held.len() >= START {
            self.playing = true;
        }
        if self.playing
            && let Some(at) = speaker_us
            && let Some(c) = self.head_capture_us()
            && self.ages.len() < MAX_AGES
        {
            self.ages.push(at as i64 - c as i64);
        }
        self.pull(out, channels, muted);
    }

    /// Fills `out` (interleaved, `channels` per frame) for the device.
    /// Silence before enough sound arrived, after running dry, and always
    /// when `muted` (A6) - muted, sound is still consumed.
    pub(crate) fn pull(&mut self, out: &mut [f32], channels: usize, muted: bool) {
        let channels = channels.max(1);
        if !self.playing && self.held.len() >= START {
            self.playing = true;
        }
        if self.playing {
            self.watch_level((out.len() / channels) as u64);
        }
        for frame in out.chunks_mut(channels) {
            let (l, r) = if self.playing {
                match self.next() {
                    Some(lr) => lr,
                    None => {
                        self.playing = false;
                        self.underruns += 1;
                        self.since_dry = Some(0);
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

    /// Starts catching up when a whole second never went down to
    /// [`TARGET`]; stops at [`START`].
    fn watch_level(&mut self, frames: u64) {
        if let Some(played) = self.since_dry {
            if self.held.len() > TARGET {
                let extra = self.held.len() - START;
                self.held.drain(..extra);
                self.consumed += extra as u64;
                self.dropped += extra as u64;
                self.pos = 0.0;
                self.resyncs += 1;
            }
            let played = played + frames;
            self.since_dry =
                (played * 1000 < RESYNC_WINDOW_MS * u64::from(self.device_rate)).then_some(played);
        }
        let held = self.held.len();
        self.window_min = self.window_min.min(held);
        self.window_frames += frames;
        if self.window_frames >= u64::from(self.device_rate) {
            if self.window_min > TARGET && !self.catching_up {
                self.catching_up = true;
                self.catch_ups += 1;
            }
            self.window_min = usize::MAX;
            self.window_frames = 0;
        }
        if self.catching_up && held <= START {
            self.catching_up = false;
        }
    }

    /// The next device sample, interpolated between 48 kHz samples.
    fn next(&mut self) -> Option<(f32, f32)> {
        let a = *self.held.front()?;
        let b = self.held.get(1).copied().unwrap_or(a);
        let t = self.pos as f32;
        let v = (a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t);
        self.pos += if self.catching_up {
            self.step * CATCH_UP
        } else {
            self.step
        };
        while self.pos >= 1.0 && !self.held.is_empty() {
            self.held.pop_front();
            self.consumed += 1;
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
                for k in 0..missing {
                    // The lost packet's sound would have been captured 20 ms
                    // per packet before this one.
                    let at = p
                        .capture_ts_us
                        .saturating_sub(u64::from(missing - k) * 20_000);
                    if let Ok(pcm) = self.decoder.conceal() {
                        jitter.push_at(&pcm, Some(at));
                        jitter.concealed += 1;
                    }
                }
            }
        }
        if let Ok(pcm) = self.decoder.decode(&p.data) {
            jitter.push_at(&pcm, Some(p.capture_ts_us));
        }
        self.next_seq = Some(p.seq.wrapping_add(1));
    }
}

/// A6: the viewer's mute, toggled by the window's local mute key
/// (Ctrl+Option+M, never sent to the host). One session per process.
pub(crate) static MUTED: AtomicBool = AtomicBool::new(false);

/// Tests that flip [`MUTED`] take turns (tests run in parallel).
#[cfg(test)]
pub(crate) static MUTE_TESTS: Mutex<()> = Mutex::new(());

/// Flips [`MUTED`]; returns the new state.
pub(crate) fn toggle_mute() -> bool {
    !MUTED.fetch_xor(true, Ordering::Relaxed)
}

/// Packets waiting for the sound thread; more are dropped (never blocks
/// the network task).
const QUEUE: usize = 16;

/// What the sound thread did (INV9: counts only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Counts {
    /// Packets received.
    pub(crate) packets: u64,
    /// Lost packets filled by concealment.
    pub(crate) concealed: u64,
    /// 48 kHz frames dropped to bound the delay.
    pub(crate) dropped: u64,
    /// Times playback ran dry.
    pub(crate) underruns: u64,
    /// 48 kHz frames still waiting at the end.
    pub(crate) held: usize,
}

/// The sound thread: owns the decoder and the output stream (cpal's
/// stream stays on the thread that made it). Dropping this ends it and
/// prints one `sound:` line of counts (INV9: never content).
#[derive(Debug)]
pub(crate) struct Sound {
    tx: Option<std::sync::mpsc::SyncSender<AudioPacket>>,
    thread: Option<std::thread::JoinHandle<Option<Counts>>>,
}

impl Sound {
    /// Starts the thread on the default output device; problems with it
    /// are printed once and the session goes on without sound.
    /// `timing`: one `audio:` line a second on stderr (AU1/AU3).
    pub(crate) fn start(timing: bool) -> Self {
        Self::start_with(Output::start, timing)
    }

    fn start_with(open: fn() -> anyhow::Result<Output>, timing: bool) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<AudioPacket>(QUEUE);
        let thread = std::thread::Builder::new()
            .name("remora-sound".into())
            .spawn(move || {
                let mut out = match open() {
                    Ok(o) => o,
                    Err(e) => {
                        println!("sound: not playing ({e:#})");
                        while rx.recv().is_ok() {}
                        return None;
                    }
                };
                let mut packets = 0u64;
                let mut last_line = std::time::Instant::now();
                loop {
                    match rx.recv_timeout(std::time::Duration::from_millis(250)) {
                        Ok(p) => {
                            packets += 1;
                            out.play(&p);
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    if timing && last_line.elapsed() >= std::time::Duration::from_secs(1) {
                        last_line = std::time::Instant::now();
                        if let Some(line) = out.timing_line() {
                            eprintln!("{line}");
                        }
                    }
                }
                out.counts(packets)
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

    /// Ends the thread after the packets already queued; its counts.
    pub(crate) fn finish(&mut self) -> Option<Counts> {
        self.tx = None;
        self.thread.take()?.join().ok().flatten()
    }
}

impl Drop for Sound {
    fn drop(&mut self) {
        if let Some(c) = self.finish() {
            println!(
                "sound: {} packets, {} concealed, {} samples dropped for delay, {} times ran dry",
                c.packets, c.concealed, c.dropped, c.underruns
            );
        }
    }
}

/// The output device side (macOS: CoreAudio through cpal).
struct Output {
    jitter: Arc<Mutex<Jitter>>,
    feeder: Feeder,
    /// Arrival (viewer clock) minus capture (host clock), µs, per packet.
    arrivals: Vec<i64>,
    /// Plays while held (macOS); `None` in tests.
    #[cfg(target_os = "macos")]
    _stream: Option<cpal::Stream>,
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
            move |out: &mut [f32], info: &cpal::OutputCallbackInfo| {
                // When this buffer reaches the speaker, on our clock: now
                // plus the device's own delay (cpal 0.18.2: buffer +
                // kAudioDevicePropertyLatency + SafetyOffset).
                let ts = info.timestamp();
                let delay = ts.playback.duration_since(ts.callback);
                let delay_us = u64::try_from(delay.as_micros()).unwrap_or(u64::MAX);
                let speaker_us =
                    remora_app::clock::monotonic_ns().map(|n| (n / 1000).saturating_add(delay_us));
                match j.lock() {
                    Ok(mut j) => {
                        j.device_delay_us = delay_us;
                        j.pull_timed(out, channels, MUTED.load(Ordering::Relaxed), speaker_us);
                    }
                    Err(_) => out.fill(0.0),
                }
            },
            |e| eprintln!("sound output: {e}"),
            None,
        )?;
        stream.play()?;
        Ok(Self {
            jitter,
            feeder: Feeder::new()?,
            arrivals: Vec::new(),
            _stream: Some(stream),
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn start() -> anyhow::Result<Self> {
        let _ = (Feeder::new, &MUTED);
        anyhow::bail!("sound playback is macOS-only for now")
    }

    fn play(&mut self, p: &AudioPacket) {
        if self.arrivals.len() < MAX_AGES
            && let Some(now) = remora_app::clock::monotonic_ns()
        {
            self.arrivals
                .push((now / 1000) as i64 - p.capture_ts_us as i64);
        }
        if let Ok(mut j) = self.jitter.lock() {
            self.feeder.feed(p, &mut j);
        }
    }

    /// `--timing`: the ages since the last line (times only: INV9).
    fn timing_line(&mut self) -> Option<String> {
        let mut j = self.jitter.lock().ok()?;
        let ages = std::mem::take(&mut j.ages);
        let arrivals = std::mem::take(&mut self.arrivals);
        Some(timing_line(
            &ages,
            &arrivals,
            j.device_delay_us,
            j.held.len(),
        ))
    }

    /// Counts (no sound content: INV9).
    fn counts(&self, packets: u64) -> Option<Counts> {
        let j = self.jitter.lock().ok()?;
        Some(Counts {
            packets,
            concealed: j.concealed,
            dropped: j.dropped,
            underruns: j.underruns,
            held: j.held.len(),
        })
    }
}

/// p-th percentile (0..=1) of `v` in ms, or "-" when empty.
fn pct_ms(v: &mut [i64], p: f64) -> String {
    if v.is_empty() {
        return "-".into();
    }
    v.sort_unstable();
    let i = ((v.len() - 1) as f64 * p).round() as usize;
    format!("{:.1}", v[i] as f64 / 1000.0)
}

/// One `audio:` line. `speaker` and `arrival` mix two clocks (viewer
/// minus host), so each alone is off by the clocks' difference; the
/// difference of the two, and the same speaker figure against the
/// video's `presented_us - capture_us`, are exact (AU3).
pub(crate) fn timing_line(ages: &[i64], arrivals: &[i64], device_us: u64, held: usize) -> String {
    let (mut a, mut r) = (ages.to_vec(), arrivals.to_vec());
    format!(
        "audio: speaker_minus_capture_ms p50 {} p95 {} (n {}), arrival_minus_capture_ms min {} p50 {} (n {}), device_delay_ms {:.1}, held_ms {:.1}",
        pct_ms(&mut a, 0.5),
        pct_ms(&mut a, 0.95),
        a.len(),
        pct_ms(&mut r, 0.0),
        pct_ms(&mut r, 0.5),
        r.len(),
        device_us as f64 / 1000.0,
        held as f64 * 1000.0 / f64::from(RATE)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(v: f32) -> Vec<f32> {
        vec![v; FRAME * CHANNELS]
    }

    /// An output with no device: the jitter buffer only (tests).
    fn silent_output() -> anyhow::Result<Output> {
        Ok(Output {
            jitter: Arc::new(Mutex::new(Jitter::new(RATE))),
            feeder: Feeder::new()?,
            arrivals: Vec::new(),
            #[cfg(target_os = "macos")]
            _stream: None,
        })
    }

    fn packets(n: u32) -> Vec<AudioPacket> {
        use remora_codec::audio::{AudioEncoder, DEFAULT_BITRATE};
        let mut enc = AudioEncoder::new(DEFAULT_BITRATE).expect("enc");
        (0..n)
            .map(|seq| AudioPacket {
                seq,
                capture_ts_us: 0,
                data: enc.encode(&frame(0.1)).expect("encode"),
            })
            .collect()
    }

    #[test]
    fn the_sound_thread_decodes_what_it_is_offered() {
        let mut s = Sound::start_with(silent_output, false);
        for p in packets(3) {
            s.offer(p);
        }
        let c = s.finish().expect("counts");
        assert_eq!(c.packets, 3);
        assert_eq!(c.held, 3 * FRAME, "every packet decoded into the buffer");
        assert_eq!(s.finish(), None, "finished once");
    }

    #[test]
    fn a_missing_device_plays_nothing_and_does_not_hang() {
        let mut s = Sound::start_with(|| anyhow::bail!("no device"), false);
        for p in packets(2) {
            s.offer(p);
        }
        assert_eq!(s.finish(), None);
    }

    #[test]
    fn toggle_mute_returns_the_new_state() {
        let _turn = MUTE_TESTS.lock();
        let now = toggle_mute();
        assert_eq!(now, MUTED.load(Ordering::Relaxed));
        assert_eq!(toggle_mute(), !now);
    }

    #[test]
    fn rate_conversion_interpolates_each_channel() {
        // 96 kHz device: every second output sample lies halfway between
        // two input samples. Left rises, right falls, so a mixed-up
        // formula or channel shows.
        let mut j = Jitter::new(96_000);
        let ramp: Vec<f32> = (0..2 * FRAME)
            .flat_map(|i| [i as f32 / 1000.0, 1.0 - i as f32 / 1000.0])
            .collect();
        j.push(&ramp);
        let mut out = vec![0.0; 2 * 8];
        j.pull(&mut out, 2, false);
        for (k, lr) in out.chunks(2).enumerate() {
            let x = k as f32 * 0.5 / 1000.0;
            assert!((lr[0] - x).abs() < 1e-6, "left {k}: {} vs {x}", lr[0]);
            assert!((lr[1] - (1.0 - x)).abs() < 1e-6, "right {k}: {}", lr[1]);
        }
    }

    #[test]
    fn a_packet_far_ahead_is_played_not_taken_for_a_late_one() {
        let ps = packets(1);
        let mut f = Feeder::new().expect("feeder");
        let mut j = Jitter::new(RATE);
        f.feed(&ps[0], &mut j);
        let mut far = ps[0].clone();
        far.seq = 1u32.wrapping_add(u32::MAX / 2);
        f.feed(&far, &mut j);
        assert_eq!(j.held(), 2 * FRAME, "too far to conceal, still played");
        assert_eq!(j.concealed, 0);
    }

    #[test]
    fn waits_for_start_then_plays_and_runs_dry_cleanly() {
        let mut j = Jitter::new(RATE);
        let mut out = vec![9.0; 2 * 100];
        j.push(&frame(0.5));
        j.push(&frame(0.5)[..FRAME]); // 30 ms: still under START
        j.pull(&mut out, 2, false);
        assert!(out.iter().all(|&s| s == 0.0), "played before START");
        j.push(&frame(0.5)[..FRAME]); // 40 ms: plays
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
    fn the_age_follows_the_sound_through_the_buffer() {
        // Two packets captured at 1.000 s and 1.020 s (host clock).
        let mut j = Jitter::new(RATE);
        j.push_at(&frame(0.1), Some(1_000_000));
        j.push_at(&frame(0.1), Some(1_020_000));
        let mut out = vec![0.0; 2 * FRAME / 2]; // 10 ms
        // Reaches the speaker at 1.100 s (viewer clock): 100 ms old.
        j.pull_timed(&mut out, 2, false, Some(1_100_000));
        // Next buffer starts 10 ms into the first packet, at 1.110 s.
        j.pull_timed(&mut out, 2, false, Some(1_110_000));
        // Then 20 ms in: the second packet's start, at 1.120 s.
        j.pull_timed(&mut out, 2, false, Some(1_120_000));
        assert_eq!(j.ages, vec![100_000, 100_000, 100_000]);
    }

    #[test]
    fn no_age_before_playing_or_without_a_capture_time() {
        let mut j = Jitter::new(RATE);
        j.push_at(&frame(0.1), Some(5));
        let mut out = vec![0.0; 2 * 10];
        j.pull_timed(&mut out, 2, false, Some(10)); // under START
        j.push(&frame(0.1));
        j.pull_timed(&mut out, 2, false, None);
        assert!(j.ages.is_empty());
    }

    #[test]
    fn the_timing_line_is_numbers_only() {
        let line = timing_line(&[30_000, 10_000, 20_000], &[5_000], 12_500, 1920);
        assert_eq!(
            line,
            "audio: speaker_minus_capture_ms p50 20.0 p95 30.0 (n 3), arrival_minus_capture_ms min 5.0 p50 5.0 (n 1), device_delay_ms 12.5, held_ms 40.0"
        );
        assert!(timing_line(&[], &[], 0, 0).contains("p50 - p95 -"));
    }

    /// A steady stream (one packet per 20 ms of playback) starting with
    /// `start` packets held; returns the sound held after `secs`.
    fn steady(start: usize, secs: usize) -> (usize, Jitter) {
        let mut j = Jitter::new(RATE);
        for _ in 0..start {
            j.push(&frame(0.1));
        }
        let mut out = vec![0.0; 2 * FRAME];
        for _ in 0..secs * 50 {
            j.push(&frame(0.1));
            j.pull(&mut out, 2, false);
        }
        (j.held(), j)
    }

    #[test]
    fn a_full_buffer_drains_back_to_start() {
        // A backlog that builds up while playing (past the start window):
        // within 10 s of steady sound it is back near START (+ one packet
        // in flight), by playing 1 % fast, not by dropping sound.
        let (_, mut j) = steady(2, 2);
        for _ in 0..3 {
            j.push(&frame(0.1));
        }
        let mut out = vec![0.0; 2 * FRAME];
        for _ in 0..500 {
            j.push(&frame(0.1));
            j.pull(&mut out, 2, false);
        }
        assert!(
            j.held() <= START + FRAME,
            "still holding {} frames",
            j.held()
        );
        assert_eq!((j.catch_ups, j.resyncs, j.dropped), (1, 0, 0));
    }

    #[test]
    fn the_first_fill_while_the_device_starts_is_dropped_at_once() {
        // Live: ~115 ms held in the first second (earbuds starting).
        let (held, j) = steady(5, 1);
        assert!(held <= START + FRAME, "{held}");
        assert_eq!(j.resyncs, 1);
    }

    #[test]
    fn a_backlog_right_after_running_dry_is_dropped_at_once() {
        let (_, mut j) = steady(2, 2); // well past the start window
        let mut out = vec![0.0; 2 * FRAME];
        for _ in 0..4 {
            j.pull(&mut out, 2, false); // nothing arrives: runs dry
        }
        assert_eq!(j.underruns, 1);
        for _ in 0..6 {
            j.push(&frame(0.1)); // the burst after the gap
        }
        j.pull(&mut out, 2, false);
        assert!(j.held() <= START, "kept a backlog of {} frames", j.held());
        assert_eq!(j.resyncs, 1);
        // Later, normal sound is never dropped this way.
        for _ in 0..100 {
            j.push(&frame(0.1));
            j.pull(&mut out, 2, false);
        }
        assert_eq!(j.resyncs, 1);
    }

    #[test]
    fn a_normal_buffer_never_speeds_up() {
        let (held, j) = steady(2, 10);
        assert_eq!(j.catch_ups, 0, "sped up at the normal level");
        assert!(held <= TARGET, "{held}");
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
