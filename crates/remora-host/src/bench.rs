//! `remora-host bench-capture` — the Phase 2 measurement tool.
//! Every number it prints is defined in docs/phase2-criteria.md.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use remora_capture::{CaptureConfig, CaptureEvent, FrameStatus, MacScreenCapture, ScreenCapture};
use remora_codec::{
    Codec, EncoderConfig, EncoderEvent, H264Profile, SyntheticSource, TuneValue, VtEncoder,
};

use crate::stats::{Samples, slope};
use crate::sysmon;

// Thresholds — copied from docs/phase2-criteria.md §2. Do not edit without §6.
// PER-CHIP: measured for the Apple M4; other hardware gets its own numbers.
// C12 (2026-10-17, criteria §6): screen change → encoded, p95 ≤ C1 + C2 budgets.
const C12_P95_MS: f64 = C1_CAPTURE_MS + C2_ENCODE_P95_MS;
// C1 and C2 below are reported for information only.
const C1_CAPTURE_MS: f64 = 4.0;
// C2 revised 2026-10-17 (criteria §6): p95 ≤ 7 ms; was an unmeasured 6 ms estimate.
const C2_ENCODE_P95_MS: f64 = 7.0;
const C3_CPU_PERCENT: f64 = 2.0;
const C4_GROWTH_MB: f64 = 2.0;
const C4_SLOPE_MB_PER_MIN: f64 = 0.1;
const C5_MIN_FRACTION: f64 = 0.98;

/// Helper processes whose CPU counts toward Remora's cost (C3).
const HELPERS: [&str; 2] = ["VTEncoderXPCService", "replayd"];

#[derive(Debug, clap::Args)]
pub(crate) struct BenchArgs {
    /// How long to run.
    #[arg(long, default_value_t = 60)]
    seconds: u64,
    /// Write the H.264 Annex B stream here (play it with ffplay/IINA, check with ffprobe).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Output width in pixels.
    #[arg(long, default_value_t = 1920)]
    width: u32,
    /// Output height (0 = keep the display's aspect ratio).
    #[arg(long, default_value_t = 0)]
    height: u32,
    /// Frame-rate cap.
    #[arg(long, default_value_t = 60)]
    fps: u32,
    /// Target bitrate in bits per second.
    #[arg(long, default_value_t = 8_000_000)]
    bitrate: u32,
    /// Use H.264 Constrained High instead of Constrained Baseline.
    #[arg(long)]
    high: bool,
    /// Encode HEVC instead of H.264 (developer experiment).
    #[arg(long)]
    hevc: bool,
    /// Force a keyframe every N frames (0 = first frame only).
    #[arg(long, default_value_t = 0)]
    keyframe_interval: u32,
    /// Encoder-only test: feed generated frames instead of capturing the screen.
    #[arg(long, conflicts_with = "no_capture")]
    synthetic: bool,
    /// Baseline for the CPU A/B: measure CPU without capturing or encoding.
    #[arg(long)]
    no_capture: bool,
    /// Report CPU time of this process and capture/encode helpers (criterion C3).
    #[arg(long)]
    measure_cpu: bool,
    /// Diagnostic only: encode each captured frame when the NEXT one arrives, to
    /// test whether the encoder waits for the GPU to finish writing the surface.
    #[arg(long, hide = true)]
    diag_encode_previous: bool,
    /// Capture this display (CGDirectDisplayID; see `remora-host list-displays`).
    #[arg(long)]
    display_id: Option<u32>,
    /// Developer experiment: set a VideoToolbox property, e.g. `--vt-prop NumberOfSlices=4`.
    #[arg(long = "vt-prop", value_name = "KEY=VALUE", value_parser = parse_prop)]
    vt_props: Vec<(String, TuneValue)>,
    /// Sample this process's memory footprint every N seconds (criterion C4; 0 = off).
    #[arg(long, default_value_t = 0)]
    sample_memory: u64,
}

fn parse_prop(s: &str) -> Result<(String, TuneValue), String> {
    let (k, v) = s.split_once('=').ok_or("expected KEY=VALUE")?;
    Ok((k.to_owned(), v.parse()?))
}

enum Msg {
    Capture {
        status: FrameStatus,
        image_size: Option<(u32, u32)>,
        /// Encoder sequence number and the frame's display time (for display → encoded).
        encoded_as: Option<(u64, Instant)>,
        delivery_ns: Option<i64>,
        dirty_rects: usize,
        submitted: bool,
        encode_error: bool,
    },
    Encoded(EncoderEvent),
    Stopped(String),
}

#[derive(Default)]
struct Tally {
    statuses: BTreeMap<String, u64>,
    per_second: Vec<(u64, u64)>, // (complete, idle) per elapsed second
    delivery: Samples,
    /// Complete frames that arrived BEFORE their display time.
    early: u64,
    /// Complete frames without a display timestamp.
    no_display_time: u64,
    encode: Samples,
    submitted: u64,
    submit_errors: u64,
    encoded: u64,
    dropped: u64,
    encode_errors: u64,
    keyframes: u64,
    bytes: u64,
    dirty_rects: u64,
    events: Vec<String>,
    last_size: Option<(u32, u32)>,
    /// Display time → encoded frame ready (the capture + encode segment as a whole).
    display_to_encoded: Samples,
    display_by_seq: std::collections::HashMap<u64, Instant>,
    completed_by_seq: std::collections::HashMap<u64, Instant>,
}

/// `a − b` in signed nanoseconds.
fn signed_ns(a: Instant, b: Instant) -> i64 {
    match a.checked_duration_since(b) {
        Some(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        None => -i64::try_from(b.duration_since(a).as_nanos()).unwrap_or(i64::MAX),
    }
}

pub(crate) fn run(a: BenchArgs) -> Result<()> {
    if a.seconds == 0 {
        bail!("--seconds must be > 0");
    }
    let pid = std::process::id();
    let mut t = Tally::default();
    let (tx, rx) = mpsc::channel::<Msg>();
    let cfg = CaptureConfig {
        width: a.width,
        height: a.height,
        max_fps: a.fps,
        ..CaptureConfig::default()
    };

    // ── Set up capture (or not) and decide the frame size ───────────────────────
    let mut capture = None;
    let (w, h) = if a.no_capture {
        (0, 0)
    } else if a.synthetic {
        // This Mac's panel is 2560×1664 (0.65): match the captured size by default.
        let h = if a.height == 0 {
            (a.width * 13 / 20) & !1
        } else {
            a.height & !1
        };
        (a.width & !1, h)
    } else {
        let c = MacScreenCapture::display(cfg, a.display_id).context("screen capture")?;
        let (dw, dh) = c.display_pixel_size();
        let size = c.output_size();
        println!("display: {dw}×{dh} px → capturing at {}×{}", size.0, size.1);
        capture = Some(c);
        size
    };

    // ── Encoder ─────────────────────────────────────────────────────────────────
    let encoder = if a.no_capture {
        None
    } else {
        let etx = tx.clone();
        let enc = VtEncoder::with_codec(
            if a.hevc { Codec::Hevc } else { Codec::H264 },
            EncoderConfig {
                width: w,
                height: h,
                fps: a.fps,
                bitrate_bps: a.bitrate,
                profile: if a.high {
                    H264Profile::ConstrainedHigh
                } else {
                    H264Profile::ConstrainedBaseline
                },
                keyframe_interval: a.keyframe_interval,
                enable_ltr: false,
            },
            Box::new(move |ev| {
                let _ = etx.send(Msg::Encoded(ev));
            }),
            &a.vt_props,
        )
        .context("hardware encoder")?;
        let props: Vec<String> = enc
            .property_report()
            .iter()
            .map(|(k, ok)| format!("{k}={}", if *ok { "ok" } else { "REJECTED" }))
            .collect();
        println!(
            "encoder: VideoToolbox H.264 hw, low-latency RC, {}",
            props.join(", ")
        );
        Some(Arc::new(Mutex::new(enc)))
    };

    let mut out = match &a.out {
        Some(p) => Some(BufWriter::with_capacity(
            1 << 20,
            File::create(p).with_context(|| format!("create {}", p.display()))?,
        )),
        None => None,
    };

    let cpu_before = a.measure_cpu.then(sysmon::all_cputimes);
    let start = Instant::now();

    // ── Start the frame source ──────────────────────────────────────────────────
    let stop_synthetic = Arc::new(AtomicBool::new(false));
    let mut synthetic_thread = None;
    if let (Some(c), Some(enc)) = (capture.as_mut(), &encoder) {
        let (enc, ctx) = (Arc::clone(enc), tx.clone());
        let delay = a.diag_encode_previous;
        let mut held = None;
        c.start(Box::new(move |ev| match ev {
            CaptureEvent::Frame(f) => {
                let (mut submitted, mut encode_error, mut enc_seq) = (false, false, None);
                if let Some(img) = f.image.as_ref() {
                    let ts = f.display_time().saturating_duration_since(start);
                    // Diagnostic: encode the PREVIOUS frame (~16 ms after it arrived).
                    let job = if delay {
                        held.replace((img.clone(), ts))
                    } else {
                        Some((img.clone(), ts))
                    };
                    if let Some((image, ts)) = job {
                        match enc.lock().map(|mut e| e.encode(&image, ts, false)) {
                            Ok(Ok(seq)) => {
                                submitted = true;
                                enc_seq = (!delay).then_some(seq);
                            }
                            _ => encode_error = true,
                        }
                    }
                }
                let _ = ctx.send(Msg::Capture {
                    status: f.status,
                    image_size: f.image.as_ref().map(|i| (i.width(), i.height())),
                    encoded_as: enc_seq.map(|s| (s, f.display_time())),
                    delivery_ns: f.delivery_ns,
                    dirty_rects: f.dirty_rects.len(),
                    submitted,
                    encode_error,
                });
            }
            CaptureEvent::Stopped(e) => {
                let _ = ctx.send(Msg::Stopped(e.to_string()));
            }
        }))
        .context("start capture")?;
    } else if let (true, Some(enc)) = (a.synthetic, &encoder) {
        let (enc, stx, stop) = (Arc::clone(enc), tx.clone(), Arc::clone(&stop_synthetic));
        let frame_time = Duration::from_secs(1) / a.fps.max(1);
        synthetic_thread = Some(std::thread::spawn(move || -> Result<()> {
            let mut src = SyntheticSource::new(w, h)?;
            let mut next = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                let img = src.next_frame()?;
                let ok = enc
                    .lock()
                    .map(|mut e| e.encode(&img, next.saturating_duration_since(start), false));
                let _ = stx.send(Msg::Capture {
                    status: FrameStatus::Complete,
                    image_size: None,
                    encoded_as: None,
                    delivery_ns: None,
                    dirty_rects: 0,
                    submitted: matches!(ok, Ok(Ok(_))),
                    encode_error: !matches!(ok, Ok(Ok(_))),
                });
                next += frame_time;
                std::thread::sleep(next.saturating_duration_since(Instant::now()));
            }
            Ok(())
        }));
    }
    drop(tx);
    sysmon::print_machine_state("start");
    println!("running for {} s …", a.seconds);

    // ── Collect ─────────────────────────────────────────────────────────────────
    let deadline = start + Duration::from_secs(a.seconds);
    let mut memory: Vec<(f64, f64)> = Vec::new();
    let mut next_mem = start;
    let mut last_status = None;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if a.sample_memory > 0 && now >= next_mem {
            if let Some(bytes) = sysmon::footprint(pid) {
                memory.push((
                    now.duration_since(start).as_secs_f64() / 60.0,
                    bytes as f64 / 1_048_576.0,
                ));
            }
            next_mem += Duration::from_secs(a.sample_memory);
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(100));
        match rx.recv_timeout(wait) {
            Ok(msg) => handle(msg, &mut t, &mut out, start, &mut last_status)?,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // ── Stop, flush, drain ──────────────────────────────────────────────────────
    if let Some(c) = capture.as_mut() {
        let _ = c.stop();
    }
    stop_synthetic.store(true, Ordering::Relaxed);
    if let Some(th) = synthetic_thread {
        th.join()
            .map_err(|_| anyhow::anyhow!("synthetic thread panicked"))??;
    }
    if let Some(enc) = &encoder {
        enc.lock()
            .map_err(|_| anyhow::anyhow!("encoder lock poisoned"))?
            .flush()?;
    }
    let wall = start.elapsed();
    sysmon::print_machine_state("end");
    let cpu_after = a.measure_cpu.then(sysmon::all_cputimes);
    while let Ok(msg) = rx.recv_timeout(Duration::from_millis(300)) {
        handle(msg, &mut t, &mut out, start, &mut last_status)?;
    }
    if let Some(o) = out.as_mut() {
        o.flush()?;
    }

    report(
        &a,
        &t,
        wall,
        cpu_before.zip(cpu_after),
        &memory,
        pid,
        (w, h),
    );
    Ok(())
}

fn handle(
    msg: Msg,
    t: &mut Tally,
    out: &mut Option<BufWriter<File>>,
    start: Instant,
    last_status: &mut Option<FrameStatus>,
) -> Result<()> {
    let secs = start.elapsed().as_secs_f64();
    match msg {
        Msg::Capture {
            status,
            image_size,
            encoded_as,
            delivery_ns,
            dirty_rects,
            submitted,
            encode_error,
        } => {
            *t.statuses.entry(format!("{status:?}")).or_default() += 1;
            let sec = secs as usize;
            if t.per_second.len() <= sec {
                t.per_second.resize(sec + 1, (0, 0));
            }
            match status {
                FrameStatus::Complete => {
                    t.per_second[sec].0 += 1;
                    // C1 uses EVERY complete frame's signed value (criteria §2):
                    // negative = delivered before the display time. Nothing is dropped.
                    match delivery_ns {
                        Some(ns) => {
                            t.delivery.push_ns(ns);
                            t.early += u64::from(ns < 0);
                        }
                        None => t.no_display_time += 1,
                    }
                }
                FrameStatus::Idle => t.per_second[sec].1 += 1,
                _ => {}
            }
            // Q4: log every transition into or out of a non-normal state.
            let normal = |s: FrameStatus| matches!(s, FrameStatus::Complete | FrameStatus::Idle);
            if last_status.is_none_or(|l| l != status && (!normal(l) || !normal(status))) {
                let line = format!("[{secs:8.3}s] capture status → {status:?}");
                println!("{line}");
                t.events.push(line);
            }
            *last_status = Some(status);
            if let Some(size) = image_size
                && t.last_size != Some(size)
            {
                if t.last_size.is_some() {
                    let line = format!("[{secs:8.3}s] frame size changed → {}×{}", size.0, size.1);
                    println!("{line}");
                    t.events.push(line);
                }
                t.last_size = Some(size);
            }
            if let Some((seq, display)) = encoded_as {
                match t.completed_by_seq.remove(&seq) {
                    Some(done) => t.display_to_encoded.push_ns(signed_ns(done, display)),
                    None => {
                        t.display_by_seq.insert(seq, display);
                    }
                }
            }
            t.dirty_rects += dirty_rects as u64;
            t.submitted += u64::from(submitted);
            t.submit_errors += u64::from(encode_error);
        }
        Msg::Encoded(EncoderEvent::Frame(f)) => {
            t.encoded += 1;
            t.keyframes += u64::from(f.keyframe);
            t.bytes += f.data.len() as u64;
            t.encode.push(f.latency());
            // The capture message may arrive after the encoded frame; keep both orders.
            match t.display_by_seq.remove(&f.seq) {
                Some(display) => t
                    .display_to_encoded
                    .push_ns(signed_ns(f.completed, display)),
                None => {
                    t.completed_by_seq.insert(f.seq, f.completed);
                }
            }
            if let Some(o) = out.as_mut() {
                o.write_all(&f.data)?;
            }
        }
        Msg::Encoded(EncoderEvent::Dropped { .. }) => t.dropped += 1,
        Msg::Encoded(EncoderEvent::Error { seq, error }) => {
            t.encode_errors += 1;
            if t.encode_errors <= 5 {
                println!("[{secs:8.3}s] encode error (frame {seq}): {error}");
            }
        }
        Msg::Stopped(e) => {
            let line = format!("[{secs:8.3}s] capture STOPPED by the OS: {e}");
            println!("{line}");
            t.events.push(line);
        }
    }
    Ok(())
}

fn verdict(pass: bool) -> &'static str {
    if pass { "PASS" } else { "FAIL" }
}

fn report(
    a: &BenchArgs,
    t: &Tally,
    wall: Duration,
    cpu: Option<(sysmon::CpuSnapshot, sysmon::CpuSnapshot)>,
    memory: &[(f64, f64)],
    pid: u32,
    size: (u32, u32),
) {
    let secs = wall.as_secs_f64();
    println!(
        "\n══════════ Remora Phase 2 bench — {}×{} @ {} fps cap, {:.1} s ══════════",
        size.0, size.1, a.fps, secs
    );
    if !a.no_capture {
        println!("callbacks by status: {:?}", t.statuses);
        let complete = t.statuses.get("Complete").copied().unwrap_or(0);
        println!(
            "complete frames: {complete} ({:.1} fps)   dirty rects/frame: {:.1}",
            complete as f64 / secs,
            if complete > 0 {
                t.dirty_rects as f64 / complete as f64
            } else {
                0.0
            }
        );
        let busiest = t.per_second.iter().map(|p| p.0).max().unwrap_or(0);
        let idle_secs = t.per_second.iter().filter(|p| p.0 == 0).count();
        println!(
            "per-second complete frames: max {busiest}; seconds with zero new frames: {idle_secs}/{}",
            t.per_second.len()
        );

        println!(
            "\n{:<26}{:>8}{:>8}{:>8}{:>8}{:>8}{:>9}",
            "latency (ms)", "p50", "p95", "p99", "max", "mean", "samples"
        );
        let row = |name: &str, s: &Samples| {
            if let Some(m) = s.summary() {
                println!(
                    "{name:<26}{:>8.2}{:>8.2}{:>8.2}{:>8.2}{:>8.2}{:>9}",
                    m.p50, m.p95, m.p99, m.max, m.mean, m.count
                );
            }
            s.summary()
        };
        let cap = if a.synthetic {
            None
        } else {
            row("C1 capture delivery", &t.delivery)
        };
        if !a.synthetic {
            let n = t.delivery.summary().map_or(0, |m| m.count);
            println!(
                "  C1 = handler − display time, signed (negative = arrived before display time; min {:.2} ms)",
                t.delivery.summary().map_or(0.0, |m| m.min)
            );
            println!(
                "  C1 accounting: {n} frames with display time ({} early, {} on time/late) + {} without = {complete} complete",
                t.early,
                n - t.early,
                t.no_display_time,
            );
        }
        let enc = row("C2 encode", &t.encode);
        let c12 = if a.synthetic {
            None
        } else {
            row("C12 screen → encoded", &t.display_to_encoded)
        };

        println!(
            "\nencoder: submitted {}  encoded {}  dropped {}  errors {} (+{} submit errors)  keyframes {}  avg bitrate {:.2} Mbit/s",
            t.submitted,
            t.encoded,
            t.dropped,
            t.encode_errors,
            t.submit_errors,
            t.keyframes,
            t.bytes as f64 * 8.0 / secs / 1e6
        );

        println!("\nverdicts (thresholds from docs/phase2-criteria.md):");
        if let Some(m) = c12 {
            println!(
                "  C12 screen → encoded ≤ {C12_P95_MS} ms p95 → {}",
                verdict(m.p95 <= C12_P95_MS)
            );
        }
        // C1/C2 are information only since 2026-10-17 (criteria §6): the boundary
        // between them doesn't match where the GPU work happens.
        if let Some(m) = cap {
            println!(
                "  (info) C1 capture vs former {C1_CAPTURE_MS} ms p50 & p95: {}",
                verdict(m.p50 <= C1_CAPTURE_MS && m.p95 <= C1_CAPTURE_MS)
            );
        }
        if let Some(m) = enc {
            println!(
                "  (info) C2 encode vs former {C2_ENCODE_P95_MS} ms p95: {}",
                verdict(m.p95 <= C2_ENCODE_P95_MS)
            );
        }
        let min_frames = (C5_MIN_FRACTION * a.seconds as f64 * f64::from(a.fps)).ceil() as u64;
        let produced = if a.synthetic { t.submitted } else { complete };
        let kept_up = t.encoded == t.submitted
            && t.dropped == 0
            && t.encode_errors == 0
            && t.submit_errors == 0;
        println!(
            "  C5 keeps up: encoded == submitted, 0 dropped/errors, ≥ {min_frames} frames ({produced}) → {}{}",
            verdict(kept_up && produced >= min_frames),
            if kept_up && produced < min_frames {
                "  (encoder kept up; the SOURCE delivered too few frames — is the screen changing every frame?)"
            } else {
                ""
            }
        );
    }

    if let Some((before, after)) = cpu {
        let deltas = sysmon::cpu_deltas(&before, &after);
        let pct = |d: Duration| d.as_secs_f64() / secs * 100.0;
        let own = deltas
            .iter()
            .find(|(p, _, _)| *p == pid)
            .map_or(Duration::ZERO, |d| d.2);
        let helpers: Duration = deltas
            .iter()
            .filter(|(_, n, _)| HELPERS.iter().any(|h| n.contains(h)))
            .map(|d| d.2)
            .sum();
        println!("\nCPU over {secs:.1} s (% of one core, Activity Monitor convention):");
        println!("  this process        {:6.2} %", pct(own));
        println!("  helpers {HELPERS:?} {:6.2} %", pct(helpers));
        println!("  top processes by CPU time used during the run:");
        for (p, name, d) in deltas.iter().take(8) {
            println!("    {:>6} {:<32} {:6.2} %", p, name, pct(*d));
        }
        if !a.no_capture {
            let total = pct(own + helpers);
            println!(
                "  C3 static CPU < {C3_CPU_PERCENT} % (own + helpers = {total:.2} %) → {}  [valid only for the static-screen test]",
                verdict(total < C3_CPU_PERCENT)
            );
        }
    }

    if !memory.is_empty() {
        let steady: Vec<(f64, f64)> = memory.iter().copied().filter(|(m, _)| *m >= 1.0).collect();
        println!(
            "\nmemory footprint samples (min, MB): {}",
            memory
                .iter()
                .map(|(m, v)| format!("{m:.1}:{v:.1}"))
                .collect::<Vec<_>>()
                .join("  ")
        );
        if let (Some(first), Some(last), Some(sl)) = (steady.first(), steady.last(), slope(&steady))
        {
            let growth = last.1 - first.1;
            println!(
                "  C4 growth min1→end {growth:+.2} MB (≤ {C4_GROWTH_MB}), slope {sl:+.3} MB/min (≤ {C4_SLOPE_MB_PER_MIN}) → {}",
                verdict(growth <= C4_GROWTH_MB && sl <= C4_SLOPE_MB_PER_MIN)
            );
        } else {
            println!("  C4 needs samples after minute 1 (run ≥ 2 min with --sample-memory)");
        }
    }
    if !t.events.is_empty() {
        println!("\nevents:");
        for e in &t.events {
            println!("  {e}");
        }
    }
    if let Some(p) = &a.out {
        println!("\nwrote {} ({:.1} MB)", p.display(), t.bytes as f64 / 1e6);
    }
}

/// `remora-host list-displays`.
pub(crate) fn list_displays() -> Result<()> {
    for (id, w, h, main) in MacScreenCapture::list_displays()? {
        println!(
            "display {id}: {w}×{h} px{}",
            if main { "  (main)" } else { "" }
        );
    }
    Ok(())
}

/// `remora-host probe-encoder`: evidence for Q1 (4:4:4) and Q2 (intra-refresh / LTR).
pub(crate) fn probe() -> Result<()> {
    use remora_codec::{list_encoders, probe_444, supported_properties};
    println!("== installed video encoders ==");
    for e in list_encoders()? {
        println!(
            "  {:<5} hw={:<5} {} ({})",
            e.codec, e.hardware, e.display_name, e.encoder_id
        );
    }
    for (codec, ll) in [
        (Codec::H264, true),
        (Codec::H264, false),
        (Codec::Hevc, false),
    ] {
        println!("\n== supported properties: {codec:?} hardware encoder, low-latency RC = {ll} ==");
        match supported_properties(codec, ll) {
            Ok(r) => {
                let refresh: Vec<_> = r
                    .keys
                    .iter()
                    .filter(|k| k.contains("Refresh") || k.contains("LTR") || k.contains("Intra"))
                    .collect();
                println!(
                    "  {} keys; refresh/LTR/intra-related: {refresh:?}",
                    r.keys.len()
                );
                println!("  ProfileLevel values: {:?}", r.profile_levels);
                println!("  all keys: {}", r.keys.join(", "));
            }
            Err(e) => println!("  not available: {e}"),
        }
    }
    for (codec, ll) in [
        (Codec::H264, true),
        (Codec::H264, false),
        (Codec::Hevc, false),
    ] {
        println!("\n== 4:4:4 encode probe: {codec:?}, low-latency RC = {ll} (source '444v') ==");
        let r = probe_444(codec, ll);
        let verdict = match r.sps_profile {
            Some(p) if p.is_444() => "stream declares 4:4:4 (chroma_format_idc = 3)",
            Some(_) => "encoder SUBSAMPLED: stream is not 4:4:4",
            None => "no stream produced",
        };
        println!("  {r:?}\n  → {verdict}");
    }
    Ok(())
}
