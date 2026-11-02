//! Spike S-A1 (throwaway): can Remora capture what the laptop plays and
//! compress it with Opus fast enough, and does it sound right on the Mac?
//! No network here (Remora never sends plaintext; the real path will be the
//! sealed datagrams): capture -> Opus -> a file, copied over SSH, decoded.
//!
//!   sa1-sound capture <seconds> <out.opuspkts>   (Linux: PipeWire sink capture)
//!   sa1-sound decode <in.opuspkts> <out.wav>     (any OS)
//!
//! File format (spike only): per packet, u16 LE length + Opus bytes.

use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::time::Instant;

const RATE: u32 = 48_000;
const CHANNELS: usize = 2;
/// 20 ms at 48 kHz.
const FRAME: usize = 960;

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * p).round() as usize]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        #[cfg(target_os = "linux")]
        Some("capture") => capture(a[2].parse()?, &a[3]),
        Some("decode") => decode(&a[2], &a[3]),
        _ => {
            eprintln!("usage: capture <secs> <out> | decode <in> <out.wav>");
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn capture(seconds: u64, out: &str) -> Result<(), Box<dyn std::error::Error>> {
    use pipewire as pw;
    use pw::{properties::properties, spa};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct St {
        format: spa::param::audio::AudioInfoRaw,
        pending: Vec<f32>,
        enc: opus::Encoder,
        file: std::fs::File,
        started: Option<Instant>,
        last: Option<Instant>,
        gaps_ms: Vec<f64>,
        enc_ms: Vec<f64>,
        bytes: usize,
        packets: usize,
        peak: f32,
    }
    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_rc(None)?;
    let mut enc = opus::Encoder::new(RATE, opus::Channels::Stereo, opus::Application::Audio)?;
    enc.set_bitrate(opus::Bitrate::Bits(128_000))?;
    let st = Rc::new(RefCell::new(St {
        format: Default::default(),
        pending: Vec::new(),
        enc,
        file: std::fs::File::create(out)?,
        started: None,
        last: None,
        gaps_ms: Vec::new(),
        enc_ms: Vec::new(),
        bytes: 0,
        packets: 0,
        peak: 0.0,
    }));
    let mut props = properties! {
        *pw::keys::MEDIA_TYPE => "Audio",
        *pw::keys::MEDIA_CATEGORY => "Capture",
        *pw::keys::MEDIA_ROLE => "Music",
    };
    // What the computer plays (the default output's monitor), not a mic.
    props.insert(*pw::keys::STREAM_CAPTURE_SINK, "true");
    let stream = pw::stream::StreamBox::new(&core, "remora-sa1", props)?;
    let ml = mainloop.clone();
    let limit = Duration::from_secs(seconds);
    let _l = stream
        .add_local_listener_with_user_data(Rc::clone(&st))
        .param_changed(|_, st, id, param| {
            if let Some(param) = param
                && id == pw::spa::param::ParamType::Format.as_raw()
            {
                let mut st = st.borrow_mut();
                if st.format.parse(param).is_ok() {
                    eprintln!("format: rate {} channels {}", st.format.rate(), st.format.channels());
                }
            }
        })
        .process(move |stream, st| {
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let n = d.chunk().size() as usize / 4;
            let Some(bytes) = d.data() else { return };
            let now = Instant::now();
            let mut st = st.borrow_mut();
            let started = *st.started.get_or_insert(now);
            if let Some(l) = st.last {
                st.gaps_ms.push(now.duration_since(l).as_secs_f64() * 1e3);
            }
            st.last = Some(now);
            for i in 0..n.min(bytes.len() / 4) {
                let s = f32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
                st.peak = st.peak.max(s.abs());
                st.pending.push(s);
            }
            while st.pending.len() >= FRAME * CHANNELS {
                let frame: Vec<f32> = st.pending.drain(..FRAME * CHANNELS).collect();
                let t = Instant::now();
                let mut out = [0u8; 4000];
                let len = st.enc.encode_float(&frame, &mut out).unwrap();
                st.enc_ms.push(t.elapsed().as_secs_f64() * 1e3);
                let st = &mut *st;
                st.file.write_all(&(len as u16).to_le_bytes()).unwrap();
                st.file.write_all(&out[..len]).unwrap();
                st.bytes += len;
                st.packets += 1;
            }
            if now.duration_since(started) >= limit {
                ml.quit();
            }
        })
        .register()?;
    let mut info = spa::param::audio::AudioInfoRaw::new();
    info.set_format(spa::param::audio::AudioFormat::F32LE);
    info.set_rate(RATE);
    info.set_channels(CHANNELS as u32);
    let obj = pw::spa::pod::Object {
        type_: pw::spa::utils::SpaTypes::ObjectParamFormat.as_raw(),
        id: pw::spa::param::ParamType::EnumFormat.as_raw(),
        properties: info.into(),
    };
    let values: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )?
    .0
    .into_inner();
    let mut params = [spa::pod::Pod::from_bytes(&values).ok_or("pod")?];
    stream.connect(
        spa::utils::Direction::Input,
        None,
        pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;
    eprintln!("capturing what this computer plays for {seconds} s (play something)");
    mainloop.run();
    let mut st = st.borrow_mut();
    let secs = st.started.zip(st.last).map_or(0.0, |(a, b)| b.duration_since(a).as_secs_f64());
    let (g50, g95, gmax) = (pct(&mut st.gaps_ms, 0.5), pct(&mut st.gaps_ms, 0.95), pct(&mut st.gaps_ms, 1.0));
    let (e50, e95) = (pct(&mut st.enc_ms, 0.5), pct(&mut st.enc_ms, 0.95));
    println!(
        "RESULT sa1 capture: {} packets (20 ms) in {secs:.1} s, {:.0} kbit/s, buffer gaps p50 {g50:.1} p95 {g95:.1} max {gmax:.1} ms, encode p50 {e50:.3} p95 {e95:.3} ms, peak level {:.2}",
        st.packets,
        st.bytes as f64 * 8.0 / secs.max(1e-9) / 1000.0,
        st.peak
    );
    Ok(())
}

fn decode(input: &str, out: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = Vec::new();
    std::fs::File::open(input)?.read_to_end(&mut data)?;
    let mut dec = opus::Decoder::new(RATE, opus::Channels::Stereo)?;
    let mut pcm: Vec<i16> = Vec::new();
    let mut times = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        i += 2;
        let pkt = &data[i..i + len];
        i += len;
        let mut frame = [0i16; FRAME * CHANNELS];
        let t = Instant::now();
        let n = dec.decode(pkt, &mut frame, false)?;
        times.push(t.elapsed().as_secs_f64() * 1e3);
        pcm.extend_from_slice(&frame[..n * CHANNELS]);
    }
    let mut w = std::fs::File::create(out)?;
    let byte_len = (pcm.len() * 2) as u32;
    w.write_all(b"RIFF")?;
    w.write_all(&(36 + byte_len).to_le_bytes())?;
    w.write_all(b"WAVEfmt ")?;
    w.write_all(&16u32.to_le_bytes())?;
    w.write_all(&1u16.to_le_bytes())?;
    w.write_all(&(CHANNELS as u16).to_le_bytes())?;
    w.write_all(&RATE.to_le_bytes())?;
    w.write_all(&(RATE * CHANNELS as u32 * 2).to_le_bytes())?;
    w.write_all(&((CHANNELS * 2) as u16).to_le_bytes())?;
    w.write_all(&16u16.to_le_bytes())?;
    w.write_all(b"data")?;
    w.write_all(&byte_len.to_le_bytes())?;
    for s in &pcm {
        w.write_all(&s.to_le_bytes())?;
    }
    let n = times.len();
    println!(
        "RESULT sa1 decode: {n} packets, {:.1} s of sound, decode p50 {:.3} p95 {:.3} ms",
        pcm.len() as f64 / CHANNELS as f64 / f64::from(RATE),
        pct(&mut times, 0.5),
        pct(&mut times, 0.95)
    );
    Ok(())
}
