//! Spike S-L1a: portal ScreenCast + PipeWire on GNOME/Wayland. Asks the
//! person (a GNOME dialog) to share one monitor with the cursor drawn in,
//! connects to PipeWire through the portal's fd, and reports for SECONDS:
//! negotiated format and size, frames per second, frame intervals.
//! GNOME sends a frame only when something on screen changes: move a window
//! or play a video during the run.
//!
//!     cargo run --release -- [seconds] [dmabuf]
//!
//! `dmabuf`: offer the linear DRM modifier and ask for DMA-BUF buffers (GPU
//! memory, no copy into shared memory); buffers are counted, not mapped.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use ashpd::desktop::PersistMode;
use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};
use pipewire as pw;
use pw::{properties::properties, spa};

struct Stats {
    format: spa::param::video::VideoInfoRaw,
    started: Option<Instant>,
    last: Option<Instant>,
    frames: u64,
    bytes: u64,
    intervals_ms: Vec<f64>,
    data_type: Option<String>,
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * p).round() as usize]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seconds: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let dmabuf = std::env::args().nth(2).as_deref() == Some("dmabuf");
    // 1. The portal: the person picks a monitor in GNOME's dialog.
    let rt = tokio::runtime::Runtime::new()?;
    let (proxy, session, node, size) = rt.block_on(async {
        let proxy = Screencast::new().await?;
        let session = proxy.create_session(Default::default()).await?;
        proxy
            .select_sources(
                &session,
                SelectSourcesOptions::default()
                    .set_cursor_mode(CursorMode::Embedded)
                    .set_sources(ashpd::enumflags2::BitFlags::from_flag(SourceType::Monitor))
                    .set_multiple(false)
                    .set_persist_mode(PersistMode::DoNot),
            )
            .await?;
        let started = Instant::now();
        let streams = proxy.start(&session, None, Default::default()).await?.response()?;
        eprintln!("portal: answered in {:.1} s", started.elapsed().as_secs_f64());
        let s = streams.streams().first().ok_or(ashpd::Error::NoResponse)?.clone();
        Ok::<_, ashpd::Error>((proxy, session, s.pipe_wire_node_id(), s.size()))
    })?;
    eprintln!("portal: PipeWire node {node}, size {size:?}");
    let fd = rt.block_on(proxy.open_pipe_wire_remote(&session, Default::default()))?;

    // 2. PipeWire on this thread, connected through the portal's fd.
    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_fd_rc(fd, None)?;
    let stats = Rc::new(RefCell::new(Stats {
        format: Default::default(),
        started: None,
        last: None,
        frames: 0,
        bytes: 0,
        intervals_ms: Vec::new(),
        data_type: None,
    }));
    let stream = pw::stream::StreamBox::new(
        &core,
        "remora-sl1",
        properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )?;
    let ml = mainloop.clone();
    let limit = Duration::from_secs(seconds);
    let _listener = stream
        .add_local_listener_with_user_data(Rc::clone(&stats))
        .state_changed(|_, _, old, new| eprintln!("stream: {old:?} -> {new:?}"))
        .param_changed(move |stream, st, id, param| {
            let Some(param) = param else { return };
            if id != pw::spa::param::ParamType::Format.as_raw() {
                return;
            }
            let mut st = st.borrow_mut();
            if st.format.parse(param).is_ok() {
                eprintln!(
                    "format: {:?} {}x{} @ {}/{}",
                    st.format.format(),
                    st.format.size().width,
                    st.format.size().height,
                    st.format.framerate().num,
                    st.format.framerate().denom
                );
                if dmabuf {
                    // Ask for DMA-BUF memory now that the format is fixed.
                    let buffers = pw::spa::pod::Object {
                        type_: pw::spa::utils::SpaTypes::ObjectParamBuffers.as_raw(),
                        id: pw::spa::param::ParamType::Buffers.as_raw(),
                        properties: vec![pw::spa::pod::Property {
                            key: pw::spa::sys::SPA_PARAM_BUFFERS_dataType,
                            flags: pw::spa::pod::PropertyFlags::empty(),
                            value: pw::spa::pod::Value::Int(
                                1 << pw::spa::buffer::DataType::DmaBuf.as_raw(),
                            ),
                        }],
                    };
                    let bytes: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
                        std::io::Cursor::new(Vec::new()),
                        &pw::spa::pod::Value::Object(buffers),
                    )
                    .expect("buffers pod")
                    .0
                    .into_inner();
                    let pod = spa::pod::Pod::from_bytes(&bytes).expect("pod");
                    let r = stream.update_params(&mut [pod]);
                    eprintln!("asked for DMA-BUF buffers: {r:?}");
                }
            }
        })
        .process(move |stream, st| {
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            let datas = buffer.datas_mut();
            if datas.is_empty() {
                return;
            }
            let size = u64::from(datas[0].chunk().size());
            let kind = format!("{:?}", datas[0].type_());
            let now = Instant::now();
            let mut st = st.borrow_mut();
            if st.data_type.is_none() {
                eprintln!("first buffer: {kind}, chunk size {size}");
                st.data_type = Some(kind.clone());
            }
            if size == 0 && !dmabuf {
                return; // a cursor-only or empty buffer: not a picture
            }
            let started = *st.started.get_or_insert(now);
            if let Some(last) = st.last {
                st.intervals_ms.push(now.duration_since(last).as_secs_f64() * 1e3);
            }
            st.last = Some(now);
            st.frames += 1;
            st.bytes += size;
            if now.duration_since(started) >= limit {
                ml.quit();
            }
        })
        .register()?;
    let mut obj = pw::spa::pod::object!(
        pw::spa::utils::SpaTypes::ObjectParamFormat,
        pw::spa::param::ParamType::EnumFormat,
        pw::spa::pod::property!(pw::spa::param::format::FormatProperties::MediaType, Id, pw::spa::param::format::MediaType::Video),
        pw::spa::pod::property!(pw::spa::param::format::FormatProperties::MediaSubtype, Id, pw::spa::param::format::MediaSubtype::Raw),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFormat,
            Choice, Enum, Id,
            pw::spa::param::video::VideoFormat::BGRx,
            pw::spa::param::video::VideoFormat::BGRx,
            pw::spa::param::video::VideoFormat::RGBx,
            pw::spa::param::video::VideoFormat::BGRA,
            pw::spa::param::video::VideoFormat::RGBA
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoSize,
            Choice, Range, Rectangle,
            pw::spa::utils::Rectangle { width: 1920, height: 1080 },
            pw::spa::utils::Rectangle { width: 1, height: 1 },
            pw::spa::utils::Rectangle { width: 8192, height: 8192 }
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFramerate,
            Choice, Range, Fraction,
            pw::spa::utils::Fraction { num: 60, denom: 1 },
            pw::spa::utils::Fraction { num: 0, denom: 1 },
            pw::spa::utils::Fraction { num: 1000, denom: 1 }
        ),
    );
    if dmabuf {
        // The linear layout (DRM_FORMAT_MOD_LINEAR = 0): every GPU path can
        // produce it. MANDATORY + DONT_FIXATE as PipeWire's DMA-BUF guide asks.
        obj.properties.push(pw::spa::pod::Property {
            key: pw::spa::param::format::FormatProperties::VideoModifier.as_raw(),
            flags: pw::spa::pod::PropertyFlags::from_bits_retain(
                pw::spa::sys::SPA_POD_PROP_FLAG_MANDATORY | pw::spa::sys::SPA_POD_PROP_FLAG_DONT_FIXATE,
            ),
            value: pw::spa::pod::Value::Choice(pw::spa::pod::ChoiceValue::Long(pw::spa::utils::Choice(
                pw::spa::utils::ChoiceFlags::empty(),
                pw::spa::utils::ChoiceEnum::Enum { default: 0, alternatives: vec![0] },
            ))),
        });
    }
    let values: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )?
    .0
    .into_inner();
    let mut params = [spa::pod::Pod::from_bytes(&values).ok_or("format pod")?];
    stream.connect(
        spa::utils::Direction::Input,
        Some(node),
        if dmabuf {
            pw::stream::StreamFlags::AUTOCONNECT
        } else {
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS
        },
        &mut params,
    )?;
    eprintln!("capturing for {seconds} s once the first frame arrives (move something on screen)");
    mainloop.run();

    let mut st = stats.borrow_mut();
    let secs = st.started.zip(st.last).map_or(0.0, |(a, b)| b.duration_since(a).as_secs_f64());
    let (p50, p95, max) = (pct(&mut st.intervals_ms, 0.5), pct(&mut st.intervals_ms, 0.95), pct(&mut st.intervals_ms, 1.0));
    println!("buffers: {}", st.data_type.clone().unwrap_or_default());
    println!(
        "RESULT sl1a{}: {} frames in {secs:.1} s ({:.1} fps), {:.1} MB/frame, interval p50 {p50:.1} p95 {p95:.1} max {max:.1} ms",
        if dmabuf { " dmabuf" } else { "" },
        st.frames,
        st.frames as f64 / secs.max(1e-9),
        st.bytes as f64 / st.frames.max(1) as f64 / 1_048_576.0
    );
    Ok(())
}
