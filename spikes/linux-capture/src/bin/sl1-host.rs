//! Spike S-L1c (roadmap D-50): the owner's Fedora laptop as a Remora host the
//! Mac's viewer can watch. Remora's own host stack (remora-net HostServer:
//! QUIC, SPAKE2 + Noise, safety code, one viewer at a time) streams the
//! S-L1b path: portal + PipeWire capture (restore token, no dialog), BGRx ->
//! YUV420 on 8 threads, openh264 with slices.
//!
//! Approval stays a person's: each prompt prints the safety code, and the
//! session starts only after `accept` on stdin; `deny` refuses, `quit` ends.
//! SPIKE SHORTCUT: capture runs from the start; pictures are only encoded and
//! sent while a session is active. The real host captures only after approval.
//!
//!     sl1-host <bind ip:port>        e.g. sl1-host 192.168.8.103:0

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ashpd::desktop::PersistMode;
use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};
use pipewire as pw;
use pw::{properties::properties, spa};
use remora_app::cli::{format_sas, offer_code, short_code_of, unix_now};
use remora_net::{HostEvent, HostServer};
use remora_session::{HostConfig, Identity};

/// BGRx -> YUV 4:2:0, BT.709 video range, rows over `threads` threads (S-L1b).
fn bgrx_to_i420(px: &[u8], w: usize, h: usize, y: &mut [u8], u: &mut [u8], v: &mut [u8], threads: usize) {
    let per = (h / 2).div_ceil(threads.max(1));
    std::thread::scope(|s| {
        let mut ys = y.chunks_mut(w * 2 * per);
        let mut us = u.chunks_mut(w / 2 * per);
        let mut vs = v.chunks_mut(w / 2 * per);
        for t in 0..threads {
            let (Some(yc), Some(uc), Some(vc)) = (ys.next(), us.next(), vs.next()) else { break };
            let first = t * per;
            s.spawn(move || {
                for pr in 0..yc.len() / w / 2 {
                    let r0 = (first + pr) * 2;
                    for x2 in 0..w / 2 {
                        let (mut rs, mut gs, mut bs) = (0i32, 0i32, 0i32);
                        for dy in 0..2 {
                            for dx in 0..2 {
                                let i = ((r0 + dy) * w + x2 * 2 + dx) * 4;
                                let (b, g, r) = (px[i] as i32, px[i + 1] as i32, px[i + 2] as i32);
                                yc[(pr * 2 + dy) * w + x2 * 2 + dx] = (16 + ((47 * r + 157 * g + 16 * b + 128) >> 8)) as u8;
                                rs += r;
                                gs += g;
                                bs += b;
                            }
                        }
                        let (r, g, b) = (rs / 4, gs / 4, bs / 4);
                        uc[pr * (w / 2) + x2] = (128 + ((-26 * r - 87 * g + 112 * b + 128) >> 8)).clamp(0, 255) as u8;
                        vc[pr * (w / 2) + x2] = (128 + ((112 * r - 102 * g - 10 * b + 128) >> 8)).clamp(0, 255) as u8;
                    }
                }
            });
        }
    });
}

struct Capture {
    format: spa::param::video::VideoInfoRaw,
    encoder: openh264::encoder::Encoder,
    sent: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind: SocketAddr = std::env::args().nth(1).ok_or("usage: sl1-host <ip:port>")?.parse()?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    // Remora's host: keys from a spike key file, one viewer at a time (H9).
    let (keys, _) = remora_app::keystore::load_or_create(std::path::Path::new("host.key"))?;
    let public = keys.identity.public();
    let cert = keys.cert("Fedora laptop", unix_now())?;
    let config = HostConfig {
        identity: Arc::new(Identity { noise: keys.noise, cert }),
        password_enabled: true,
        trusted: vec![],
        one_active_session: true,
    };
    let (server, mut events) = rt.block_on(HostServer::bind(bind, config))?;
    let server = Arc::new(server);
    let addr = server.local_addr()?;
    println!("device: {}", short_code_of(&public));
    println!("listening: {addr}");
    println!("code: {}", offer_code(addr, &public, server.issue_nonce(Duration::from_secs(300)), unix_now(), 300));
    println!("password: {}", server.otp().reveal());

    let active = Arc::new(AtomicBool::new(false));
    let force_key = Arc::new(AtomicBool::new(true));
    let pending: Arc<Mutex<Option<(remora_session::SessionId, remora_crypto::sas::Sas)>>> = Arc::default();
    {
        let (active, force_key, pending) = (Arc::clone(&active), Arc::clone(&force_key), Arc::clone(&pending));
        rt.spawn(async move {
            while let Some(ev) = events.recv().await {
                match ev {
                    HostEvent::Prompt { id, sas, viewer_name, .. } => {
                        println!("prompt: {viewer_name:?} safety code {} - type accept or deny", format_sas(sas));
                        *pending.lock().unwrap() = Some((id, sas));
                    }
                    HostEvent::Active { .. } => {
                        println!("SESSION ACTIVE");
                        force_key.store(true, Ordering::Relaxed);
                        active.store(true, Ordering::Relaxed);
                    }
                    HostEvent::ForceKeyframe => force_key.store(true, Ordering::Relaxed),
                    HostEvent::Closed { code, .. } => {
                        println!("session ended ({code:?})");
                        active.store(false, Ordering::Relaxed);
                    }
                    HostEvent::Lost { .. } => {
                        println!("connection lost");
                        active.store(false, Ordering::Relaxed);
                    }
                    HostEvent::RefusedBusy { peer } => println!("refused (busy): {}", peer.ip()),
                    HostEvent::Failed { reason, .. } => println!("failed: {reason}"),
                    _ => {}
                }
            }
        });
    }
    {
        let (server, pending) = (Arc::clone(&server), Arc::clone(&pending));
        std::thread::spawn(move || {
            for line in std::io::stdin().lines() {
                let Ok(line) = line else { break };
                match line.trim() {
                    "accept" => match pending.lock().unwrap().take() {
                        Some((id, sas)) => println!("approve: {:?}", server.approve(id, sas)),
                        None => println!("nothing to accept"),
                    },
                    "deny" => {
                        if let Some((id, _)) = pending.lock().unwrap().take() {
                            server.deny(id);
                        }
                    }
                    "quit" => std::process::exit(0),
                    _ => {}
                }
            }
        });
    }

    // The portal, with the owner's saved permission (restore token).
    let token_path = std::path::PathBuf::from("restore-token");
    let token = std::fs::read_to_string(&token_path).ok().map(|s| s.trim().to_owned());
    let (proxy, session, node) = rt.block_on(async {
        let proxy = Screencast::new().await?;
        let session = proxy.create_session(Default::default()).await?;
        proxy
            .select_sources(
                &session,
                SelectSourcesOptions::default()
                    .set_cursor_mode(CursorMode::Embedded)
                    .set_sources(ashpd::enumflags2::BitFlags::from_flag(SourceType::Monitor))
                    .set_multiple(false)
                    .set_persist_mode(PersistMode::ExplicitlyRevoked)
                    .set_restore_token(token.as_deref()),
            )
            .await?;
        let streams = proxy.start(&session, None, Default::default()).await?.response()?;
        if let Some(new) = streams.restore_token() {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&token_path) {
                let _ = f.write_all(new.as_bytes());
            }
        }
        let s = streams.streams().first().ok_or(ashpd::Error::NoResponse)?.clone();
        Ok::<_, ashpd::Error>((proxy, session, s.pipe_wire_node_id()))
    })?;
    let fd = rt.block_on(proxy.open_pipe_wire_remote(&session, Default::default()))?;
    eprintln!("capture: PipeWire node {node}");

    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_fd_rc(fd, None)?;
    use openh264::encoder::{Complexity, EncoderConfig, FrameRate, UsageType};
    let encoder = openh264::encoder::Encoder::with_api_config(
        openh264::OpenH264API::from_source(),
        EncoderConfig::new()
            .usage_type(UsageType::ScreenContentRealTime)
            .complexity(Complexity::Low)
            .num_threads(8)
            .max_frame_rate(FrameRate::from_hz(60.0))
            .skip_frames(false)
            .max_slice_len(1200),
    )?;
    let cap = Rc::new(RefCell::new(Capture { format: Default::default(), encoder, sent: 0 }));
    let stream = pw::stream::StreamBox::new(
        &core,
        "remora-sl1-host",
        properties! { *pw::keys::MEDIA_TYPE => "Video", *pw::keys::MEDIA_CATEGORY => "Capture", *pw::keys::MEDIA_ROLE => "Screen" },
    )?;
    let srv = Arc::clone(&server);
    let _listener = stream
        .add_local_listener_with_user_data(Rc::clone(&cap))
        .param_changed(|_, c, id, param| {
            if let Some(param) = param
                && id == pw::spa::param::ParamType::Format.as_raw()
            {
                let mut c = c.borrow_mut();
                if c.format.parse(param).is_ok() {
                    eprintln!("capture: {:?} {}x{}", c.format.format(), c.format.size().width, c.format.size().height);
                }
            }
        })
        .process(move |stream, c| {
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            if !active.load(Ordering::Relaxed) {
                return;
            }
            let datas = buffer.datas_mut();
            if datas.is_empty() || datas[0].chunk().size() == 0 {
                return;
            }
            let stride = datas[0].chunk().stride() as usize;
            let mut c = c.borrow_mut();
            let (w, h) = (c.format.size().width as usize, c.format.size().height as usize);
            let Some(px) = datas[0].data() else { return };
            if w == 0 || stride != w * 4 || px.len() < w * h * 4 {
                return;
            }
            let (mut yp, mut up, mut vp) = (vec![0u8; w * h], vec![0u8; w * h / 4], vec![0u8; w * h / 4]);
            bgrx_to_i420(&px[..w * h * 4], w, h, &mut yp, &mut up, &mut vp, 8);
            let forced = force_key.swap(false, Ordering::Relaxed);
            if forced {
                c.encoder.force_intra_frame();
            }
            let slices = openh264::formats::YUVSlices::new((&yp, &up, &vp), (w, h), (w, w / 2, w / 2));
            let Ok(bits) = c.encoder.encode(&slices) else { return };
            let ftype = bits.frame_type();
            let keyframe = matches!(ftype, openh264::encoder::FrameType::IDR);
            let data = bits.to_vec();
            if forced || keyframe {
                // NAL unit types after each Annex B start code (diagnostics).
                let mut nals = Vec::new();
                let mut i = 0;
                while i + 3 < data.len() {
                    if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
                        nals.push(data[i + 3] & 0x1f);
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
                nals.dedup();
                eprintln!("forced {forced}: frame type {ftype:?}, keyframe flag {keyframe}, {} bytes, NAL types {nals:?}", data.len());
            }
            if data.is_empty() {
                return;
            }
            if let Err(e) = srv.send_video(keyframe, 0, &data) {
                eprintln!("send_video: {e}");
            }
            c.sent += 1;
            if c.sent % 300 == 0 {
                eprintln!("sent {} pictures", c.sent);
            }
        })
        .register()?;
    let obj = pw::spa::pod::object!(
        pw::spa::utils::SpaTypes::ObjectParamFormat,
        pw::spa::param::ParamType::EnumFormat,
        pw::spa::pod::property!(pw::spa::param::format::FormatProperties::MediaType, Id, pw::spa::param::format::MediaType::Video),
        pw::spa::pod::property!(pw::spa::param::format::FormatProperties::MediaSubtype, Id, pw::spa::param::format::MediaSubtype::Raw),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFormat,
            Choice, Enum, Id,
            pw::spa::param::video::VideoFormat::BGRx,
            pw::spa::param::video::VideoFormat::BGRx
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
        pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;
    eprintln!("ready: waiting for a viewer");
    mainloop.run();
    Ok(())
}
