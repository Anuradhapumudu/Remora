//! Linux: what the computer is playing, through PipeWire
//! (phase4.8-criteria; spike S-A1).
//!
//! * `stream.capture.sink = true` asks PipeWire for the default output's
//!   monitor: the sound being played, not a microphone. A user's own
//!   process may record the user's own output with no portal or dialog
//!   (S-A1, laptop). The speakers keep playing (owner, Q1: "Keep playing").
//! * `node.latency = 480/48000` asks for 10 ms buffers instead of the
//!   default 2048 samples (42.7 ms measured in S-A1), so less delay waits
//!   in PipeWire. PipeWire may give more if the graph needs it.
//! * Samples arrive as interleaved 32-bit float stereo at 48 kHz and go to
//!   the sink as they come (any length); the host cuts 20 ms frames.
//! * Never logs or stores sound (INV9); no file writes (policy).

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use pipewire as pw;
use pw::{properties::properties, spa};

use crate::CaptureError;

/// Receives interleaved stereo samples (48 kHz, -1..=1) on the PipeWire
/// thread. Must return quickly.
pub type SoundSink = Box<dyn FnMut(&[f32]) + Send + 'static>;

/// Largest buffer accepted from PipeWire, in samples (1 s of stereo).
const MAX_SAMPLES: usize = 96_000;

fn os(api: &'static str, e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Os {
        api,
        code: 0,
        message: e.to_string(),
    }
}

/// Records what this computer plays until dropped.
pub struct SoundCapture {
    quit: pw::channel::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for SoundCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SoundCapture")
    }
}

impl SoundCapture {
    /// Starts recording the default output into `sink`.
    pub fn start(sink: SoundSink) -> Result<Self, CaptureError> {
        let (quit, quit_rx) = pw::channel::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("remora-sound".into())
            .spawn(move || {
                if let Err(e) = run(sink, quit_rx, &ready_tx) {
                    let _ = ready_tx.send(Err(e));
                }
            })
            .map_err(|e| os("spawn", e))?;
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self {
                quit,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = quit.send(());
                Err(CaptureError::Timeout("connecting to PipeWire for sound"))
            }
        }
    }
}

impl Drop for SoundCapture {
    /// Stops recording (A1: when the last session ends).
    fn drop(&mut self) {
        let _ = self.quit.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn run(
    sink: SoundSink,
    quit: pw::channel::Receiver<()>,
    ready: &mpsc::Sender<Result<(), CaptureError>>,
) -> Result<(), CaptureError> {
    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None).map_err(|e| os("pw_main_loop_new", e))?;
    let context =
        pw::context::ContextRc::new(&mainloop, None).map_err(|e| os("pw_context_new", e))?;
    let core = context
        .connect_rc(None)
        .map_err(|e| os("pw_context_connect", e))?;
    let mut props = properties! {
        *pw::keys::MEDIA_TYPE => "Audio",
        *pw::keys::MEDIA_CATEGORY => "Capture",
        *pw::keys::MEDIA_ROLE => "Communication",
        *pw::keys::NODE_LATENCY => "480/48000",
    };
    props.insert(*pw::keys::STREAM_CAPTURE_SINK, "true");
    let stream = pw::stream::StreamBox::new(&core, "remora-sound", props)
        .map_err(|e| os("pw_stream_new", e))?;
    let state = Rc::new(RefCell::new((sink, Vec::<f32>::new())));
    let _listener = stream
        .add_local_listener_with_user_data(Rc::clone(&state))
        .process(|stream, st| {
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let size = d.chunk().size() as usize;
            let Some(bytes) = d.data() else { return };
            let n = (size.min(bytes.len()) / 4).min(MAX_SAMPLES);
            let mut st = st.borrow_mut();
            let (sink, scratch) = &mut *st;
            scratch.clear();
            scratch.extend(
                bytes[..n * 4]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| f32::from_le_bytes(*b)),
            );
            sink(scratch);
        })
        .register()
        .map_err(|e| os("pw_stream_add_listener", e))?;
    let mut info = spa::param::audio::AudioInfoRaw::new();
    info.set_format(spa::param::audio::AudioFormat::F32LE);
    info.set_rate(48_000);
    info.set_channels(2);
    let obj = pw::spa::pod::Object {
        type_: pw::spa::utils::SpaTypes::ObjectParamFormat.as_raw(),
        id: pw::spa::param::ParamType::EnumFormat.as_raw(),
        properties: info.into(),
    };
    let values: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )
    .map_err(|e| os("format pod", e))?
    .0
    .into_inner();
    let pod = spa::pod::Pod::from_bytes(&values).ok_or(CaptureError::InvalidState("format pod"))?;
    stream
        .connect(
            spa::utils::Direction::Input,
            None,
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
            &mut [pod],
        )
        .map_err(|e| os("pw_stream_connect", e))?;
    let ml = mainloop.clone();
    let _quit = quit.attach(mainloop.loop_(), move |()| ml.quit());
    let _ = ready.send(Ok(()));
    mainloop.run();
    let _ = stream.disconnect();
    Ok(())
}
