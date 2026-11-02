//! Linux: the desktop portal (xdg-desktop-portal) and PipeWire, as on
//! GNOME Wayland (phase4.6-criteria; spikes S-L1, S-L2).
//!
//! * **One portal session for screen and input.** GNOME relates absolute
//!   pointer motion to a screen-cast stream, so remote control needs a
//!   RemoteDesktop session that also selects the monitor. When
//!   [`PortalOptions::control`] is set this backend opens that combined
//!   session and hands out a [`PortalInput`] for `remora-input`'s Linux
//!   injector; otherwise a ScreenCast-only session (no input permission is
//!   even asked for). Architecture D48.
//! * **The person's permission is saved once** (owner, Q5): the portal
//!   returns a *restore token* (persist mode "until revoked"); the next
//!   session presents it and GNOME shows no dialog. The token is a
//!   capability, so (L8) its file is created 0600, it is never logged and
//!   its type's `Debug` is redacted. Revoke: GNOME Settings → Privacy →
//!   Screen Sharing, or delete the file (`remora-host forget-permission`).
//! * **GNOME's own indicator** (top-bar icon while the screen is shared) is
//!   shown by the desktop, not by us (INV11; owner saw it, criteria §0).
//!
//! Threads: one *portal* runtime for the whole process runs the D-Bus
//! calls (setup, then every input event, in order); a *PipeWire* thread per
//! capture runs PipeWire's main loop and copies each picture into a
//! [`CpuImage`].
//!
//! **Why one runtime for the process, never one per session:** `ashpd`
//! keeps a single D-Bus connection per process (ashpd-0.13.13
//! `src/proxy.rs:27`, `static SESSION: OnceLock<zbus::Connection>`), and
//! zbus runs that connection's reader on the tokio runtime that was
//! current when it was made (zbus-5.19.0 `src/abstractions/executor.rs:47`).
//! The first version made a runtime per session; when the first session
//! ended its runtime took the reader with it, and every later session
//! waited forever for replies nobody read (laptop, 2026-11-02: the second
//! viewer's session hung for 120 s with no dialog).

use std::cell::RefCell;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ashpd::desktop::PersistMode;
use ashpd::desktop::remote_desktop::{
    Axis, DeviceType, KeyState, NotifyPointerAxisOptions, RemoteDesktop, SelectDevicesOptions,
};
use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};
use futures_util::StreamExt;
use pipewire as pw;
use pw::{properties::properties, spa};

use crate::{
    CaptureConfig, CaptureError, CaptureEvent, CapturedFrame, CpuImage, EventSink, FrameStatus,
    ScreenCapture,
};

/// How long the portal may take to answer, including the person reading
/// GNOME's dialog the first time (later sessions answer in well under a
/// second: S-L2).
const PORTAL_ANSWER: Duration = Duration::from_secs(120);

/// Largest picture accepted from PipeWire (a 8K monitor), so a bogus
/// format can't make us allocate without bound.
const MAX_SIDE: u32 = 8192;

/// What to ask the portal for.
#[derive(Debug, Clone)]
pub struct PortalOptions {
    /// Where the restore token is kept (`None`: never saved, GNOME asks
    /// every time).
    pub token_file: Option<PathBuf>,
    /// Also ask for keyboard and pointer (remote control).
    pub control: bool,
}

/// The portal's restore token: lets the next session start without the
/// dialog. Never printed (L8).
struct RestoreToken(String);

impl std::fmt::Debug for RestoreToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RestoreToken([redacted])")
    }
}

impl RestoreToken {
    fn load(path: &std::path::Path) -> Option<Self> {
        let s = std::fs::read_to_string(path).ok()?;
        let s = s.trim();
        // A token is a short opaque string (GNOME: a UUID).
        (!s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic()))
            .then(|| Self(s.to_owned()))
    }

    /// Writes the token readable by this user only (L8): a new file is
    /// created 0600 and renamed over the old one.
    fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("new");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        // create_new + mode: but the umask can only remove bits; make sure.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(self.0.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    }
}

/// One input event for the portal, in the portal's own units.
#[derive(Debug, Clone, Copy, PartialEq)]
enum InputCmd {
    /// Absolute position in the stream's logical pixels.
    Motion(f64, f64),
    /// evdev button code, pressed?
    Button(i32, bool),
    /// evdev key code, pressed?
    Key(i32, bool),
    /// Smooth scroll in logical pixels.
    Axis(f64, f64),
    /// Wheel clicks: vertical, horizontal.
    Steps(i32, i32),
}

enum PortalCmd {
    Input(InputCmd),
    Close,
}

/// Sends input into the portal session that is showing the screen. Cheap
/// to clone. Calls never block: events are queued in order for the portal
/// thread; a failure (the session was closed, e.g. from GNOME's top-bar
/// menu) makes every later call return an error.
#[derive(Clone)]
pub struct PortalInput {
    tx: tokio::sync::mpsc::UnboundedSender<PortalCmd>,
    failed: Arc<Mutex<Option<String>>>,
    size: (u32, u32),
}

impl std::fmt::Debug for PortalInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalInput")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl PortalInput {
    /// The shared monitor's size in the portal's logical pixels (what
    /// [`motion`](Self::motion) is measured in).
    pub fn size(&self) -> (u32, u32) {
        self.size
    }

    fn send(&self, cmd: InputCmd) -> Result<(), CaptureError> {
        if let Some(why) = self.failed.lock().ok().and_then(|f| f.clone()) {
            return Err(CaptureError::Refused(why));
        }
        self.tx
            .send(PortalCmd::Input(cmd))
            .map_err(|_| CaptureError::InvalidState("the portal session has ended"))
    }

    /// Moves the pointer to (x, y) logical pixels of the shared monitor.
    pub fn motion(&self, x: f64, y: f64) -> Result<(), CaptureError> {
        self.send(InputCmd::Motion(x, y))
    }

    /// Presses or releases an evdev button (`BTN_LEFT` …).
    pub fn button(&self, evdev_button: u32, down: bool) -> Result<(), CaptureError> {
        let b = i32::try_from(evdev_button).map_err(|_| CaptureError::InvalidState("button"))?;
        self.send(InputCmd::Button(b, down))
    }

    /// Presses or releases an evdev key (`KEY_A` …).
    pub fn key(&self, evdev_key: u32, down: bool) -> Result<(), CaptureError> {
        let k = i32::try_from(evdev_key).map_err(|_| CaptureError::InvalidState("key"))?;
        self.send(InputCmd::Key(k, down))
    }

    /// Smooth scroll by (dx, dy) logical pixels (positive: right, down).
    pub fn scroll_pixels(&self, dx: f64, dy: f64) -> Result<(), CaptureError> {
        self.send(InputCmd::Axis(dx, dy))
    }

    /// Wheel clicks (positive: down, right).
    pub fn scroll_steps(&self, vertical: i32, horizontal: i32) -> Result<(), CaptureError> {
        self.send(InputCmd::Steps(vertical, horizontal))
    }
}

/// What the portal thread returns once the person (or the token) agreed.
struct Started {
    fd: OwnedFd,
    node: u32,
    size: (u32, u32),
}

/// Screen capture through the desktop portal and PipeWire.
pub struct PortalCapture {
    cfg: CaptureConfig,
    size: (u32, u32),
    node: u32,
    fd: Option<OwnedFd>,
    portal_tx: tokio::sync::mpsc::UnboundedSender<PortalCmd>,
    /// The session's task on the portal runtime, and a signal when it is
    /// done (the session closed).
    portal: Option<(tokio::task::JoinHandle<()>, mpsc::Receiver<()>)>,
    input: Option<PortalInput>,
    pipewire: Option<(pw::channel::Sender<()>, JoinHandle<()>)>,
}

impl std::fmt::Debug for PortalCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalCapture")
            .field("size", &self.size)
            .field("control", &self.input.is_some())
            .finish_non_exhaustive()
    }
}

fn os(api: &'static str, e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Os {
        api,
        code: 0,
        message: e.to_string(),
    }
}

/// Maps a portal error: "the person said no" is told apart from failures.
fn portal_err(api: &'static str, e: ashpd::Error) -> CaptureError {
    match e {
        ashpd::Error::Response(r) => CaptureError::Refused(format!("{api}: {r:?}")),
        ashpd::Error::Portal(p) => CaptureError::Refused(format!("{api}: {p}")),
        other => os(api, other),
    }
}

impl PortalCapture {
    /// Opens the portal session: with a saved token at once, otherwise
    /// after the person answers GNOME's dialog (up to [`PORTAL_ANSWER`]).
    /// Nothing is captured until [`ScreenCapture::start`].
    pub fn open(cfg: CaptureConfig, opts: PortalOptions) -> Result<Self, CaptureError> {
        let (portal_tx, portal_rx) = tokio::sync::mpsc::unbounded_channel();
        let (started_tx, started_rx) = mpsc::channel();
        let failed = Arc::new(Mutex::new(None));
        let control = opts.control;
        let f = Arc::clone(&failed);
        let (done_tx, done_rx) = mpsc::channel();
        let task = portal_runtime()?.spawn(async move {
            portal_task(opts, started_tx, portal_rx, f).await;
            let _ = done_tx.send(());
        });
        let started = match started_rx.recv_timeout(PORTAL_ANSWER) {
            Ok(r) => r,
            Err(_) => {
                // Dropping the pending request withdraws it.
                task.abort();
                return Err(CaptureError::Timeout("the screen-sharing dialog"));
            }
        };
        let started = match started {
            Ok(s) => s,
            Err(e) => {
                let _ = done_rx.recv_timeout(Duration::from_secs(5));
                return Err(e);
            }
        };
        let input = control.then(|| PortalInput {
            tx: portal_tx.clone(),
            failed,
            size: started.size,
        });
        Ok(Self {
            cfg,
            size: started.size,
            node: started.node,
            fd: Some(started.fd),
            portal_tx,
            portal: Some((task, done_rx)),
            input,
            pipewire: None,
        })
    }

    /// The input side of this session, if control was asked for.
    pub fn input(&self) -> Option<PortalInput> {
        self.input.clone()
    }
}

impl ScreenCapture for PortalCapture {
    fn start(&mut self, sink: EventSink) -> Result<(), CaptureError> {
        if self.pipewire.is_some() {
            return Err(CaptureError::InvalidState("already running"));
        }
        let fd = self
            .fd
            .take()
            .ok_or(CaptureError::InvalidState("a portal capture starts once"))?;
        let (quit_tx, quit_rx) = pw::channel::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (node, cfg) = (self.node, self.cfg);
        let thread = std::thread::Builder::new()
            .name("remora-pipewire".into())
            .spawn(move || {
                if let Err(e) = pipewire_thread(fd, node, cfg, sink, quit_rx, &ready_tx) {
                    let _ = ready_tx.send(Err(e));
                }
            })
            .map_err(|e| os("spawn", e))?;
        match ready_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {
                self.pipewire = Some((quit_tx, thread));
                Ok(())
            }
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = quit_tx.send(());
                Err(CaptureError::Timeout("connecting to PipeWire"))
            }
        }
    }

    fn stop(&mut self) -> Result<(), CaptureError> {
        if let Some((quit, thread)) = self.pipewire.take() {
            let _ = quit.send(());
            thread
                .join()
                .map_err(|_| CaptureError::InvalidState("the PipeWire thread panicked"))?;
        }
        Ok(())
    }

    fn output_size(&self) -> (u32, u32) {
        self.size
    }
}

impl Drop for PortalCapture {
    /// Stops capture and closes the portal session (GNOME's indicator goes
    /// away; the injector stops working).
    fn drop(&mut self) {
        let _ = self.stop();
        let _ = self.portal_tx.send(PortalCmd::Close);
        if let Some((task, done)) = self.portal.take()
            && done.recv_timeout(Duration::from_secs(5)).is_err()
        {
            task.abort(); // the portal did not answer Close in time
        }
    }
}

/// The process's portal runtime (module docs: why exactly one, kept for
/// the life of the process). One worker thread: portal calls are D-Bus
/// round trips, never CPU work.
fn portal_runtime() -> Result<&'static tokio::runtime::Runtime, CaptureError> {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    if let Some(rt) = RT.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("remora-portal")
        .enable_all()
        .build()
        .map_err(|e| os("tokio runtime", e))?;
    // A race leaves one spare runtime unused and dropped here, before any
    // connection was made on it.
    Ok(RT.get_or_init(|| rt))
}

/// One portal session: set it up, report it, then apply input events in
/// order until told to close (or the session is closed by the desktop).
async fn portal_task(
    opts: PortalOptions,
    started: mpsc::Sender<Result<Started, CaptureError>>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<PortalCmd>,
    failed: Arc<Mutex<Option<String>>>,
) {
    {
        let token = opts.token_file.as_deref().and_then(RestoreToken::load);
        let monitor = SelectSourcesOptions::default()
            .set_cursor_mode(CursorMode::Embedded)
            .set_sources(ashpd::enumflags2::BitFlags::from_flag(SourceType::Monitor))
            .set_multiple(false);
        let screencast = match Screencast::new().await {
            Ok(s) => s,
            Err(e) => {
                let _ = started.send(Err(portal_err("ScreenCast portal", e)));
                return;
            }
        };
        let fail = |why: String| {
            if let Ok(mut f) = failed.lock() {
                *f = Some(why);
            }
        };
        if opts.control {
            let rd = match RemoteDesktop::new().await {
                Ok(r) => r,
                Err(e) => {
                    let _ = started.send(Err(portal_err("RemoteDesktop portal", e)));
                    return;
                }
            };
            let session = match async {
                let session = rd.create_session(Default::default()).await?;
                rd.select_devices(
                    &session,
                    SelectDevicesOptions::default()
                        .set_devices(DeviceType::Keyboard | DeviceType::Pointer)
                        .set_persist_mode(PersistMode::ExplicitlyRevoked)
                        .set_restore_token(token.as_ref().map(|t| t.0.as_str())),
                )
                .await?;
                screencast.select_sources(&session, monitor).await?;
                Ok::<_, ashpd::Error>(session)
            }
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = started.send(Err(portal_err("RemoteDesktop session", e)));
                    return;
                }
            };
            let answer = async {
                let r = rd
                    .start(&session, None, Default::default())
                    .await?
                    .response()?;
                let fd = screencast
                    .open_pipe_wire_remote(&session, Default::default())
                    .await?;
                Ok::<_, ashpd::Error>((r, fd))
            }
            .await;
            let (devices, fd) = match answer {
                Ok(a) => a,
                Err(e) => {
                    let _ = started.send(Err(portal_err("RemoteDesktop start", e)));
                    return;
                }
            };
            save_token(&opts, devices.restore_token());
            let Some(stream) = devices.streams().first() else {
                let _ = started.send(Err(CaptureError::NoDisplay));
                return;
            };
            let node = stream.pipe_wire_node_id();
            let size = logical_size(stream.size());
            if started.send(Ok(Started { fd, node, size })).is_err() {
                let _ = session.close().await;
                return;
            }
            // GNOME's top-bar "Stop" closes the session from the desktop side.
            let mut closed = session.receive_closed().await.ok().map(Box::pin);
            loop {
                let cmd = tokio::select! {
                    cmd = rx.recv() => cmd,
                    _ = async {
                        match closed.as_mut() {
                            Some(c) => {
                                let _ = c.next().await;
                            }
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        fail("the desktop closed the remote-desktop session".into());
                        return;
                    }
                };
                match cmd {
                    Some(PortalCmd::Input(i)) => {
                        if let Err(e) = inject(&rd, &session, node, i).await {
                            // Codes and the API name only, never the event (INV9).
                            fail(format!("RemoteDesktop: {e}"));
                        }
                    }
                    Some(PortalCmd::Close) | None => break,
                }
            }
            let _ = session.close().await;
        } else {
            let answer = async {
                let session = screencast.create_session(Default::default()).await?;
                screencast
                    .select_sources(
                        &session,
                        monitor
                            .set_persist_mode(PersistMode::ExplicitlyRevoked)
                            .set_restore_token(token.as_ref().map(|t| t.0.as_str())),
                    )
                    .await?;
                let r = screencast
                    .start(&session, None, Default::default())
                    .await?
                    .response()?;
                let fd = screencast
                    .open_pipe_wire_remote(&session, Default::default())
                    .await?;
                Ok::<_, ashpd::Error>((session, r, fd))
            }
            .await;
            let (session, streams, fd) = match answer {
                Ok(a) => a,
                Err(e) => {
                    let _ = started.send(Err(portal_err("ScreenCast", e)));
                    return;
                }
            };
            save_token(&opts, streams.restore_token());
            let Some(stream) = streams.streams().first() else {
                let _ = started.send(Err(CaptureError::NoDisplay));
                return;
            };
            let node = stream.pipe_wire_node_id();
            let size = logical_size(stream.size());
            if started.send(Ok(Started { fd, node, size })).is_ok() {
                while let Some(PortalCmd::Input(_)) = rx.recv().await {}
            }
            let _ = session.close().await;
        }
    }
}

fn save_token(opts: &PortalOptions, new: Option<&str>) {
    let (Some(path), Some(new)) = (opts.token_file.as_deref(), new) else {
        return;
    };
    // GNOME hands out a new token for each session; keep the latest.
    if let Err(e) = RestoreToken(new.to_owned()).save(path) {
        // The path and the error, never the token (L8).
        eprintln!(
            "could not save the screen-sharing permission in {}: {e}",
            path.display()
        );
    }
}

fn logical_size(size: Option<(i32, i32)>) -> (u32, u32) {
    size.and_then(|(w, h)| Some((u32::try_from(w).ok()?, u32::try_from(h).ok()?)))
        .filter(|&(w, h)| w > 0 && h > 0)
        .unwrap_or((1920, 1080))
}

async fn inject(
    rd: &RemoteDesktop,
    session: &ashpd::desktop::Session<RemoteDesktop>,
    node: u32,
    cmd: InputCmd,
) -> Result<(), ashpd::Error> {
    let state = |down: bool| {
        if down {
            KeyState::Pressed
        } else {
            KeyState::Released
        }
    };
    match cmd {
        InputCmd::Motion(x, y) => {
            rd.notify_pointer_motion_absolute(session, node, x, y, Default::default())
                .await
        }
        InputCmd::Button(b, down) => {
            rd.notify_pointer_button(session, b, state(down), Default::default())
                .await
        }
        InputCmd::Key(k, down) => {
            rd.notify_keyboard_keycode(session, k, state(down), Default::default())
                .await
        }
        InputCmd::Axis(dx, dy) => {
            rd.notify_pointer_axis(
                session,
                dx,
                dy,
                NotifyPointerAxisOptions::default().set_finish(true),
            )
            .await
        }
        InputCmd::Steps(v, h) => {
            if v != 0 {
                rd.notify_pointer_axis_discrete(session, Axis::Vertical, v, Default::default())
                    .await?;
            }
            if h != 0 {
                rd.notify_pointer_axis_discrete(session, Axis::Horizontal, h, Default::default())
                    .await?;
            }
            Ok(())
        }
    }
}

/// Per-stream state on the PipeWire thread.
struct Stream {
    format: spa::param::video::VideoInfoRaw,
    sink: EventSink,
    seq: u64,
    stopped: bool,
}

/// Runs PipeWire's main loop until `quit`; `ready` gets the result of
/// connecting.
fn pipewire_thread(
    fd: OwnedFd,
    node: u32,
    cfg: CaptureConfig,
    sink: EventSink,
    quit: pw::channel::Receiver<()>,
    ready: &mpsc::Sender<Result<(), CaptureError>>,
) -> Result<(), CaptureError> {
    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None).map_err(|e| os("pw_main_loop_new", e))?;
    let context =
        pw::context::ContextRc::new(&mainloop, None).map_err(|e| os("pw_context_new", e))?;
    let core = context
        .connect_fd_rc(fd, None)
        .map_err(|e| os("pw_context_connect_fd", e))?;
    let state = Rc::new(RefCell::new(Stream {
        format: Default::default(),
        sink,
        seq: 0,
        stopped: false,
    }));
    let stream = pw::stream::StreamBox::new(
        &core,
        "remora-host",
        properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )
    .map_err(|e| os("pw_stream_new", e))?;
    let min_gap = Duration::from_secs(1) / cfg.max_fps.max(1);
    let last = Rc::new(RefCell::new(None::<Instant>));
    let _listener = stream
        .add_local_listener_with_user_data(Rc::clone(&state))
        .state_changed(|_, st, _old, new| {
            let mut st = st.borrow_mut();
            if st.stopped {
                return;
            }
            match new {
                pw::stream::StreamState::Error(e) => {
                    st.stopped = true;
                    (st.sink)(CaptureEvent::Stopped(os("PipeWire stream", e)));
                }
                // The desktop ended the cast (GNOME's "Stop sharing").
                pw::stream::StreamState::Unconnected => {
                    st.stopped = true;
                    (st.sink)(CaptureEvent::Stopped(CaptureError::Refused(
                        "screen sharing was stopped on this computer".into(),
                    )));
                }
                _ => {}
            }
        })
        .param_changed(|_, st, id, param| {
            if let Some(param) = param
                && id == pw::spa::param::ParamType::Format.as_raw()
            {
                let _ = st.borrow_mut().format.parse(param);
            }
        })
        .process(move |stream, st| {
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let now = Instant::now();
            if last
                .borrow()
                .is_some_and(|t| now.duration_since(t) < min_gap)
            {
                return; // over max_fps: the OS keeps the newest, we skip this one
            }
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let chunk = d.chunk();
            let (size, offset) = (chunk.size() as usize, chunk.offset() as usize);
            let stride = usize::try_from(chunk.stride()).unwrap_or(0);
            if size == 0 {
                return; // cursor-only or empty: not a picture
            }
            let mut st = st.borrow_mut();
            let (w, h) = (st.format.size().width, st.format.size().height);
            let Some(image) = d
                .data()
                .and_then(|px| copy_picture(px, offset, size, stride, w, h))
            else {
                return;
            };
            *last.borrow_mut() = Some(now);
            st.seq += 1;
            let seq = st.seq;
            (st.sink)(CaptureEvent::Frame(CapturedFrame {
                seq,
                status: FrameStatus::Complete,
                arrival: now,
                delivery_ns: None,
                dirty_rects: Vec::new(),
                image: Some(image),
            }));
        })
        .register()
        .map_err(|e| os("pw_stream_add_listener", e))?;

    let values = format_pod().map_err(|e| os("format pod", e))?;
    let pod = spa::pod::Pod::from_bytes(&values).ok_or(CaptureError::InvalidState("format pod"))?;
    stream
        .connect(
            spa::utils::Direction::Input,
            Some(node),
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
            &mut [pod],
        )
        .map_err(|e| os("pw_stream_connect", e))?;
    let ml = mainloop.clone();
    let st = Rc::clone(&state);
    let _quit = quit.attach(mainloop.loop_(), move |()| {
        // Our own stop: the stream going Unconnected next is not the
        // desktop ending the cast, so it is not reported as one.
        st.borrow_mut().stopped = true;
        ml.quit();
    });
    let _ = ready.send(Ok(()));
    mainloop.run();
    let _ = stream.disconnect();
    Ok(())
}

/// The formats we accept: 4-byte B G R x/A (what GNOME offers for a
/// monitor in shared memory; S-L1a), any size up to [`MAX_SIDE`].
fn format_pod() -> Result<Vec<u8>, spa::pod::serialize::GenError> {
    use pw::spa::param::format::{FormatProperties, MediaSubtype, MediaType};
    use pw::spa::param::video::VideoFormat;
    let obj = pw::spa::pod::object!(
        pw::spa::utils::SpaTypes::ObjectParamFormat,
        pw::spa::param::ParamType::EnumFormat,
        pw::spa::pod::property!(FormatProperties::MediaType, Id, MediaType::Video),
        pw::spa::pod::property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        pw::spa::pod::property!(
            FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            VideoFormat::BGRx,
            VideoFormat::BGRx,
            VideoFormat::BGRA
        ),
        pw::spa::pod::property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            pw::spa::utils::Rectangle {
                width: 1920,
                height: 1080
            },
            pw::spa::utils::Rectangle {
                width: 2,
                height: 2
            },
            pw::spa::utils::Rectangle {
                width: MAX_SIDE,
                height: MAX_SIDE
            }
        ),
        pw::spa::pod::property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            pw::spa::utils::Fraction { num: 60, denom: 1 },
            pw::spa::utils::Fraction { num: 0, denom: 1 },
            pw::spa::utils::Fraction {
                num: 1000,
                denom: 1
            }
        ),
    );
    Ok(pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )?
    .0
    .into_inner())
}

/// Copies one PipeWire picture (rows `stride` bytes apart, starting at
/// `offset`, `size` bytes valid) into a packed [`CpuImage`]; `None` if the
/// numbers don't fit the buffer (checked before allocating).
pub(crate) fn copy_picture(
    px: &[u8],
    offset: usize,
    size: usize,
    stride: usize,
    w: u32,
    h: u32,
) -> Option<CpuImage> {
    if w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE {
        return None;
    }
    let (wu, hu) = (w as usize, h as usize);
    let row = wu * 4;
    let valid = px.get(offset..offset.checked_add(size)?)?;
    let needed = stride.checked_mul(hu - 1)?.checked_add(row)?;
    if stride < row || valid.len() < needed {
        return None;
    }
    let mut out = Vec::with_capacity(row * hu);
    for r in 0..hu {
        out.extend_from_slice(&valid[r * stride..r * stride + row]);
    }
    CpuImage::new(w, h, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_picture_drops_the_row_padding() {
        // 2x2 picture, rows 12 bytes apart (4 bytes of padding), offset 3.
        let mut px = vec![0xEE; 3];
        px.extend([1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0]);
        px.extend([9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0]);
        let img = copy_picture(&px, 3, 24, 12, 2, 2).expect("fits");
        assert_eq!(img.bgrx(), (1..=16).collect::<Vec<u8>>());
    }

    #[test]
    fn copy_picture_refuses_numbers_that_do_not_fit() {
        let px = vec![0; 64];
        assert!(copy_picture(&px, 0, 64, 8, 2, 2).is_some());
        assert!(copy_picture(&px, 0, 64, 4, 2, 2).is_none(), "stride < row");
        assert!(
            copy_picture(&px, 0, 15, 8, 2, 2).is_none(),
            "size too small"
        );
        assert!(copy_picture(&px, 60, 8, 8, 2, 2).is_none(), "past the end");
        assert!(
            copy_picture(&px, usize::MAX, 8, 8, 2, 2).is_none(),
            "overflow"
        );
        assert!(copy_picture(&px, 0, 64, 8, 0, 2).is_none(), "empty");
        assert!(
            copy_picture(&px, 0, 64, 8, MAX_SIDE + 1, 1).is_none(),
            "huge"
        );
    }

    #[test]
    fn l8_the_restore_token_is_never_printed_and_saved_0600() {
        use std::os::unix::fs::PermissionsExt;
        let t = RestoreToken("secret-capability".into());
        assert_eq!(format!("{t:?}"), "RestoreToken([redacted])");
        let dir = std::env::temp_dir().join(format!("remora-token-{}", std::process::id()));
        let path = dir.join("portal-token");
        t.save(&path).expect("save");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "token file mode {mode:o}");
        assert_eq!(
            RestoreToken::load(&path).map(|t| t.0),
            Some("secret-capability".into())
        );
        std::fs::write(&path, "two words").expect("write");
        assert!(RestoreToken::load(&path).is_none(), "not a token");
        let _ = std::fs::remove_dir_all(dir);
    }
}
