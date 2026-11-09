//! The video window (phase4-criteria R1, R3; macOS).
//!
//! winit owns the main thread (macOS requires it); the session runs on
//! its own thread and hands decoded pictures over through the event
//! loop's proxy. A picture is uploaded and drawn **as soon as it
//! arrives**, not at the next redraw tick, and presented with
//! `Immediate` when the surface offers it (else `Fifo` with a frame
//! latency of 1): the refresh wait stays out of our path (D34).
//!
//! The window opens with the first picture, so the terminal flow (safety
//! code, waiting for approval) is unchanged. Closing it ends the session
//! with a Goodbye. Once per second the title and one stderr line show
//! frames drawn, decode and draw times (p50/p95) and the decoder's
//! counters (R3) — numbers only, never screen content or text from the
//! host (INV9).

use std::sync::Arc;
use std::time::{Duration, Instant};

use remora_viewer::render::Renderer;
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::window::{Window, WindowId};

use crate::decode::{Counters, Picture};

/// What the session thread tells the window.
pub(crate) enum Event {
    /// A decoded picture to draw.
    Picture(Picture),
    /// The decoder's counters (sent once, when decoding starts).
    Counters(Arc<Counters>),
    /// The stream paused (`Some`) or resumed (`None`).
    Pause(Option<crate::Pause>),
    /// The connection, for mouse and keyboard (sent once, after connecting).
    Client(remora_net::ViewerClient),
    /// The session ended with this exit code.
    Ended(u8),
}

/// Asks the session thread to disconnect (the window was closed).
pub(crate) type CloseRequest = tokio::sync::oneshot::Sender<()>;

struct Gpu {
    surface: wgpu::Surface<'static>,
    config: wgpu::SurfaceConfiguration,
    renderer: Renderer,
}

/// The video window and everything it draws, apart from the event loop
/// that drives it (the CLI's own loop, [`run`]; the Phase 4.5 GUI will put
/// it on Slint's, option C′, phase4.5-criteria §2). It opens with the
/// first picture.
pub(crate) struct VideoWindow {
    window: Option<Arc<Window>>,
    gpu: Option<Gpu>,
    counters: Option<Arc<Counters>>,
    stats: Stats,
    /// `connect --timing`: one stderr line per drawn frame (P1/P2).
    timing: bool,
    /// Pictures not drawn because the window had no drawable, and the
    /// last reason (R3: e.g. a hidden window gets none).
    no_drawable: (u64, &'static str),
    /// While the stream is paused: the title says why, counting down
    /// every second if the host's display is unavailable (D-29).
    pause: Option<crate::Pause>,
    /// O1 (phase4.5-criteria §7, D-35): the window is covered.
    covered: Covered,
    /// The host's device ID for the title (the GUI sets it; empty in the CLI).
    host: String,
    /// Mouse and keyboard → `Input` messages (phase4.6-criteria step 3).
    input: crate::input::InputState,
    /// Where input goes; set once the session is connected, cleared when
    /// the window closes.
    client: Option<remora_net::ViewerClient>,
    /// A6: the local mute key.
    mute: MuteKey,
}

/// A6 (phase4.8): Ctrl+Option+M mutes or unmutes the sound on this Mac.
/// The M press and its release are not sent to the host; Ctrl and Option
/// are (harmless on their own).
#[derive(Debug, Default)]
pub(crate) struct MuteKey {
    mods: winit::keyboard::ModifiersState,
    /// The M of the chord is down: its release is not sent either.
    held: bool,
}

impl MuteKey {
    /// The modifier keys changed.
    pub(crate) fn set_mods(&mut self, mods: winit::keyboard::ModifiersState) {
        self.mods = mods;
    }

    /// A key; returns `true` when it belongs to the mute key (not sent).
    /// The first press toggles the mute; auto-repeats (pressed again while
    /// held) do not.
    pub(crate) fn key(&mut self, code: winit::keyboard::KeyCode, pressed: bool) -> bool {
        use winit::keyboard::{KeyCode, ModifiersState};
        if code != KeyCode::KeyM {
            return false;
        }
        if !pressed {
            return std::mem::take(&mut self.held);
        }
        let chord = self
            .mods
            .contains(ModifiersState::CONTROL | ModifiersState::ALT)
            && !self
                .mods
                .intersects(ModifiersState::SUPER | ModifiersState::SHIFT);
        if !chord && !self.held {
            return false;
        }
        if !self.held {
            let muted = crate::sound::toggle_mute();
            eprintln!(
                "{}",
                if muted {
                    "sound muted (Ctrl+Option+M to unmute)"
                } else {
                    "sound on"
                }
            );
        }
        self.held = true;
        true
    }
}

/// The video window's title (owner, 2026-11-01, phase4.5-criteria §16):
/// "Remora — <host> · <status>", with the developer stats line on stderr
/// only; without a known host (the CLI) "Remora viewer — <status>".
pub(crate) fn title_for(host: &str, status: &str) -> String {
    let who = if host.is_empty() {
        "Remora viewer".to_owned()
    } else {
        format!("Remora \u{2014} {host}")
    };
    if status.is_empty() {
        who
    } else {
        format!("{who} \u{00B7} {status}")
    }
}

/// O1: while the window is covered (`Occluded(true)`), pictures are still
/// decoded (the decoder's reference chain must stay intact) but not
/// uploaded or drawn; the first picture after `Occluded(false)` is drawn.
#[derive(Debug, Default)]
pub(crate) struct Covered {
    now: bool,
    /// Pictures not drawn because the window was covered.
    pub(crate) skipped: u64,
}

impl Covered {
    /// The window's occlusion changed.
    pub(crate) fn set(&mut self, covered: bool) {
        self.now = covered;
    }

    /// A decoded picture arrived: draw it?
    pub(crate) fn draw(&mut self) -> bool {
        if self.now {
            self.skipped += 1;
        }
        !self.now
    }
}

/// What the CLI's event loop keeps besides the window.
struct App {
    video: VideoWindow,
    close: Option<CloseRequest>,
    exit_code: Option<u8>,
    /// Signalled when the session thread has finished (Cmd+Q waits for it).
    done: std::sync::mpsc::Receiver<()>,
}

/// A presented frame: CPU time for acquire + draw + present, and with
/// timing on, when the GPU had finished the draw and when `present`
/// returned (shared clock, µs).
struct Drawn {
    cpu: Duration,
    /// When a surface texture to draw into was obtained.
    acquired_us: u64,
    gpu_done_us: Option<u64>,
    presented_us: u64,
}

/// Runs the window until the session ends; `session` runs on another
/// thread with a proxy to send [`Event`]s and the receiver of a close
/// request. Returns the session's exit code.
pub(crate) fn run(
    timing: bool,
    session: impl FnOnce(EventLoopProxy<Event>, tokio::sync::oneshot::Receiver<()>) + Send + 'static,
) -> anyhow::Result<u8> {
    let event_loop = EventLoop::<Event>::with_user_event().build()?;
    let proxy = event_loop.create_proxy();
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("remora-session".into())
        .spawn(move || {
            session(proxy, close_rx);
            let _ = done_tx.send(());
        })?;
    let mut app = App {
        video: VideoWindow::new(timing),
        close: Some(close_tx),
        exit_code: None,
        done,
    };
    event_loop.run_app(&mut app)?;
    let _ = thread.join();
    Ok(app.exit_code.unwrap_or(remora_app::cli::exit::ERROR))
}

impl VideoWindow {
    /// No window yet; it opens with the first picture.
    pub(crate) fn new(timing: bool) -> Self {
        Self {
            window: None,
            gpu: None,
            counters: None,
            stats: Stats::new(),
            timing,
            no_drawable: (0, ""),
            pause: None,
            covered: Covered::default(),
            host: String::new(),
            input: crate::input::InputState::default(),
            client: None,
            mute: MuteKey::default(),
        }
    }

    /// The connection mouse and keyboard events go to (`None`: not sent).
    pub(crate) fn set_client(&mut self, client: Option<remora_net::ViewerClient>) {
        self.client = client;
        self.show_local_cursor();
    }

    /// While this window controls the host, the Mac's own pointer is
    /// hidden over it: the host's pointer is drawn into the picture, and
    /// two pointers made it unclear which one clicks (owner, 2026-11-02).
    /// winit 0.30.13 hides it through the view's cursor rect
    /// (`platform_impl/macos/window_delegate.rs:1138`,
    /// `invalidateCursorRectsForView`), i.e. over the view only; its docs
    /// say "while focused" — which one holds is checked by hand (step 6).
    fn show_local_cursor(&self) {
        if let Some(w) = &self.window {
            w.set_cursor_visible(self.client.is_none());
        }
    }

    fn send(&self, messages: impl IntoIterator<Item = remora_proto::messages::Input>) {
        if let Some(c) = &self.client {
            for m in messages {
                c.send_input(m);
            }
        }
    }

    /// Whether `id` is this window.
    pub(crate) fn is(&self, id: WindowId) -> bool {
        self.window.as_ref().is_some_and(|w| w.id() == id)
    }

    /// The host's device ID, for the title.
    pub(crate) fn set_host(&mut self, host: String) {
        self.host = host;
    }

    /// The decoder's counters, for the stats line.
    pub(crate) fn set_counters(&mut self, c: Arc<Counters>) {
        self.counters = Some(c);
    }

    /// The stream paused (`Some`) or resumed (`None`).
    pub(crate) fn set_pause(&mut self, p: Option<crate::Pause>) {
        self.pause = p;
        match p {
            Some(_) => self.show_pause(),
            None => {
                if let Some(w) = &self.window {
                    w.set_title(&title_for(&self.host, ""));
                }
            }
        }
    }

    /// Once a second while paused with a countdown: the title's time left.
    /// Returns whether it wants to be called again in a second.
    pub(crate) fn tick(&self) -> bool {
        match &self.pause {
            Some(p) => {
                self.show_pause();
                p.deadline.is_some()
            }
            None => false,
        }
    }

    /// Closes the window (the session is ending).
    pub(crate) fn close(&mut self) {
        self.client = None;
        if let Some(w) = self.window.take() {
            w.set_visible(false);
        }
        self.gpu = None;
    }

    fn open(&mut self, el: &ActiveEventLoop, width: u32, height: u32) -> anyhow::Result<()> {
        // Start at half the picture size on a Retina screen (1 picture
        // pixel per screen pixel), never larger than 1280 points wide.
        let scale = (1280.0 / f64::from(width)).min(0.5);
        let attrs = Window::default_attributes()
            .with_title("Remora viewer")
            .with_inner_size(winit::dpi::LogicalSize::new(
                f64::from(width) * scale,
                f64::from(height) * scale,
            ));
        let window = Arc::new(el.create_window(attrs)?);
        let mut desc = wgpu::InstanceDescriptor::new_without_display_handle();
        desc.backends = wgpu::Backends::METAL;
        let instance = wgpu::Instance::new(desc);
        let surface = instance.create_surface(Arc::clone(&window))?;
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            compatible_surface: Some(&surface),
            ..Default::default()
        }))?;
        let (device, queue) = pollster::block_on(adapter.request_device(&Default::default()))?;
        let caps = surface.get_capabilities(&adapter);
        // A non-sRGB format: the shader already outputs display values.
        let format = caps
            .formats
            .iter()
            .copied()
            .find(|f| !f.is_srgb())
            .or_else(|| caps.formats.first().copied())
            .ok_or_else(|| anyhow::anyhow!("the window surface offers no format"))?;
        let present_mode = if caps.present_modes.contains(&wgpu::PresentMode::Immediate) {
            wgpu::PresentMode::Immediate
        } else {
            wgpu::PresentMode::Fifo
        };
        let size = window.inner_size();
        self.input.resized(size.width, size.height);
        let mut config = surface
            .get_default_config(&adapter, size.width.max(1), size.height.max(1))
            .ok_or_else(|| anyhow::anyhow!("the window surface does not fit the GPU"))?;
        config.format = format;
        config.present_mode = present_mode;
        config.desired_maximum_frame_latency = 1;
        surface.configure(&device, &config);
        eprintln!("window: present mode {present_mode:?}, format {format:?}");
        self.gpu = Some(Gpu {
            surface,
            config,
            renderer: Renderer::new(device, queue, format),
        });
        self.window = Some(window);
        self.show_local_cursor();
        Ok(())
    }

    /// Draws the last uploaded picture and presents it; `None` if nothing
    /// was drawn. With `timed`, also waits until the GPU has finished the
    /// draw (phase4-criteria §3's end point: the `on_submitted_work_done`
    /// callback); only `connect --timing` does, as the wait blocks this
    /// thread for the GPU's work.
    fn present(&mut self, timed: bool) -> Option<Drawn> {
        let gpu = self.gpu.as_mut()?;
        let started = Instant::now();
        let frame = match gpu.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(f)
            | wgpu::CurrentSurfaceTexture::Suboptimal(f) => f,
            other => {
                let why = match other {
                    wgpu::CurrentSurfaceTexture::Outdated => "outdated",
                    wgpu::CurrentSurfaceTexture::Lost => "lost",
                    wgpu::CurrentSurfaceTexture::Occluded => "occluded",
                    wgpu::CurrentSurfaceTexture::Timeout => "timeout",
                    _ => "other",
                };
                if matches!(why, "outdated" | "lost") {
                    gpu.surface.configure(gpu.renderer.device(), &gpu.config);
                }
                self.no_drawable = (self.no_drawable.0 + 1, why);
                return None;
            }
        };
        let acquired_us = crate::decode::now_us();
        let view = frame.texture.create_view(&Default::default());
        let drawn = gpu.renderer.draw(&view);
        let done = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        if timed && drawn {
            let d = std::sync::Arc::clone(&done);
            gpu.renderer.queue().on_submitted_work_done(move || {
                d.store(
                    crate::decode::now_us(),
                    std::sync::atomic::Ordering::Relaxed,
                );
            });
        }
        gpu.renderer.queue().present(frame);
        let presented_us = crate::decode::now_us();
        let cpu = started.elapsed();
        let gpu_done_us = (timed && drawn)
            .then(|| {
                let _ = gpu
                    .renderer
                    .device()
                    .poll(wgpu::PollType::wait_indefinitely());
                done.load(std::sync::atomic::Ordering::Relaxed)
            })
            .filter(|&t| t > 0);
        drawn.then_some(Drawn {
            cpu,
            acquired_us,
            gpu_done_us,
            presented_us,
        })
    }

    fn show(&mut self, el: &ActiveEventLoop, picture: Picture) {
        let image = picture.frame.image();
        let (w, h) = (image.width(), image.height());
        if self.window.is_none()
            && let Err(e) = self.open(el, w, h)
        {
            eprintln!("window: {e:#}");
            return;
        }
        let Some(gpu) = self.gpu.as_mut() else {
            return;
        };
        let started = Instant::now();
        // decoded -> drawn, split (phase4-criteria §3 stage budget): the
        // hand-off to this thread, the upload, getting a surface, the GPU.
        let window_us = crate::decode::now_us();
        let uploaded = picture.frame.with_nv12(|nv12| gpu.renderer.upload(nv12));
        if uploaded.is_err() {
            return;
        }
        let upload = started.elapsed();
        let uploaded_us = crate::decode::now_us();
        if let Some(d) = self.present(self.timing) {
            self.stats.drawn(picture.decode, upload + d.cpu);
            if let Some(gpu_done_us) = d.gpu_done_us {
                // Times only, never content (INV9).
                eprintln!(
                    "timing: capture_us={} received_us={} decoded_us={} window_us={window_us} uploaded_us={uploaded_us} acquired_us={} drawn_us={gpu_done_us} presented_us={}",
                    picture.capture_us,
                    picture.received_us,
                    picture.decoded_us,
                    d.acquired_us,
                    d.presented_us
                );
            }
        }
        self.report();
    }

    /// The title while paused (the stats line takes it back on resume).
    fn show_pause(&self) {
        if let (Some(w), Some(p)) = (&self.window, &self.pause) {
            w.set_title(&title_for(&self.host, &p.text()));
        }
    }

    /// Once per second: title and one stderr line (R3).
    fn report(&mut self) {
        let Some(mut line) = self.stats.line(self.counters.as_deref()) else {
            return;
        };
        if self.no_drawable.0 > 0 {
            line.push_str(&format!(
                ", no drawable {} ({})",
                self.no_drawable.0, self.no_drawable.1
            ));
        }
        if self.covered.skipped > 0 {
            line.push_str(&format!(
                ", not drawn while covered {}",
                self.covered.skipped
            ));
        }
        eprintln!("stats: {line}");
        if let Some(w) = &self.window {
            // The title keeps the frame rate only ("53 fps"); the full line is
            // for developers and the measuring scripts, on stderr.
            let fps = line.split(',').next().unwrap_or("");
            w.set_title(&title_for(&self.host, fps));
        }
    }
}

impl VideoWindow {
    /// A decoded picture: opens the window on the first, uploads and draws
    /// it at once (D34) unless the window is covered (O1). Either way the
    /// decoder may hand over the next one.
    pub(crate) fn picture(&mut self, el: &ActiveEventLoop, p: Picture) {
        if self.window.is_none() || self.covered.draw() {
            self.show(el, p);
        }
        if let Some(c) = &self.counters {
            c.shown();
        }
        // Coalesced pointer motion: at most one per drawn picture.
        let pending = self.input.flush(Instant::now());
        self.send(pending);
    }

    /// An event for this window; returns `true` when the person closed it
    /// (the session should end with a Goodbye).
    pub(crate) fn window_event(&mut self, event: &WindowEvent) -> bool {
        let local = match event {
            WindowEvent::ModifiersChanged(m) => {
                self.mute.set_mods(m.state());
                false
            }
            WindowEvent::KeyboardInput { event: k, .. } => match k.physical_key {
                winit::keyboard::PhysicalKey::Code(code) => self
                    .mute
                    .key(code, k.state == winit::event::ElementState::Pressed),
                winit::keyboard::PhysicalKey::Unidentified(_) => false,
            },
            _ => false,
        };
        if !local {
            let messages = self.input.event(event, Instant::now());
            self.send(messages);
        }
        match event {
            WindowEvent::CloseRequested => {
                self.close();
                return true;
            }
            WindowEvent::Resized(size) => {
                if let Some(gpu) = self.gpu.as_mut() {
                    gpu.config.width = size.width.max(1);
                    gpu.config.height = size.height.max(1);
                    gpu.surface.configure(gpu.renderer.device(), &gpu.config);
                }
                // Redraws the current picture; not a new frame (P7).
                let _ = self.present(false);
            }
            WindowEvent::RedrawRequested => {
                let _ = self.present(false);
            }
            // O1: on macOS from the window's occlusion state (winit
            // window_delegate.rs:352).
            WindowEvent::Occluded(covered) => self.covered.set(*covered),
            _ => {}
        }
        false
    }
}

impl ApplicationHandler<Event> for App {
    fn resumed(&mut self, _el: &ActiveEventLoop) {}

    /// Also on Cmd+Q, after which macOS ends the process: say goodbye
    /// first (see `quit.rs`). After a normal end the thread is already done.
    fn exiting(&mut self, _el: &ActiveEventLoop) {
        let close = self.close.take();
        crate::quit::goodbye(
            || {
                if let Some(c) = close {
                    let _ = c.send(());
                }
            },
            &self.done,
            crate::quit::QUIT_WAIT,
        );
    }

    /// While paused, wake once a second to update the title's countdown.
    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        if self.video.tick() {
            el.set_control_flow(ControlFlow::WaitUntil(
                Instant::now() + Duration::from_secs(1),
            ));
        } else {
            el.set_control_flow(ControlFlow::Wait);
        }
    }

    fn user_event(&mut self, el: &ActiveEventLoop, event: Event) {
        match event {
            Event::Picture(p) => self.video.picture(el, p),
            Event::Counters(c) => self.video.set_counters(c),
            Event::Pause(p) => self.video.set_pause(p),
            Event::Client(c) => self.video.set_client(Some(c)),
            Event::Ended(code) => {
                self.exit_code = Some(code);
                el.exit();
            }
        }
    }

    fn window_event(&mut self, _el: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        // The session sends a Goodbye and then reports how it ended
        // (Event::Ended), which closes the event loop.
        if self.video.window_event(&event)
            && let Some(close) = self.close.take()
        {
            let _ = close.send(());
        }
    }
}

/// Per-second numbers for R3.
struct Stats {
    since: Instant,
    decode: Vec<Duration>,
    draw: Vec<Duration>,
}

impl Stats {
    fn new() -> Self {
        Self {
            since: Instant::now(),
            decode: Vec::new(),
            draw: Vec::new(),
        }
    }

    fn drawn(&mut self, decode: Duration, draw: Duration) {
        self.decode.push(decode);
        self.draw.push(draw);
    }

    /// The line for the last second, once a second has passed.
    fn line(&mut self, counters: Option<&Counters>) -> Option<String> {
        let elapsed = self.since.elapsed();
        if elapsed < Duration::from_secs(1) {
            return None;
        }
        let fps = self.draw.len() as f64 / elapsed.as_secs_f64();
        let (d50, d95) = percentiles(&mut self.decode);
        let (r50, r95) = percentiles(&mut self.draw);
        let t = counters.map(Counters::get).unwrap_or_default();
        let (refused, waiting, failed, dropped) = (t.refused, t.waiting, t.failed, t.dropped);
        self.since = Instant::now();
        self.decode.clear();
        self.draw.clear();
        let line = format!(
            "{fps:.0} fps, decode p50 {d50:.1} / p95 {d95:.1} ms, upload+draw p50 {r50:.1} / p95 {r95:.1} ms, refused {refused}, waiting {waiting}, failed {failed}, dropped {dropped}"
        );
        #[cfg(target_os = "macos")]
        let line = match counters.and_then(Counters::held) {
            Some((n, bytes)) => line + &held_text(n, bytes),
            None => line,
        };
        // LP4 (phase4.6-criteria): stale periods so far, at the end so the
        // fields scripts read keep their place.
        let line = match counters.and_then(Counters::recovery) {
            Some((n, p50, p95, max)) => {
                line + &format!(", recovered {n} (p50 {p50} / p95 {p95} / max {max} ms)")
            }
            None => line,
        };
        Some(line)
    }
}

/// The memory self-count on the stats line (phase4.5-criteria §3b): the
/// decoded pictures that exist and their size, which the footprint does
/// not include. `scripts/macos/p5-recheck.py` reads it.
#[cfg(target_os = "macos")]
fn held_text(pictures: u64, bytes: u64) -> String {
    format!(
        ", pictures held {pictures} ({:.1} MB)",
        bytes as f64 / (1024.0 * 1024.0)
    )
}

/// p50 and p95 in milliseconds (0 if empty).
fn percentiles(v: &mut [Duration]) -> (f64, f64) {
    if v.is_empty() {
        return (0.0, 0.0);
    }
    v.sort_unstable();
    let at = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize].as_secs_f64() * 1e3;
    (at(0.5), at(0.95))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn a6_the_mute_key_toggles_and_is_never_sent() {
        let _turn = crate::sound::MUTE_TESTS.lock();
        use winit::keyboard::{KeyCode, ModifiersState};
        let mut k = MuteKey::default();
        let before = crate::sound::MUTED.load(std::sync::atomic::Ordering::Relaxed);
        // Plain M (and Cmd+Ctrl+Option+M) go to the host.
        assert!(!k.key(KeyCode::KeyM, true));
        assert!(!k.key(KeyCode::KeyM, false));
        k.set_mods(ModifiersState::CONTROL | ModifiersState::ALT | ModifiersState::SUPER);
        assert!(!k.key(KeyCode::KeyM, true));
        assert!(!k.key(KeyCode::KeyM, false));
        // Ctrl+Option+M: press, a repeat and the release (even after the
        // modifiers are let go first) stay here; one toggle.
        k.set_mods(ModifiersState::CONTROL | ModifiersState::ALT);
        assert!(k.key(KeyCode::KeyM, true));
        let pressed = crate::sound::MUTED.load(std::sync::atomic::Ordering::Relaxed);
        assert_ne!(before, pressed, "the press itself toggles");
        assert!(k.key(KeyCode::KeyM, true)); // auto-repeat: no second toggle
        k.set_mods(ModifiersState::empty());
        assert!(k.key(KeyCode::KeyM, false));
        assert!(!k.key(KeyCode::KeyN, true));
        let after = crate::sound::MUTED.load(std::sync::atomic::Ordering::Relaxed);
        assert_ne!(before, after, "one press, one toggle");
        crate::sound::toggle_mute();
    }

    #[test]
    fn the_title_names_the_host_and_keeps_only_the_frame_rate() {
        assert_eq!(
            title_for("8531 422 5411-5", "53 fps"),
            "Remora \u{2014} 8531 422 5411-5 \u{00B7} 53 fps"
        );
        assert_eq!(
            title_for("8531 422 5411-5", ""),
            "Remora \u{2014} 8531 422 5411-5"
        );
        assert_eq!(title_for("", "60 fps"), "Remora viewer \u{00B7} 60 fps");
    }

    #[test]
    fn o1_covered_window_draws_nothing_then_draws_at_once() {
        let mut c = Covered::default();
        assert!(c.draw(), "not covered: drawn");
        c.set(true);
        assert!(!c.draw());
        assert!(!c.draw());
        assert_eq!(c.skipped, 2, "decoded, counted, not drawn");
        c.set(false);
        assert!(c.draw(), "the first picture after uncovering is drawn");
        assert_eq!(c.skipped, 2);
    }

    #[test]
    fn o1_the_windows_occlusion_events_reach_it() {
        // winit's own events, before any window exists (none is needed).
        let mut v = VideoWindow::new(false);
        assert!(!v.window_event(&WindowEvent::Occluded(true)));
        assert!(!v.covered.draw(), "covered: not drawn");
        assert!(!v.window_event(&WindowEvent::Occluded(false)));
        assert!(v.covered.draw(), "uncovered: drawn");
        assert!(
            v.window_event(&WindowEvent::CloseRequested),
            "closing ends the session"
        );
    }

    #[test]
    fn self_count_on_the_stats_line() {
        // Two 1920 x 1248 NV12 pictures.
        assert_eq!(
            held_text(2, 2 * 1920 * 1248 * 3 / 2),
            ", pictures held 2 (6.9 MB)"
        );
        assert_eq!(held_text(0, 0), ", pictures held 0 (0.0 MB)");
    }
}
