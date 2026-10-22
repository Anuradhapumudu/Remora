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
use winit::event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy};
use winit::window::{Window, WindowId};

use crate::decode::{Counters, Picture};

/// What the session thread tells the window.
pub(crate) enum Event {
    /// A decoded picture to draw.
    Picture(Picture),
    /// The decoder's counters (sent once, when decoding starts).
    Counters(Arc<Counters>),
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

struct App {
    window: Option<Arc<Window>>,
    gpu: Option<Gpu>,
    close: Option<CloseRequest>,
    counters: Option<Arc<Counters>>,
    exit_code: Option<u8>,
    stats: Stats,
    /// `connect --timing`: one stderr line per drawn frame (P1/P2).
    timing: bool,
    /// Pictures not drawn because the window had no drawable, and the
    /// last reason (R3: e.g. a hidden window gets none).
    no_drawable: (u64, &'static str),
}

/// A presented frame: CPU time for acquire + draw + present, and with
/// timing on, when the GPU had finished the draw and when `present`
/// returned (shared clock, µs).
struct Drawn {
    cpu: Duration,
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
    let thread = std::thread::Builder::new()
        .name("remora-session".into())
        .spawn(move || session(proxy, close_rx))?;
    let mut app = App {
        window: None,
        gpu: None,
        close: Some(close_tx),
        counters: None,
        exit_code: None,
        stats: Stats::new(),
        timing,
        no_drawable: (0, ""),
    };
    event_loop.run_app(&mut app)?;
    let _ = thread.join();
    Ok(app.exit_code.unwrap_or(remora_app::cli::exit::ERROR))
}

impl App {
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
        let uploaded = picture.frame.with_nv12(|nv12| gpu.renderer.upload(nv12));
        if uploaded.is_err() {
            return;
        }
        let upload = started.elapsed();
        if let Some(d) = self.present(self.timing) {
            self.stats.drawn(picture.decode, upload + d.cpu);
            if let Some(gpu_done_us) = d.gpu_done_us {
                // Times only, never content (INV9).
                eprintln!(
                    "timing: capture_us={} received_us={} decoded_us={} drawn_us={gpu_done_us} presented_us={}",
                    picture.capture_us, picture.received_us, picture.decoded_us, d.presented_us
                );
            }
        }
        self.report();
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
        eprintln!("stats: {line}");
        if let Some(w) = &self.window {
            w.set_title(&format!("Remora viewer — {line}"));
        }
    }
}

impl ApplicationHandler<Event> for App {
    fn resumed(&mut self, _el: &ActiveEventLoop) {}

    fn user_event(&mut self, el: &ActiveEventLoop, event: Event) {
        match event {
            Event::Picture(p) => {
                self.show(el, p);
                if let Some(c) = &self.counters {
                    c.shown();
                }
            }
            Event::Counters(c) => self.counters = Some(c),
            Event::Ended(code) => {
                self.exit_code = Some(code);
                el.exit();
            }
        }
    }

    fn window_event(&mut self, _el: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => {
                // The session sends a Goodbye and then reports how it
                // ended (Event::Ended), which closes the event loop.
                if let Some(close) = self.close.take() {
                    let _ = close.send(());
                }
                if let Some(w) = self.window.take() {
                    w.set_visible(false);
                }
                self.gpu = None;
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
            _ => {}
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
        Some(format!(
            "{fps:.0} fps, decode p50 {d50:.1} / p95 {d95:.1} ms, upload+draw p50 {r50:.1} / p95 {r95:.1} ms, refused {refused}, waiting {waiting}, failed {failed}, dropped {dropped}"
        ))
    }
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
