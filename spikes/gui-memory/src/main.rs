//! Spike S1 (throwaway). A stand-in viewer: the real viewer's NV12 renderer
//! drawing 1920 × 1248 pictures at 60 fps into our own winit + wgpu window
//! (`Immediate`, drawn on arrival, at most 2 pictures in flight, as D41),
//! optionally next to a Slint window with the connect form's widgets.
//!
//!   s0  video window only, plain winit event loop (the viewer today)
//!   s1  + Slint, femtovg on wgpu, Slint's OWN wgpu device
//!   s2  + Slint, femtovg on wgpu, sharing OUR wgpu device (Manual)
//!   s3  + Slint, software renderer
//!
//! s1–s3 run option C′: Slint owns the event loop, our window is created
//! with `invoke_from_active_event_loop` and its events arrive through a
//! `CustomApplicationHandler`. `--close-ui-after S` hides the Slint window
//! S seconds in (S1-4). Memory is sampled from outside (measure.py).

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use remora_codec::Nv12;
use remora_viewer::render::Renderer;
use winit::event::WindowEvent;
use winit::event_loop::ActiveEventLoop;
use winit::window::{Window, WindowId};

const W: u32 = 1920;
const H: u32 = 1248;

slint::slint! {
    import { Button, LineEdit, VerticalBox, HorizontalBox } from "std-widgets.slint";
    export component Form inherits Window {
        title: "Remora — connect (spike)";
        always-on-top: true;
        in property <string> countdown: "Display unavailable — 120 s left";
        callback accept();
        VerticalBox {
            Text { text: "Connection code"; }
            LineEdit { placeholder-text: "paste the code"; }
            Text { text: "Password"; }
            LineEdit { input-type: password; }
            Text { text: "Safety code"; }
            Text { text: "123 456"; font-size: 32px; }
            Text { text: "Unverified — compare this code with the person at the host"; }
            Text { text: root.countdown; font-size: 20px; }
            HorizontalBox {
                Button { text: "The codes match"; }
                Button { text: "They don't match"; }
                accept-btn := Button { text: "Connect"; clicked => { root.accept(); } }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    S0,
    S1,
    S2,
    S3,
}

struct Frame {
    data: Arc<Vec<u8>>,
    sent: Instant,
}

/// The video window and its numbers.
struct Video {
    window: Arc<Window>,
    surface: wgpu::Surface<'static>,
    config: wgpu::SurfaceConfiguration,
    renderer: Renderer,
    occluded: bool,
    occluded_events: Vec<(f64, bool)>,
    skipped_occluded: u64,
    draws: u64,
    no_drawable: u64,
    last_draw: Option<Instant>,
    intervals_ms: Vec<f64>,
    handoff_ms: Vec<f64>,
    started: Instant,
}

thread_local! {
    static VIDEO: RefCell<Option<Video>> = const { RefCell::new(None) };
    static SHARED: RefCell<Option<(wgpu::Instance, wgpu::Adapter, wgpu::Device, wgpu::Queue)>> =
        const { RefCell::new(None) };
}

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

fn gpu() -> (wgpu::Instance, wgpu::Adapter, wgpu::Device, wgpu::Queue) {
    let mut desc = wgpu::InstanceDescriptor::new_without_display_handle();
    desc.backends = wgpu::Backends::METAL;
    let instance = wgpu::Instance::new(desc);
    let adapter = pollster::block_on(instance.request_adapter(&Default::default())).unwrap();
    let (device, queue) = pollster::block_on(adapter.request_device(&Default::default())).unwrap();
    (instance, adapter, device, queue)
}

fn open_video(el: &ActiveEventLoop, shared: Option<(wgpu::Instance, wgpu::Adapter, wgpu::Device, wgpu::Queue)>) {
    let attrs = Window::default_attributes()
        .with_title("video (spike)")
        // Measurement only: P5 is "window in front"; keep it unoccluded.
        .with_window_level(winit::window::WindowLevel::AlwaysOnTop)
        .with_position(winit::dpi::LogicalPosition::new(40.0, 60.0))
        .with_inner_size(winit::dpi::LogicalSize::new(f64::from(W) * 0.5, f64::from(H) * 0.5));
    let window = Arc::new(el.create_window(attrs).unwrap());
    let (instance, adapter, device, queue) = shared.unwrap_or_else(gpu);
    let surface = instance.create_surface(Arc::clone(&window)).unwrap();
    let caps = surface.get_capabilities(&adapter);
    let format = caps.formats.iter().copied().find(|f| !f.is_srgb()).unwrap_or(caps.formats[0]);
    let present_mode = if caps.present_modes.contains(&wgpu::PresentMode::Immediate) {
        wgpu::PresentMode::Immediate
    } else {
        wgpu::PresentMode::Fifo
    };
    let size = window.inner_size();
    let mut config = surface.get_default_config(&adapter, size.width.max(1), size.height.max(1)).unwrap();
    config.format = format;
    config.present_mode = present_mode;
    config.desired_maximum_frame_latency = 1;
    surface.configure(&device, &config);
    eprintln!("video window: present mode {present_mode:?}, format {format:?}");
    VIDEO.with(|v| {
        *v.borrow_mut() = Some(Video {
            window,
            surface,
            config,
            renderer: Renderer::new(device, queue, format),
            occluded: false,
            occluded_events: Vec::new(),
            skipped_occluded: 0,
            draws: 0,
            no_drawable: 0,
            last_draw: None,
            intervals_ms: Vec::new(),
            handoff_ms: Vec::new(),
            started: Instant::now(),
        })
    });
}

/// Upload and draw a picture as soon as it arrives (D41).
fn on_frame(f: Frame) {
    IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
    VIDEO.with(|v| {
        let mut v = v.borrow_mut();
        let Some(v) = v.as_mut() else { return };
        if v.occluded {
            v.skipped_occluded += 1;
            return;
        }
        let now = Instant::now();
        v.handoff_ms.push(now.duration_since(f.sent).as_secs_f64() * 1e3);
        let (y, uv) = f.data.split_at((W * H) as usize);
        let pic = Nv12::new(W, H, y, W as usize, uv, W as usize).unwrap();
        v.renderer.upload(&pic);
        let frame = match v.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(t) | wgpu::CurrentSurfaceTexture::Suboptimal(t) => t,
            _ => {
                v.no_drawable += 1;
                v.surface.configure(v.renderer.device(), &v.config);
                return;
            }
        };
        let view = frame.texture.create_view(&Default::default());
        v.renderer.draw(&view);
        v.renderer.queue().present(frame);
        if let Some(last) = v.last_draw {
            v.intervals_ms.push(now.duration_since(last).as_secs_f64() * 1e3);
        }
        v.last_draw = Some(now);
        v.draws += 1;
    });
}

fn video_event(id: WindowId, event: &WindowEvent) -> bool {
    VIDEO.with(|v| {
        let mut v = v.borrow_mut();
        let Some(v) = v.as_mut() else { return false };
        if v.window.id() != id {
            return false;
        }
        match event {
            WindowEvent::Resized(s) => {
                v.config.width = s.width.max(1);
                v.config.height = s.height.max(1);
                v.surface.configure(v.renderer.device(), &v.config);
            }
            WindowEvent::Occluded(o) => {
                v.occluded = *o;
                let t = v.started.elapsed().as_secs_f64();
                v.occluded_events.push((t, *o));
                eprintln!("[{t:7.1} s] video window Occluded({o})");
            }
            _ => {}
        }
        true
    })
}

fn frames() -> [Arc<Vec<u8>>; 2] {
    let make = |shift: u8| {
        let mut d = vec![128u8; (W * H * 3 / 2) as usize];
        for (i, b) in d[..(W * H) as usize].iter_mut().enumerate() {
            *b = 16 + ((i as u32 % W) as u8).wrapping_add(shift) % 200;
        }
        Arc::new(d)
    };
    [make(0), make(100)]
}

/// 60 fps producer; drops a picture when 2 are already on their way (D41).
fn producer(send: impl Fn(Frame) + Send + 'static, seconds: f64) {
    std::thread::spawn(move || {
        let fr = frames();
        let start = Instant::now();
        let mut n: u64 = 0;
        loop {
            let due = start + Duration::from_secs_f64(n as f64 / 60.0);
            let now = Instant::now();
            if due > now {
                std::thread::sleep(due - now);
            }
            if start.elapsed().as_secs_f64() > seconds {
                break;
            }
            if IN_FLIGHT.load(Ordering::Relaxed) < 2 {
                IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
                send(Frame { data: Arc::clone(&fr[(n % 2) as usize]), sent: Instant::now() });
            }
            n += 1;
        }
    });
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * p).round() as usize]
}

fn report(mode: &str) {
    VIDEO.with(|v| {
        let mut v = v.borrow_mut();
        let Some(v) = v.as_mut() else {
            eprintln!("RESULT {mode}: no video window");
            return;
        };
        let secs = v.started.elapsed().as_secs_f64();
        let (i50, i95) = (pct(&mut v.intervals_ms, 0.5), pct(&mut v.intervals_ms, 0.95));
        let (h50, h95) = (pct(&mut v.handoff_ms, 0.5), pct(&mut v.handoff_ms, 0.95));
        eprintln!(
            "RESULT {mode}: draws {} in {secs:.1} s ({:.1} fps); interval p50 {i50:.2} p95 {i95:.2} ms; \
             handoff p50 {h50:.3} p95 {h95:.3} ms; no drawable {}; skipped while occluded {}; occluded events {:?}",
            v.draws,
            v.draws as f64 / secs,
            v.no_drawable,
            v.skipped_occluded,
            v.occluded_events
        );
    });
}

// ---- s0: plain winit, as the viewer today ----------------------------------

struct Plain {
    deadline: Instant,
}

impl winit::application::ApplicationHandler<Frame> for Plain {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if VIDEO.with(|v| v.borrow().is_none()) {
            open_video(el, None);
        }
    }
    fn user_event(&mut self, _el: &ActiveEventLoop, f: Frame) {
        on_frame(f);
    }
    fn window_event(&mut self, el: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        if matches!(event, WindowEvent::CloseRequested) {
            el.exit();
        }
        video_event(id, &event);
    }
    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        if Instant::now() >= self.deadline {
            el.exit();
        }
        el.set_control_flow(winit::event_loop::ControlFlow::WaitUntil(self.deadline));
    }
}

// ---- s1–s3: Slint owns the loop (option C′) --------------------------------

struct Hook;

impl slint::winit_030::CustomApplicationHandler for Hook {
    fn window_event(
        &mut self,
        _el: &ActiveEventLoop,
        id: WindowId,
        _w: Option<&Window>,
        slint_window: Option<&slint::Window>,
        event: &WindowEvent,
    ) -> slint::winit_030::EventResult {
        if slint_window.is_none() && video_event(id, event) {
            if matches!(event, WindowEvent::CloseRequested) {
                let _ = slint::quit_event_loop();
            }
            return slint::winit_030::EventResult::PreventDefault;
        }
        slint::winit_030::EventResult::Propagate
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode_name = args.get(1).cloned().unwrap_or_else(|| "s0".into());
    let mode = match mode_name.as_str() {
        "s0" => Mode::S0,
        "s1" => Mode::S1,
        "s2" => Mode::S2,
        "s3" => Mode::S3,
        m => panic!("unknown mode {m}"),
    };
    let flag = |name: &str| {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(|v| v.parse::<f64>().unwrap())
    };
    let seconds = flag("--seconds").unwrap_or(180.0);
    let close_ui_after = flag("--close-ui-after");
    eprintln!("pid {} mode {mode_name} seconds {seconds}", std::process::id());

    if mode == Mode::S0 {
        let el = winit::event_loop::EventLoop::<Frame>::with_user_event().build().unwrap();
        let proxy = el.create_proxy();
        producer(move |f| drop(proxy.send_event(f)), seconds);
        let mut app = Plain { deadline: Instant::now() + Duration::from_secs_f64(seconds) };
        el.run_app(&mut app).unwrap();
        report(&mode_name);
        return;
    }

    let mut selector = slint::BackendSelector::new()
        .backend_name("winit".into())
        .with_winit_custom_application_handler(Hook);
    match mode {
        Mode::S1 => {
            selector = selector.require_wgpu_30(slint::wgpu_30::WGPUConfiguration::default());
        }
        Mode::S2 => {
            let (instance, adapter, device, queue) = gpu();
            SHARED.with(|s| {
                *s.borrow_mut() = Some((instance.clone(), adapter.clone(), device.clone(), queue.clone()))
            });
            selector = selector.require_wgpu_30(slint::wgpu_30::WGPUConfiguration::Manual {
                instance,
                adapter,
                device,
                queue,
            });
        }
        Mode::S3 => selector = selector.renderer_name("software".into()),
        Mode::S0 => unreachable!(),
    }
    selector.select().unwrap();

    let form = Form::new().unwrap();
    form.window().set_position(slint::LogicalPosition::new(1020.0, 60.0));
    form.show().unwrap();
    let shared = SHARED.with(|s| s.borrow().clone());
    slint::winit_030::invoke_from_active_event_loop(move |el| open_video(el, shared)).unwrap();
    producer(
        |f| {
            let _ = slint::winit_030::invoke_from_active_event_loop(move |_el| on_frame(f));
        },
        seconds,
    );

    // The D-33 countdown: one text change (one UI redraw) per second.
    let tick = slint::Timer::default();
    let weak = form.as_weak();
    let mut left = 120;
    tick.start(slint::TimerMode::Repeated, Duration::from_secs(1), move || {
        left = if left == 0 { 120 } else { left - 1 };
        if let Some(f) = weak.upgrade() {
            f.set_countdown(format!("Display unavailable — {left} s left").into());
        }
    });
    let hide = slint::Timer::default();
    if let Some(s) = close_ui_after {
        let weak = form.as_weak();
        hide.start(slint::TimerMode::SingleShot, Duration::from_secs_f64(s), move || {
            if let Some(f) = weak.upgrade() {
                f.hide().unwrap();
                eprintln!("Slint window hidden");
            }
        });
    }
    let stop = slint::Timer::default();
    stop.start(slint::TimerMode::SingleShot, Duration::from_secs_f64(seconds), || {
        let _ = slint::quit_event_loop();
    });
    slint::run_event_loop_until_quit().unwrap();
    report(&mode_name);
}
