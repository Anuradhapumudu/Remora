//! THROWAWAY spike (owner, 2026-10-19). Questions:
//! 1. Can a VideoToolbox-style NV12 IOSurface reach wgpu WITHOUT a CPU copy?
//! 2. What does the per-frame GPU work cost, zero-copy vs CPU upload?
//! 3. Does Slint (unstable-wgpu-30) show a per-frame wgpu texture, and does
//!    it present without waiting for vsync?
//!
//! `bench`  - headless: zero-copy import + NV12->RGBA pass vs CPU upload.
//! `window` - Slint window showing the converted texture every frame;
//!            measures the frame interval for 4 s, then quits.

use std::ptr::{self, NonNull};
use std::time::{Duration, Instant};

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_core_foundation::{CFDictionary, CFNumber, CFRetained, CFString, CFType};
use objc2_core_video::{
    CVPixelBuffer, CVPixelBufferCreate, CVPixelBufferGetBaseAddressOfPlane,
    CVPixelBufferGetBytesPerRowOfPlane, CVPixelBufferGetIOSurface, CVPixelBufferLockBaseAddress,
    CVPixelBufferLockFlags, CVPixelBufferUnlockBaseAddress, kCVPixelBufferHeightKey,
    kCVPixelBufferIOSurfacePropertiesKey, kCVPixelBufferPixelFormatTypeKey,
    kCVPixelBufferWidthKey, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
};
use objc2_metal::{
    MTLDevice, MTLPixelFormat, MTLStorageMode, MTLTextureDescriptor, MTLTextureType,
    MTLTextureUsage,
};
use wgpu::hal;

const W: u32 = 1920;
const H: u32 = 1080;

// ---------------------------------------------------------------- NV12 --

fn nv12_pixel_buffer(frame: u32) -> CFRetained<CVPixelBuffer> {
    let (k_fmt, k_w, k_h, k_io) = unsafe {
        (
            kCVPixelBufferPixelFormatTypeKey,
            kCVPixelBufferWidthKey,
            kCVPixelBufferHeightKey,
            kCVPixelBufferIOSurfacePropertiesKey,
        )
    };
    let empty = CFDictionary::<CFString, CFType>::empty();
    let attrs = CFDictionary::<CFString, CFType>::from_slices(
        &[k_fmt, k_w, k_h, k_io],
        &[
            &*CFNumber::new_i32(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange as i32),
            &*CFNumber::new_i32(W as i32),
            &*CFNumber::new_i32(H as i32),
            empty.as_opaque(),
        ],
    );
    let mut pb: *mut CVPixelBuffer = ptr::null_mut();
    let st = unsafe {
        CVPixelBufferCreate(
            None,
            W as usize,
            H as usize,
            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
            Some(attrs.as_opaque()),
            NonNull::from(&mut pb),
        )
    };
    assert_eq!(st, 0, "CVPixelBufferCreate");
    let pb = unsafe { CFRetained::from_raw(NonNull::new(pb).unwrap()) };
    // A moving pattern so frames differ.
    unsafe {
        CVPixelBufferLockBaseAddress(&pb, CVPixelBufferLockFlags(0));
        for plane in 0..2usize {
            let base = CVPixelBufferGetBaseAddressOfPlane(&pb, plane) as *mut u8;
            let stride = CVPixelBufferGetBytesPerRowOfPlane(&pb, plane);
            let rows = if plane == 0 { H } else { H / 2 } as usize;
            for y in 0..rows {
                let row = std::slice::from_raw_parts_mut(base.add(y * stride), stride);
                for (x, b) in row.iter_mut().enumerate() {
                    *b = ((x as u32 + y as u32 + frame * 7) & 0xff) as u8;
                }
            }
        }
        CVPixelBufferUnlockBaseAddress(&pb, CVPixelBufferLockFlags(0));
    }
    pb
}

/// ZERO-COPY: one IOSurface plane as a Metal texture, wrapped as a wgpu
/// texture. No pixel is copied: the GPU reads the IOSurface memory.
fn plane_texture(
    device: &wgpu::Device,
    pb: &CVPixelBuffer,
    plane: usize,
) -> wgpu::Texture {
    let surface = CVPixelBufferGetIOSurface(Some(pb)).expect("IOSurface-backed");
    let (fmt, mfmt, w, h) = if plane == 0 {
        (wgpu::TextureFormat::R8Unorm, MTLPixelFormat::R8Unorm, W, H)
    } else {
        (wgpu::TextureFormat::Rg8Unorm, MTLPixelFormat::RG8Unorm, W / 2, H / 2)
    };
    let hal_device = unsafe { device.as_hal::<hal::api::Metal>() }.expect("Metal backend");
    let mtl: &Retained<ProtocolObject<dyn MTLDevice>> = hal_device.raw_device();
    let desc = unsafe {
        MTLTextureDescriptor::texture2DDescriptorWithPixelFormat_width_height_mipmapped(
            mfmt, w as usize, h as usize, false,
        )
    };
    desc.setUsage(MTLTextureUsage::ShaderRead);
    desc.setStorageMode(MTLStorageMode::Shared);
    let raw = mtl
        .newTextureWithDescriptor_iosurface_plane(&desc, &surface, plane)
        .expect("newTextureWithDescriptor:iosurface:plane:");
    let hal_tex = unsafe {
        hal::metal::Device::texture_from_raw(
            raw,
            fmt,
            MTLTextureType::Type2D,
            1,
            1,
            hal::CopyExtent { width: w, height: h, depth: 1 },
            None,
        )
    };
    unsafe {
        device.create_texture_from_hal::<hal::api::Metal>(
            hal_tex,
            &wgpu::TextureDescriptor {
                label: Some("iosurface plane"),
                size: wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: fmt,
                usage: wgpu::TextureUsages::TEXTURE_BINDING,
                view_formats: &[],
            },
            wgpu::TextureUses::RESOURCE,
        )
    }
}

// --------------------------------------------------- NV12 -> RGBA pass --

const SHADER: &str = r#"
@group(0) @binding(0) var y_tex: texture_2d<f32>;
@group(0) @binding(1) var uv_tex: texture_2d<f32>;
@group(0) @binding(2) var samp: sampler;
struct V { @builtin(position) p: vec4<f32>, @location(0) uv: vec2<f32> };
@vertex fn vs(@builtin(vertex_index) i: u32) -> V {
    let xy = vec2<f32>(f32((i << 1u) & 2u), f32(i & 2u));
    var o: V; o.p = vec4<f32>(xy * 2.0 - 1.0, 0.0, 1.0); o.uv = vec2<f32>(xy.x, 1.0 - xy.y); return o;
}
@fragment fn fs(v: V) -> @location(0) vec4<f32> {
    // BT.709 video range
    let y = (textureSample(y_tex, samp, v.uv).r - 16.0 / 255.0) * 1.164;
    let c = textureSample(uv_tex, samp, v.uv).rg - vec2<f32>(0.5, 0.5);
    return vec4<f32>(y + 1.793 * c.y, y - 0.213 * c.x - 0.533 * c.y, y + 2.112 * c.x, 1.0);
}
"#;

struct Converter {
    pipeline: wgpu::RenderPipeline,
    layout: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
}

impl Converter {
    fn new(device: &wgpu::Device) -> Self {
        Self::with_format(device, wgpu::TextureFormat::Rgba8Unorm)
    }

    fn with_format(device: &wgpu::Device, target: wgpu::TextureFormat) -> Self {
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: None,
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let tex = |b| wgpu::BindGroupLayoutEntry {
            binding: b,
            visibility: wgpu::ShaderStages::FRAGMENT,
            ty: wgpu::BindingType::Texture {
                sample_type: wgpu::TextureSampleType::Float { filterable: true },
                view_dimension: wgpu::TextureViewDimension::D2,
                multisampled: false,
            },
            count: None,
        };
        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: None,
            entries: &[
                tex(0),
                tex(1),
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });
        let pl = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: None,
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: None,
            layout: Some(&pl),
            vertex: wgpu::VertexState {
                module: &module,
                entry_point: Some("vs"),
                compilation_options: Default::default(),
                buffers: &[],
            },
            fragment: Some(wgpu::FragmentState {
                module: &module,
                entry_point: Some("fs"),
                compilation_options: Default::default(),
                targets: &[Some(target.into())],
            }),
            primitive: Default::default(),
            depth_stencil: None,
            multisample: Default::default(),
            multiview_mask: None,
            cache: None,
        });
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });
        Self { pipeline, layout, sampler }
    }

    fn run(&self, device: &wgpu::Device, queue: &wgpu::Queue, y: &wgpu::Texture, uv: &wgpu::Texture, out: &wgpu::Texture) {
        self.run_view(device, queue, y, uv, &out.create_view(&Default::default()));
    }

    fn run_view(&self, device: &wgpu::Device, queue: &wgpu::Queue, y: &wgpu::Texture, uv: &wgpu::Texture, ov: &wgpu::TextureView) {
        let yv = y.create_view(&Default::default());
        let uvv = uv.create_view(&Default::default());
        let bg = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: None,
            layout: &self.layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: wgpu::BindingResource::TextureView(&yv) },
                wgpu::BindGroupEntry { binding: 1, resource: wgpu::BindingResource::TextureView(&uvv) },
                wgpu::BindGroupEntry { binding: 2, resource: wgpu::BindingResource::Sampler(&self.sampler) },
            ],
        });
        let mut enc = device.create_command_encoder(&Default::default());
        {
            let mut pass = enc.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: None,
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: ov,
                    depth_slice: None,
                    resolve_target: None,
                    ops: wgpu::Operations { load: wgpu::LoadOp::Clear(wgpu::Color::BLACK), store: wgpu::StoreOp::Store },
                })],
                ..Default::default()
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &bg, &[]);
            pass.draw(0..3, 0..1);
        }
        queue.submit([enc.finish()]);
    }
}

fn rgba_target(device: &wgpu::Device) -> wgpu::Texture {
    // What Slint requires: Rgba8Unorm with TEXTURE_BINDING | RENDER_ATTACHMENT.
    device.create_texture(&wgpu::TextureDescriptor {
        label: Some("video rgba"),
        size: wgpu::Extent3d { width: W, height: H, depth_or_array_layers: 1 },
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: wgpu::TextureFormat::Rgba8Unorm,
        usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_DST | wgpu::TextureUsages::COPY_SRC,
        view_formats: &[],
    })
}

fn plain_texture(device: &wgpu::Device, fmt: wgpu::TextureFormat, w: u32, h: u32) -> wgpu::Texture {
    device.create_texture(&wgpu::TextureDescriptor {
        label: None,
        size: wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 },
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: fmt,
        usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
        view_formats: &[],
    })
}

fn wait(device: &wgpu::Device) {
    device.poll(wgpu::PollType::wait_indefinitely()).unwrap();
}

fn stats(name: &str, mut ms: Vec<f64>) {
    ms.sort_by(f64::total_cmp);
    let p = |q: f64| ms[((ms.len() - 1) as f64 * q).round() as usize];
    println!("{name}: n={} p50 {:.3} ms  p95 {:.3} ms  max {:.3} ms", ms.len(), p(0.5), p(0.95), ms[ms.len() - 1]);
}

// --------------------------------------------------------------- bench --

fn bench() {
    let instance = { let mut d = wgpu::InstanceDescriptor::new_without_display_handle(); d.backends = wgpu::Backends::METAL; wgpu::Instance::new(d) };
    let adapter = pollster::block_on(instance.request_adapter(&Default::default())).unwrap();
    println!("adapter: {:?}", adapter.get_info().name);
    let (device, queue) = pollster::block_on(adapter.request_device(&Default::default())).unwrap();
    let conv = Converter::new(&device);
    let out = rgba_target(&device);
    let frames: Vec<_> = (0..8).map(nv12_pixel_buffer).collect();

    // (a) ZERO-COPY: wrap the IOSurface planes, convert on the GPU.
    let mut zc = Vec::new();
    for i in 0..300 {
        let pb = &frames[i % frames.len()];
        let t = Instant::now();
        let y = plane_texture(&device, pb, 0);
        let uv = plane_texture(&device, pb, 1);
        conv.run(&device, &queue, &y, &uv, &out);
        wait(&device);
        zc.push(t.elapsed().as_secs_f64() * 1e3);
    }
    stats("zero-copy  (wrap IOSurface planes + NV12->RGBA pass, to GPU completion)", zc);

    // (b) CPU UPLOAD of NV12 (3.1 MB) + the same pass.
    let y = plain_texture(&device, wgpu::TextureFormat::R8Unorm, W, H);
    let uv = plain_texture(&device, wgpu::TextureFormat::Rg8Unorm, W / 2, H / 2);
    let ybuf = vec![128u8; (W * H) as usize];
    let uvbuf = vec![128u8; (W * H / 2) as usize];
    let mut cu = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        queue.write_texture(y.as_image_copy(), &ybuf, wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(W), rows_per_image: None }, y.size());
        queue.write_texture(uv.as_image_copy(), &uvbuf, wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(W), rows_per_image: None }, uv.size());
        conv.run(&device, &queue, &y, &uv, &out);
        wait(&device);
        cu.push(t.elapsed().as_secs_f64() * 1e3);
    }
    stats("CPU upload (NV12 3.1 MB write_texture + same pass)", cu);

    // (b2) The REAL fallback: upload straight from the (decoder's) locked
    // CVPixelBuffer planes, honouring its row stride. Includes lock/unlock.
    let mut cv = Vec::new();
    for i in 0..300 {
        let pb = &frames[i % frames.len()];
        let t = Instant::now();
        unsafe {
            CVPixelBufferLockBaseAddress(pb, CVPixelBufferLockFlags(1)); // read-only
            for (plane, tex, rows) in [(0usize, &y, H), (1, &uv, H / 2)] {
                let base = CVPixelBufferGetBaseAddressOfPlane(pb, plane) as *const u8;
                let stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
                let data = std::slice::from_raw_parts(base, stride * rows as usize);
                queue.write_texture(tex.as_image_copy(), data, wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(stride as u32), rows_per_image: None }, tex.size());
            }
            CVPixelBufferUnlockBaseAddress(pb, CVPixelBufferLockFlags(1));
        }
        conv.run(&device, &queue, &y, &uv, &out);
        wait(&device);
        cv.push(t.elapsed().as_secs_f64() * 1e3);
    }
    stats("CPU upload from locked CVPixelBuffer (real fallback) + same pass", cv);

    // (c) CPU UPLOAD of already-converted RGBA (8.3 MB) - what a CPU-side
    // conversion would need.
    let rgba = vec![200u8; (W * H * 4) as usize];
    let mut ru = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        queue.write_texture(out.as_image_copy(), &rgba, wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(W * 4), rows_per_image: None }, out.size());
        queue.submit([]);
        wait(&device);
        ru.push(t.elapsed().as_secs_f64() * 1e3);
    }
    stats("CPU upload (RGBA 8.3 MB write_texture)", ru);
}

// -------------------------------------------------------------- window --

slint::slint! {
    export component Video inherits Window {
        preferred-width: 960px;
        preferred-height: 560px;
        title: "slint-wgpu spike";
        in property <image> frame;
        in property <string> info;
        VerticalLayout {
            Image { source: root.frame; image-fit: contain; }
            Text { text: root.info; }
        }
    }
}

fn window() {
    use std::cell::RefCell;
    use std::rc::Rc;
    slint::BackendSelector::new()
        .require_wgpu_30(slint::wgpu_30::WGPUConfiguration::default())
        .select()
        .expect("wgpu 30 backend");
    let app = Video::new().unwrap();
    struct St {
        gpu: Option<(wgpu::Device, wgpu::Queue, Converter)>,
        frames: Vec<CFRetained<CVPixelBuffer>>,
        n: usize,
        stamps: Vec<Instant>,
        start: Instant,
    }
    let st = Rc::new(RefCell::new(St {
        gpu: None,
        frames: (0..8).map(nv12_pixel_buffer).collect(),
        n: 0,
        stamps: Vec::new(),
        start: Instant::now(),
    }));
    let weak = app.as_weak();
    let st2 = st.clone();
    app.window()
        .set_rendering_notifier(move |state, api| {
            let mut s = st2.borrow_mut();
            match state {
                slint::RenderingState::RenderingSetup => {
                    if let slint::GraphicsAPI::WGPU30 { device, queue, .. } = api {
                        println!("rendering notifier: GraphicsAPI::WGPU30 (Slint's own device and queue)");
                        let conv = Converter::new(device);
                        s.gpu = Some((device.clone(), queue.clone(), conv));
                    }
                }
                slint::RenderingState::AfterRendering => {
                    s.stamps.push(Instant::now());
                    let elapsed = s.start.elapsed();
                    let Some((device, queue, conv)) = s.gpu.as_ref().map(|(d, q, c)| (d.clone(), q.clone(), c as *const Converter)) else { return };
                    // Next frame: zero-copy planes -> NV12->RGBA -> new Slint image.
                    let idx = s.n % s.frames.len();
                    let pb = s.frames[idx].clone();
                    s.n += 1;
                    drop(s);
                    let y = plane_texture(&device, &pb, 0);
                    let uv = plane_texture(&device, &pb, 1);
                    let out = rgba_target(&device);
                    unsafe { &*conv }.run(&device, &queue, &y, &uv, &out);
                    let img = slint::Image::try_from(out).expect("Slint accepts the RGBA texture");
                    // Already on the UI thread: set the image directly.
                    if let Some(a) = weak.upgrade() {
                        a.set_frame(img);
                        a.window().request_redraw();
                    }
                    if elapsed > Duration::from_secs(4) {
                        slint::quit_event_loop().unwrap();
                    }
                }
                _ => {}
            }
        })
        .unwrap();
    app.set_info("zero-copy NV12 IOSurface -> wgpu -> RGBA -> slint::Image".into());
    app.run().unwrap();
    let s = st.borrow();
    let ms: Vec<f64> = s.stamps.windows(2).map(|w| (w[1] - w[0]).as_secs_f64() * 1e3).skip(10).collect();
    println!("frames shown: {}", s.n);
    if ms.len() > 5 {
        stats("Slint frame interval (AfterRendering to AfterRendering)", ms);
    }
}

/// Reads back the zero-copy result and compares it with the same BT.709
/// formula on the CPU, at sample pixels. Proves the GPU really read the
/// IOSurface bytes (a black or stale texture would also be fast).
fn verify(plant_wrong_plane: bool) {
    let instance = { let mut d = wgpu::InstanceDescriptor::new_without_display_handle(); d.backends = wgpu::Backends::METAL; wgpu::Instance::new(d) };
    let adapter = pollster::block_on(instance.request_adapter(&Default::default())).unwrap();
    let (device, queue) = pollster::block_on(adapter.request_device(&Default::default())).unwrap();
    let conv = Converter::new(&device);
    let out = rgba_target(&device);
    let pb = nv12_pixel_buffer(3);
    let y = plane_texture(&device, &pb, 0);
    let uv = plane_texture(&device, &pb, if plant_wrong_plane { 0 } else { 1 });
    let uv = if plant_wrong_plane {
        // PLANT: feed a texture of the wrong content as the chroma plane.
        drop(uv);
        let t = plain_texture(&device, wgpu::TextureFormat::Rg8Unorm, W / 2, H / 2);
        queue.write_texture(t.as_image_copy(), &vec![0u8; (W * H / 2) as usize], wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(W), rows_per_image: None }, t.size());
        t
    } else { uv };
    conv.run(&device, &queue, &y, &uv, &out);
    let buf = device.create_buffer(&wgpu::BufferDescriptor { label: None, size: (W * H * 4) as u64, usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ, mapped_at_creation: false });
    let mut enc = device.create_command_encoder(&Default::default());
    enc.copy_texture_to_buffer(out.as_image_copy(), wgpu::TexelCopyBufferInfo { buffer: &buf, layout: wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(W * 4), rows_per_image: None } }, out.size());
    queue.submit([enc.finish()]);
    buf.slice(..).map_async(wgpu::MapMode::Read, |_| {});
    wait(&device);
    let px = buf.slice(..).get_mapped_range().unwrap();
    // CPU reference from the same buffer's bytes.
    let (ybase, ystride, uvbase, uvstride) = unsafe {
        CVPixelBufferLockBaseAddress(&pb, CVPixelBufferLockFlags(0));
        (CVPixelBufferGetBaseAddressOfPlane(&pb, 0) as *const u8, CVPixelBufferGetBytesPerRowOfPlane(&pb, 0),
         CVPixelBufferGetBaseAddressOfPlane(&pb, 1) as *const u8, CVPixelBufferGetBytesPerRowOfPlane(&pb, 1))
    };
    let mut worst = 0i32;
    let mut checked = 0;
    for &(x, yy) in &[(0u32, 0u32), (100, 50), (640, 360), (1001, 777), (1918, 1078), (37, 1001), (1500, 3)] {
        // Sample at even pixel centres where linear filtering of chroma is exact-ish: use x,y even.
        let (x, yy) = (x & !1, yy & !1);
        let (yv, u, v) = unsafe {
            (*ybase.add(yy as usize * ystride + x as usize) as f32 / 255.0,
             *uvbase.add((yy / 2) as usize * uvstride + (x / 2) as usize * 2) as f32 / 255.0,
             *uvbase.add((yy / 2) as usize * uvstride + (x / 2) as usize * 2 + 1) as f32 / 255.0)
        };
        let l = (yv - 16.0 / 255.0) * 1.164; let (cu, cv) = (u - 0.5, v - 0.5);
        let exp = [l + 1.793 * cv, l - 0.213 * cu - 0.533 * cv, l + 2.112 * cu].map(|c| (c.clamp(0.0, 1.0) * 255.0).round() as i32);
        let o = ((yy * W + x) * 4) as usize;
        let got = [px[o] as i32, px[o + 1] as i32, px[o + 2] as i32];
        let d = (0..3).map(|i| (got[i] - exp[i]).abs()).max().unwrap();
        worst = worst.max(d); checked += 1;
        println!("  ({x:4},{yy:4}) expected {exp:?} got {got:?}");
    }
    unsafe { CVPixelBufferUnlockBaseAddress(&pb, CVPixelBufferLockFlags(0)); }
    // Chroma is sampled with linear filtering between neighbours; allow a small tolerance.
    let ok = worst <= 40;
    println!("verify: {checked} pixels, worst channel error {worst} -> {}", if ok { "MATCH" } else { "MISMATCH" });
    if !ok { std::process::exit(1); }
}

// ----------------------------------------------------- raw winit+wgpu --

/// The alternative render path: our own winit window and wgpu surface, so we
/// choose the present mode. Zero-copy NV12 planes are converted straight into
/// the swapchain image (no intermediate RGBA texture).
fn raw(mode: wgpu::PresentMode) {
    use std::sync::Arc;
    use winit::application::ApplicationHandler;
    use winit::event::WindowEvent;
    use winit::event_loop::{ActiveEventLoop, EventLoop};
    use winit::window::{Window, WindowId};

    struct App {
        mode: wgpu::PresentMode,
        win: Option<Arc<Window>>,
        gpu: Option<(wgpu::Surface<'static>, wgpu::Device, wgpu::Queue, Converter)>,
        frames: Vec<CFRetained<CVPixelBuffer>>,
        stamps: Vec<Instant>,
        work_ms: Vec<f64>,
        start: Option<Instant>,
    }
    impl ApplicationHandler for App {
        fn resumed(&mut self, el: &ActiveEventLoop) {
            let win = Arc::new(el.create_window(Window::default_attributes().with_title("raw wgpu spike").with_inner_size(winit::dpi::LogicalSize::new(960, 540))).unwrap());
            let mut d = wgpu::InstanceDescriptor::new_without_display_handle();
            d.backends = wgpu::Backends::METAL;
            let instance = wgpu::Instance::new(d);
            let surface = instance.create_surface(win.clone()).unwrap();
            let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions { compatible_surface: Some(&surface), ..Default::default() })).unwrap();
            let (device, queue) = pollster::block_on(adapter.request_device(&Default::default())).unwrap();
            let caps = surface.get_capabilities(&adapter);
            println!("surface present modes: {:?}", caps.present_modes);
            let fmt = caps.formats.iter().copied().find(|f| !f.is_srgb()).unwrap_or(caps.formats[0]);
            let size = win.inner_size();
            let mut cfg = surface.get_default_config(&adapter, size.width, size.height).unwrap();
            cfg.format = fmt;
            cfg.present_mode = self.mode;
            cfg.desired_maximum_frame_latency = 1;
            surface.configure(&device, &cfg);
            println!("configured: {:?}, format {:?}", cfg.present_mode, fmt);
            let conv = Converter::with_format(&device, fmt);
            self.gpu = Some((surface, device, queue, conv));
            self.win = Some(win.clone());
            self.start = Some(Instant::now());
            win.request_redraw();
        }
        fn window_event(&mut self, el: &ActiveEventLoop, _: WindowId, ev: WindowEvent) {
            if let WindowEvent::RedrawRequested = ev {
                let (surface, device, queue, conv) = self.gpu.as_ref().unwrap();
                let t = Instant::now();
                let frame = match surface.get_current_texture() {
                    wgpu::CurrentSurfaceTexture::Success(f) | wgpu::CurrentSurfaceTexture::Suboptimal(f) => f,
                    other => { println!("acquire: {}", match other { wgpu::CurrentSurfaceTexture::Timeout => "timeout", wgpu::CurrentSurfaceTexture::Occluded => "occluded", _ => "other" }); self.win.as_ref().unwrap().request_redraw(); return; }
                };
                let pb = &self.frames[self.stamps.len() % self.frames.len()];
                let y = plane_texture(device, pb, 0);
                let uv = plane_texture(device, pb, 1);
                conv.run_view(device, queue, &y, &uv, &frame.texture.create_view(&Default::default()));
                queue.present(frame);
                self.work_ms.push(t.elapsed().as_secs_f64() * 1e3);
                self.stamps.push(Instant::now());
                if self.start.unwrap().elapsed() > Duration::from_secs(3) {
                    el.exit();
                } else {
                    self.win.as_ref().unwrap().request_redraw();
                }
            }
        }
    }
    let el = EventLoop::new().unwrap();
    let mut app = App { mode, win: None, gpu: None, frames: (0..8).map(nv12_pixel_buffer).collect(), stamps: vec![], work_ms: vec![], start: None };
    el.run_app(&mut app).unwrap();
    let ms: Vec<f64> = app.stamps.windows(2).map(|w| (w[1] - w[0]).as_secs_f64() * 1e3).skip(10).collect();
    println!("frames presented: {}", app.stamps.len());
    stats("frame interval", ms);
    stats("CPU time per frame (acquire + import + encode + present)", app.work_ms.into_iter().skip(10).collect());
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("verify") => verify(false),
        Some("verify-plant") => verify(true),
        Some("window") => window(),
        Some("raw-fifo") => raw(wgpu::PresentMode::Fifo),
        Some("raw-immediate") => raw(wgpu::PresentMode::Immediate),
        _ => bench(),
    }
}
