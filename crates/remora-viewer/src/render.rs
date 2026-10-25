//! Drawing decoded pictures (phase4-criteria R1, R2, P7).
//!
//! The NV12 planes are copied from the locked decoder picture into two
//! textures (luma `R8Unorm`, chroma `Rg8Unorm`) and converted to RGB by a
//! fragment shader (BT.709, video range) in one full-screen triangle. Same
//! shader and upload path as the render spike (architecture D32, D34),
//! which was pixel-verified (worst error 2/255) and measured at 0.75–0.80
//! ms p95 at 1080p.
//!
//! The colour matrix is fixed at BT.709 video range, what VideoToolbox's
//! H.264 encoder is configured for on the host; reading the matrix from
//! the stream's VUI is not done yet (P7 reads only brightness).

use remora_codec::Nv12;

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

/// The two plane textures of the current picture size.
struct Planes {
    y: wgpu::Texture,
    uv: wgpu::Texture,
    bind: wgpu::BindGroup,
}

/// Draws the most recently uploaded picture into any texture view of the
/// format it was made for.
pub struct Renderer {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::RenderPipeline,
    layout: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
    planes: Option<Planes>,
}

impl Renderer {
    /// A renderer drawing into textures of `format`.
    pub fn new(device: wgpu::Device, queue: wgpu::Queue, format: wgpu::TextureFormat) -> Self {
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("nv12"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let tex = |binding| wgpu::BindGroupLayoutEntry {
            binding,
            visibility: wgpu::ShaderStages::FRAGMENT,
            ty: wgpu::BindingType::Texture {
                sample_type: wgpu::TextureSampleType::Float { filterable: true },
                view_dimension: wgpu::TextureViewDimension::D2,
                multisampled: false,
            },
            count: None,
        };
        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("nv12"),
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
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("nv12"),
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("nv12"),
            layout: Some(&pipeline_layout),
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
                targets: &[Some(format.into())],
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
        Self {
            device,
            queue,
            pipeline,
            layout,
            sampler,
            planes: None,
        }
    }

    /// The device it draws with.
    pub fn device(&self) -> &wgpu::Device {
        &self.device
    }

    /// The queue it submits to.
    pub fn queue(&self) -> &wgpu::Queue {
        &self.queue
    }

    /// Copies a picture's planes to the GPU (new textures when its size
    /// changes). The next [`draw`](Self::draw) shows it.
    pub fn upload(&mut self, picture: &Nv12<'_>) {
        let (w, h) = (picture.width(), picture.height());
        let chroma = (w.div_ceil(2), h.div_ceil(2));
        let fits = self
            .planes
            .as_ref()
            .is_some_and(|p| p.y.width() == w && p.y.height() == h);
        if !fits {
            self.planes = Some(self.make_planes(w, h, chroma));
        }
        let Some(planes) = &self.planes else {
            return;
        };
        // `Nv12::new` checked that both slices hold every row at these
        // strides, so these copies stay inside the slices.
        let (y, y_stride) = picture.y();
        let (uv, uv_stride) = picture.uv();
        for (texture, data, stride) in [(&planes.y, y, y_stride), (&planes.uv, uv, uv_stride)] {
            self.queue.write_texture(
                texture.as_image_copy(),
                data,
                wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: u32::try_from(stride).ok(),
                    rows_per_image: None,
                },
                texture.size(),
            );
        }
        // Send the copies now. wgpu stages each `write_texture` until the
        // next submit (wgpu-core 30.0.1 `src/device/queue.rs:1529`, an
        // empty submit included) and frees finished staging memory there;
        // a window that cannot draw never submits, so without this every
        // picture's ~3 MB copy piled up (2.4 GB in 15 s, test
        // `p5_pictures_that_are_never_drawn_do_not_pile_up`).
        self.queue.submit([]);
    }

    fn make_planes(&self, w: u32, h: u32, chroma: (u32, u32)) -> Planes {
        let texture = |format, width, height| {
            self.device.create_texture(&wgpu::TextureDescriptor {
                label: Some("nv12 plane"),
                size: wgpu::Extent3d {
                    width,
                    height,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format,
                usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
                view_formats: &[],
            })
        };
        let y = texture(wgpu::TextureFormat::R8Unorm, w, h);
        let uv = texture(wgpu::TextureFormat::Rg8Unorm, chroma.0, chroma.1);
        let yv = y.create_view(&Default::default());
        let uvv = uv.create_view(&Default::default());
        let bind = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("nv12"),
            layout: &self.layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: wgpu::BindingResource::TextureView(&yv),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: wgpu::BindingResource::TextureView(&uvv),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: wgpu::BindingResource::Sampler(&self.sampler),
                },
            ],
        });
        Planes { y, uv, bind }
    }

    /// Draws the last uploaded picture, stretched to `target`. Returns
    /// `false` if nothing was uploaded yet.
    pub fn draw(&self, target: &wgpu::TextureView) -> bool {
        let Some(planes) = &self.planes else {
            return false;
        };
        let mut encoder = self.device.create_command_encoder(&Default::default());
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("nv12"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: target,
                    depth_slice: None,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                ..Default::default()
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &planes.bind, &[]);
            pass.draw(0..3, 0..1);
        }
        self.queue.submit([encoder.finish()]);
        true
    }
}

/// A GPU device with no window (tests, measurements). `None` if this
/// machine has no Metal adapter.
pub fn headless() -> Option<(wgpu::Device, wgpu::Queue)> {
    let mut desc = wgpu::InstanceDescriptor::new_without_display_handle();
    desc.backends = wgpu::Backends::METAL;
    let instance = wgpu::Instance::new(desc);
    let adapter = pollster::block_on(instance.request_adapter(&Default::default())).ok()?;
    pollster::block_on(adapter.request_device(&Default::default())).ok()
}

/// An `Rgba8Unorm` texture to draw into and read back (P7: the barcode is
/// read from what was drawn).
pub struct Offscreen {
    texture: wgpu::Texture,
}

impl Offscreen {
    /// A `width × height` target.
    pub fn new(device: &wgpu::Device, width: u32, height: u32) -> Self {
        let texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("offscreen"),
            size: wgpu::Extent3d {
                width,
                height,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Rgba8Unorm,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
            view_formats: &[],
        });
        Self { texture }
    }

    /// The view to draw into.
    pub fn view(&self) -> wgpu::TextureView {
        self.texture
            .create_view(&wgpu::TextureViewDescriptor::default())
    }

    /// Reads the pixels back, `width × 4` bytes per row, after the GPU has
    /// finished every submitted draw. Empty if the read-back failed.
    pub fn read(&self, device: &wgpu::Device, queue: &wgpu::Queue) -> Vec<u8> {
        let (w, h) = (self.texture.width(), self.texture.height());
        let row = w as usize * 4;
        // Buffer copies need rows padded to 256 bytes (wgpu's
        // COPY_BYTES_PER_ROW_ALIGNMENT).
        let padded = row.next_multiple_of(wgpu::COPY_BYTES_PER_ROW_ALIGNMENT as usize);
        let buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("read back"),
            size: (padded * h as usize) as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let mut encoder = device.create_command_encoder(&Default::default());
        encoder.copy_texture_to_buffer(
            self.texture.as_image_copy(),
            wgpu::TexelCopyBufferInfo {
                buffer: &buffer,
                layout: wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: u32::try_from(padded).ok(),
                    rows_per_image: None,
                },
            },
            self.texture.size(),
        );
        queue.submit([encoder.finish()]);
        let slice = buffer.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| {
            let _ = tx.send(r);
        });
        if device.poll(wgpu::PollType::wait_indefinitely()).is_err()
            || !matches!(rx.recv(), Ok(Ok(())))
        {
            return Vec::new();
        }
        let Ok(data) = slice.get_mapped_range() else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(row * h as usize);
        for line in data.chunks(padded) {
            out.extend_from_slice(&line[..row]);
        }
        drop(data);
        buffer.unmap();
        out
    }
}
