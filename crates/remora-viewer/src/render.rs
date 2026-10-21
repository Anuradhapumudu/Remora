//! Drawing decoded pictures (phase4-criteria R1, R2, P7).
//!
//! The NV12 planes are copied from the locked decoder picture into two
//! textures (luma `R8Unorm`, chroma `Rg8Unorm`) and converted to RGB by a
//! fragment shader (BT.709, video range) in one full-screen triangle. Same
//! shader and upload path as the render spike (architecture D32, D34),
//! which was pixel-verified (worst error 2/255) and measured at 0.75–0.80
//! ms p95 at 1080p.

use remora_codec::Nv12;

/// Draws the most recently uploaded picture into any texture view of the
/// format it was made for.
pub struct Renderer {
    device: wgpu::Device,
    queue: wgpu::Queue,
}

impl Renderer {
    /// A renderer drawing into textures of `format`.
    pub fn new(device: wgpu::Device, queue: wgpu::Queue, format: wgpu::TextureFormat) -> Self {
        let _ = format;
        Self { device, queue } // RED: not yet
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
        let _ = picture; // RED: not yet
    }

    /// Draws the last uploaded picture, stretched to `target`. Returns
    /// `false` if nothing was uploaded yet.
    pub fn draw(&self, target: &wgpu::TextureView) -> bool {
        let _ = target;
        false // RED: not yet
    }
}

/// A GPU device with no window (tests, measurements). `None` if this
/// machine has no Metal adapter.
pub fn headless() -> Option<(wgpu::Device, wgpu::Queue)> {
    None // RED: not yet
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
    /// finished every submitted draw.
    pub fn read(&self, device: &wgpu::Device, queue: &wgpu::Queue) -> Vec<u8> {
        let _ = (device, queue);
        Vec::new() // RED: not yet
    }
}
