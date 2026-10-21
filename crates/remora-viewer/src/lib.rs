//! Remora viewer: the parts the `remora-viewer` binary and its tests share.
//!
//! [`render`] draws decoded NV12 pictures with wgpu (phase4-criteria R1,
//! R2); macOS only until Phase 6.5.

#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
pub mod render;
