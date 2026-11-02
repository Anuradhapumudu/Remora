//! Per-OS backends. The only place in this crate allowed to use `unsafe`.

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod macos_window;

// No `unsafe` here: the portal is reached through remora-capture (D48).
#[cfg(target_os = "linux")]
pub(crate) mod linux;
