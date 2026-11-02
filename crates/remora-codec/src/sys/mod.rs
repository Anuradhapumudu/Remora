//! Per-OS codec backends. The only place in this crate allowed to use `unsafe`.

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod macos;

// No `unsafe` here: the openh264 crate wraps the C library.
#[cfg(target_os = "linux")]
pub(crate) mod linux;
