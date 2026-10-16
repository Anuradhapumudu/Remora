//! Per-OS capture backends. The only place in this crate allowed to use `unsafe`.

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod macos;
