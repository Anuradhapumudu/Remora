//! Per-OS capture backends. The only place in this crate allowed to use `unsafe`.

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod macos;

// No `unsafe` here: the pipewire and ashpd crates wrap the C and D-Bus APIs.
#[cfg(target_os = "linux")]
pub(crate) mod linux;
