//! OS-specific code behind small functions; nothing above this module knows
//! which OS it runs on (CLAUDE.md conventions).

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(crate) use macos::monotonic_ns;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::monotonic_ns;

/// No backend yet on this OS.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn monotonic_ns() -> Option<u64> {
    None
}
