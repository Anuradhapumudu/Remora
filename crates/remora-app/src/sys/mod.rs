//! OS-specific code behind small functions; nothing above this module knows
//! which OS it runs on (CLAUDE.md conventions).

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(crate) use macos::monotonic_ns;

/// No backend yet on this OS.
#[cfg(not(target_os = "macos"))]
pub(crate) fn monotonic_ns() -> Option<u64> {
    None
}
