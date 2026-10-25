//! The shared monotonic clock for latency measurement (phase4-criteria §2).
//!
//! Host and viewer run as **two processes**. End-to-end latency subtracts a
//! host timestamp (capture) from a viewer timestamp (drawn), which is only
//! meaningful if both processes read **the same clock**. On macOS that is the
//! mach host clock (`mach_absolute_time`, the clock ScreenCaptureKit stamps
//! frames with). That the two processes really agree is not assumed: test
//! P0 (`tests/p0_clock.rs`) measures it across a process boundary.
//!
//! `std::time::Instant` cannot be used: it is opaque, so its value cannot be
//! sent to another process.

/// Nanoseconds on the system-wide monotonic clock, or `None` on an OS whose
/// backend does not exist yet (Windows and Linux arrive in their phases).
pub fn monotonic_ns() -> Option<u64> {
    crate::sys::monotonic_ns()
}
