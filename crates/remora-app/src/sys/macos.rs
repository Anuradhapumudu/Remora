//! macOS: the mach host clock through CoreVideo's host-time functions
//! (safe bindings in objc2-core-video 0.3.2, `CVHostTime.rs:14` and `:28`;
//! no `unsafe`). This is the clock ScreenCaptureKit timestamps frames with,
//! so capture times and viewer times are directly comparable.

use objc2_core_video::{CVGetCurrentHostTime, CVGetHostClockFrequency};

pub(crate) fn monotonic_ns() -> Option<u64> {
    // Ticks per second: 24 MHz on Apple Silicon. A nonsense frequency means
    // no usable clock rather than a wrong one.
    let freq = CVGetHostClockFrequency();
    if !(freq.is_finite() && freq >= 1.0) {
        return None;
    }
    let ticks = CVGetCurrentHostTime();
    // u128 so ticks * 1e9 cannot overflow; the frequency is a whole number of
    // Hz on every Mac we know of, and the fraction would be sub-ppm anyway.
    let ns = u128::from(ticks) * 1_000_000_000 / (freq as u128);
    u64::try_from(ns).ok()
}
