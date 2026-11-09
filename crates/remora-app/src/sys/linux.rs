//! Linux: `CLOCK_MONOTONIC` through rustix's safe `clock_gettime`
//! (rustix-1.1.5 `src/time/clock.rs:60`; no `unsafe` here). It is
//! system-wide, so two processes on one machine read the same clock
//! (test P0 measures that rather than assuming it). Rust's own `Instant`
//! uses the same clock on Linux but is opaque.

use rustix::time::{ClockId, clock_gettime};

pub(crate) fn monotonic_ns() -> Option<u64> {
    let t = clock_gettime(ClockId::Monotonic);
    let secs = u64::try_from(t.tv_sec).ok()?;
    let nanos = u64::try_from(t.tv_nsec).ok()?;
    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}
