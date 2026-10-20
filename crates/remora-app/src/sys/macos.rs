//! macOS: the mach host clock through CoreVideo's host-time functions
//! (safe bindings in objc2-core-video 0.3.2, `CVHostTime.rs`; no `unsafe`).

pub(crate) fn monotonic_ns() -> Option<u64> {
    todo!("P0 written first")
}
