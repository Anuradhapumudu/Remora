//! Counting global allocator for "rejected before allocating" tests
//! (phase3-criteria A26, threat model INV7).
//!
//! POLICY EXCEPTION — owner-approved as architecture.md decision D19 (NOT a
//! general precedent): this is the only
//! `unsafe` in the workspace that is not an OS FFI binding — Rust's
//! `GlobalAlloc` trait is `unsafe` by definition. It is confined to this file,
//! delegates every call unchanged to the system allocator, and lives in a
//! test-only crate that the policy test forbids as a normal dependency of any
//! other crate (it may only appear under `[dev-dependencies]`).
//!
//! Usage in a test binary:
//! ```ignore
//! #[global_allocator]
//! static ALLOC: remora_testkit::CountingAlloc = remora_testkit::CountingAlloc;
//! let (_, stats) = remora_testkit::count_allocations(|| parse(input));
//! assert!(stats.peak_bytes < 4096);
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    // `const` initialisers: accessing these never allocates (no lazy init).
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static CURRENT: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
    static TOTAL: Cell<usize> = const { Cell::new(0) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
}

/// Allocations made on the measuring thread inside [`count_allocations`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocStats {
    /// Highest number of live bytes allocated during the closure.
    pub peak_bytes: usize,
    /// Sum of all allocation sizes during the closure.
    pub total_bytes: usize,
    /// Number of allocations during the closure.
    pub allocations: usize,
}

/// A global allocator that counts the current thread's allocations while a
/// [`count_allocations`] measurement is running.
pub struct CountingAlloc;

fn on_alloc(size: usize) {
    // `try_with`: the thread-locals may already be destroyed during thread exit.
    let active = ACTIVE.try_with(Cell::get).unwrap_or(false);
    if active {
        let _ = CURRENT.try_with(|c| {
            let now = c.get().saturating_add(size);
            c.set(now);
            let _ = PEAK.try_with(|p| p.set(p.get().max(now)));
        });
        let _ = TOTAL.try_with(|t| t.set(t.get().saturating_add(size)));
        let _ = COUNT.try_with(|n| n.set(n.get() + 1));
    }
}

fn on_dealloc(size: usize) {
    if ACTIVE.try_with(Cell::get).unwrap_or(false) {
        let _ = CURRENT.try_with(|c| c.set(c.get().saturating_sub(size)));
    }
}

// SAFETY: every method forwards its arguments unchanged to `System`, which
// upholds the `GlobalAlloc` contract; the extra bookkeeping only touches
// thread-local `Cell`s with `const` initialisers, which never allocate and so
// cannot recurse into this allocator.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        on_alloc(layout.size());
        // SAFETY: same contract as our caller's; forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        on_dealloc(layout.size());
        // SAFETY: `ptr` was allocated by `System` with this `layout` (we forward
        // every allocation to `System`).
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        on_alloc(layout.size());
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        on_dealloc(layout.size());
        on_alloc(new_size);
        // SAFETY: `ptr`/`layout` come from `System` (see `dealloc`); forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Runs `f` and reports the allocations it made **on this thread**.
/// Only meaningful in a binary that installs [`CountingAlloc`] as its
/// `#[global_allocator]`; otherwise every count is zero.
pub fn count_allocations<R>(f: impl FnOnce() -> R) -> (R, AllocStats) {
    for c in [&CURRENT, &PEAK, &TOTAL, &COUNT] {
        c.with(|v| v.set(0));
    }
    ACTIVE.with(|a| a.set(true));
    let r = f();
    ACTIVE.with(|a| a.set(false));
    let stats = AllocStats {
        peak_bytes: PEAK.with(Cell::get),
        total_bytes: TOTAL.with(Cell::get),
        allocations: COUNT.with(Cell::get),
    };
    (r, stats)
}
