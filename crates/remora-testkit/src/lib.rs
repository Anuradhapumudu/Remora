//! Remora's security test harness (phase3-criteria §7b step 1).
//!
//! * [`link`] — in-process viewer↔host links with a scriptable man-in-the-middle
//!   (record, replay, flip, drop, duplicate, truncate, replace, reorder).
//! * [`canary`] — planted secrets + capture of every log line; finds leaks in
//!   raw, hex, base64 and `Debug` form (A28, INV8).
//! * [`count_allocations`] / [`CountingAlloc`] — proves inputs are rejected
//!   before memory is allocated (A26, INV7).
//! * [`stats`] — binomial tails and χ² thresholds for the secondary
//!   statistical tests (A17, A18, A29).
//! * [`mock`] — call logs to prove something did NOT happen (A20, INV1).
//! * [`policy`] — fails the build if `unsafe`, `spake2`/`snow` or this crate
//!   appear where they must not (A31, A35).
//!
//! Test-only: may appear only under `[dev-dependencies]` (enforced by [`policy`]).

// `unsafe_code` is denied workspace-wide. Only `src/sys/count_alloc.rs` opts in
// (a `GlobalAlloc` impl is `unsafe` by definition) — a documented policy
// exception; see that file.

pub mod canary;
pub mod link;
pub mod mock;
pub mod policy;
pub mod stats;
mod sys;

pub use sys::count_alloc::{AllocStats, CountingAlloc, count_allocations};
