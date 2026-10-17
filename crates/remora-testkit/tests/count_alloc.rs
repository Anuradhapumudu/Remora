//! The counting allocator must measure real allocations — otherwise every
//! "rejected before allocating" test (A26) would pass vacuously.

use remora_testkit::{CountingAlloc, count_allocations};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

#[test]
fn measures_allocations_on_this_thread() {
    let (v, stats) = count_allocations(|| Vec::<u8>::with_capacity(10_000));
    assert!(v.capacity() >= 10_000);
    assert!(stats.peak_bytes >= 10_000, "{stats:?}");
    assert!(stats.allocations >= 1);
}

#[test]
fn reports_nothing_when_nothing_is_allocated() {
    let (sum, stats) = count_allocations(|| (1..=100u32).sum::<u32>());
    assert_eq!(sum, 5050);
    assert_eq!(stats.total_bytes, 0, "{stats:?}");
}

#[test]
fn peak_tracks_live_bytes_not_total() {
    let ((), stats) = count_allocations(|| {
        for _ in 0..10 {
            drop(Vec::<u8>::with_capacity(1_000));
        }
    });
    assert!(stats.total_bytes >= 10_000);
    assert!(
        stats.peak_bytes < 2_000,
        "freed buffers must not count toward the peak: {stats:?}"
    );
}
