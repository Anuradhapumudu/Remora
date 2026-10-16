//! Latency statistics for the Phase 2 benchmark.
//!
//! A fixed-size histogram, not a growing list of samples: the benchmark runs for
//! 10+ minutes while measuring its own memory (criterion C4), so the instrument
//! must not grow with run length. Percentiles are exact to one bucket (10 µs);
//! min, max and mean are exact.

use std::time::Duration;

/// Bucket width in nanoseconds (10 µs).
const BUCKET_NS: i64 = 10_000;
/// Lowest value with its own bucket: −100 ms (frames can arrive before their timestamp).
const MIN_NS: i64 = -100_000_000;
/// Number of buckets: covers −100 ms … +200 ms.
const BUCKETS: usize = 30_000;

/// Signed nanosecond samples summarized by a fixed histogram.
#[derive(Debug)]
pub(crate) struct Samples {
    counts: Box<[u32]>,
    below: u64,
    above: u64,
    count: u64,
    sum: i128,
    min: i64,
    max: i64,
}

/// Percentile summary in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Summary {
    pub(crate) count: u64,
    pub(crate) min: f64,
    pub(crate) p50: f64,
    pub(crate) p95: f64,
    pub(crate) p99: f64,
    pub(crate) max: f64,
    pub(crate) mean: f64,
}

impl Default for Samples {
    fn default() -> Self {
        Self {
            // Allocated once (~120 KB of zeroed memory); never grows.
            counts: vec![0u32; BUCKETS].into_boxed_slice(),
            below: 0,
            above: 0,
            count: 0,
            sum: 0,
            min: i64::MAX,
            max: i64::MIN,
        }
    }
}

impl Samples {
    pub(crate) fn push(&mut self, d: Duration) {
        self.push_ns(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
    }

    /// Signed sample (e.g. a frame delivered *before* its timestamp is negative).
    pub(crate) fn push_ns(&mut self, ns: i64) {
        self.count += 1;
        self.sum += i128::from(ns);
        self.min = self.min.min(ns);
        self.max = self.max.max(ns);
        if ns < MIN_NS {
            self.below += 1;
            return;
        }
        match usize::try_from((ns - MIN_NS) / BUCKET_NS) {
            Ok(i) if i < BUCKETS => self.counts[i] = self.counts[i].saturating_add(1),
            _ => self.above += 1,
        }
    }

    /// Nearest-rank percentile, reported as the upper edge of its bucket (so it
    /// never understates by more than one 10 µs bucket), clamped to [min, max].
    fn percentile_ns(&self, p: f64) -> i64 {
        let rank = ((p / 100.0) * self.count as f64).ceil().max(1.0) as u64;
        let mut seen = self.below;
        if rank <= seen {
            return self.min;
        }
        for (i, &c) in self.counts.iter().enumerate() {
            seen += u64::from(c);
            if rank <= seen {
                let upper = MIN_NS + (i as i64 + 1) * BUCKET_NS;
                return upper.clamp(self.min, self.max);
            }
        }
        self.max
    }

    pub(crate) fn summary(&self) -> Option<Summary> {
        if self.count == 0 {
            return None;
        }
        let ms = |ns: i64| ns as f64 / 1e6;
        Some(Summary {
            count: self.count,
            min: ms(self.min),
            p50: ms(self.percentile_ns(50.0)),
            p95: ms(self.percentile_ns(95.0)),
            p99: ms(self.percentile_ns(99.0)),
            max: ms(self.max),
            mean: (self.sum as f64 / self.count as f64) / 1e6,
        })
    }
}

/// Least-squares slope of `(x, y)` points (y per unit x); `None` with < 2 distinct x.
pub(crate) fn slope(points: &[(f64, f64)]) -> Option<f64> {
    let n = points.len() as f64;
    if points.len() < 2 {
        return None;
    }
    let (sx, sy) = points
        .iter()
        .fold((0.0, 0.0), |(a, b), &(x, y)| (a + x, b + y));
    let (mx, my) = (sx / n, sy / n);
    let (num, den) = points.iter().fold((0.0, 0.0), |(num, den), &(x, y)| {
        (num + (x - mx) * (y - my), den + (x - mx) * (x - mx))
    });
    (den > 0.0).then(|| num / den)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() <= 0.010_001 // within one bucket (10 µs = 0.01 ms)
    }

    #[test]
    fn nearest_rank_percentiles_within_one_bucket() {
        let mut s = Samples::default();
        for v in 1..=100 {
            s.push(Duration::from_millis(v));
        }
        let sum = s.summary().unwrap();
        assert_eq!(sum.count, 100);
        assert!(close(sum.p50, 50.0), "{}", sum.p50);
        assert!(close(sum.p95, 95.0), "{}", sum.p95);
        assert!(close(sum.p99, 99.0), "{}", sum.p99);
        assert_eq!(sum.max, 100.0);
        assert_eq!(sum.min, 1.0);
        assert!((sum.mean - 50.5).abs() < 1e-9);
    }

    #[test]
    fn negative_samples_are_ranked_not_dropped() {
        let mut s = Samples::default();
        for ns in [-6_000_000, -5_000_000, -1_000_000, 1_000_000, 2_000_000] {
            s.push_ns(ns);
        }
        let sum = s.summary().unwrap();
        assert_eq!(sum.count, 5);
        assert_eq!(sum.min, -6.0);
        assert!(close(sum.p50, -1.0), "{}", sum.p50);
        assert_eq!(sum.p95, 2.0); // clamped to the exact max
        assert_eq!(sum.max, 2.0);
    }

    #[test]
    fn out_of_range_values_are_counted_not_lost() {
        let mut s = Samples::default();
        s.push_ns(-500_000_000); // below range
        s.push_ns(1_000_000);
        s.push_ns(900_000_000); // above range
        let sum = s.summary().unwrap();
        assert_eq!(sum.count, 3);
        assert_eq!(sum.min, -500.0);
        assert_eq!(sum.max, 900.0);
        assert!(close(sum.p50, 1.0));
        assert_eq!(sum.p99, 900.0);
    }

    #[test]
    fn single_sample_and_empty() {
        let mut s = Samples::default();
        assert!(s.summary().is_none());
        s.push(Duration::from_millis(7));
        let sum = s.summary().unwrap();
        assert_eq!((sum.p50, sum.p95, sum.max), (7.0, 7.0, 7.0));
    }

    #[test]
    fn slope_of_line_and_degenerate_input() {
        assert_eq!(slope(&[(0.0, 1.0), (1.0, 3.0), (2.0, 5.0)]), Some(2.0));
        assert_eq!(slope(&[(1.0, 1.0)]), None);
        assert_eq!(slope(&[(1.0, 1.0), (1.0, 2.0)]), None);
    }
}
