//! Latency statistics for the Phase 2 benchmark.

use std::time::Duration;

/// A set of (possibly negative) nanosecond samples with percentile summaries.
#[derive(Debug, Default)]
pub(crate) struct Samples {
    nanos: Vec<i64>,
}

/// Percentile summary in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Summary {
    pub(crate) count: usize,
    pub(crate) min: f64,
    pub(crate) p50: f64,
    pub(crate) p95: f64,
    pub(crate) p99: f64,
    pub(crate) max: f64,
    pub(crate) mean: f64,
}

impl Samples {
    /// Pre-allocates for `capacity` samples so recording never reallocates mid-run.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            nanos: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn push(&mut self, d: Duration) {
        self.push_ns(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
    }

    /// Signed sample (e.g. a frame delivered *before* its timestamp is negative).
    pub(crate) fn push_ns(&mut self, ns: i64) {
        self.nanos.push(ns);
    }

    /// Nearest-rank percentiles (no interpolation): p95 is a real observed sample.
    /// Works on signed values, so negative samples are ranked, not dropped.
    pub(crate) fn summary(&self) -> Option<Summary> {
        if self.nanos.is_empty() {
            return None;
        }
        let mut sorted = self.nanos.clone();
        sorted.sort_unstable();
        let n = sorted.len();
        let rank = |p: f64| {
            let idx = ((p / 100.0) * n as f64).ceil() as usize;
            sorted[idx.clamp(1, n) - 1] as f64 / 1e6
        };
        let mean = sorted.iter().map(|&v| v as f64).sum::<f64>() / n as f64 / 1e6;
        Some(Summary {
            count: n,
            min: sorted[0] as f64 / 1e6,
            p50: rank(50.0),
            p95: rank(95.0),
            p99: rank(99.0),
            max: sorted[n - 1] as f64 / 1e6,
            mean,
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

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn nearest_rank_percentiles() {
        let mut s = Samples::with_capacity(100);
        for v in 1..=100 {
            s.push(ms(v));
        }
        let sum = s.summary().unwrap();
        assert_eq!(sum.count, 100);
        assert_eq!(sum.p50, 50.0);
        assert_eq!(sum.p95, 95.0);
        assert_eq!(sum.p99, 99.0);
        assert_eq!(sum.max, 100.0);
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
        assert_eq!(sum.p50, -1.0);
        assert_eq!(sum.p95, 2.0);
        assert_eq!(sum.max, 2.0);
    }

    #[test]
    fn single_sample_and_empty() {
        let mut s = Samples::default();
        assert!(s.summary().is_none());
        s.push(ms(7));
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
