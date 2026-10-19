//! Statistics for the secondary (sampling) security tests — phase3-criteria
//! §3.4a and A29. Each function is checked against published reference values.

/// Inverse of the standard normal CDF (Acklam's rational approximation,
/// relative error < 1.2e-9). `p` must be in (0, 1).
pub fn normal_quantile(p: f64) -> f64 {
    const A: [f64; 6] = [
        -3.969683028665376e1,
        2.209460984245205e2,
        -2.759285104469687e2,
        1.38357751867269e2,
        -3.066479806614716e1,
        2.506628277459239,
    ];
    const B: [f64; 5] = [
        -5.447609879822406e1,
        1.615858368580409e2,
        -1.556989798598866e2,
        6.680131188771972e1,
        -1.328068155288572e1,
    ];
    const C: [f64; 6] = [
        -7.784894002430293e-3,
        -3.223964580411365e-1,
        -2.400758277161838,
        -2.549732539343734,
        4.374664141464968,
        2.938163982698783,
    ];
    const D: [f64; 4] = [
        7.784695709041462e-3,
        3.224671290700398e-1,
        2.445134137142996,
        3.754408661907416,
    ];
    const LOW: f64 = 0.02425;
    let tail = |q: f64| {
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    };
    if p < LOW {
        tail((-2.0 * p.ln()).sqrt())
    } else if p > 1.0 - LOW {
        -tail((-2.0 * (1.0 - p).ln()).sqrt())
    } else {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    }
}

/// Upper critical value of the χ² distribution: the x with P(χ²_df > x) = `alpha`.
/// Wilson–Hilferty approximation; accurate to well under 0.5 % for df ≥ 30,
/// which is the only range our tests use (asserted).
pub fn chi_square_critical(df: u32, alpha: f64) -> f64 {
    assert!(df >= 30, "Wilson–Hilferty is only used for df ≥ 30");
    let k = f64::from(df);
    let z = normal_quantile(1.0 - alpha);
    k * (1.0 - 2.0 / (9.0 * k) + z * (2.0 / (9.0 * k)).sqrt()).powi(3)
}

/// Pearson χ² statistic of `observed` counts against a uniform expectation.
pub fn chi_square_uniform(observed: &[u64]) -> f64 {
    let total: u64 = observed.iter().sum();
    let expected = total as f64 / observed.len() as f64;
    observed
        .iter()
        .map(|&o| (o as f64 - expected).powi(2) / expected)
        .sum()
}

/// P(X ≥ k) for X ~ Binomial(n, p), computed exactly from the lower tail.
pub fn binomial_tail_ge(n: u64, p: f64, k: u64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let mut pmf = (1.0 - p).powf(n as f64); // P(X = 0)
    let mut below = 0.0;
    for i in 0..k.min(n + 1) {
        below += pmf;
        pmf *= (n - i) as f64 / (i + 1) as f64 * p / (1.0 - p);
    }
    (1.0 - below).max(0.0)
}

/// Median of `xs` (sorts in place). `None` for an empty slice.
pub fn median(xs: &mut [f64]) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_by(f64::total_cmp);
    let n = xs.len();
    Some(if n % 2 == 1 {
        xs[n / 2]
    } else {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(a: f64, b: f64) -> f64 {
        ((a - b) / b).abs()
    }

    #[test]
    fn normal_quantile_matches_tables() {
        assert!((normal_quantile(0.975) - 1.959_963_985).abs() < 1e-8);
        assert!((normal_quantile(0.5)).abs() < 1e-12);
        assert!((normal_quantile(1e-6) + 4.753_424_309).abs() < 1e-6);
    }

    #[test]
    fn chi_square_critical_matches_published_values() {
        // Standard χ² table values (upper tail).
        assert!(rel(chi_square_critical(100, 0.05), 124.342) < 0.001);
        assert!(rel(chi_square_critical(50, 0.01), 76.154) < 0.001);
        assert!(rel(chi_square_critical(30, 0.001), 59.703) < 0.002);
        // The threshold used by phase3-criteria A18-stat / A29.
        let c = chi_square_critical(999, 1e-6);
        assert!((c - 1226.1).abs() < 0.5, "{c}");
    }

    #[test]
    fn chi_square_statistic_basics() {
        assert_eq!(chi_square_uniform(&[10, 10, 10, 10]), 0.0);
        assert!((chi_square_uniform(&[0, 20]) - 20.0).abs() < 1e-12);
    }

    #[test]
    fn binomial_tail_matches_criteria_reasoning() {
        // phase3-criteria §3.4a: N = 10 000, p = 1e-6.
        let p_ge1 = binomial_tail_ge(10_000, 1e-6, 1);
        let p_ge2 = binomial_tail_ge(10_000, 1e-6, 2);
        assert!(rel(p_ge1, 0.009_950) < 0.001, "{p_ge1}");
        assert!(rel(p_ge2, 4.967e-5) < 0.002, "{p_ge2}");
        // Power against a 1000× advantage.
        assert!(binomial_tail_ge(10_000, 1e-3, 2) > 0.999);
        assert_eq!(binomial_tail_ge(5, 0.5, 0), 1.0);
        assert!((binomial_tail_ge(1, 0.5, 1) - 0.5).abs() < 1e-12);
    }

    #[test]
    fn median_odd_even_empty() {
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&mut [4.0, 1.0, 2.0, 3.0]), Some(2.5));
        assert_eq!(median(&mut []), None);
    }
}
