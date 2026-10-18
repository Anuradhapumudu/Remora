//! phase3-criteria A29: OTP generation is unbiased. Structural test primary
//! (rejection sampling with an injected RNG), χ² secondary. Written before the
//! implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use rand_core::{CryptoRng, RngCore};
use remora_crypto::otp::{OTP_SPACE, ProductionRng, REJECT_FROM, generate_otp};
use remora_crypto::secret::{Otp, OtpError};
use remora_testkit::stats::{chi_square_critical, chi_square_uniform};

/// Hands out a fixed script of `u32`s (as little-endian bytes, whatever
/// method the generator uses to read them) and counts how many were taken.
struct ScriptRng {
    script: Vec<u32>,
    taken: usize,
}

impl ScriptRng {
    fn new(script: &[u32]) -> Self {
        Self {
            script: script.to_vec(),
            taken: 0,
        }
    }
    fn next(&mut self) -> u32 {
        let v = *self
            .script
            .get(self.taken)
            .unwrap_or_else(|| panic!("generator drew more than {} values", self.script.len()));
        self.taken += 1;
        v
    }
}

impl RngCore for ScriptRng {
    fn next_u32(&mut self) -> u32 {
        self.next()
    }
    fn next_u64(&mut self) -> u64 {
        panic!("generator must draw u32 values (next_u32 / 4-byte fills)")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert_eq!(
            dest.len(),
            4,
            "generator must draw exactly 4 bytes at a time"
        );
        dest.copy_from_slice(&self.next().to_le_bytes());
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for ScriptRng {}

#[test]
fn reject_threshold_is_the_largest_multiple_of_the_space() {
    assert_eq!(REJECT_FROM, 4_294_000_000);
    assert_eq!(REJECT_FROM % OTP_SPACE, 0);
    assert!(u64::from(u32::MAX) + 1 - u64::from(REJECT_FROM) < u64::from(OTP_SPACE));
}

#[test]
fn values_in_the_biased_tail_are_redrawn_not_mapped() {
    // Every tail value (the biased last partial block) must be thrown away.
    for tail in [REJECT_FROM, REJECT_FROM + 1, 4_294_500_000, u32::MAX] {
        let mut rng = ScriptRng::new(&[tail, 123_456]);
        let otp = generate_otp(&mut rng);
        assert_eq!(
            otp.reveal(),
            "123456",
            "tail value {tail} was mapped instead of redrawn"
        );
        assert_eq!(rng.taken, 2);
    }
    // Several tail values in a row: still redrawn each time.
    let mut rng = ScriptRng::new(&[u32::MAX, REJECT_FROM, u32::MAX - 7, 42]);
    assert_eq!(generate_otp(&mut rng).reveal(), "000042");
    assert_eq!(rng.taken, 4);
}

#[test]
fn values_below_the_threshold_are_used_once_with_leading_zeros() {
    for (draw, want) in [
        (0, "000000"),
        (7, "000007"),
        (999_999, "999999"),
        (1_000_000, "000000"),
        (REJECT_FROM - 1, "999999"),
        (4_293_123_456, "123456"),
    ] {
        let mut rng = ScriptRng::new(&[draw]);
        assert_eq!(generate_otp(&mut rng).reveal(), want, "draw {draw}");
        assert_eq!(rng.taken, 1, "draw {draw} must not be rejected");
    }
}

#[test]
fn production_rng_is_the_os_csprng() {
    // Compile-time: generate_otp_os is tied to rand_core::OsRng through the
    // ProductionRng alias. If someone swaps the alias, this stops compiling.
    fn same_type<T>(_: &T, _: &T) {}
    same_type(&ProductionRng::default(), &rand_core::OsRng);
    let otp = remora_crypto::otp::generate_otp_os();
    assert_eq!(otp.reveal().len(), 6);
    assert!(otp.reveal().bytes().all(|b| b.is_ascii_digit()));
}

#[test]
fn chi_square_over_a_million_otps_in_1000_bins() {
    // Secondary. Detects gross bias only — it CANNOT see the modulo bias the
    // structural test above targets (≈ 0.1 counts per bin vs σ ≈ 31.6).
    let mut bins = vec![0u64; 1000];
    let mut rng = rand_core::OsRng;
    for _ in 0..1_000_000 {
        let otp = generate_otp(&mut rng);
        let v: usize = otp.reveal().parse().unwrap();
        bins[v / 1000] += 1;
    }
    let chi2 = chi_square_uniform(&bins);
    let critical = chi_square_critical(999, 1e-6);
    assert!((1226.0..1226.3).contains(&critical), "critical {critical}");
    assert!(chi2 <= critical, "χ² = {chi2} > {critical}");
}

#[test]
fn parse_accepts_exactly_six_ascii_digits() {
    assert_eq!(Otp::parse("482913").unwrap().reveal(), "482913");
    assert_eq!(Otp::parse("000000").unwrap().reveal(), "000000");
    assert_eq!(Otp::parse("48291").unwrap_err(), OtpError::WrongLength);
    assert_eq!(Otp::parse("4829130").unwrap_err(), OtpError::WrongLength);
    assert_eq!(Otp::parse("").unwrap_err(), OtpError::WrongLength);
    assert_eq!(Otp::parse("48291a").unwrap_err(), OtpError::NotDigit);
    assert_eq!(Otp::parse("48 913").unwrap_err(), OtpError::NotDigit);
    assert_eq!(Otp::parse("-48291").unwrap_err(), OtpError::NotDigit);
    // Non-ASCII digits (Arabic-Indic, full-width) are not accepted.
    assert!(Otp::parse("٤٨٢٩١٣").is_err());
    assert!(Otp::parse("４８２９１３").is_err());
}
