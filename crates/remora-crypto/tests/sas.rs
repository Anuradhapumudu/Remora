//! phase3-criteria A17-S3 (the SAS depends on every bit of h, n_i, n_r) and
//! A18-stat (the responder's fixed choices cannot pin the SAS). Written
//! before the implementation.

use blake2::{Blake2s256, Digest};
use remora_crypto::sas::{COMMIT_CONTEXT, SAS_CONTEXT, Sas, commitment, sas, verify_commitment};
use remora_testkit::stats::{chi_square_critical, chi_square_uniform};

fn inputs() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut h = [0u8; 32];
    let mut n_i = [0u8; 32];
    let mut n_r = [0u8; 32];
    for i in 0..32u8 {
        h[usize::from(i)] = i.wrapping_mul(7);
        n_i[usize::from(i)] = i.wrapping_mul(13) ^ 0x5A;
        n_r[usize::from(i)] = i.wrapping_mul(29) ^ 0xC3;
    }
    (h, n_i, n_r)
}

#[test]
fn sas_is_the_documented_formula() {
    let (h, n_i, n_r) = inputs();
    let mut d = Blake2s256::new();
    d.update(SAS_CONTEXT);
    d.update(h);
    d.update(n_i);
    d.update(n_r);
    let out = d.finalize();
    let want = u64::from_be_bytes(out[..8].try_into().unwrap()) % 1_000_000;
    assert_eq!(u64::from(sas(&h, &n_i, &n_r).value()), want);
    assert_eq!(SAS_CONTEXT, b"remora/1/sas");
}

#[test]
fn commitment_is_the_documented_formula_and_verifies() {
    let (_, _, n_r) = inputs();
    let mut d = Blake2s256::new();
    d.update(COMMIT_CONTEXT);
    d.update(n_r);
    let want: [u8; 32] = d.finalize().into();
    assert_eq!(commitment(&n_r), want);
    assert!(verify_commitment(&want, &n_r));
    assert_eq!(COMMIT_CONTEXT, b"remora/1/sas-commit");
}

#[test]
fn verify_commitment_rejects_every_single_bit_change() {
    let (_, _, n_r) = inputs();
    let c = commitment(&n_r);
    for bit in 0..256 {
        let mut bad_n = n_r;
        bad_n[bit / 8] ^= 1 << (bit % 8);
        assert!(!verify_commitment(&c, &bad_n), "n_r bit {bit}");
        let mut bad_c = c;
        bad_c[bit / 8] ^= 1 << (bit % 8);
        assert!(!verify_commitment(&bad_c, &n_r), "C_r bit {bit}");
    }
}

#[test]
fn a17_s3_flipping_any_input_bit_changes_the_sas() {
    // Fixed inputs; a collision is possible at 10⁻⁶ per flip, so with 768
    // flips the chance this fixed choice has one is ≈ 7.7 × 10⁻⁴ — and it
    // is checked once, here, for these inputs.
    let (h, n_i, n_r) = inputs();
    let base = sas(&h, &n_i, &n_r);
    for bit in 0..256 {
        let flip = |mut a: [u8; 32]| {
            a[bit / 8] ^= 1 << (bit % 8);
            a
        };
        assert_ne!(sas(&flip(h), &n_i, &n_r), base, "h bit {bit}");
        assert_ne!(sas(&h, &flip(n_i), &n_r), base, "n_i bit {bit}");
        assert_ne!(sas(&h, &n_i, &flip(n_r)), base, "n_r bit {bit}");
    }
}

#[test]
fn a17_s3_inputs_are_not_interchangeable() {
    // Swapping the roles of the inputs gives a different code (domain
    // ordering is part of the formula).
    let (h, n_i, n_r) = inputs();
    let base = sas(&h, &n_i, &n_r);
    assert_ne!(sas(&h, &n_r, &n_i), base);
    assert_ne!(sas(&n_i, &h, &n_r), base);
}

#[test]
fn display_is_six_digits_with_leading_zeros() {
    // Search a few inputs for small values to check formatting.
    let (h, mut n_i, n_r) = inputs();
    let mut found_small = false;
    for i in 0..200_000u32 {
        n_i[..4].copy_from_slice(&i.to_le_bytes());
        let s: Sas = sas(&h, &n_i, &n_r);
        let text = s.to_string();
        assert_eq!(text.len(), 6);
        assert_eq!(text.parse::<u32>().unwrap(), s.value());
        assert!(s.value() < 1_000_000);
        if s.value() < 100_000 {
            assert!(text.starts_with('0'));
            found_small = true;
        }
    }
    assert!(found_small);
}

#[test]
fn a18_stat_responder_fixed_choices_cannot_pin_the_sas() {
    // Fix everything the responder controls (h stands in for its ephemeral
    // key's effect, and n_r), vary only the initiator's n_i over 10⁶ runs,
    // bucket into 1000 bins. FAIL if χ²(999) > 1226.1 (p = 10⁻⁶).
    let (h, _, n_r) = inputs();
    let mut bins = vec![0u64; 1000];
    let mut n_i = [0u8; 32];
    for i in 0..1_000_000u64 {
        n_i[..8].copy_from_slice(&i.to_le_bytes());
        bins[(sas(&h, &n_i, &n_r).value() / 1000) as usize] += 1;
    }
    let chi2 = chi_square_uniform(&bins);
    let critical = chi_square_critical(999, 1e-6);
    assert!(chi2 <= critical, "χ² = {chi2} > {critical}");
}
