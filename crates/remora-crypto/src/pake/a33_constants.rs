//! phase3-criteria A33: re-derive SPAKE2's M, N (and S) from python-spake2's
//! published seed procedure and compare with the constants compiled into the
//! `spake2` 0.4.0 crate.
//!
//! The procedure, read from python-spake2 0.9 (sdist sha256
//! 421fc4a8d5ac395af7af0206ffd9e6cdf188c105cb1b883d9d683312bb5a9334, files
//! src/spake2/params.py, groups.py, ed25519_basic.py, 2026-10-18):
//!
//! 1. `h = HKDF-SHA256(salt = "", ikm = seed, info = "SPAKE2 arbitrary element", L = 48)`
//!    with seeds `b"M"`, `b"N"`, `b"symmetric"`;
//! 2. `y = int.from_bytes(h, big-endian) mod p`;
//! 3. for `plus = 0, 1, 2, …`: take `y + plus`, the **even** root `x`
//!    (`xrecover`); skip if not on the curve; `P8 = 8·(x, y)`; skip if `P8`
//!    is the identity; the result is `P8`.
//!
//! "Nothing up my sleeve": M and N are hashes of public one-letter strings,
//! so nobody chose them — the property SPAKE2's security needs (nobody may
//! know their discrete logarithm). This test shows the crate uses exactly
//! these points; it cannot show the hash-to-curve method itself is sound.

use ::spake2::Group;
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use sha2::Sha256;

/// p = 2²⁵⁵ − 19 as little-endian 64-bit limbs.
const P: [u64; 4] = [
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];

/// Reduces a 384-bit big-endian number mod p. 2²⁵⁵ ≡ 19 (mod p), so
/// `hi·2²⁵⁵ + lo ≡ 19·hi + lo`; two folds bring it below 2²⁵⁶, then at most
/// two subtractions of p finish the job.
fn reduce_mod_p(be: &[u8; 48]) -> [u64; 4] {
    // little-endian 64-bit limbs of the 384-bit input
    let mut n = [0u64; 6];
    for (i, limb) in n.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&be[48 - 8 * (i + 1)..48 - 8 * i]);
        *limb = u64::from_be_bytes(b);
    }
    let mut v: Vec<u64> = n.to_vec();
    for _ in 0..3 {
        // split at bit 255
        let mut lo = [v[0], v[1], v[2], v[3] & 0x7fff_ffff_ffff_ffff, 0, 0];
        let mut hi = [0u64; 6];
        // hi = v >> 255
        for i in 0..6 {
            let a = v.get(i + 3).copied().unwrap_or(0) >> 63;
            let b = v.get(i + 4).copied().unwrap_or(0) << 1;
            hi[i] = a | b;
        }
        // lo += 19 * hi
        let mut carry: u128 = 0;
        for i in 0..6 {
            let t = u128::from(lo[i]) + 19 * u128::from(hi[i]) + carry;
            lo[i] = t as u64;
            carry = t >> 64;
        }
        assert_eq!(carry, 0);
        v = lo.to_vec();
    }
    assert!(v[4] == 0 && v[5] == 0);
    let mut r = [v[0], v[1], v[2], v[3]];
    while ge(&r, &P) {
        r = sub(&r, &P);
    }
    r
}

fn ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, o1) = a[i].overflowing_sub(b[i]);
        let (d2, o2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = u64::from(o1 || o2);
    }
    r
}

fn add_small(a: &[u64; 4], k: u64) -> [u64; 4] {
    let mut r = *a;
    let mut carry = k;
    for limb in r.iter_mut() {
        let (s, o) = limb.overflowing_add(carry);
        *limb = s;
        carry = u64::from(o);
    }
    if ge(&r, &P) { sub(&r, &P) } else { r }
}

fn arbitrary_element(seed: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 48];
    Hkdf::<Sha256>::new(Some(b""), seed)
        .expand(b"SPAKE2 arbitrary element", &mut h)
        .unwrap();
    let y0 = reduce_mod_p(&h);
    for plus in 0u64.. {
        let y = add_small(&y0, plus);
        let mut enc = [0u8; 32];
        for (i, limb) in y.iter().enumerate() {
            enc[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
        }
        // sign bit 0 = the even x, as python's xrecover returns. y < p, so
        // the encoding is canonical.
        let Some(p) = CompressedEdwardsY(enc).decompress() else {
            continue;
        };
        let p8 = p.mul_by_cofactor();
        if p8 == curve25519_dalek::EdwardsPoint::default() {
            continue;
        }
        assert!(p8.is_torsion_free());
        return p8.compress().to_bytes();
    }
    unreachable!()
}

#[test]
fn reduction_matches_known_values() {
    let mut be = [0u8; 48];
    be[47] = 5;
    assert_eq!(reduce_mod_p(&be), [5, 0, 0, 0]);
    // p itself (as a 384-bit number) reduces to 0; p + 7 to 7.
    let mut p_be = [0u8; 48];
    for (i, limb) in P.iter().enumerate() {
        p_be[48 - 8 * (i + 1)..48 - 8 * i].copy_from_slice(&limb.to_be_bytes());
    }
    assert_eq!(reduce_mod_p(&p_be), [0, 0, 0, 0]);
    p_be[47] += 7;
    assert_eq!(reduce_mod_p(&p_be), [7, 0, 0, 0]);
    // 2^383 mod p = 19 * 2^128 mod p ... = 2^128 * 19 (since 2^383 = 2^255 * 2^128)
    let mut top = [0u8; 48];
    top[0] = 0x80;
    assert_eq!(reduce_mod_p(&top), [0, 0, 19, 0]);
}

#[test]
fn m_n_s_rederive_to_the_crate_constants() {
    let crate_m = ::spake2::Ed25519Group::const_m().compress().to_bytes();
    let crate_n = ::spake2::Ed25519Group::const_n().compress().to_bytes();
    let crate_s = ::spake2::Ed25519Group::const_s().compress().to_bytes();
    assert_eq!(arbitrary_element(b"M"), crate_m, "M");
    assert_eq!(arbitrary_element(b"N"), crate_n, "N");
    assert_eq!(arbitrary_element(b"symmetric"), crate_s, "S");
    // And the hex the crate's comments (and crypto-claims-audit §1) quote.
    let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    assert_eq!(
        hex(crate_m),
        "15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312"
    );
    assert_eq!(
        hex(crate_n),
        "f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3"
    );
}
