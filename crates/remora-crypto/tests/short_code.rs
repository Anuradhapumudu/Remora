//! Device short code (protocol.md §3.2, D27): 11 digits + Damm check digit.
//! The Damm table's error-detection properties are PROVEN here by
//! exhaustive computation on the table compiled into the code, so they do
//! not rest on remembering or citing it. Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use rand_core::OsRng;
use remora_crypto::identity::{
    DAMM_TABLE, DeviceId, IdentityKeypair, SHORT_CODE_DIGITS, ShortCode, ShortCodeError,
    damm_check_digit,
};

fn interim(ds: &[u8]) -> u8 {
    ds.iter()
        .fold(0, |i, &d| DAMM_TABLE[usize::from(i)][usize::from(d)])
}

#[test]
fn damm_table_is_a_weakly_totally_antisymmetric_quasigroup_with_zero_diagonal() {
    for r in 0..10 {
        let mut row: Vec<u8> = DAMM_TABLE[r].to_vec();
        row.sort_unstable();
        assert_eq!(
            row,
            (0..10).collect::<Vec<u8>>(),
            "row {r} is not a permutation"
        );
        let mut col: Vec<u8> = (0..10).map(|i| DAMM_TABLE[i][r]).collect();
        col.sort_unstable();
        assert_eq!(
            col,
            (0..10).collect::<Vec<u8>>(),
            "column {r} is not a permutation"
        );
        assert_eq!(DAMM_TABLE[r][r], 0, "diagonal at {r}");
    }
    for c in 0..10usize {
        for x in 0..10usize {
            for y in 0..10usize {
                let a = DAMM_TABLE[usize::from(DAMM_TABLE[c][x])][y];
                let b = DAMM_TABLE[usize::from(DAMM_TABLE[c][y])][x];
                assert!(
                    a != b || x == y,
                    "anti-symmetry fails for c={c} x={x} y={y}"
                );
            }
        }
    }
}

#[test]
fn every_single_error_and_adjacent_transposition_is_detected() {
    // All 10^5 five-digit payloads (the property is per position, so this
    // covers every kind of error at every place it can occur).
    for n in 0..100_000u32 {
        let mut ds: Vec<u8> = format!("{n:05}").bytes().map(|b| b - b'0').collect();
        ds.push(damm_check_digit(&ds));
        assert_eq!(interim(&ds), 0, "valid code must check to 0: {ds:?}");
        for p in 0..ds.len() {
            for v in 0..10u8 {
                if v != ds[p] {
                    let mut e = ds.clone();
                    e[p] = v;
                    assert_ne!(
                        interim(&e),
                        0,
                        "single error undetected: {ds:?} pos {p} -> {v}"
                    );
                }
            }
        }
        for p in 0..ds.len() - 1 {
            if ds[p] != ds[p + 1] {
                let mut e = ds.clone();
                e.swap(p, p + 1);
                assert_ne!(interim(&e), 0, "transposition undetected: {ds:?} at {p}");
            }
        }
    }
}

#[test]
fn short_code_is_the_documented_derivation() {
    let id = DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public());
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&id.as_bytes()[..8]);
    let n = u64::from_be_bytes(first8) % 100_000_000_000;
    let digits: Vec<u8> = format!("{n:011}").bytes().map(|b| b - b'0').collect();
    let check = damm_check_digit(&digits);
    let want = format!(
        "{} {} {}-{}",
        &format!("{n:011}")[0..4],
        &format!("{n:011}")[4..7],
        &format!("{n:011}")[7..11],
        check
    );
    assert_eq!(id.short_code().to_string(), want);
    assert_eq!(SHORT_CODE_DIGITS, 11);
}

#[test]
fn display_parse_roundtrip_and_leading_zeros() {
    let zero = DeviceId::from_bytes([0; 10]);
    assert_eq!(zero.short_code().to_string(), "0000 000 0000-0");
    for _ in 0..200 {
        let id = DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public());
        let code = id.short_code();
        let text = code.to_string();
        assert_eq!(text.len(), "0000 000 0000-0".len());
        assert_eq!(ShortCode::parse(&text).unwrap(), code);
        assert_eq!(
            ShortCode::parse(&text.replace([' ', '-'], "")).unwrap(),
            code
        );
        assert!(code.matches(&id));
    }
}

#[test]
fn typos_are_rejected_by_the_check_digit() {
    let id = DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public());
    let digits: Vec<char> = id
        .short_code()
        .to_string()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    for p in 0..digits.len() {
        for v in '0'..='9' {
            if v != digits[p] {
                let mut t = digits.clone();
                t[p] = v;
                let s: String = t.into_iter().collect();
                assert_eq!(ShortCode::parse(&s), Err(ShortCodeError::CheckDigit), "{s}");
            }
        }
    }
    for p in 0..digits.len() - 1 {
        if digits[p] != digits[p + 1] {
            let mut t = digits.clone();
            t.swap(p, p + 1);
            let s: String = t.into_iter().collect();
            assert_eq!(ShortCode::parse(&s), Err(ShortCodeError::CheckDigit), "{s}");
        }
    }
}

#[test]
fn malformed_input_is_rejected() {
    assert_eq!(ShortCode::parse(""), Err(ShortCodeError::WrongLength));
    assert_eq!(
        ShortCode::parse("1234 567 8901"),
        Err(ShortCodeError::WrongLength)
    );
    assert_eq!(
        ShortCode::parse("1234 567 8901-23"),
        Err(ShortCodeError::WrongLength)
    );
    assert_eq!(
        ShortCode::parse("1234 567 89O1-2"),
        Err(ShortCodeError::NotDigit)
    );
    assert_eq!(
        ShortCode::parse("1234_567_8901-2"),
        Err(ShortCodeError::NotDigit)
    );
    assert_eq!(
        ShortCode::parse("١٢٣٤ ٥٦٧ ٨٩٠١-٢"),
        Err(ShortCodeError::NotDigit)
    );
    // Absurdly long input is refused without trouble.
    assert!(ShortCode::parse(&"9".repeat(1 << 16)).is_err());
}

#[test]
fn a_code_matches_only_its_own_device() {
    let a = DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public());
    let b = DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public());
    assert!(a.short_code().matches(&a));
    assert!(!a.short_code().matches(&b));
}
