//! CLI helpers. Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use rand_core::OsRng;
use remora_app::cli::{
    CliError, Looks, format_sas, identity_hex, looks_like, misplaced, offer_code, parse_identity,
    short_code_of,
};
use remora_crypto::identity::{DeviceId, IdentityKeypair};
use remora_proto::code::{CandidateKind, CodeKind, ConnectionCode};

#[test]
fn sas_reads_as_two_groups_of_three_with_leading_zeros() {
    let s = remora_crypto::sas::sas(&[0; 32], &[0; 32], &[0; 32]);
    let text = format_sas(s);
    assert_eq!(text.len(), 7);
    assert_eq!(&text[3..4], " ");
    assert_eq!(text.replace(' ', ""), s.to_string());
}

#[test]
fn identity_hex_round_trip_and_strict_parsing() {
    let k = IdentityKeypair::generate(&mut OsRng).public();
    let h = identity_hex(&k);
    assert_eq!(h.len(), 64);
    assert!(
        h.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
    assert_eq!(parse_identity(&h).unwrap(), k);
    assert_eq!(parse_identity(&h.to_uppercase()).unwrap(), k);
    for bad in [
        "",
        &h[..63],
        &format!("{h}0"),
        &h.replacen('a', "g", 1),
        &format!(" {}", &h[1..]),
    ] {
        if bad != h {
            assert_eq!(parse_identity(bad), Err(CliError::BadIdentity), "{bad:?}");
        }
    }
}

#[test]
fn offer_code_carries_key_nonce_expiry_and_address() {
    let k = IdentityKeypair::generate(&mut OsRng).public();
    let addr = "127.0.0.1:4433".parse().unwrap();
    let now = 1_760_000_000;
    let text = offer_code(addr, &k, [7; 16], now, 300);
    let code = ConnectionCode::parse(&text, now).unwrap();
    assert_eq!(code.kind, CodeKind::Offer);
    assert_eq!(code.identity_key, *k.as_bytes());
    assert_eq!(code.nonce, [7; 16]);
    assert_eq!(u64::from(code.expires_at), now + 300);
    assert_eq!(code.candidates.len(), 1);
    assert_eq!(code.candidates[0].addr, addr);
    assert_eq!(code.candidates[0].kind, CandidateKind::Host);
    // Expired after its ttl (A07, checked by remora-proto before any traffic).
    assert!(ConnectionCode::parse(&text, now + 301).is_err());
}

#[test]
fn short_code_of_is_the_device_ids_short_code() {
    let k = IdentityKeypair::generate(&mut OsRng).public();
    assert_eq!(short_code_of(&k), DeviceId::of(&k).short_code());
}

// F-UX5 (walkthrough 2026-10-21): the owner's real mistakes, from the
// screenshots - the password as the code, the code or the host's identity
// as --pin, a device code where a key belongs.
const CODE: &str = "remora1:AQBq2D4cW7dGxEyBTCGlr2KFrSwMYF_dkUBj0T6KG-ZbhSq5V6VD63vPf4arFz12PoonUGuFD5C2WjvCzk_sw9_Fcw8ODg_QLe8BQH8AAAHIM4VUNHI";
const KEY: &str = "5fdd914063d13e8a1be65b852ab957a543eb7bcf7f86ab173d763e8a27506b85";

#[test]
fn f_ux5_looks_like_recognises_each_host_line_by_shape() {
    assert_eq!(looks_like(CODE), Some(Looks::ConnectionCode));
    assert_eq!(looks_like(KEY), Some(Looks::IdentityKey));
    assert_eq!(looks_like(&KEY.to_uppercase()), Some(Looks::IdentityKey));
    assert_eq!(looks_like("957588"), Some(Looks::Password));
    assert_eq!(looks_like(" 957588 "), Some(Looks::Password));
    // A real device code from the walkthrough (check digit valid).
    assert_eq!(looks_like("8531 422 5411-5"), Some(Looks::DeviceCode));
    assert_eq!(looks_like("853142254115"), Some(Looks::DeviceCode));
    // Near misses are nothing in particular.
    assert_eq!(looks_like("8531 422 5411-4"), None, "bad check digit");
    assert_eq!(looks_like(&KEY[1..]), None, "63 hex digits");
    assert_eq!(looks_like("95758"), None);
    assert_eq!(looks_like("hello"), None);
    assert_eq!(looks_like(""), None);
}

#[test]
fn f_ux5_misplaced_names_the_line_to_copy_and_what_was_given() {
    let m = misplaced(Looks::ConnectionCode, "957588");
    assert!(m.contains("'code:'") && m.contains("password"), "{m}");
    let m = misplaced(Looks::IdentityKey, CODE);
    assert!(
        m.contains("'identity:'") && m.contains("connection code"),
        "{m}"
    );
    let m = misplaced(Looks::IdentityKey, "8531 422 5411-5");
    assert!(
        m.contains("'identity:'") && m.contains("device code"),
        "{m}"
    );
    let m = misplaced(Looks::ConnectionCode, KEY);
    assert!(m.contains("'code:'") && m.contains("identity key"), "{m}");
    // Unrecognisable input still gets the line to copy.
    let m = misplaced(Looks::Password, "hello");
    assert!(m.contains("'password:'"), "{m}");
    // The right kind with a typo: no "looks like" claim.
    let m = misplaced(Looks::IdentityKey, &KEY[1..]);
    assert!(
        m.contains("'identity:'") && !m.contains("looks like"),
        "{m}"
    );
    // Right shape, but damaged or expired: no "looks like a connection
    // code" for a connection code (mutation-gate finding).
    let m = misplaced(Looks::ConnectionCode, "remora1:damaged");
    assert!(m.contains("'code:'") && !m.contains("looks like"), "{m}");
}

#[test]
fn f_ux5_a_hint_never_repeats_the_value() {
    // It may be the password typed into the wrong field.
    for (want, text) in [
        (Looks::ConnectionCode, "957588"),
        (Looks::IdentityKey, "957588"),
        (Looks::DeviceCode, "957588"),
        (Looks::IdentityKey, CODE),
        (Looks::Password, KEY),
    ] {
        let m = misplaced(want, text);
        assert!(!m.contains(text.trim()), "{want:?}: {m}");
    }
}
