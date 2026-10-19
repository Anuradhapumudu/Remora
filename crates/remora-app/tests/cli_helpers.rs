//! CLI helpers. Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use rand_core::OsRng;
use remora_app::cli::{
    CliError, format_sas, identity_hex, offer_code, parse_identity, short_code_of,
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
