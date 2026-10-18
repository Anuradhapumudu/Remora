//! phase3-criteria A32 (small-order / torsion / identity SPAKE2 elements are
//! rejected by OUR wrapper before the crate sees them) and the PAKE half of
//! A01. Written before the implementation.
//!
//! The known-bad encodings below were computed on 2026-10-18 by an
//! independent pure-Python implementation of edwards25519 (integer
//! arithmetic only, no curve library): all 8 points of the 8-torsion
//! subgroup, every canonical and non-canonical 32-byte encoding of each.
//! They are hard-coded so the test does not trust the code it is testing.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use curve25519_dalek::edwards::CompressedEdwardsY;
use rand_core::OsRng;
use remora_crypto::identity::{DeviceId, IdentityKeypair};
use remora_crypto::pake::{
    PAKE_MESSAGE_LEN, Pake, PakeContext, PakeError, PakeMessage, PakeRole, SIDE_HOST, SIDE_VIEWER,
    Spake2Ed25519, validate_peer_message,
};
use remora_crypto::secret::Otp;

/// (order, canonical?, encoding)
const SMALL_ORDER: [(u8, bool, &str); 14] = [
    (
        1,
        true,
        "0100000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        1,
        false,
        "0100000000000000000000000000000000000000000000000000000000000080",
    ),
    (
        1,
        false,
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ),
    (
        1,
        false,
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        2,
        true,
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ),
    (
        2,
        false,
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        4,
        true,
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        4,
        true,
        "0000000000000000000000000000000000000000000000000000000000000080",
    ),
    (
        4,
        false,
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ),
    (
        4,
        false,
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        8,
        true,
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    ),
    (
        8,
        true,
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ),
    (
        8,
        true,
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    ),
    (
        8,
        true,
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ),
];

/// y values whose x² is not a square: not points at all.
const OFF_CURVE: [&str; 3] = [
    "0200000000000000000000000000000000000000000000000000000000000000",
    "0700000000000000000000000000000000000000000000000000000000000000",
    "0800000000000000000000000000000000000000000000000000000000000000",
];

/// y = 2²⁵⁵ − 1 ≡ 18 (mod p): a non-canonical encoding of a point that is
/// neither small-order nor torsion-free.
const NONCANONICAL_LARGE: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn msg(side: u8, point: [u8; 32]) -> PakeMessage {
    let mut b = [0u8; PAKE_MESSAGE_LEN];
    b[0] = side;
    b[1..].copy_from_slice(&point);
    PakeMessage::from_bytes(&b).unwrap()
}

fn ctx() -> PakeContext {
    PakeContext {
        host_device_id: DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public()),
        nonce: [9; 16],
    }
}

fn otp(s: &str) -> Otp {
    Otp::parse(s).unwrap()
}

#[test]
fn the_vectors_really_are_what_they_claim() {
    // Cross-check the hard-coded table against curve25519-dalek (a second,
    // independent implementation): decodes, small order, canonical flag.
    for (order, canonical, h) in SMALL_ORDER {
        let p = CompressedEdwardsY(hex32(h)).decompress().expect(h);
        assert!(p.is_small_order(), "{h}");
        assert_eq!(p.compress().to_bytes() == hex32(h), canonical, "{h}");
        let mut q = p;
        for _ in 1..order {
            q += p;
        }
        assert!(
            q == curve25519_dalek::EdwardsPoint::default(),
            "order of {h}"
        );
    }
    for h in OFF_CURVE {
        assert!(CompressedEdwardsY(hex32(h)).decompress().is_none(), "{h}");
    }
    let p = CompressedEdwardsY(hex32(NONCANONICAL_LARGE))
        .decompress()
        .unwrap();
    assert!(!p.is_small_order() && !p.is_torsion_free());
}

#[test]
fn every_small_order_encoding_is_rejected_by_the_validator() {
    for role in [PakeRole::Viewer, PakeRole::Host] {
        for (_, canonical, h) in SMALL_ORDER {
            let m = msg(role.peer_side(), hex32(h));
            let want = if canonical {
                PakeError::SmallOrder
            } else {
                PakeError::NonCanonical
            };
            assert_eq!(validate_peer_message(&m, role), Err(want), "{role:?} {h}");
        }
    }
}

#[test]
fn every_small_order_encoding_is_rejected_by_finish_too() {
    // Not only the validator: finish() must call it before the crate runs.
    for (_, canonical, h) in SMALL_ORDER {
        let (host, _) = Spake2Ed25519::start(PakeRole::Host, &otp("111111"), &ctx(), &mut OsRng);
        let want = if canonical {
            PakeError::SmallOrder
        } else {
            PakeError::NonCanonical
        };
        assert_eq!(
            host.finish(&msg(SIDE_VIEWER, hex32(h))).err(),
            Some(want),
            "{h}"
        );
    }
}

#[test]
fn valid_point_plus_each_torsion_component_is_rejected() {
    // An honest element with a small-order point added: on the curve, not
    // small order, but outside the prime-order subgroup.
    let (_, honest) = Spake2Ed25519::start(PakeRole::Viewer, &otp("111111"), &ctx(), &mut OsRng);
    let x = CompressedEdwardsY(honest.as_bytes()[1..].try_into().unwrap())
        .decompress()
        .unwrap();
    assert!(
        x.is_torsion_free(),
        "honest element must be in the prime-order subgroup"
    );
    for (order, canonical, h) in SMALL_ORDER {
        if order == 1 || !canonical {
            continue;
        }
        let t = CompressedEdwardsY(hex32(h)).decompress().unwrap();
        let bad = (x + t).compress().to_bytes();
        let m = msg(SIDE_VIEWER, bad);
        assert_eq!(
            validate_peer_message(&m, PakeRole::Host),
            Err(PakeError::NotTorsionFree),
            "X + {h}"
        );
        let (host, _) = Spake2Ed25519::start(PakeRole::Host, &otp("111111"), &ctx(), &mut OsRng);
        assert_eq!(
            host.finish(&m).err(),
            Some(PakeError::NotTorsionFree),
            "X + {h}"
        );
    }
}

#[test]
fn off_curve_non_canonical_and_wrong_side_rejected() {
    for h in OFF_CURVE {
        let m = msg(SIDE_VIEWER, hex32(h));
        assert_eq!(
            validate_peer_message(&m, PakeRole::Host),
            Err(PakeError::NotOnCurve)
        );
    }
    let m = msg(SIDE_VIEWER, hex32(NONCANONICAL_LARGE));
    assert_eq!(
        validate_peer_message(&m, PakeRole::Host),
        Err(PakeError::NonCanonical)
    );

    // Wrong side byte on an otherwise valid element — including a reflected
    // own message (host receives 'B').
    let (_, honest) = Spake2Ed25519::start(PakeRole::Viewer, &otp("111111"), &ctx(), &mut OsRng);
    let point: [u8; 32] = honest.as_bytes()[1..].try_into().unwrap();
    for side in [SIDE_HOST, 0x00, 0x53, 0xFF, SIDE_VIEWER ^ 0x80] {
        assert_eq!(
            validate_peer_message(&msg(side, point), PakeRole::Host),
            Err(PakeError::WrongSide),
            "side {side:#x}"
        );
    }
    assert_eq!(validate_peer_message(&honest, PakeRole::Host), Ok(()));
    assert_eq!(
        validate_peer_message(&honest, PakeRole::Viewer),
        Err(PakeError::WrongSide)
    );
}

#[test]
fn wrong_length_rejected_at_the_type_boundary() {
    for len in [0, 1, 32, 34, 65, 4096] {
        assert_eq!(
            PakeMessage::from_bytes(&vec![SIDE_VIEWER; len]),
            Err(PakeError::WrongLength { len })
        );
    }
}

#[test]
fn reflected_message_fails_finish() {
    let (viewer, own) = Spake2Ed25519::start(PakeRole::Viewer, &otp("111111"), &ctx(), &mut OsRng);
    assert_eq!(viewer.finish(&own).err(), Some(PakeError::WrongSide));
}

#[test]
fn same_password_gives_the_same_key_wrong_password_a_different_one() {
    let c = ctx();
    let (a, ma) = Spake2Ed25519::start(PakeRole::Viewer, &otp("482913"), &c, &mut OsRng);
    let (b, mb) = Spake2Ed25519::start(PakeRole::Host, &otp("482913"), &c, &mut OsRng);
    assert!(a.finish(&mb).unwrap().ct_eq(&b.finish(&ma).unwrap()));

    // A01 (PAKE part): wrong password ⇒ unrelated keys, no error yet (the
    // mismatch surfaces at Noise msg1, see handshake tests).
    let (a, ma) = Spake2Ed25519::start(PakeRole::Viewer, &otp("482914"), &c, &mut OsRng);
    let (b, mb) = Spake2Ed25519::start(PakeRole::Host, &otp("482913"), &c, &mut OsRng);
    assert!(!a.finish(&mb).unwrap().ct_eq(&b.finish(&ma).unwrap()));
}

#[test]
fn context_is_bound_into_the_key() {
    // Different nonce or host device ID ⇒ different key even with the
    // right password (id_b = "remora/1/host:" ‖ device_id ‖ nonce).
    let c = ctx();
    let mut other_nonce = c;
    other_nonce.nonce[15] ^= 1;
    let other_host = PakeContext {
        host_device_id: DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public()),
        nonce: c.nonce,
    };
    for c2 in [other_nonce, other_host] {
        let (a, ma) = Spake2Ed25519::start(PakeRole::Viewer, &otp("482913"), &c, &mut OsRng);
        let (b, mb) = Spake2Ed25519::start(PakeRole::Host, &otp("482913"), &c2, &mut OsRng);
        assert!(!a.finish(&mb).unwrap().ct_eq(&b.finish(&ma).unwrap()));
    }
}

#[test]
fn messages_carry_the_right_side_byte_and_a_valid_element() {
    let (_, ma) = Spake2Ed25519::start(PakeRole::Viewer, &otp("000000"), &ctx(), &mut OsRng);
    let (_, mb) = Spake2Ed25519::start(PakeRole::Host, &otp("000000"), &ctx(), &mut OsRng);
    assert_eq!(ma.as_bytes()[0], SIDE_VIEWER);
    assert_eq!(mb.as_bytes()[0], SIDE_HOST);
    assert_eq!(validate_peer_message(&ma, PakeRole::Host), Ok(()));
    assert_eq!(validate_peer_message(&mb, PakeRole::Viewer), Ok(()));
}
