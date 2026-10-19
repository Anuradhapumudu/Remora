//! phase3-criteria A15 (cert binding and `verify_strict`), device ID and the
//! cert parser's limits (A26). Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use blake2::{Blake2s256, Digest};
use rand_core::OsRng;
use remora_crypto::identity::{
    CERT_FIXED_LEN, CERT_MAX_LEN, CertError, DEVICE_ID_CONTEXT, DeviceId, IdentityCert,
    IdentityKeypair, IdentityPublic, NoiseStaticPublic,
};
use remora_testkit::{CountingAlloc, count_allocations};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn noise_key(b: u8) -> NoiseStaticPublic {
    NoiseStaticPublic::from_bytes([b; 32])
}

#[test]
fn sign_encode_decode_verify_roundtrip() {
    let id = IdentityKeypair::generate(&mut OsRng);
    let cert = id
        .sign_cert(&noise_key(3), "Pumudu's MacBook", 1_760_000_000)
        .unwrap();
    assert_eq!(cert.identity(), &id.public());
    assert_eq!(cert.noise_static(), &noise_key(3));
    assert_eq!(cert.device_name(), "Pumudu's MacBook");
    assert_eq!(cert.created_unix(), 1_760_000_000);
    assert_eq!(cert.verify(), Ok(()));
    let bytes = cert.encode();
    assert_eq!(bytes.len(), CERT_FIXED_LEN + "Pumudu's MacBook".len());
    let back = IdentityCert::decode(&bytes).unwrap();
    assert_eq!(back, cert);
    assert_eq!(back.verify(), Ok(()));
}

#[test]
fn encoding_layout_is_exactly_as_documented() {
    let id = IdentityKeypair::generate(&mut OsRng);
    let cert = id
        .sign_cert(&noise_key(0xAB), "dev", 0x0102_0304_0506_0708)
        .unwrap();
    let b = cert.encode();
    assert_eq!(&b[0..32], id.public().as_bytes());
    assert_eq!(&b[32..64], &[0xAB; 32]);
    assert_eq!(&b[64..72], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(b[72], 3);
    assert_eq!(&b[73..76], b"dev");
    assert_eq!(b.len(), 76 + 64);
}

#[test]
fn signature_covers_noise_key_name_and_time() {
    // The signed message is CERT_CONTEXT ‖ noise ‖ len ‖ name ‖ created_be.
    // Rebuild it independently and check with ed25519-dalek directly.
    use ed25519_dalek::{Signature, VerifyingKey};
    let id = IdentityKeypair::generate(&mut OsRng);
    let cert = id.sign_cert(&noise_key(5), "box", 77).unwrap();
    let b = cert.encode();
    let mut m = b"remora/1/cert".to_vec();
    m.extend_from_slice(&[5; 32]);
    m.push(3);
    m.extend_from_slice(b"box");
    m.extend_from_slice(&77u64.to_be_bytes());
    let vk = VerifyingKey::from_bytes(id.public().as_bytes()).unwrap();
    let sig = Signature::from_bytes(b[b.len() - 64..].try_into().unwrap());
    assert!(vk.verify_strict(&m, &sig).is_ok());
}

#[test]
fn every_single_bit_flip_of_a_cert_is_rejected() {
    // A09-style exhaustive tamper over the cert itself.
    let id = IdentityKeypair::generate(&mut OsRng);
    let good = id
        .sign_cert(&noise_key(9), "host-pc", 1_760_000_000)
        .unwrap()
        .encode();
    for byte in 0..good.len() {
        for bit in 0..8 {
            let mut b = good.clone();
            b[byte] ^= 1 << bit;
            let outcome = IdentityCert::decode(&b).and_then(|c| c.verify());
            assert!(outcome.is_err(), "flip byte {byte} bit {bit} accepted");
        }
    }
}

#[test]
fn a15_swapped_key_cert_still_verifies_but_names_the_wrong_noise_key() {
    // A cert signed by A for Noise key B is a VALID signature; the binding
    // check against the authenticated Noise key lives in the handshake
    // (tests/handshake.rs: CertKeyMismatch). Here: the cert says B, not A.
    let a = IdentityKeypair::generate(&mut OsRng);
    let cert = a.sign_cert(&noise_key(0xBB), "x", 1).unwrap();
    assert_eq!(cert.verify(), Ok(()));
    assert_eq!(cert.noise_static(), &noise_key(0xBB));
}

#[test]
fn cert_from_one_key_with_another_keys_identity_is_rejected() {
    let a = IdentityKeypair::generate(&mut OsRng);
    let b = IdentityKeypair::generate(&mut OsRng);
    let mut bytes = a.sign_cert(&noise_key(1), "x", 1).unwrap().encode();
    bytes[0..32].copy_from_slice(b.public().as_bytes());
    let cert = IdentityCert::decode(&bytes).unwrap();
    assert_eq!(cert.verify(), Err(CertError::SignatureInvalid));
}

#[test]
fn small_order_identity_key_forgery_is_rejected() {
    // Classic Ed25519 forgery: public key A = identity point, R = identity,
    // s = 0. Plain `verify` checks [s]B == R + [k]A, i.e. 0 == 0 + 0 — true
    // for EVERY message. `verify_strict` rejects small-order A and R.
    let identity_point = {
        let mut p = [0u8; 32];
        p[0] = 1;
        p
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&identity_point); // identity_pub
    bytes.extend_from_slice(&[7; 32]); // noise key
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.push(1);
    bytes.push(b'x');
    bytes.extend_from_slice(&identity_point); // R
    bytes.extend_from_slice(&[0; 32]); // s
    let outcome = IdentityCert::decode(&bytes).and_then(|c| c.verify());
    assert!(
        matches!(
            outcome,
            Err(CertError::SignatureInvalid | CertError::BadIdentityKey)
        ),
        "{outcome:?}"
    );
}

#[test]
fn malleated_signature_is_rejected() {
    // s' = s + ℓ is the same signature to a lax verifier; verify_strict
    // requires canonical s.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let id = IdentityKeypair::generate(&mut OsRng);
    let mut bytes = id.sign_cert(&noise_key(1), "x", 1).unwrap().encode();
    let n = bytes.len();
    let mut carry = 0u16;
    for i in 0..32 {
        let t = u16::from(bytes[n - 32 + i]) + u16::from(L[i]) + carry;
        bytes[n - 32 + i] = t as u8;
        carry = t >> 8;
    }
    let cert = IdentityCert::decode(&bytes).unwrap();
    assert_eq!(cert.verify(), Err(CertError::SignatureInvalid));
}

#[test]
fn name_limits() {
    let id = IdentityKeypair::generate(&mut OsRng);
    assert!(id.sign_cert(&noise_key(1), &"n".repeat(64), 1).is_ok());
    assert_eq!(
        id.sign_cert(&noise_key(1), &"n".repeat(65), 1).unwrap_err(),
        CertError::NameTooLong
    );
    // 64 bytes, not 64 characters: 22 × "é" (2 bytes) = 44 ok; 33 × = 66 not.
    assert!(id.sign_cert(&noise_key(1), &"é".repeat(32), 1).is_ok());
    assert_eq!(
        id.sign_cert(&noise_key(1), &"é".repeat(33), 1).unwrap_err(),
        CertError::NameTooLong
    );
    assert!(id.sign_cert(&noise_key(1), "", 1).is_ok());
}

#[test]
fn decode_rejects_bad_lengths_and_names() {
    let id = IdentityKeypair::generate(&mut OsRng);
    let good = id.sign_cert(&noise_key(1), "abc", 1).unwrap().encode();
    for cut in [0, 1, 31, 72, 73, 75, good.len() - 1] {
        assert_eq!(
            IdentityCert::decode(&good[..cut]).unwrap_err(),
            CertError::Truncated,
            "{cut}"
        );
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        IdentityCert::decode(&trailing).unwrap_err(),
        CertError::TooLong
    );

    let mut long_name = good.clone();
    long_name[72] = 65;
    assert_eq!(
        IdentityCert::decode(&long_name).unwrap_err(),
        CertError::NameTooLong
    );

    let mut not_utf8 = good.clone();
    not_utf8[73] = 0xFF;
    assert_eq!(
        IdentityCert::decode(&not_utf8).unwrap_err(),
        CertError::NameNotUtf8
    );

    assert_eq!(
        IdentityCert::decode(&vec![0; CERT_MAX_LEN + 1]).unwrap_err(),
        CertError::TooLong
    );
}

#[test]
fn decode_of_huge_input_allocates_nothing_proportional() {
    let huge = vec![0u8; 1 << 20];
    let (r, stats) = count_allocations(|| IdentityCert::decode(&huge).map(|_| ()));
    assert_eq!(r, Err(CertError::TooLong));
    assert!(stats.peak_bytes <= 256, "{stats:?}");
}

#[test]
fn device_id_is_the_first_80_bits_of_the_domain_separated_hash() {
    let id = IdentityKeypair::generate(&mut OsRng);
    let mut h = Blake2s256::new();
    h.update(DEVICE_ID_CONTEXT);
    h.update(id.public().as_bytes());
    let full = h.finalize();
    assert_eq!(DeviceId::of(&id.public()).as_bytes(), &full[..10]);
    assert_eq!(DEVICE_ID_CONTEXT, b"remora/1/device-id");
    // Different keys, different IDs (2⁻⁸⁰ collision chance).
    let other = IdentityKeypair::generate(&mut OsRng);
    assert_ne!(DeviceId::of(&id.public()), DeviceId::of(&other.public()));
    assert_ne!(
        DeviceId::of(&IdentityPublic::from_bytes([0; 32])),
        DeviceId::of(&IdentityPublic::from_bytes([1; 32]))
    );
}

#[test]
fn layout_constants_are_exact() {
    // Mutation-gate finding: the constants were only compared with
    // themselves. Pin them to the documented layout (protocol.md §3.2).
    assert_eq!(CERT_FIXED_LEN, 137);
    assert_eq!(CERT_MAX_LEN, 201);
    let id = IdentityKeypair::generate(&mut OsRng);
    let max = id
        .sign_cert(&noise_key(1), &"n".repeat(64), 1)
        .unwrap()
        .encode();
    assert_eq!(max.len(), 201);
    assert!(IdentityCert::decode(&max).is_ok());
    let mut over = max.clone();
    over.push(0);
    assert_eq!(IdentityCert::decode(&over).unwrap_err(), CertError::TooLong);
}
