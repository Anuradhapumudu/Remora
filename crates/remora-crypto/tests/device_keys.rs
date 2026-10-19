//! Device key encoding (stored by the apps in an owner-only file; the OS
//! keychain replaces it before v0.1). Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use rand_core::OsRng;
use remora_crypto::identity::{DEVICE_KEYS_LEN, DEVICE_KEYS_MAGIC, DeviceKeys, DeviceKeysError};
use remora_testkit::canary::{Canary, find_leaks};

#[test]
fn encode_decode_roundtrip_keeps_both_keys() {
    let k = DeviceKeys::generate(&mut OsRng);
    let bytes = k.encode();
    assert_eq!(bytes.len(), DEVICE_KEYS_LEN);
    assert_eq!(&bytes[..8], DEVICE_KEYS_MAGIC);
    let back = DeviceKeys::decode(&bytes).unwrap();
    assert_eq!(back.identity.public(), k.identity.public());
    assert_eq!(back.noise.public(), k.noise.public());
    // And the reloaded keys still work: a cert made with them verifies.
    assert_eq!(back.cert("dev", 1).unwrap().verify(), Ok(()));
}

#[test]
fn layout_is_magic_then_the_two_secrets() {
    let k = DeviceKeys::generate(&mut OsRng);
    let b = k.encode();
    let rebuilt =
        remora_crypto::noise::NoiseStaticKeypair::from_secret(b[40..72].try_into().unwrap());
    assert_eq!(rebuilt.public(), k.noise.public());
    assert_eq!(DEVICE_KEYS_LEN, 72);
}

#[test]
fn decode_rejects_wrong_length_and_magic() {
    let k = DeviceKeys::generate(&mut OsRng);
    let good = k.encode();
    for len in [0, 8, 71, 73, 4096] {
        let mut v = good.to_vec();
        v.resize(len, 0);
        assert_eq!(
            DeviceKeys::decode(&v).err(),
            Some(DeviceKeysError::WrongLength),
            "{len}"
        );
    }
    let mut bad = good.to_vec();
    bad[0] ^= 1;
    assert_eq!(
        DeviceKeys::decode(&bad).err(),
        Some(DeviceKeysError::BadMagic)
    );
}

#[test]
fn two_generations_differ() {
    let a = DeviceKeys::generate(&mut OsRng);
    let b = DeviceKeys::generate(&mut OsRng);
    assert_ne!(a.identity.public(), b.identity.public());
    assert_ne!(a.noise.public(), b.noise.public());
}

#[test]
fn debug_never_shows_the_secrets() {
    let k = DeviceKeys::generate(&mut OsRng);
    let shown = format!("{k:?} {k:#?}");
    assert_eq!(format!("{k:?}"), "[redacted]");
    let enc = k.encode();
    let canaries = [
        Canary::new("identity secret", enc[8..40].to_vec()),
        Canary::new("noise secret", enc[40..72].to_vec()),
    ];
    assert!(find_leaks(&shown, &canaries).is_empty());
    fn zod<T: zeroize::ZeroizeOnDrop>() {}
    zod::<DeviceKeys>();
}
