//! phase3-criteria A28 / threat model INV8 (crypto part): secret types never
//! show their bytes in `Debug`, and they wipe themselves on drop. The
//! whole-suite canary scan over logs runs at the end of Phase 3. Written
//! before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use rand_core::OsRng;
use remora_crypto::identity::IdentityKeypair;
use remora_crypto::noise::NoiseStaticKeypair;
use remora_crypto::otp::generate_otp;
use remora_crypto::password::validate_unattended_password;
use remora_crypto::secret::{Exporter, MediaKey, Otp, PakeKey, Psk, UnattendedPassword};
use remora_testkit::canary::{Canary, find_leaks};
use zeroize::ZeroizeOnDrop;

/// Compile-time: every secret type is `ZeroizeOnDrop`. Removing the derive
/// from any of them stops this test from compiling.
#[test]
fn secret_types_are_zeroize_on_drop() {
    fn assert_zod<T: ZeroizeOnDrop>() {}
    assert_zod::<Otp>();
    assert_zod::<PakeKey>();
    assert_zod::<Psk>();
    assert_zod::<Exporter>();
    assert_zod::<MediaKey>();
    assert_zod::<UnattendedPassword>();
    assert_zod::<IdentityKeypair>();
    assert_zod::<NoiseStaticKeypair>();
}

#[test]
fn debug_output_never_contains_the_secret() {
    let otp = Otp::parse("907315").unwrap();
    let media = MediaKey::from_bytes([0xA7; 32]);
    let exporter = Exporter::from_bytes([0x3C; 32]);
    let pw = validate_unattended_password("Canary-Unattended-Pw-77").unwrap();
    let canaries = [
        Canary::new("otp", "907315"),
        Canary::new("media", vec![0xA7; 32]),
        Canary::new("exporter", vec![0x3C; 32]),
        Canary::new("unattended", "Canary-Unattended-Pw-77"),
    ];
    let text = format!(
        "{otp:?} {otp:#?} {media:?} {exporter:?} {pw:?} {:?} {:?}",
        IdentityKeypair::generate(&mut OsRng),
        NoiseStaticKeypair::generate(&mut OsRng),
    );
    assert!(find_leaks(&text, &canaries).is_empty(), "{text}");
    assert!(text.contains("[redacted]"));
}

#[test]
fn generated_otp_debug_is_redacted() {
    let otp = generate_otp(&mut OsRng);
    let shown = format!("{otp:?}");
    assert_eq!(shown, "[redacted]");
    assert!(!shown.contains(otp.reveal()));
}

#[test]
fn every_secret_holding_type_prints_exactly_redacted() {
    // Per type, not as one combined string: a single empty Debug impl must
    // not hide behind the others (mutation-gate finding).
    use remora_crypto::pake::{Pake, PakeContext, PakeRole, Spake2Ed25519};
    let ctx = PakeContext {
        host_device_id: remora_crypto::identity::DeviceId::from_bytes([0; 10]),
        nonce: [0; 16],
    };
    let (pake, _) = Spake2Ed25519::start(
        PakeRole::Viewer,
        &Otp::parse("907315").unwrap(),
        &ctx,
        &mut OsRng,
    );
    for shown in [
        format!("{:?}", Otp::parse("907315").unwrap()),
        format!("{:?}", MediaKey::from_bytes([0xA7; 32])),
        format!("{:?}", Exporter::from_bytes([0x3C; 32])),
        format!("{:?}", IdentityKeypair::generate(&mut OsRng)),
        format!("{:?}", NoiseStaticKeypair::generate(&mut OsRng)),
        format!("{pake:?}"),
    ] {
        assert_eq!(shown, "[redacted]");
    }
}

#[test]
fn media_sender_and_receiver_debug_show_state_but_never_the_key() {
    use remora_crypto::media::{MediaReceiver, MediaSender};
    let key = [0xA7u8; 32];
    let s = MediaSender::new(9, MediaKey::from_bytes(key));
    let mut r = MediaReceiver::new();
    r.add_key(9, MediaKey::from_bytes(key)).unwrap();
    let canaries = [Canary::new("media key", key.to_vec())];
    let sd = format!("{s:?}");
    let rd = format!("{r:?}");
    assert!(
        sd.contains("key_id: 9") && sd.contains("next_counter: 0"),
        "{sd}"
    );
    assert!(
        rd.contains("live_keys: 1") && rd.contains("dropped: 0"),
        "{rd}"
    );
    assert!(find_leaks(&format!("{sd} {rd} {s:#?} {r:#?}"), &canaries).is_empty());
}
