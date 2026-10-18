//! phase3-criteria A28 / threat model INV8 (crypto part): secret types never
//! show their bytes in `Debug`, and they wipe themselves on drop. The
//! whole-suite canary scan over logs runs at the end of Phase 3. Written
//! before the implementation.

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
