//! Arbitrary bytes into the PAKE element validator (A32) and SPAKE2 finish:
//! no panic, and anything finish() accepts passed the validator.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_crypto::identity::{DeviceId, IdentityPublic};
use remora_crypto::pake::{
    Pake, PakeContext, PakeMessage, PakeRole, Spake2Ed25519, validate_peer_message,
};
use remora_crypto::secret::Otp;

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = PakeMessage::from_bytes(data) else {
        return;
    };
    let valid = validate_peer_message(&msg, PakeRole::Host).is_ok();
    let ctx = PakeContext {
        host_device_id: DeviceId::of(&IdentityPublic::from_bytes([0; 32])),
        nonce: [0; 16],
    };
    let Ok(otp) = Otp::parse("123456") else {
        return;
    };
    let (host, _) = Spake2Ed25519::start(PakeRole::Host, &otp, &ctx, &mut rand_core::OsRng);
    assert_eq!(host.finish(&msg).is_ok(), valid);
});
