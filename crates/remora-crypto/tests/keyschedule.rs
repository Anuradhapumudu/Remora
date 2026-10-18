//! Key schedule (protocol.md §3.1), checked against an independent
//! computation with the hash/HKDF crates directly. Written before the
//! implementation.

use blake2::{Blake2s256, Digest};
use rand_core::OsRng;
use remora_crypto::identity::{DeviceId, IdentityKeypair};
use remora_crypto::keyschedule::{
    EXPORTER_LABEL, PROLOGUE_PREFIX, PSK_INFO, derive_psk, prologue, transcript_hash,
};
use remora_crypto::pake::{Pake, PakeContext, PakeRole, Spake2Ed25519};
use remora_crypto::secret::{Exporter, Otp};

fn hellos(vh: &[u8], hh: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(vh.len() as u32).to_be_bytes());
    v.extend_from_slice(vh);
    v.extend_from_slice(&(hh.len() as u32).to_be_bytes());
    v.extend_from_slice(hh);
    v
}

#[test]
fn labels() {
    assert_eq!(EXPORTER_LABEL, b"EXPORTER-remora/1");
    assert_eq!(PSK_INFO, b"remora/1/noise-psk");
    assert_eq!(PROLOGUE_PREFIX, b"remora/1");
}

#[test]
fn prologue_is_prefix_exporter_and_hash_of_length_prefixed_hellos() {
    let p = prologue(&Exporter::from_bytes([0xEE; 32]), b"VH", b"HHH");
    let mut want = b"remora/1".to_vec();
    want.extend_from_slice(&[0xEE; 32]);
    want.extend_from_slice(&Blake2s256::digest(hellos(b"VH", b"HHH")));
    assert_eq!(p.as_bytes(), want.as_slice());
}

#[test]
fn hello_boundary_shift_changes_prologue_and_transcript() {
    let e = Exporter::from_bytes([1; 32]);
    assert_ne!(prologue(&e, b"ab", b"c"), prologue(&e, b"a", b"bc"));
    let c = ctx();
    let (_, a) = Spake2Ed25519::start(
        PakeRole::Viewer,
        &Otp::parse("123456").unwrap(),
        &c,
        &mut OsRng,
    );
    let (_, b) = Spake2Ed25519::start(
        PakeRole::Host,
        &Otp::parse("123456").unwrap(),
        &c,
        &mut OsRng,
    );
    assert_ne!(
        transcript_hash(b"ab", b"c", &a, &b),
        transcript_hash(b"a", b"bc", &a, &b)
    );
    assert_ne!(
        transcript_hash(b"ab", b"c", &a, &b),
        transcript_hash(b"ab", b"c", &b, &a)
    );
}

fn ctx() -> PakeContext {
    PakeContext {
        host_device_id: DeviceId::of(&IdentityKeypair::generate(&mut OsRng).public()),
        nonce: [0; 16],
    }
}

#[test]
fn transcript_and_psk_match_an_independent_computation() {
    let c = ctx();
    let otp = Otp::parse("654321").unwrap();
    let (va, ma) = Spake2Ed25519::start(PakeRole::Viewer, &otp, &c, &mut OsRng);
    let (hb, mb) = Spake2Ed25519::start(PakeRole::Host, &otp, &c, &mut OsRng);
    let t = transcript_hash(b"vh", b"hh", &ma, &mb);
    let mut d = Blake2s256::new();
    d.update(hellos(b"vh", b"hh"));
    d.update(ma.as_bytes());
    d.update(mb.as_bytes());
    let want_t: [u8; 32] = d.finalize().into();
    assert_eq!(t, want_t);

    let e = Exporter::from_bytes([0x42; 32]);
    let kv = va.finish(&mb).unwrap();
    let kh = hb.finish(&ma).unwrap();
    let psk_v = derive_psk(&e, &kv, &t);
    let psk_h = derive_psk(&e, &kh, &t);
    assert!(psk_v.ct_eq(&psk_h));

    // K is not exposed outside the crate; the exact HKDF formula is checked
    // by the unit test in src/keyschedule.rs. Here: the exporter and the
    // transcript both change the PSK.
    let psk_other_e = derive_psk(&Exporter::from_bytes([0x43; 32]), &kv, &t);
    let mut t2 = t;
    t2[0] ^= 1;
    let psk_other_t = derive_psk(&e, &kv, &t2);
    assert!(!psk_v.ct_eq(&psk_other_e));
    assert!(!psk_v.ct_eq(&psk_other_t));
}
