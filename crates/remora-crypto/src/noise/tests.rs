//! Crate-internal handshake tests that need a raw `snow` peer (only this
//! module may name `snow`, A35): A17-S1 (structural) and A17-S2.

use rand_core::OsRng;

use super::*;
use crate::identity::{IdentityCert, IdentityKeypair};
use crate::keyschedule::prologue;
use crate::sas::commitment;
use crate::secret::{Exporter, Psk};

struct Fixture {
    psk: Psk,
    pro: crate::keyschedule::Prologue,
    viewer: NoiseStaticKeypair,
    host: NoiseStaticKeypair,
    host_cert: IdentityCert,
}

fn fixture() -> Fixture {
    let host = NoiseStaticKeypair::generate(&mut OsRng);
    let host_cert = IdentityKeypair::generate(&mut OsRng)
        .sign_cert(host.public(), "host", 1)
        .unwrap();
    Fixture {
        psk: Psk([5; 32]),
        pro: prologue(&Exporter([1; 32]), b"vh", b"hh"),
        viewer: NoiseStaticKeypair::generate(&mut OsRng),
        host,
        host_cert,
    }
}

fn raw(f: &Fixture, initiator: bool) -> snow::HandshakeState {
    let b = snow::Builder::new(PATTERN_PASSWORD.parse().unwrap())
        .prologue(f.pro.as_bytes())
        .unwrap()
        .psk(0, &f.psk.0)
        .unwrap();
    if initiator {
        b.local_private_key(&f.viewer.secret)
            .unwrap()
            .build_initiator()
            .unwrap()
    } else {
        b.local_private_key(&f.host.secret)
            .unwrap()
            .build_responder()
            .unwrap()
    }
}

#[test]
fn a17_s2_msg2_without_a_well_formed_commitment_is_rejected() {
    let f = fixture();
    let cert = f.host_cert.encode();
    let with = |extra: &[u8]| [cert.as_slice(), extra].concat();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("cert only, no C_r", cert.clone()),
        ("C_r one byte short", with(&[0; 31])),
        ("C_r one byte long", with(&[0; 33])),
        ("shorter than the cert's fixed part", cert[..72].to_vec()),
        ("only 32 bytes", vec![0; 32]),
    ];
    for (what, payload) in cases {
        let (viewer, m1) =
            viewer_start(HandshakeMode::Password(&f.psk), &f.pro, &f.viewer).unwrap();
        let mut evil = raw(&f, false);
        let mut buf = vec![0u8; 65_535];
        evil.read_message(&m1, &mut buf).unwrap();
        let n = evil.write_message(&payload, &mut buf).unwrap();
        // read_msg2 fails, so no ViewerGotMsg2 exists and write_msg3 — the
        // only place n_i is drawn — cannot be called.
        assert_eq!(
            viewer.read_msg2(&buf[..n], &PeerPolicy::AnyKey).err(),
            Some(HandshakeError::MalformedPayload),
            "{what}"
        );
    }
}

#[test]
fn a17_s1_msg2_commits_to_the_n_r_drawn_at_msg1() {
    let f = fixture();
    let mut viewer = raw(&f, true);
    let mut buf = vec![0u8; 65_535];
    let n = viewer.write_message(&[], &mut buf).unwrap();
    let host = host_start(HandshakeMode::Password(&f.psk), &f.pro, &f.host).unwrap();
    let host = host.read_msg1(&buf[..n], &mut OsRng).unwrap();
    let n_r = host.n_r;
    let (host, m2) = host.write_msg2(&f.host_cert).unwrap();
    assert_eq!(host.n_r, n_r, "n_r unchanged by writing msg2");
    let mut payload = vec![0u8; 65_535];
    let p = viewer.read_message(&m2, &mut payload).unwrap();
    let payload = &payload[..p];
    assert_eq!(
        &payload[..payload.len() - 32],
        f.host_cert.encode().as_slice()
    );
    assert_eq!(&payload[payload.len() - 32..], &commitment(&n_r));
}

#[test]
fn a17_s1_reveal_hands_out_the_committed_n_r() {
    let f = fixture();
    let viewer_id = IdentityKeypair::generate(&mut OsRng);
    let viewer_cert = viewer_id.sign_cert(f.viewer.public(), "viewer", 1).unwrap();
    let (v, m1) = viewer_start(HandshakeMode::Password(&f.psk), &f.pro, &f.viewer).unwrap();
    let h = host_start(HandshakeMode::Password(&f.psk), &f.pro, &f.host).unwrap();
    let h = h.read_msg1(&m1, &mut OsRng).unwrap();
    let committed = h.n_r;
    let (h, m2) = h.write_msg2(&f.host_cert).unwrap();
    let v = v.read_msg2(&m2, &PeerPolicy::AnyKey).unwrap();
    assert_eq!(v.c_r, commitment(&committed));
    let (_, m3) = v.write_msg3(&viewer_cert, &mut OsRng).unwrap();
    let h = h.read_msg3(&m3, &PeerPolicy::AnyKey).unwrap();
    let (_, revealed) = h.reveal();
    assert_eq!(revealed, committed);
}

#[test]
fn established_sas_is_the_documented_formula() {
    let f = fixture();
    let viewer_id = IdentityKeypair::generate(&mut OsRng);
    let viewer_cert = viewer_id.sign_cert(f.viewer.public(), "viewer", 1).unwrap();
    let (v, m1) = viewer_start(HandshakeMode::Password(&f.psk), &f.pro, &f.viewer).unwrap();
    let h = host_start(HandshakeMode::Password(&f.psk), &f.pro, &f.host).unwrap();
    let h = h.read_msg1(&m1, &mut OsRng).unwrap();
    let (h, m2) = h.write_msg2(&f.host_cert).unwrap();
    let v = v.read_msg2(&m2, &PeerPolicy::AnyKey).unwrap();
    let (v, m3) = v.write_msg3(&viewer_cert, &mut OsRng).unwrap();
    let h = h.read_msg3(&m3, &PeerPolicy::AnyKey).unwrap();
    assert_eq!(h.h, v.h, "both sides have the same handshake hash");
    assert_eq!(h.n_i, v.n_i);
    let want = crate::sas::sas(&h.h, &h.n_i, &h.n_r);
    let (est, _) = h.reveal();
    assert_eq!(est.sas(), want);
}
