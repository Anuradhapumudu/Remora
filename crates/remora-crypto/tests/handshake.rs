//! Handshake attack tests at the crypto layer (phase3-criteria A01, A05,
//! A08, A09, A10, A14, A15, A16, A17-S1/S2/S5, A19, A25-T). The network layer
//! re-runs the relevant ones over QUIC with close codes and timing
//! (remora-net). A17-S2's malformed-msg2 case needs a raw `snow` responder
//! and lives in the crate's unit tests (src/noise/tests.rs). Written before
//! the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use rand_core::OsRng;
use remora_crypto::identity::{CertError, DeviceId, IdentityCert};
use remora_crypto::keyschedule::{Prologue, prologue};
use remora_crypto::noise::{
    HandshakeError, HandshakeMode, PeerPolicy, TransportError, host_start, viewer_start,
};

fn trusted_setup<'a>(
    viewer: &'a Party,
    host: &'a Party,
    pv: &'a Prologue,
    ph: &'a Prologue,
) -> Setup<'a> {
    Setup {
        viewer: viewer.side(),
        host: host.side(),
        viewer_mode: HandshakeMode::Trusted,
        host_mode: HandshakeMode::Trusted,
        viewer_prologue: pv,
        host_prologue: ph,
        viewer_policy: PeerPolicy::Pinned(host.id.public()),
        host_policy: PeerPolicy::TrustedSet(vec![viewer.id.public()]),
    }
}

/// `cert` with one bit of its signature flipped.
fn bad_signature(cert: &IdentityCert) -> IdentityCert {
    let mut b = cert.encode();
    let n = b.len();
    b[n - 5] ^= 0x10;
    IdentityCert::decode(&b).unwrap()
}

// ------------------------------------------------------------ functional --

#[test]
fn password_mode_completes_with_the_same_sas_on_both_sides() {
    let f = password_fixture();
    let r = run(f.setup()).unwrap();
    assert_eq!(r.viewer.sas(), r.host.sas());
    assert_eq!(r.viewer.peer_cert(), &f.host.cert);
    assert_eq!(r.host.peer_cert(), &f.viewer.cert);
    assert_eq!(r.msgs.len(), 4);
}

#[test]
fn trusted_mode_completes_with_pinned_keys() {
    let (viewer, host) = (party("viewer"), party("host"));
    let (pv, ph) = prologues(&exporter(2), &exporter(2));
    let r = run(trusted_setup(&viewer, &host, &pv, &ph)).unwrap();
    assert_eq!(r.viewer.sas(), r.host.sas());
}

#[test]
fn sessions_get_different_safety_codes_almost_always() {
    let f = password_fixture();
    let codes: std::collections::HashSet<_> = (0..50)
        .map(|_| run(f.setup()).unwrap().viewer.sas())
        .collect();
    // 50 draws from 10⁶ codes: P(any repeat) ≈ 1.2e-3.
    assert!(codes.len() >= 49, "{codes:?}");
}

#[test]
fn transport_works_both_ways_after_the_reveal() {
    let f = password_fixture();
    let mut r = run(f.setup()).unwrap();
    let c = r.viewer.encrypt(b"hello host").unwrap();
    assert_eq!(r.host.decrypt(&c).unwrap(), b"hello host");
    let c = r.host.encrypt(b"hello viewer").unwrap();
    assert_eq!(r.viewer.decrypt(&c).unwrap(), b"hello viewer");
}

// ---------------------------------------------------------------- A01 ----

#[test]
fn a01_wrong_password_fails_at_msg1() {
    let (viewer, host) = (party("viewer"), party("host"));
    let (psk_v, psk_h) = psks(
        &otp("482914"),
        &otp("482913"),
        &host,
        &exporter(1),
        &exporter(1),
    );
    assert!(!psk_v.ct_eq(&psk_h));
    let (pv, ph) = prologues(&exporter(1), &exporter(1));
    let r = run(Setup {
        viewer: viewer.side(),
        host: host.side(),
        viewer_mode: HandshakeMode::Password(&psk_v),
        host_mode: HandshakeMode::Password(&psk_h),
        viewer_prologue: &pv,
        host_prologue: &ph,
        viewer_policy: PeerPolicy::AnyKey,
        host_policy: PeerPolicy::AnyKey,
    });
    // Failure at index 0: read_msg1 consumed the host state, so nothing is
    // left that could write msg2 — the host's identity is never sent.
    assert_eq!(r.err(), Some((0, HandshakeError::Msg1Auth)));
}

#[test]
fn a01_failed_msg1_draws_no_nonce() {
    // n_r is drawn only after msg1 authenticates.
    let f = password_fixture();
    let (_, wrong) = psks(
        &otp("000001"),
        &otp("000002"),
        &f.host,
        &exporter(1),
        &exporter(1),
    );
    let (_, m1) =
        viewer_start(HandshakeMode::Password(&f.psk_v), &f.pro_v, &f.viewer.noise).unwrap();
    let h = host_start(HandshakeMode::Password(&wrong), &f.pro_h, &f.host.noise).unwrap();
    let mut rng = RecordingRng::default();
    assert_eq!(
        h.read_msg1(&m1, &mut rng).err(),
        Some(HandshakeError::Msg1Auth)
    );
    assert_eq!(rng.calls.get(), 0);
}

#[test]
fn a01_msg1_carries_an_authentication_tag_even_with_an_empty_payload() {
    // Evidence for crypto-claims-audit C3: in XXpsk0, msg1 = e (32 B) + a
    // 16-byte AEAD tag over the empty payload. Without the tag a wrong PSK
    // could not be detected at msg1.
    let f = password_fixture();
    let (_, m1) =
        viewer_start(HandshakeMode::Password(&f.psk_v), &f.pro_v, &f.viewer.noise).unwrap();
    assert_eq!(m1.len(), 32 + 16);
    let (_, m1) = viewer_start(HandshakeMode::Trusted, &f.pro_v, &f.viewer.noise).unwrap();
    assert_eq!(m1.len(), 32, "XX msg1 is the bare ephemeral key");
}

// ------------------------------------------------------ A14 / A08 / A05 --

#[test]
fn a14_quic_mitm_with_the_right_password_fails_at_msg1() {
    // The MITM terminates TLS on both sides: two different exporters, which
    // enter both the PSK (HKDF salt) and the prologue.
    let (viewer, host) = (party("viewer"), party("host"));
    let (psk_v, psk_h) = psks(
        &otp("482913"),
        &otp("482913"),
        &host,
        &exporter(1),
        &exporter(2),
    );
    let (pv, ph) = prologues(&exporter(1), &exporter(2));
    let r = run(Setup {
        viewer: viewer.side(),
        host: host.side(),
        viewer_mode: HandshakeMode::Password(&psk_v),
        host_mode: HandshakeMode::Password(&psk_h),
        viewer_prologue: &pv,
        host_prologue: &ph,
        viewer_policy: PeerPolicy::AnyKey,
        host_policy: PeerPolicy::AnyKey,
    });
    assert_eq!(r.err(), Some((0, HandshakeError::Msg1Auth)));
}

#[test]
fn a14_prologue_alone_catches_an_exporter_mismatch() {
    // Same PSK, different exporter in the prologue only.
    let f = password_fixture();
    let (_, ph) = prologues(&exporter(1), &exporter(9));
    let r = run(Setup {
        host_prologue: &ph,
        ..f.setup()
    });
    assert_eq!(r.err(), Some((0, HandshakeError::Msg1Auth)));
}

#[test]
fn a14_trusted_mode_exporter_mismatch_fails_at_msg2() {
    let (viewer, host) = (party("viewer"), party("host"));
    let (pv, ph) = prologues(&exporter(1), &exporter(2));
    let r = run(trusted_setup(&viewer, &host, &pv, &ph));
    // XX msg1 has no tag; the viewer catches it decrypting msg2.
    assert_eq!(r.err(), Some((1, HandshakeError::Msg2Auth)));
}

#[test]
fn a08_tampered_hello_changes_the_prologue() {
    let f = password_fixture();
    for (vh, hh) in [
        (&b"viewer-hello-bytez"[..], common::HH),
        (common::VH, &b"host-hello-bytez"[..]),
        // boundary shift: same concatenation, different split
        (&b"viewer-hello-bytesh"[..], &b"ost-hello-bytes"[..]),
    ] {
        let ph = prologue(&exporter(1), vh, hh);
        let r = run(Setup {
            host_prologue: &ph,
            ..f.setup()
        });
        assert_eq!(
            r.err(),
            Some((0, HandshakeError::Msg1Auth)),
            "{vh:?} {hh:?}"
        );
    }
    // Trusted mode: the prologue is the only binding.
    let (viewer, host) = (party("viewer"), party("host"));
    let pv = prologue(&exporter(1), common::VH, common::HH);
    let ph = prologue(&exporter(1), b"viewer-hello-bytez", common::HH);
    let r = run(trusted_setup(&viewer, &host, &pv, &ph));
    assert_eq!(r.err(), Some((1, HandshakeError::Msg2Auth)));
}

#[test]
fn a08_mode_mismatch_fails() {
    let f = password_fixture();
    let r = run(Setup {
        host_mode: HandshakeMode::Trusted,
        host_policy: PeerPolicy::TrustedSet(vec![f.viewer.id.public()]),
        ..f.setup()
    });
    assert!(r.is_err());
    let r = run(Setup {
        viewer_mode: HandshakeMode::Trusted,
        viewer_policy: PeerPolicy::Pinned(f.host.id.public()),
        ..f.setup()
    });
    assert!(r.is_err());
}

#[test]
fn a05_recorded_msg1_replayed_on_a_new_connection_fails() {
    let f = password_fixture();
    let rec = run(f.setup()).unwrap();
    let (_, psk_h2) = psks(
        &otp("482913"),
        &otp("482913"),
        &f.host,
        &exporter(3),
        &exporter(3),
    );
    let (_, ph2) = prologues(&exporter(3), &exporter(3));
    let h = host_start(HandshakeMode::Password(&psk_h2), &ph2, &f.host.noise).unwrap();
    assert_eq!(
        h.read_msg1(&rec.msgs[0], &mut OsRng).err(),
        Some(HandshakeError::Msg1Auth)
    );
}

// ---------------------------------------------------------------- A09 ----

#[test]
fn a09_every_bit_flip_of_every_handshake_message_fails() {
    let f = password_fixture();
    let honest = run(f.setup()).unwrap();
    let mut variants = 0usize;
    for (i, m) in honest.msgs.iter().enumerate() {
        for byte in 0..m.len() {
            for bit in 0..8 {
                let r = run_with(f.setup(), |j, msg| {
                    if j == i {
                        msg[byte] ^= 1 << bit;
                    }
                });
                assert!(
                    r.is_err(),
                    "msg {i} byte {byte} bit {bit} reached Established"
                );
                variants += 1;
            }
        }
    }
    let total: usize = honest.msgs.iter().map(|m| 8 * m.len()).sum();
    assert_eq!(variants, total);
}

#[test]
fn a09_truncated_and_extended_messages_fail() {
    let f = password_fixture();
    for i in 0..4 {
        let r = run_with(f.setup(), |j, msg| {
            if j == i {
                msg.pop();
            }
        });
        assert!(r.is_err(), "truncated msg {i}");
        let r = run_with(f.setup(), |j, msg| {
            if j == i {
                msg.push(0);
            }
        });
        assert!(r.is_err(), "extended msg {i}");
    }
}

#[test]
fn oversized_handshake_message_is_refused() {
    let f = password_fixture();
    let h = host_start(HandshakeMode::Password(&f.psk_h), &f.pro_h, &f.host.noise).unwrap();
    assert_eq!(
        h.read_msg1(&vec![0; 65_536], &mut OsRng).err(),
        Some(HandshakeError::TooLarge)
    );
}

// ---------------------------------------------------------- A15 / A16 ----

#[test]
fn a15_host_cert_for_another_noise_key_is_rejected() {
    let f = password_fixture();
    let other = party("other");
    let swapped = f
        .host
        .id
        .sign_cert(other.noise.public(), "host", 1)
        .unwrap();
    let r = run(Setup {
        host: Side {
            noise: &f.host.noise,
            cert: &swapped,
        },
        ..f.setup()
    });
    assert_eq!(r.err(), Some((1, HandshakeError::CertKeyMismatch)));
}

#[test]
fn a15_viewer_cert_for_another_noise_key_is_rejected() {
    let f = password_fixture();
    let other = party("other");
    let swapped = f
        .viewer
        .id
        .sign_cert(other.noise.public(), "viewer", 1)
        .unwrap();
    let r = run(Setup {
        viewer: Side {
            noise: &f.viewer.noise,
            cert: &swapped,
        },
        ..f.setup()
    });
    assert_eq!(r.err(), Some((2, HandshakeError::CertKeyMismatch)));
}

#[test]
fn a15_another_devices_genuine_cert_is_rejected() {
    let f = password_fixture();
    let stranger = party("stranger");
    let r = run(Setup {
        host: Side {
            noise: &f.host.noise,
            cert: &stranger.cert,
        },
        viewer_policy: PeerPolicy::AnyKey,
        ..f.setup()
    });
    assert_eq!(r.err(), Some((1, HandshakeError::CertKeyMismatch)));
}

#[test]
fn a15_bad_cert_signature_is_rejected_on_both_sides() {
    let f = password_fixture();
    let bad_h = bad_signature(&f.host.cert);
    let r = run(Setup {
        host: Side {
            noise: &f.host.noise,
            cert: &bad_h,
        },
        ..f.setup()
    });
    assert_eq!(
        r.err(),
        Some((1, HandshakeError::Cert(CertError::SignatureInvalid)))
    );
    let bad_v = bad_signature(&f.viewer.cert);
    let r = run(Setup {
        viewer: Side {
            noise: &f.viewer.noise,
            cert: &bad_v,
        },
        ..f.setup()
    });
    assert_eq!(
        r.err(),
        Some((2, HandshakeError::Cert(CertError::SignatureInvalid)))
    );
}

#[test]
fn a16_viewer_asked_for_device_x_and_got_key_y() {
    // EvilSignal answers device ID X with its own key and knows the password.
    // The viewer aborts at msg2: no SAS, no PendingApproval.
    let f = password_fixture();
    let wanted = party("the real host");
    let r = run(Setup {
        viewer_policy: PeerPolicy::DeviceId(DeviceId::of(&wanted.id.public())),
        ..f.setup()
    });
    assert_eq!(r.err(), Some((1, HandshakeError::DeviceIdMismatch)));
}

// ---------------------------------------------------------- A19 / A25-T --

#[test]
fn a19_pinned_host_whose_key_changed_is_a_hard_failure() {
    let (viewer, host, old) = (party("viewer"), party("host"), party("host, old key"));
    let (pv, ph) = prologues(&exporter(4), &exporter(4));
    let r = run(Setup {
        viewer_policy: PeerPolicy::Pinned(old.id.public()),
        ..trusted_setup(&viewer, &host, &pv, &ph)
    });
    assert_eq!(r.err(), Some((1, HandshakeError::PinnedKeyChanged)));
}

#[test]
fn a25t_host_rejects_a_viewer_not_in_the_trusted_set() {
    let (viewer, host, someone) = (party("viewer"), party("host"), party("someone"));
    let (pv, ph) = prologues(&exporter(4), &exporter(4));
    for set in [vec![someone.id.public()], vec![]] {
        let r = run(Setup {
            host_policy: PeerPolicy::TrustedSet(set),
            ..trusted_setup(&viewer, &host, &pv, &ph)
        });
        assert_eq!(r.err(), Some((2, HandshakeError::UntrustedKey)));
    }
}

#[test]
fn a25t_trusted_mode_without_a_pin_is_refused() {
    let (viewer, host) = (party("viewer"), party("host"));
    let (pv, ph) = prologues(&exporter(4), &exporter(4));
    for viewer_policy in [
        PeerPolicy::AnyKey,
        PeerPolicy::DeviceId(DeviceId::of(&host.id.public())),
    ] {
        let r = run(Setup {
            viewer_policy,
            ..trusted_setup(&viewer, &host, &pv, &ph)
        });
        assert_eq!(r.err(), Some((1, HandshakeError::TrustedModeRequiresPin)));
    }
    for host_policy in [
        PeerPolicy::AnyKey,
        PeerPolicy::DeviceId(DeviceId::of(&viewer.id.public())),
    ] {
        let r = run(Setup {
            host_policy,
            ..trusted_setup(&viewer, &host, &pv, &ph)
        });
        assert_eq!(r.err(), Some((2, HandshakeError::TrustedModeRequiresPin)));
    }
}

#[test]
fn a25t_trusted_mode_still_verifies_noise_binding_and_signature() {
    let (viewer, host, other) = (party("viewer"), party("host"), party("other"));
    let (pv, ph) = prologues(&exporter(4), &exporter(4));
    // Pinned identity is right, but the cert names another Noise key.
    let lying = host.id.sign_cert(other.noise.public(), "host", 1).unwrap();
    let r = run(Setup {
        host: Side {
            noise: &host.noise,
            cert: &lying,
        },
        ..trusted_setup(&viewer, &host, &pv, &ph)
    });
    assert_eq!(r.err(), Some((1, HandshakeError::CertKeyMismatch)));
    // Pinned identity is right, signature is not.
    let bad = bad_signature(&host.cert);
    let r = run(Setup {
        host: Side {
            noise: &host.noise,
            cert: &bad,
        },
        ..trusted_setup(&viewer, &host, &pv, &ph)
    });
    assert_eq!(
        r.err(),
        Some((1, HandshakeError::Cert(CertError::SignatureInvalid)))
    );
}

// ------------------------------------------------------------- A17-S* ----

#[test]
fn a17_s1_every_single_bit_change_of_n_r_after_msg3_is_caught() {
    // A scripted responder that, after seeing n_i in msg3, reveals n_r' ≠ n_r
    // (properly encrypted, so only the commitment check can catch it).
    let f = password_fixture();
    for bit in 0..256 {
        let (v, mut host_est, mut n_r) =
            to_viewer_await_reveal(&f.viewer, &f.host, &f.psk_v, &f.psk_h, &f.pro_v);
        n_r[bit / 8] ^= 1 << (bit % 8);
        let frame = host_est.encrypt(&reveal_envelope(&n_r)).unwrap();
        assert_eq!(
            v.read_reveal(&frame).err(),
            Some(HandshakeError::CommitmentMismatch),
            "bit {bit}"
        );
    }
}

#[test]
fn a25t_trusted_mode_still_runs_commit_reveal() {
    let (viewer, host) = (party("viewer"), party("host"));
    let (pv, ph) = prologues(&exporter(4), &exporter(4));
    let (v, m1) = viewer_start(HandshakeMode::Trusted, &pv, &viewer.noise).unwrap();
    let h = host_start(HandshakeMode::Trusted, &ph, &host.noise).unwrap();
    let h = h.read_msg1(&m1, &mut OsRng).unwrap();
    let (h, m2) = h.write_msg2(&host.cert).unwrap();
    let v = v
        .read_msg2(&m2, &PeerPolicy::Pinned(host.id.public()))
        .unwrap();
    let (v, m3) = v.write_msg3(&viewer.cert, &mut OsRng).unwrap();
    let h = h
        .read_msg3(&m3, &PeerPolicy::TrustedSet(vec![viewer.id.public()]))
        .unwrap();
    let (mut host_est, mut n_r) = h.reveal();
    n_r[31] ^= 0x80;
    let frame = host_est.encrypt(&reveal_envelope(&n_r)).unwrap();
    assert_eq!(
        v.read_reveal(&frame).err(),
        Some(HandshakeError::CommitmentMismatch)
    );
}

#[test]
fn a17_s1_reveal_must_be_a_well_formed_sas_reveal() {
    use prost::Message;
    use remora_proto::messages::{Control, Envelope, Goodbye, control, envelope};
    let f = password_fixture();
    let bye = Envelope {
        msg: Some(envelope::Msg::Control(Control {
            kind: Some(control::Kind::Bye(Goodbye {})),
        })),
    }
    .encode_to_vec();
    for payload in [
        bye,
        reveal_envelope(&[0; 31]),
        reveal_envelope(&[0; 33]),
        reveal_envelope(&[]),
        vec![0xFF, 0xFF, 0xFF],
        Vec::new(),
    ] {
        let (v, mut host_est, _) =
            to_viewer_await_reveal(&f.viewer, &f.host, &f.psk_v, &f.psk_h, &f.pro_v);
        let frame = host_est.encrypt(&payload).unwrap();
        assert_eq!(
            v.read_reveal(&frame).err(),
            Some(HandshakeError::RevealExpected),
            "{payload:?}"
        );
    }
    let (v, _, _) = to_viewer_await_reveal(&f.viewer, &f.host, &f.psk_v, &f.psk_h, &f.pro_v);
    assert_eq!(
        v.read_reveal(&[0; 64]).err(),
        Some(HandshakeError::RevealAuth)
    );
}

#[test]
fn a17_s2_n_i_is_drawn_only_when_msg3_is_written() {
    // n_i can only come from ViewerGotMsg2::write_msg3, i.e. after msg2 (and
    // C_r) was processed; it is drawn exactly once.
    let f = password_fixture();
    let (v, _) = to_viewer_got_msg2(&f.viewer, &f.host, &f.psk_v, &f.psk_h, &f.pro_v);
    let mut rng = RecordingRng::default();
    let _ = v.write_msg3(&f.viewer.cert, &mut rng).unwrap();
    assert_eq!(rng.calls.get(), 1);
    assert_eq!(rng.outputs.borrow()[0].len(), 32);
}

#[test]
fn a17_s2_cert_name_length_frames_the_payload() {
    // Payload = cert ‖ 32 bytes, framed by the cert's own name length. Every
    // name length 0..=64 must round-trip (so C_r / n_i are found exactly).
    let f = password_fixture();
    for len in [0usize, 1, 31, 32, 33, 63, 64] {
        let host_cert = f
            .host
            .id
            .sign_cert(f.host.noise.public(), &"h".repeat(len), 1)
            .unwrap();
        let viewer_cert = f
            .viewer
            .id
            .sign_cert(f.viewer.noise.public(), &"v".repeat(len), 1)
            .unwrap();
        let r = run(Setup {
            host: Side {
                noise: &f.host.noise,
                cert: &host_cert,
            },
            viewer: Side {
                noise: &f.viewer.noise,
                cert: &viewer_cert,
            },
            ..f.setup()
        })
        .unwrap();
        assert_eq!(r.viewer.sas(), r.host.sas(), "name length {len}");
    }
}

#[test]
fn a17_s5_each_side_draws_exactly_one_fresh_256_bit_value_per_session() {
    let f = password_fixture();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..2_000 {
        let mut host_rng = RecordingRng::default();
        let mut viewer_rng = RecordingRng::default();
        let (v, m1) =
            viewer_start(HandshakeMode::Password(&f.psk_v), &f.pro_v, &f.viewer.noise).unwrap();
        let h = host_start(HandshakeMode::Password(&f.psk_h), &f.pro_h, &f.host.noise).unwrap();
        let h = h.read_msg1(&m1, &mut host_rng).unwrap();
        let (h, m2) = h.write_msg2(&f.host.cert).unwrap();
        let v = v.read_msg2(&m2, &PeerPolicy::AnyKey).unwrap();
        let (v, m3) = v.write_msg3(&f.viewer.cert, &mut viewer_rng).unwrap();
        let h = h.read_msg3(&m3, &PeerPolicy::AnyKey).unwrap();
        let (mut host_est, n_r) = h.reveal();
        let frame = host_est.encrypt(&reveal_envelope(&n_r)).unwrap();
        v.read_reveal(&frame).unwrap();
        assert_eq!(host_rng.calls.get(), 1);
        assert_eq!(viewer_rng.calls.get(), 1);
        let n_r_drawn = host_rng.outputs.borrow()[0].clone();
        let n_i_drawn = viewer_rng.outputs.borrow()[0].clone();
        assert_eq!(n_r_drawn.len(), 32);
        assert_eq!(n_i_drawn.len(), 32);
        assert_eq!(n_r_drawn, n_r.to_vec(), "n_r is exactly the drawn value");
        assert!(seen.insert(n_r_drawn), "n_r repeated");
        assert!(seen.insert(n_i_drawn), "n_i repeated");
    }
}

// ---------------------------------------------------------------- A10 ----

#[test]
fn a10_flipped_truncated_or_extended_transport_message_fails() {
    let f = password_fixture();
    for edit in 0..3 {
        let mut r = run(f.setup()).unwrap();
        let mut c = r.viewer.encrypt(b"input: click").unwrap();
        match edit {
            0 => c[3] ^= 0x40,
            1 => {
                c.pop();
            }
            _ => c.push(0),
        }
        assert_eq!(
            r.host.decrypt(&c).err(),
            Some(TransportError::Auth),
            "edit {edit}"
        );
    }
}

#[test]
fn a10_duplicated_reordered_or_dropped_transport_message_fails() {
    // Noise transport nonces are implicit and sequential.
    let f = password_fixture();
    let mut r = run(f.setup()).unwrap();
    let c1 = r.viewer.encrypt(b"one").unwrap();
    assert_eq!(r.host.decrypt(&c1).unwrap(), b"one");
    assert_eq!(
        r.host.decrypt(&c1).err(),
        Some(TransportError::Auth),
        "duplicate"
    );

    let mut r = run(f.setup()).unwrap();
    let _c1 = r.viewer.encrypt(b"one").unwrap();
    let c2 = r.viewer.encrypt(b"two").unwrap();
    assert_eq!(
        r.host.decrypt(&c2).err(),
        Some(TransportError::Auth),
        "reordered / dropped"
    );
}

#[test]
fn transport_size_limits() {
    let f = password_fixture();
    let mut r = run(f.setup()).unwrap();
    assert!(r.viewer.encrypt(&vec![0; 65_535 - 16]).is_ok());
    assert_eq!(
        r.viewer.encrypt(&vec![0; 65_535 - 15]).err(),
        Some(TransportError::TooLarge)
    );
    assert_eq!(
        r.host.decrypt(&vec![0; 65_536]).err(),
        Some(TransportError::TooLarge)
    );
}

// ------------------------------------------------- payload parser (A26) --

#[test]
fn handshake_payload_is_cert_then_exactly_32_bytes() {
    use remora_crypto::noise::decode_handshake_payload;
    let f = password_fixture();
    let cert = f.host.cert.encode();
    let ok = [cert.as_slice(), &[0xAB; 32]].concat();
    let (c, tail) = decode_handshake_payload(&ok).unwrap();
    assert_eq!(c, f.host.cert);
    assert_eq!(tail, [0xAB; 32]);
    for bad in [
        Vec::new(),
        cert.clone(),
        [cert.as_slice(), &[0; 31]].concat(),
        [cert.as_slice(), &[0; 33]].concat(),
        cert[..72].to_vec(),
        vec![0; 1 << 16],
    ] {
        assert_eq!(
            decode_handshake_payload(&bad).err(),
            Some(HandshakeError::MalformedPayload),
            "len {}",
            bad.len()
        );
    }
}

#[test]
fn size_limit_is_exactly_the_noise_maximum() {
    // 65 535 bytes is allowed (fails authentication), 65 536 is TooLarge.
    let f = password_fixture();
    let h = host_start(HandshakeMode::Password(&f.psk_h), &f.pro_h, &f.host.noise).unwrap();
    assert_eq!(
        h.read_msg1(&vec![0; 65_535], &mut OsRng).err(),
        Some(HandshakeError::Msg1Auth)
    );
    let mut r = run(f.setup()).unwrap();
    assert_eq!(
        r.host.decrypt(&vec![0; 65_535]).err(),
        Some(TransportError::Auth)
    );
}

#[test]
fn a17_sas_binds_the_handshake_transcript_not_only_the_nonces() {
    // Two sessions whose nonces are forced EQUAL (fixed RNG) must still get
    // different codes, because h (the Noise handshake hash) differs: fresh
    // ephemeral keys every time. This is what makes a MITM's two sessions
    // disagree. (Mutation-gate finding: a constant h was not caught.)
    struct FixedRng;
    impl rand_core::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            7
        }
        fn next_u64(&mut self) -> u64 {
            7
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            d.fill(7);
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> {
            d.fill(7);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for FixedRng {}
    let f = password_fixture();
    let mut codes = std::collections::HashSet::new();
    for _ in 0..20 {
        let (v, m1) =
            viewer_start(HandshakeMode::Password(&f.psk_v), &f.pro_v, &f.viewer.noise).unwrap();
        let h = host_start(HandshakeMode::Password(&f.psk_h), &f.pro_h, &f.host.noise).unwrap();
        let h = h.read_msg1(&m1, &mut FixedRng).unwrap();
        let (h, m2) = h.write_msg2(&f.host.cert).unwrap();
        let v = v.read_msg2(&m2, &PeerPolicy::AnyKey).unwrap();
        let (v, m3) = v.write_msg3(&f.viewer.cert, &mut FixedRng).unwrap();
        let h = h.read_msg3(&m3, &PeerPolicy::AnyKey).unwrap();
        let (mut host_est, n_r) = h.reveal();
        let frame = host_est.encrypt(&reveal_envelope(&n_r)).unwrap();
        let viewer_est = v.read_reveal(&frame).unwrap();
        assert_eq!(viewer_est.sas(), host_est.sas());
        codes.insert(host_est.sas());
    }
    // 20 codes from 10⁶ with h fresh each time: two or more repeats has
    // probability < 10⁻⁷; a constant h gives 1 distinct code.
    assert!(codes.len() >= 19, "SAS ignores h: {codes:?}");
}

#[test]
fn payload_with_an_oversized_name_length_is_a_framing_error() {
    use remora_crypto::noise::decode_handshake_payload;
    let f = password_fixture();
    let mut p = [f.host.cert.encode().as_slice(), &[0; 32]].concat();
    // name_len 65 and a payload length that matches it exactly.
    p[72] = 65;
    p.resize(137 + 65 + 32, b'x');
    assert_eq!(
        decode_handshake_payload(&p).err(),
        Some(HandshakeError::MalformedPayload)
    );
    p[72] = 255;
    p.resize(137 + 255 + 32, b'x');
    assert_eq!(
        decode_handshake_payload(&p).err(),
        Some(HandshakeError::MalformedPayload)
    );
}

#[test]
fn noise_key_rebuilt_from_its_secret_is_the_same_key() {
    use rand_core::RngCore;
    use remora_crypto::noise::NoiseStaticKeypair;
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let a = NoiseStaticKeypair::from_secret(secret);
    let b = NoiseStaticKeypair::from_secret(secret);
    assert_eq!(a.public(), b.public());
    let mut other = secret;
    other[5] ^= 1;
    assert_ne!(NoiseStaticKeypair::from_secret(other).public(), a.public());
    // RFC 7748 §6.1 (rfc-editor.org/rfc/rfc7748.txt, lines 768-771, read
    // 2026-10-18): Alice's X25519 private key and X25519(a, 9). Copied as
    // hex strings verbatim from the RFC text, not typed from memory.
    let hex = |h: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    };
    let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    assert_eq!(
        NoiseStaticKeypair::from_secret(alice).public().as_bytes(),
        &alice_pub
    );
}
