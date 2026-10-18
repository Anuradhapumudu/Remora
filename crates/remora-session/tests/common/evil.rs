//! Scripted attackers that run the real handshake with remora-crypto
//! directly (not through remora-session), then send whatever they like
//! encrypted on the established channel (A20, A21).
#![allow(dead_code, unreachable_pub)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use prost::Message;
use rand_core::OsRng;
use remora_crypto::identity::DeviceId;
use remora_crypto::keyschedule::{derive_psk, prologue, transcript_hash};
use remora_crypto::noise::{Established, HandshakeMode, PeerPolicy, host_start, viewer_start};
use remora_crypto::pake::{Pake, PakeContext, PakeMessage, PakeRole, Spake2Ed25519};
use remora_crypto::secret::Otp;
use remora_proto::messages::{
    Control, Envelope, HostHello, Mode, SasReveal, SessionPending, ViewerHello, control, envelope,
};
use remora_session::{Host, HostAction, SessionId, ViewerAction, ViewerSession};

use super::{Device, Log, T0, exporter, ip, viewer_cfg};

pub const NONCE: [u8; 16] = [3; 16];

pub fn viewer_hello(mode: Mode) -> Vec<u8> {
    ViewerHello {
        versions: vec![1],
        mode: mode as i32,
        nonce: NONCE.to_vec(),
    }
    .encode_to_vec()
}

fn sends(actions: &[HostAction], id: SessionId) -> Vec<Vec<u8>> {
    actions
        .iter()
        .filter_map(|a| match a {
            HostAction::Send { id: i, frame } if *i == id => Some(frame.clone()),
            _ => None,
        })
        .collect()
}

/// A viewer that completes the password handshake honestly and is left
/// holding its Noise transport while the host is in PendingApproval.
pub struct EvilViewer {
    pub id: SessionId,
    pub est: Established,
    pub host_log: Vec<HostAction>,
}

pub fn evil_viewer_pending(host: &mut Host, viewer: &Device, otp: &Otp) -> EvilViewer {
    host.issue_nonce(NONCE, T0.plus(300_000));
    let id = host
        .accept_connection(ip(66), exporter(7), T0, &mut OsRng)
        .unwrap();
    let mut log = Vec::new();
    let vh = viewer_hello(Mode::Password);
    let out = host.on_frame(id, &vh, T0, &mut OsRng);
    let hh = sends(&out, id).remove(0);
    log.extend(out);
    let host_hello = HostHello::decode(hh.as_slice()).unwrap();
    let ctx = PakeContext {
        host_device_id: DeviceId::from_bytes(
            host_hello.host_device_id.as_slice().try_into().unwrap(),
        ),
        nonce: NONCE,
    };
    let (pake, spake_a) = Spake2Ed25519::start(PakeRole::Viewer, otp, &ctx, &mut OsRng);
    let out = host.on_frame(id, spake_a.as_bytes(), T0, &mut OsRng);
    let spake_b = PakeMessage::from_bytes(&sends(&out, id).remove(0)).unwrap();
    log.extend(out);
    let k = pake.finish(&spake_b).unwrap();
    let t = transcript_hash(&vh, &hh, &spake_a, &spake_b);
    let psk = derive_psk(&exporter(7), &k, &t);
    let pro = prologue(&exporter(7), &vh, &hh);
    let (v, m1) =
        viewer_start(HandshakeMode::Password(&psk), &pro, &viewer.identity.noise).unwrap();
    let out = host.on_frame(id, &m1, T0, &mut OsRng);
    let m2 = sends(&out, id).remove(0);
    log.extend(out);
    let v = v.read_msg2(&m2, &PeerPolicy::AnyKey).unwrap();
    let (v, m3) = v.write_msg3(&viewer.identity.cert, &mut OsRng).unwrap();
    let out = host.on_frame(id, &m3, T0, &mut OsRng);
    let mut frames = sends(&out, id);
    log.extend(out);
    let mut est = v.read_reveal(&frames.remove(0)).unwrap();
    for f in frames {
        est.decrypt(&f).unwrap(); // SessionPending
    }
    EvilViewer {
        id,
        est,
        host_log: log,
    }
}

/// A host that completes the password handshake honestly and is left
/// holding its transport while the viewer waits for approval.
pub struct EvilHost {
    pub est: Established,
    pub viewer: ViewerSession,
    pub log: Log,
}

/// Up to "viewer sent msg3": the viewer waits for the reveal (SasReveal).
pub fn evil_host_viewer_awaiting_reveal(
    viewer_dev: &Device,
    host_dev: &Device,
    otp: &Otp,
) -> (EvilHost, [u8; 32]) {
    let mode = remora_session::ViewerMode::Password {
        otp: otp.clone(),
        expect: None,
    };
    let (mut viewer, first) =
        ViewerSession::start(viewer_cfg(viewer_dev, mode), NONCE, exporter(7), T0);
    let mut log = Log::default();
    let take = |acts: &[ViewerAction]| -> Vec<u8> {
        acts.iter()
            .find_map(|a| match a {
                ViewerAction::Send(f) => Some(f.clone()),
                _ => None,
            })
            .expect("viewer sent a frame")
    };
    let vh = take(&first);
    log.viewer.extend(first);
    let hh = HostHello {
        version: 1,
        host_device_id: DeviceId::of(&host_dev.key.public()).as_bytes().to_vec(),
    }
    .encode_to_vec();
    let out = viewer.on_frame(&hh, T0, &mut OsRng);
    let spake_a = PakeMessage::from_bytes(&take(&out)).unwrap();
    log.viewer.extend(out);
    let ctx = PakeContext {
        host_device_id: DeviceId::of(&host_dev.key.public()),
        nonce: NONCE,
    };
    let (pake, spake_b) = Spake2Ed25519::start(PakeRole::Host, otp, &ctx, &mut OsRng);
    let k = pake.finish(&spake_a).unwrap();
    let out = viewer.on_frame(spake_b.as_bytes(), T0, &mut OsRng);
    let m1 = take(&out);
    log.viewer.extend(out);
    let t = transcript_hash(&vh, &hh, &spake_a, &spake_b);
    let psk = derive_psk(&exporter(7), &k, &t);
    let pro = prologue(&exporter(7), &vh, &hh);
    let h = host_start(
        HandshakeMode::Password(&psk),
        &pro,
        &host_dev.identity.noise,
    )
    .unwrap();
    let h = h.read_msg1(&m1, &mut OsRng).unwrap();
    let (h, m2) = h.write_msg2(&host_dev.identity.cert).unwrap();
    let out = viewer.on_frame(&m2, T0, &mut OsRng);
    let m3 = take(&out);
    log.viewer.extend(out);
    let h = h.read_msg3(&m3, &PeerPolicy::AnyKey).unwrap();
    let (est, n_r) = h.reveal();
    (EvilHost { est, viewer, log }, n_r)
}

/// Up to "viewer shows the SAS and waits for approval" (PendingApproval).
pub fn evil_host_viewer_pending(viewer_dev: &Device, host_dev: &Device, otp: &Otp) -> EvilHost {
    let (mut e, n_r) = evil_host_viewer_awaiting_reveal(viewer_dev, host_dev, otp);
    let reveal = e
        .est
        .encrypt(&control_envelope(control::Kind::SasReveal(SasReveal {
            n_r: n_r.to_vec(),
        })))
        .unwrap();
    let out = e.viewer.on_frame(&reveal, T0, &mut OsRng);
    e.log.viewer.extend(out);
    let pending = e
        .est
        .encrypt(&control_envelope(control::Kind::Pending(SessionPending {})))
        .unwrap();
    let out = e.viewer.on_frame(&pending, T0, &mut OsRng);
    e.log.viewer.extend(out);
    e
}

pub fn control_envelope(k: control::Kind) -> Vec<u8> {
    Envelope {
        msg: Some(envelope::Msg::Control(Control { kind: Some(k) })),
    }
    .encode_to_vec()
}
