//! Shared helpers for remora-crypto's attack tests.
#![allow(dead_code)] // each test binary uses a different subset

use std::cell::Cell;

use rand_core::{CryptoRng, OsRng, RngCore};
use remora_crypto::identity::{DeviceId, IdentityCert, IdentityKeypair};
use remora_crypto::keyschedule::{Prologue, derive_psk, prologue, transcript_hash};
use remora_crypto::noise::{
    Established, HandshakeError, HandshakeMode, HostAwaitMsg3, NoiseStaticKeypair, PeerPolicy,
    ViewerAwaitReveal, ViewerGotMsg2, host_start, viewer_start,
};
use remora_crypto::pake::{Pake, PakeContext, PakeRole, Spake2Ed25519};
use remora_crypto::secret::{Exporter, Otp, Psk};

/// One device: identity, Noise static key and a cert binding them.
pub(crate) struct Party {
    pub(crate) id: IdentityKeypair,
    pub(crate) noise: NoiseStaticKeypair,
    pub(crate) cert: IdentityCert,
}

pub(crate) fn party(name: &str) -> Party {
    let id = IdentityKeypair::generate(&mut OsRng);
    let noise = NoiseStaticKeypair::generate(&mut OsRng);
    let cert = id.sign_cert(noise.public(), name, 1_760_000_000).unwrap();
    Party { id, noise, cert }
}

pub(crate) const VH: &[u8] = b"viewer-hello-bytes";
pub(crate) const HH: &[u8] = b"host-hello-bytes";
pub(crate) const NONCE: [u8; 16] = [7; 16];

pub(crate) fn exporter(byte: u8) -> Exporter {
    Exporter::from_bytes([byte; 32])
}

pub(crate) fn otp(s: &str) -> Otp {
    Otp::parse(s).unwrap()
}

/// Runs SPAKE2 for both sides and derives each side's PSK. Each side uses its
/// own password, exporter and view of the hellos (a MITM may make them differ).
pub(crate) fn psks(
    viewer_otp: &Otp,
    host_otp: &Otp,
    host: &Party,
    viewer_exporter: &Exporter,
    host_exporter: &Exporter,
) -> (Psk, Psk) {
    let ctx = PakeContext {
        host_device_id: DeviceId::of(&host.id.public()),
        nonce: NONCE,
    };
    let (a, msg_a) = Spake2Ed25519::start(PakeRole::Viewer, viewer_otp, &ctx, &mut OsRng);
    let (b, msg_b) = Spake2Ed25519::start(PakeRole::Host, host_otp, &ctx, &mut OsRng);
    let ka = a.finish(&msg_b).unwrap();
    let kb = b.finish(&msg_a).unwrap();
    let t = transcript_hash(VH, HH, &msg_a, &msg_b);
    (
        derive_psk(viewer_exporter, &ka, &t),
        derive_psk(host_exporter, &kb, &t),
    )
}

pub(crate) fn prologues(
    viewer_exporter: &Exporter,
    host_exporter: &Exporter,
) -> (Prologue, Prologue) {
    (
        prologue(viewer_exporter, VH, HH),
        prologue(host_exporter, VH, HH),
    )
}

/// What one side brings: its Noise key and the cert it presents. A lying
/// peer is just a cert that does not match the key.
#[derive(Clone, Copy)]
pub(crate) struct Side<'a> {
    pub(crate) noise: &'a NoiseStaticKeypair,
    pub(crate) cert: &'a IdentityCert,
}

impl Party {
    pub(crate) fn side(&self) -> Side<'_> {
        Side {
            noise: &self.noise,
            cert: &self.cert,
        }
    }
}

/// Everything one handshake needs, per side.
pub(crate) struct Setup<'a> {
    pub(crate) viewer: Side<'a>,
    pub(crate) host: Side<'a>,
    pub(crate) viewer_mode: HandshakeMode<'a>,
    pub(crate) host_mode: HandshakeMode<'a>,
    pub(crate) viewer_prologue: &'a Prologue,
    pub(crate) host_prologue: &'a Prologue,
    pub(crate) viewer_policy: PeerPolicy,
    pub(crate) host_policy: PeerPolicy,
}

/// The three handshake messages and both end states, or the first failure.
pub(crate) struct Run {
    pub(crate) msgs: Vec<Vec<u8>>,
    pub(crate) viewer: Established,
    pub(crate) host: Established,
}

/// Runs msg1..msg3 and the reveal honestly; `tamper(i, msg)` may modify
/// message `i` (0 = msg1, 1 = msg2, 2 = msg3, 3 = reveal) in flight.
pub(crate) fn run_with(
    s: Setup<'_>,
    mut tamper: impl FnMut(usize, &mut Vec<u8>),
) -> Result<Run, (usize, HandshakeError)> {
    let mut msgs = Vec::new();
    let (v, mut m1) =
        viewer_start(s.viewer_mode, s.viewer_prologue, s.viewer.noise).map_err(|e| (0, e))?;
    let h = host_start(s.host_mode, s.host_prologue, s.host.noise).map_err(|e| (0, e))?;
    tamper(0, &mut m1);
    msgs.push(m1.clone());
    let h = h.read_msg1(&m1, &mut OsRng).map_err(|e| (0, e))?;
    let (h, mut m2) = h.write_msg2(s.host.cert).map_err(|e| (1, e))?;
    tamper(1, &mut m2);
    msgs.push(m2.clone());
    let v = v.read_msg2(&m2, &s.viewer_policy).map_err(|e| (1, e))?;
    let (v, mut m3) = v
        .write_msg3(s.viewer.cert, &mut OsRng)
        .map_err(|e| (2, e))?;
    tamper(2, &mut m3);
    msgs.push(m3.clone());
    let h = h.read_msg3(&m3, &s.host_policy).map_err(|e| (2, e))?;
    let (mut host, n_r) = h.reveal();
    let mut r = host
        .encrypt(&reveal_envelope(&n_r))
        .map_err(|_| (3, HandshakeError::Internal))?;
    tamper(3, &mut r);
    msgs.push(r.clone());
    let viewer = v.read_reveal(&r).map_err(|e| (3, e))?;
    Ok(Run { msgs, viewer, host })
}

pub(crate) fn run(s: Setup<'_>) -> Result<Run, (usize, HandshakeError)> {
    run_with(s, |_, _| {})
}

/// Encoded `Envelope { control: SasReveal { n_r } }`.
pub(crate) fn reveal_envelope(n_r: &[u8]) -> Vec<u8> {
    use prost::Message;
    use remora_proto::messages::{Control, Envelope, SasReveal, control, envelope};
    Envelope {
        msg: Some(envelope::Msg::Control(Control {
            kind: Some(control::Kind::SasReveal(SasReveal { n_r: n_r.to_vec() })),
        })),
    }
    .encode_to_vec()
}

/// Drives a password-mode handshake up to "viewer processed msg2", for tests
/// that need to stop in the middle.
pub(crate) fn to_viewer_got_msg2(
    viewer: &Party,
    host: &Party,
    psk_v: &Psk,
    psk_h: &Psk,
    pro: &Prologue,
) -> (ViewerGotMsg2, HostAwaitMsg3) {
    let (v, m1) = viewer_start(HandshakeMode::Password(psk_v), pro, &viewer.noise).unwrap();
    let h = host_start(HandshakeMode::Password(psk_h), pro, &host.noise).unwrap();
    let h = h.read_msg1(&m1, &mut OsRng).unwrap();
    let (h, m2) = h.write_msg2(&host.cert).unwrap();
    let v = v.read_msg2(&m2, &PeerPolicy::AnyKey).unwrap();
    (v, h)
}

/// Drives up to "viewer sent msg3; host knows n_r", returning n_r too.
pub(crate) fn to_viewer_await_reveal(
    viewer: &Party,
    host: &Party,
    psk_v: &Psk,
    psk_h: &Psk,
    pro: &Prologue,
) -> (ViewerAwaitReveal, Established, [u8; 32]) {
    let (v, h) = to_viewer_got_msg2(viewer, host, psk_v, psk_h, pro);
    let (v, m3) = v.write_msg3(&viewer.cert, &mut OsRng).unwrap();
    let h = h.read_msg3(&m3, &PeerPolicy::AnyKey).unwrap();
    let (host_est, n_r) = h.reveal();
    (v, host_est, n_r)
}

/// An RNG that counts `fill_bytes`/`next_*` calls and records every value
/// it hands out (A17-S5). Values come from the OS CSPRNG.
#[derive(Default)]
pub(crate) struct RecordingRng {
    pub(crate) calls: Cell<usize>,
    pub(crate) outputs: std::cell::RefCell<Vec<Vec<u8>>>,
}

impl RngCore for RecordingRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
        self.calls.set(self.calls.get() + 1);
        self.outputs.borrow_mut().push(dest.to_vec());
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for RecordingRng {}

/// Standard password-mode setup with matching passwords and exporters.
pub(crate) struct PasswordFixture {
    pub(crate) viewer: Party,
    pub(crate) host: Party,
    pub(crate) psk_v: Psk,
    pub(crate) psk_h: Psk,
    pub(crate) pro_v: Prologue,
    pub(crate) pro_h: Prologue,
}

pub(crate) fn password_fixture() -> PasswordFixture {
    let viewer = party("viewer");
    let host = party("host");
    let (psk_v, psk_h) = psks(
        &otp("482913"),
        &otp("482913"),
        &host,
        &exporter(1),
        &exporter(1),
    );
    let (pro_v, pro_h) = prologues(&exporter(1), &exporter(1));
    PasswordFixture {
        viewer,
        host,
        psk_v,
        psk_h,
        pro_v,
        pro_h,
    }
}

impl PasswordFixture {
    pub(crate) fn setup(&self) -> Setup<'_> {
        Setup {
            viewer: self.viewer.side(),
            host: self.host.side(),
            viewer_mode: HandshakeMode::Password(&self.psk_v),
            host_mode: HandshakeMode::Password(&self.psk_h),
            viewer_prologue: &self.pro_v,
            host_prologue: &self.pro_h,
            viewer_policy: PeerPolicy::DeviceId(DeviceId::of(&self.host.id.public())),
            host_policy: PeerPolicy::AnyKey,
        }
    }
}
