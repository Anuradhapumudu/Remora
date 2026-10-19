//! Handshake type-states (see the module docs of [`super`]).

use rand_core::{CryptoRng, RngCore};

use remora_proto::messages::{Control, control, decode_envelope, envelope};

use super::{
    HandshakeError, HandshakeMode, NOISE_MAX_MESSAGE, NOISE_TAG_LEN, NoiseStaticKeypair,
    PATTERN_PASSWORD, PATTERN_TRUSTED, PeerPolicy, TransportError, decode_handshake_payload,
};
use crate::identity::{DeviceId, IdentityCert};
use crate::keyschedule::Prologue;
use crate::sas::{Sas, commitment, sas, verify_commitment};

/// Viewer: msg1 sent, waiting for msg2.
pub struct ViewerAwaitMsg2 {
    pub(crate) hs: snow::HandshakeState,
    pub(crate) trusted: bool,
}

/// Viewer: msg2 verified; holds the host's commitment `C_r`.
pub struct ViewerGotMsg2 {
    pub(crate) hs: snow::HandshakeState,
    pub(crate) peer: IdentityCert,
    pub(crate) c_r: [u8; 32],
}

/// Viewer: msg3 sent (with `n_i`), waiting for the host's reveal.
pub struct ViewerAwaitReveal {
    pub(crate) transport: snow::TransportState,
    pub(crate) peer: IdentityCert,
    pub(crate) c_r: [u8; 32],
    pub(crate) n_i: [u8; 32],
    pub(crate) h: [u8; 32],
}

/// Host: waiting for msg1.
pub struct HostAwaitMsg1 {
    pub(crate) hs: snow::HandshakeState,
    pub(crate) trusted: bool,
}

/// Host: msg1 authenticated; `n_r` drawn and fixed.
pub struct HostGotMsg1 {
    pub(crate) hs: snow::HandshakeState,
    pub(crate) trusted: bool,
    pub(crate) n_r: [u8; 32],
}

/// Host: msg2 sent (with `C_r`), waiting for msg3.
pub struct HostAwaitMsg3 {
    pub(crate) hs: snow::HandshakeState,
    pub(crate) trusted: bool,
    pub(crate) n_r: [u8; 32],
}

/// Host: msg3 verified; holds the viewer's `n_i`.
pub struct HostGotMsg3 {
    pub(crate) transport: snow::TransportState,
    pub(crate) peer: IdentityCert,
    pub(crate) n_i: [u8; 32],
    pub(crate) n_r: [u8; 32],
    pub(crate) h: [u8; 32],
}

/// Handshake complete, commitment verified: the safety code exists.
pub struct Established {
    pub(crate) transport: snow::TransportState,
    pub(crate) peer: IdentityCert,
    pub(crate) sas: Sas,
}

macro_rules! redacted_debug {
    ($($t:ty),*) => {$(
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($t), " { [redacted] }"))
            }
        }
    )*};
}
redacted_debug!(
    ViewerAwaitMsg2,
    ViewerGotMsg2,
    ViewerAwaitReveal,
    HostAwaitMsg1,
    HostGotMsg1,
    HostAwaitMsg3,
    HostGotMsg3,
    Established
);

/// Viewer: starts the handshake; returns msg1.
pub fn viewer_start(
    mode: HandshakeMode<'_>,
    prologue: &Prologue,
    local: &NoiseStaticKeypair,
) -> Result<(ViewerAwaitMsg2, Vec<u8>), HandshakeError> {
    let trusted = matches!(mode, HandshakeMode::Trusted);
    let mut hs = builder(&mode, prologue, local)?
        .build_initiator()
        .map_err(|_| HandshakeError::Internal)?;
    let msg1 = write(&mut hs, &[])?;
    Ok((ViewerAwaitMsg2 { hs, trusted }, msg1))
}

impl ViewerAwaitMsg2 {
    /// Reads msg2: decrypts, parses `cert_h ‖ C_r`, verifies the cert
    /// (signature, Noise-key binding, `policy`).
    pub fn read_msg2(
        mut self,
        msg2: &[u8],
        policy: &PeerPolicy,
    ) -> Result<ViewerGotMsg2, HandshakeError> {
        let payload = read(&mut self.hs, msg2, HandshakeError::Msg2Auth)?;
        let (peer, c_r) = decode_handshake_payload(&payload)?;
        verify_peer(&peer, &self.hs, policy, self.trusted)?;
        Ok(ViewerGotMsg2 {
            hs: self.hs,
            peer,
            c_r,
        })
    }
}

impl ViewerGotMsg2 {
    /// The host's verified identity.
    pub fn peer_cert(&self) -> &IdentityCert {
        &self.peer
    }

    /// Draws `n_i` (exactly one 32-byte value from `rng`) and writes msg3
    /// carrying our cert and `n_i`.
    pub fn write_msg3<R: RngCore + CryptoRng>(
        mut self,
        own_cert: &IdentityCert,
        rng: &mut R,
    ) -> Result<(ViewerAwaitReveal, Vec<u8>), HandshakeError> {
        let mut n_i = [0u8; 32];
        rng.fill_bytes(&mut n_i);
        let mut payload = own_cert.encode();
        payload.extend_from_slice(&n_i);
        let msg3 = write(&mut self.hs, &payload)?;
        let h = handshake_hash(&self.hs)?;
        let transport = self
            .hs
            .into_transport_mode()
            .map_err(|_| HandshakeError::Internal)?;
        Ok((
            ViewerAwaitReveal {
                transport,
                peer: self.peer,
                c_r: self.c_r,
                n_i,
                h,
            },
            msg3,
        ))
    }
}

impl ViewerAwaitReveal {
    /// Reads the host's first transport message: it must be an `Envelope`
    /// holding `Control::SasReveal` with a 32-byte `n_r` that opens `C_r`.
    pub fn read_reveal(mut self, frame: &[u8]) -> Result<Established, HandshakeError> {
        let plaintext = transport_decrypt(&mut self.transport, frame)
            .map_err(|_| HandshakeError::RevealAuth)?;
        let n_r = parse_reveal(&plaintext)?;
        if !verify_commitment(&self.c_r, &n_r) {
            return Err(HandshakeError::CommitmentMismatch);
        }
        Ok(Established {
            transport: self.transport,
            peer: self.peer,
            sas: sas(&self.h, &self.n_i, &n_r),
        })
    }
}

/// Host: prepares to receive msg1.
pub fn host_start(
    mode: HandshakeMode<'_>,
    prologue: &Prologue,
    local: &NoiseStaticKeypair,
) -> Result<HostAwaitMsg1, HandshakeError> {
    let trusted = matches!(mode, HandshakeMode::Trusted);
    let hs = builder(&mode, prologue, local)?
        .build_responder()
        .map_err(|_| HandshakeError::Internal)?;
    Ok(HostAwaitMsg1 { hs, trusted })
}

impl HostAwaitMsg1 {
    /// Reads msg1 and, only if it authenticates, draws `n_r` (exactly one
    /// 32-byte value from `rng`).
    pub fn read_msg1<R: RngCore + CryptoRng>(
        mut self,
        msg1: &[u8],
        rng: &mut R,
    ) -> Result<HostGotMsg1, HandshakeError> {
        let payload = read(&mut self.hs, msg1, HandshakeError::Msg1Auth)?;
        if !payload.is_empty() {
            return Err(HandshakeError::MalformedPayload);
        }
        // A17-S1: n_r is fixed here, before msg2 (which commits to it) can
        // be written, and no method changes it afterwards.
        let mut n_r = [0u8; 32];
        rng.fill_bytes(&mut n_r);
        Ok(HostGotMsg1 {
            hs: self.hs,
            trusted: self.trusted,
            n_r,
        })
    }
}

impl HostGotMsg1 {
    /// Writes msg2 carrying our cert and `C_r = commitment(n_r)`.
    pub fn write_msg2(
        mut self,
        own_cert: &IdentityCert,
    ) -> Result<(HostAwaitMsg3, Vec<u8>), HandshakeError> {
        let mut payload = own_cert.encode();
        payload.extend_from_slice(&commitment(&self.n_r));
        let msg2 = write(&mut self.hs, &payload)?;
        Ok((
            HostAwaitMsg3 {
                hs: self.hs,
                trusted: self.trusted,
                n_r: self.n_r,
            },
            msg2,
        ))
    }
}

impl HostAwaitMsg3 {
    /// Reads msg3: decrypts, parses `cert_v ‖ n_i`, verifies the cert.
    pub fn read_msg3(
        mut self,
        msg3: &[u8],
        policy: &PeerPolicy,
    ) -> Result<HostGotMsg3, HandshakeError> {
        let payload = read(&mut self.hs, msg3, HandshakeError::Msg3Auth)?;
        let (peer, n_i) = decode_handshake_payload(&payload)?;
        verify_peer(&peer, &self.hs, policy, self.trusted)?;
        let h = handshake_hash(&self.hs)?;
        let transport = self
            .hs
            .into_transport_mode()
            .map_err(|_| HandshakeError::Internal)?;
        Ok(HostGotMsg3 {
            transport,
            peer,
            n_i,
            n_r: self.n_r,
            h,
        })
    }
}

impl HostGotMsg3 {
    /// The viewer's verified identity.
    pub fn peer_cert(&self) -> &IdentityCert {
        &self.peer
    }

    /// Finishes: computes the SAS and hands out `n_r`, which the caller must
    /// send as `SasReveal` in the **first** transport message (encrypted with
    /// [`Established::encrypt`]).
    pub fn reveal(self) -> (Established, [u8; 32]) {
        let sas = sas(&self.h, &self.n_i, &self.n_r);
        (
            Established {
                transport: self.transport,
                peer: self.peer,
                sas,
            },
            self.n_r,
        )
    }
}

impl Established {
    /// The safety code both screens show.
    pub fn sas(&self) -> Sas {
        self.sas
    }

    /// The peer's verified identity.
    pub fn peer_cert(&self) -> &IdentityCert {
        &self.peer
    }

    /// Encrypts one transport message (≤ 65 519 bytes of plaintext).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        if plaintext.len() > NOISE_MAX_MESSAGE - NOISE_TAG_LEN {
            return Err(TransportError::TooLarge);
        }
        let mut buf = vec![0u8; plaintext.len() + NOISE_TAG_LEN];
        let n = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|_| TransportError::Internal)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypts the next transport message, in order.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        transport_decrypt(&mut self.transport, ciphertext)
    }
}

// ------------------------------------------------------------- helpers --

/// A `snow` builder for `mode`, with prologue, static key and (password
/// mode) the PSK at position 0.
fn builder<'a>(
    mode: &HandshakeMode<'a>,
    prologue: &'a Prologue,
    local: &'a NoiseStaticKeypair,
) -> Result<snow::Builder<'a>, HandshakeError> {
    let pattern = match mode {
        HandshakeMode::Password(_) => PATTERN_PASSWORD,
        HandshakeMode::Trusted => PATTERN_TRUSTED,
    };
    let params = pattern.parse().map_err(|_| HandshakeError::Internal)?;
    let b = snow::Builder::new(params)
        .prologue(prologue.as_bytes())
        .map_err(|_| HandshakeError::Internal)?
        .local_private_key(&local.secret)
        .map_err(|_| HandshakeError::Internal)?;
    match mode {
        HandshakeMode::Password(psk) => b.psk(0, &psk.0).map_err(|_| HandshakeError::Internal),
        HandshakeMode::Trusted => Ok(b),
    }
}

/// Writes one handshake message.
fn write(hs: &mut snow::HandshakeState, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let mut buf = vec![0u8; NOISE_MAX_MESSAGE];
    let n = hs
        .write_message(payload, &mut buf)
        .map_err(|_| HandshakeError::Internal)?;
    buf.truncate(n);
    Ok(buf)
}

/// Reads one handshake message; any `snow` failure is `auth_error` (a
/// decryption failure is the only way a well-sized message can fail).
fn read(
    hs: &mut snow::HandshakeState,
    msg: &[u8],
    auth_error: HandshakeError,
) -> Result<Vec<u8>, HandshakeError> {
    if msg.len() > NOISE_MAX_MESSAGE {
        return Err(HandshakeError::TooLarge);
    }
    let mut buf = vec![0u8; msg.len()];
    let n = hs.read_message(msg, &mut buf).map_err(|_| auth_error)?;
    buf.truncate(n);
    Ok(buf)
}

/// The final handshake hash `h` (32 bytes for BLAKE2s).
fn handshake_hash(hs: &snow::HandshakeState) -> Result<[u8; 32], HandshakeError> {
    hs.get_handshake_hash()
        .try_into()
        .map_err(|_| HandshakeError::Internal)
}

/// The peer's cert must (1) be validly signed (`verify_strict`), (2) name
/// the static key Noise just authenticated, and (3) satisfy `policy`.
/// Trusted mode accepts only a pinned key or a trusted set (A25-T).
///
/// **Every check runs before the verdict** (phase3-criteria §3.1a: no early
/// return inside a step), so which check failed does not change how long
/// this takes beyond the work itself; the first failure in the order above
/// is reported. The network layer adds the 200 ms response floor on top.
fn verify_peer(
    cert: &IdentityCert,
    hs: &snow::HandshakeState,
    policy: &PeerPolicy,
    trusted: bool,
) -> Result<(), HandshakeError> {
    let mode_ok = !trusted || matches!(policy, PeerPolicy::Pinned(_) | PeerPolicy::TrustedSet(_));
    let signature = cert.verify().map_err(HandshakeError::Cert);
    let binding_ok = hs
        .get_remote_static()
        .is_some_and(|remote| remote == cert.noise_static().as_bytes());
    let policy_result = match policy {
        PeerPolicy::AnyKey => Ok(()),
        PeerPolicy::DeviceId(want) => (DeviceId::of(cert.identity()) == *want)
            .then_some(())
            .ok_or(HandshakeError::DeviceIdMismatch),
        PeerPolicy::Pinned(key) => (cert.identity() == key)
            .then_some(())
            .ok_or(HandshakeError::PinnedKeyChanged),
        PeerPolicy::TrustedSet(keys) => keys
            .contains(cert.identity())
            .then_some(())
            .ok_or(HandshakeError::UntrustedKey),
    };
    if !mode_ok {
        return Err(HandshakeError::TrustedModeRequiresPin);
    }
    signature?;
    if !binding_ok {
        return Err(HandshakeError::CertKeyMismatch);
    }
    policy_result
}

fn transport_decrypt(
    t: &mut snow::TransportState,
    ciphertext: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if ciphertext.len() > NOISE_MAX_MESSAGE {
        return Err(TransportError::TooLarge);
    }
    let mut buf = vec![0u8; ciphertext.len()];
    let n = t
        .read_message(ciphertext, &mut buf)
        .map_err(|_| TransportError::Auth)?;
    buf.truncate(n);
    Ok(buf)
}

/// `Envelope { Control { SasReveal { n_r: 32 bytes } } }`, nothing else.
fn parse_reveal(plaintext: &[u8]) -> Result<[u8; 32], HandshakeError> {
    let env = decode_envelope(plaintext).map_err(|_| HandshakeError::RevealExpected)?;
    match env.msg {
        Some(envelope::Msg::Control(Control {
            kind: Some(control::Kind::SasReveal(r)),
        })) => r
            .n_r
            .as_slice()
            .try_into()
            .map_err(|_| HandshakeError::RevealExpected),
        _ => Err(HandshakeError::RevealExpected),
    }
}
