//! Handshake type-states (see the module docs of [`super`]).

use rand_core::{CryptoRng, RngCore};

use super::{HandshakeError, HandshakeMode, NoiseStaticKeypair, PeerPolicy, TransportError};
use crate::identity::IdentityCert;
use crate::keyschedule::Prologue;
use crate::sas::Sas;

/// Viewer: msg1 sent, waiting for msg2.
pub struct ViewerAwaitMsg2 {
    pub(crate) hs: snow::HandshakeState,
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
}

/// Host: msg1 authenticated; `n_r` drawn and fixed.
pub struct HostGotMsg1 {
    pub(crate) hs: snow::HandshakeState,
    pub(crate) n_r: [u8; 32],
}

/// Host: msg2 sent (with `C_r`), waiting for msg3.
pub struct HostAwaitMsg3 {
    pub(crate) hs: snow::HandshakeState,
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
    let _ = (mode, prologue, local);
    todo!()
}

impl ViewerAwaitMsg2 {
    /// Reads msg2: decrypts, parses `cert_h ‖ C_r`, verifies the cert
    /// (signature, Noise-key binding, `policy`).
    pub fn read_msg2(
        self,
        msg2: &[u8],
        policy: &PeerPolicy,
    ) -> Result<ViewerGotMsg2, HandshakeError> {
        let _ = (msg2, policy);
        todo!()
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
        self,
        own_cert: &IdentityCert,
        rng: &mut R,
    ) -> Result<(ViewerAwaitReveal, Vec<u8>), HandshakeError> {
        let _ = (own_cert, rng);
        todo!()
    }
}

impl ViewerAwaitReveal {
    /// Reads the host's first transport message: it must be an `Envelope`
    /// holding `Control::SasReveal` with a 32-byte `n_r` that opens `C_r`.
    pub fn read_reveal(self, frame: &[u8]) -> Result<Established, HandshakeError> {
        let _ = frame;
        todo!()
    }
}

/// Host: prepares to receive msg1.
pub fn host_start(
    mode: HandshakeMode<'_>,
    prologue: &Prologue,
    local: &NoiseStaticKeypair,
) -> Result<HostAwaitMsg1, HandshakeError> {
    let _ = (mode, prologue, local);
    todo!()
}

impl HostAwaitMsg1 {
    /// Reads msg1 and, only if it authenticates, draws `n_r` (exactly one
    /// 32-byte value from `rng`).
    pub fn read_msg1<R: RngCore + CryptoRng>(
        self,
        msg1: &[u8],
        rng: &mut R,
    ) -> Result<HostGotMsg1, HandshakeError> {
        let _ = (msg1, rng);
        todo!()
    }
}

impl HostGotMsg1 {
    /// Writes msg2 carrying our cert and `C_r = commitment(n_r)`.
    pub fn write_msg2(
        self,
        own_cert: &IdentityCert,
    ) -> Result<(HostAwaitMsg3, Vec<u8>), HandshakeError> {
        let _ = own_cert;
        todo!()
    }
}

impl HostAwaitMsg3 {
    /// Reads msg3: decrypts, parses `cert_v ‖ n_i`, verifies the cert.
    pub fn read_msg3(
        self,
        msg3: &[u8],
        policy: &PeerPolicy,
    ) -> Result<HostGotMsg3, HandshakeError> {
        let _ = (msg3, policy);
        todo!()
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
        todo!()
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
        let _ = plaintext;
        todo!()
    }

    /// Decrypts the next transport message, in order.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let _ = ciphertext;
        todo!()
    }
}
