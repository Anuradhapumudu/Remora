//! Key schedule (protocol.md §3.1).
//!
//! ```text
//! exporter   = QUIC exporter (label "EXPORTER-remora/1", 32 bytes)
//! hellos     = u32_be(len VH) ‖ VH ‖ u32_be(len HH) ‖ HH
//! transcript = BLAKE2s(hellos ‖ SpakeA ‖ SpakeB)
//! psk        = HKDF-SHA256(salt = exporter, ikm = K, info = PSK_INFO ‖ transcript)
//! prologue   = PROLOGUE_PREFIX ‖ exporter ‖ BLAKE2s(hellos)
//! ```
//!
//! The hellos are **length-prefixed** before hashing so that no byte can move
//! from one hello to the other without changing the hash (plain
//! concatenation would make `VH ‖ HH` and `VH' ‖ HH'` with a shifted boundary
//! hash equal).

use crate::pake::PakeMessage;
use crate::secret::{Exporter, PakeKey, Psk};

/// QUIC exporter label.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-remora/1";
/// HKDF `info` prefix for the Noise PSK.
pub const PSK_INFO: &[u8] = b"remora/1/noise-psk";
/// Noise prologue prefix.
pub const PROLOGUE_PREFIX: &[u8] = b"remora/1";

/// The Noise prologue: binds the QUIC session and both hellos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prologue(pub(crate) Vec<u8>);

impl Prologue {
    /// The bytes handed to Noise.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// `BLAKE2s(hellos ‖ SpakeA ‖ SpakeB)`.
pub fn transcript_hash(
    viewer_hello: &[u8],
    host_hello: &[u8],
    spake_a: &PakeMessage,
    spake_b: &PakeMessage,
) -> [u8; 32] {
    let _ = (viewer_hello, host_hello, spake_a, spake_b);
    todo!()
}

/// `HKDF-SHA256(salt = exporter, ikm = K, info = PSK_INFO ‖ transcript)`.
pub fn derive_psk(exporter: &Exporter, k: &PakeKey, transcript: &[u8; 32]) -> Psk {
    let _ = (exporter, k, transcript);
    todo!()
}

/// `PROLOGUE_PREFIX ‖ exporter ‖ BLAKE2s(hellos)`.
pub fn prologue(exporter: &Exporter, viewer_hello: &[u8], host_hello: &[u8]) -> Prologue {
    let _ = (exporter, viewer_hello, host_hello);
    todo!()
}

#[cfg(test)]
mod tests {
    use hkdf::Hkdf;
    use sha2::Sha256;

    use super::*;

    #[test]
    fn psk_is_hkdf_sha256_of_k_salted_with_the_exporter() {
        let exporter = Exporter([0x11; 32]);
        let k = PakeKey([0x22; 32]);
        let t = [0x33; 32];
        let mut want = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&[0x11; 32]), &[0x22; 32])
            .expand_multi_info(&[PSK_INFO, &t], &mut want)
            .unwrap();
        assert_eq!(derive_psk(&exporter, &k, &t).0, want);
    }
}
