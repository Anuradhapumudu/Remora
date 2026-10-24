//! The one place media datagrams are handed to QUIC (phase4-criteria M2).
//!
//! [`MediaPath::send`] takes a [`SealedDatagram`], which only
//! `remora_crypto::media::MediaSender::seal` can make, and the policy
//! scanner allows quinn's `send_datagram` in **this file only**: so there is
//! no code path that sends media without our encryption (INV2). QUIC's own
//! encryption is not counted on for that - it would hide a missing seal
//! from anyone watching the wire.

use remora_crypto::media::SealedDatagram;

/// Media send path of one host (and the test tap).
#[derive(Debug, Default)]
pub(crate) struct MediaPath {
    /// Every payload handed to quinn, for the M1a test (feature
    /// `test-tap`, enabled only by this crate's own tests).
    #[cfg(feature = "test-tap")]
    pub(crate) tap: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>,
}

impl MediaPath {
    /// Hands one sealed datagram to QUIC. Loss is normal for datagrams
    /// (the viewer counts what it misses), so a refusal is not fatal.
    pub(crate) fn send(&self, conn: &quinn::Connection, datagram: SealedDatagram) {
        let bytes = datagram.into_bytes();
        #[cfg(feature = "test-tap")]
        if let Some(tap) = self
            .tap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let _ = tap.send(bytes.clone());
        }
        if let Err(e) = conn.send_datagram(bytes::Bytes::from(bytes)) {
            tracing::debug!(error = %e, "media datagram not sent");
        }
    }
}
