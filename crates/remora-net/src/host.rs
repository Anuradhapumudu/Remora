//! The host's async driver: accepts QUIC connections, feeds stream-0
//! frames and datagrams to the sans-IO [`remora_session::Host`], performs
//! its actions, and applies the [`crate::AUTH_FAILURE_FLOOR`].

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use remora_crypto::identity::IdentityPublic;
use remora_crypto::sas::Sas;
use remora_session::{
    AppMessage, ApproveError, CloseCode, FailReason, Host, HostConfig, SessionId, Step,
};
use tokio::sync::mpsc;

use crate::NetError;

/// What the host UI / CLI is told.
#[derive(Debug, Clone, PartialEq)]
pub enum HostEvent {
    /// Show the accept prompt.
    Prompt {
        /// Session.
        id: SessionId,
        /// Safety code to show.
        sas: Sas,
        /// Viewer's device name (untrusted).
        viewer_name: String,
        /// Viewer's identity key.
        viewer_key: IdentityPublic,
    },
    /// Withdraw the prompt for `id`.
    PromptClosed {
        /// Session.
        id: SessionId,
    },
    /// The session is active: show the indicator.
    Active {
        /// Session.
        id: SessionId,
    },
    /// An application message (Active only).
    Deliver {
        /// Session.
        id: SessionId,
        /// The message.
        msg: AppMessage,
    },
    /// A handshake failed (also logged as one WARN `handshake_failed`).
    Failed {
        /// Session.
        id: SessionId,
        /// Precise local reason.
        reason: FailReason,
        /// Where.
        step: Step,
        /// Password attempt number, if counted.
        attempt: Option<u32>,
        /// Peer address.
        peer: SocketAddr,
    },
    /// Three failures: a new password is in effect (show it).
    OtpRotated,
    /// The password was used: a new one is in effect (INV15).
    OtpUsed {
        /// Session that used it.
        id: SessionId,
    },
    /// The connection for `id` was closed with `code`.
    Closed {
        /// Session.
        id: SessionId,
        /// Code sent to the peer.
        code: CloseCode,
    },
}

/// A running host endpoint.
pub struct HostServer {
    pub(crate) endpoint: quinn::Endpoint,
    pub(crate) host: Arc<Mutex<Host>>,
    pub(crate) conns: Arc<Mutex<std::collections::HashMap<SessionId, quinn::Connection>>>,
    pub(crate) streams:
        Arc<Mutex<std::collections::HashMap<SessionId, mpsc::UnboundedSender<Vec<u8>>>>>,
    pub(crate) events: mpsc::UnboundedSender<HostEvent>,
    pub(crate) start: tokio::time::Instant,
}

impl std::fmt::Debug for HostServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostServer").finish_non_exhaustive()
    }
}

impl HostServer {
    /// Binds a QUIC endpoint on `addr` and starts accepting connections.
    pub async fn bind(
        addr: SocketAddr,
        config: HostConfig,
    ) -> Result<(HostServer, mpsc::UnboundedReceiver<HostEvent>), NetError> {
        let _ = (addr, config);
        todo!()
    }

    /// The bound address.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// The current one-time password (show it on the host's screen).
    pub fn otp(&self) -> remora_crypto::secret::Otp {
        todo!()
    }

    /// Issues a connection-code nonce valid for `ttl` (A06).
    pub fn issue_nonce(&self, ttl: std::time::Duration) -> [u8; 16] {
        let _ = ttl;
        todo!()
    }

    /// Accept on the prompt for `id` showing `sas`.
    pub fn approve(&self, id: SessionId, sas: Sas) -> Result<(), ApproveError> {
        let _ = (id, sas);
        todo!()
    }

    /// Deny the prompt for `id`.
    pub fn deny(&self, id: SessionId) {
        let _ = id;
        todo!()
    }

    /// Disconnect session `id` (any state).
    pub fn disconnect(&self, id: SessionId) {
        let _ = id;
        todo!()
    }

    /// Stops accepting and closes every connection.
    pub fn shutdown(&self) {
        self.endpoint
            .close(crate::to_varint(CloseCode::Normal), b"");
    }
}
