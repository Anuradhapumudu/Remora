//! The viewer's async driver for one connection.

use std::net::SocketAddr;

use remora_crypto::identity::IdentityCert;
use remora_crypto::sas::Sas;
use remora_session::{AppMessage, CloseCode, FailReason, Step, ViewerConfig};
use tokio::sync::mpsc;

use crate::NetError;

/// What the viewer UI / CLI is told.
#[derive(Debug, Clone, PartialEq)]
pub enum ViewerEvent {
    /// Show the safety code.
    ShowSas {
        /// The code.
        sas: Sas,
        /// The host's verified identity.
        host: IdentityCert,
    },
    /// The host approved.
    Active,
    /// An application message from the host.
    Deliver(AppMessage),
    /// The session failed locally.
    Failed {
        /// Reason.
        reason: FailReason,
        /// Where.
        step: Step,
    },
    /// The connection ended. `remote` is the code the host closed with, if
    /// it closed first.
    Closed {
        /// Code we sent, if we closed.
        local: Option<CloseCode>,
        /// Code the host sent, if it closed.
        remote: Option<CloseCode>,
    },
}

/// Handle to a running viewer connection.
#[derive(Debug)]
pub struct ViewerClient {
    pub(crate) commands: mpsc::UnboundedSender<ViewerCommand>,
}

#[derive(Debug)]
pub(crate) enum ViewerCommand {
    Input(remora_proto::messages::Input),
    Disconnect,
}

/// Connects to a host at `addr` and runs the viewer side of the handshake.
pub async fn connect(
    addr: SocketAddr,
    config: ViewerConfig,
    nonce: [u8; 16],
) -> Result<(ViewerClient, mpsc::UnboundedReceiver<ViewerEvent>), NetError> {
    let _ = (addr, config, nonce);
    todo!()
}

impl ViewerClient {
    /// Sends an input event (dropped unless the session is Active).
    pub fn send_input(&self, input: remora_proto::messages::Input) {
        let _ = self.commands.send(ViewerCommand::Input(input));
    }

    /// Ends the session.
    pub fn disconnect(&self) {
        let _ = self.commands.send(ViewerCommand::Disconnect);
    }
}
