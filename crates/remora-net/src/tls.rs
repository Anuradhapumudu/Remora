//! Throw-away TLS for QUIC (D1): TLS here is plumbing, not authentication.

use crate::NetError;

/// ALPN protocol identifier.
pub const ALPN: &[u8] = b"remora/1";
/// SNI / certificate name (never resolved; `.invalid` is reserved).
pub const SERVER_NAME: &str = "remora.invalid";

/// A server configuration with a freshly generated self-signed certificate,
/// ALPN [`ALPN`] and QUIC datagrams enabled.
pub fn server_config() -> Result<quinn::ServerConfig, NetError> {
    todo!()
}

/// A client configuration that accepts **any** server certificate (the
/// peer is authenticated by SPAKE2 + Noise instead) but still verifies the
/// TLS 1.3 handshake signature against the certificate presented.
pub fn client_config() -> Result<quinn::ClientConfig, NetError> {
    todo!()
}
