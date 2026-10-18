//! Throw-away TLS for QUIC (D1): TLS here is plumbing, not authentication.
//!
//! The server presents a fresh self-signed certificate; the client accepts
//! any certificate. That is safe **only** because the peers authenticate
//! with SPAKE2 + Noise and bind this TLS session into the Noise prologue
//! with the exporter: a MITM that terminates TLS gets two different
//! exporters and the Noise handshake fails (A14). The client still checks
//! the TLS 1.3 handshake signature against the certificate it was shown,
//! so the TLS layer itself is internally consistent.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::NetError;

/// ALPN protocol identifier.
pub const ALPN: &[u8] = b"remora/1";
/// SNI / certificate name (never resolved; `.invalid` is reserved).
pub const SERVER_NAME: &str = "remora.invalid";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn cfg_err(e: impl std::fmt::Display) -> NetError {
    NetError::Config(e.to_string())
}

/// A server configuration with a freshly generated self-signed certificate,
/// ALPN [`ALPN`] and QUIC datagrams enabled.
pub fn server_config() -> Result<quinn::ServerConfig, NetError> {
    let ck = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).map_err(cfg_err)?;
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(cfg_err)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(cfg_err)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).map_err(cfg_err)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
}

/// A client configuration that accepts **any** server certificate (the
/// peer is authenticated by SPAKE2 + Noise instead) but still verifies the
/// TLS 1.3 handshake signature against the certificate presented.
pub fn client_config() -> Result<quinn::ClientConfig, NetError> {
    let provider = provider();
    let verifier = AnyCertificate {
        algorithms: provider.signature_verification_algorithms,
    };
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(cfg_err)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(cfg_err)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

/// Accepts any certificate (see the module docs for why that is safe
/// here) and verifies the TLS 1.3 handshake signature with it.
#[derive(Debug)]
struct AnyCertificate {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is never negotiated (TLS 1.3 only).
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
