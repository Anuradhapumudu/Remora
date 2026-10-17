//! Copy-paste connection codes (protocol.md §2): `remora1:` + base64url (no
//! padding) of a binary offer/answer with a CRC-32 typo check.
//!
//! The code is **untrusted** (threat model §7.4): it only says where to connect
//! and which key to expect; authentication happens in the handshake.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::crc32::crc32;
use crate::limits::{CLOCK_SKEW_SECS, CODE_TEXT_MAX, CODE_VALIDITY_SECS, MAX_CANDIDATES};

/// Fixed part of the binary layout: version, kind, expiry, nonce, identity
/// key, ICE ufrag, ICE password, candidate count.
const FIXED_LEN: usize = 1 + 1 + 4 + 16 + 32 + 4 + 16 + 1;
const CRC_LEN: usize = 4;
const MIN_LEN: usize = FIXED_LEN + CRC_LEN;
const MAX_LEN: usize = FIXED_LEN + MAX_CANDIDATES * (1 + 16 + 2) + CRC_LEN;

/// Text prefix of every code.
pub const PREFIX: &str = "remora1:";
/// Binary format version.
pub const FORMAT_VERSION: u8 = 1;

/// Offer (host → viewer) or answer (viewer → host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeKind {
    /// Created by the host.
    Offer,
    /// Created by the viewer in reply.
    Answer,
}

/// Candidate type (ICE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// A local interface address.
    Host,
    /// The public address a STUN server saw.
    ServerReflexive,
}

/// One network address the peer can try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Candidate type.
    pub kind: CandidateKind,
    /// Address and port (port ≠ 0).
    pub addr: SocketAddr,
}

/// A decoded connection code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCode {
    /// Offer or answer.
    pub kind: CodeKind,
    /// Unix time (seconds) after which the code is invalid.
    pub expires_at: u32,
    /// Single-use nonce (the answer echoes the offer's).
    pub nonce: [u8; 16],
    /// Sender's Ed25519 identity public key (validated by `remora-crypto`).
    pub identity_key: [u8; 32],
    /// ICE username fragment.
    pub ice_ufrag: [u8; 4],
    /// ICE password.
    pub ice_pwd: [u8; 16],
    /// Up to [`crate::limits::MAX_CANDIDATES`] addresses.
    pub candidates: Vec<Candidate>,
}

/// Why a code was rejected. Checked in this order; nothing is decoded before
/// the length check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    /// Text longer than [`crate::limits::CODE_TEXT_MAX`].
    #[error("connection code too long")]
    TooLong,
    /// Missing `remora1:` prefix.
    #[error("not a Remora connection code")]
    BadPrefix,
    /// Not canonical base64url without padding.
    #[error("connection code is not valid base64url")]
    BadEncoding,
    /// Decoded length impossible for any valid code.
    #[error("connection code has an impossible length")]
    BadLength,
    /// CRC mismatch: almost certainly a copy-paste typo.
    #[error("connection code is damaged (typo?)")]
    Corrupted,
    /// A format version this build doesn't understand.
    #[error("unsupported connection code version {0}")]
    UnsupportedVersion(u8),
    /// Structurally invalid content.
    #[error("malformed connection code: {0}")]
    Malformed(&'static str),
    /// The code has expired.
    #[error("connection code expired")]
    Expired,
    /// Expiry further in the future than allowed (bad clock or forged code).
    #[error("connection code expiry is too far in the future")]
    FutureDated,
}

impl ConnectionCode {
    /// Encodes to `remora1:…` text. At most [`MAX_CANDIDATES`] candidates are
    /// written (any beyond that are left out).
    pub fn encode(&self) -> String {
        let mut b = Vec::with_capacity(MAX_LEN);
        b.push(FORMAT_VERSION);
        b.push(match self.kind {
            CodeKind::Offer => 0,
            CodeKind::Answer => 1,
        });
        b.extend_from_slice(&self.expires_at.to_be_bytes());
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.identity_key);
        b.extend_from_slice(&self.ice_ufrag);
        b.extend_from_slice(&self.ice_pwd);
        let candidates = &self.candidates[..self.candidates.len().min(MAX_CANDIDATES)];
        b.push(candidates.len() as u8);
        for c in candidates {
            let kind = match c.kind {
                CandidateKind::Host => 0,
                CandidateKind::ServerReflexive => 1,
            };
            match c.addr.ip() {
                IpAddr::V4(ip) => {
                    b.push(0x40 | kind);
                    b.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    b.push(0x60 | kind);
                    b.extend_from_slice(&ip.octets());
                }
            }
            b.extend_from_slice(&c.addr.port().to_be_bytes());
        }
        let crc = crc32(&b);
        b.extend_from_slice(&crc.to_be_bytes());
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&b))
    }

    /// Parses and validates `text` at time `now` (Unix seconds). Surrounding
    /// whitespace is ignored (pasted codes often carry a newline).
    pub fn parse(text: &str, now: u64) -> Result<Self, CodeError> {
        // Length first: nothing is decoded or allocated for oversized input.
        if text.len() > CODE_TEXT_MAX {
            return Err(CodeError::TooLong);
        }
        let body = text
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(CodeError::BadPrefix)?;
        let raw = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| CodeError::BadEncoding)?;
        if !(MIN_LEN..=MAX_LEN).contains(&raw.len()) {
            return Err(CodeError::BadLength);
        }
        let (payload, crc) = raw.split_at(raw.len() - CRC_LEN);
        let crc = u32::from_be_bytes([crc[0], crc[1], crc[2], crc[3]]);
        if crc32(payload) != crc {
            return Err(CodeError::Corrupted);
        }
        let mut r = Reader(payload);
        let version = r.u8()?;
        if version != FORMAT_VERSION {
            return Err(CodeError::UnsupportedVersion(version));
        }
        let kind = match r.u8()? {
            0 => CodeKind::Offer,
            1 => CodeKind::Answer,
            _ => return Err(CodeError::Malformed("kind")),
        };
        let expires_at = u32::from_be_bytes(r.array()?);
        let nonce = r.array()?;
        let identity_key = r.array()?;
        let ice_ufrag = r.array()?;
        let ice_pwd = r.array()?;
        let count = usize::from(r.u8()?);
        if count > MAX_CANDIDATES {
            return Err(CodeError::Malformed("too many candidates"));
        }
        let mut candidates = Vec::with_capacity(count);
        for _ in 0..count {
            candidates.push(r.candidate()?);
        }
        if !r.0.is_empty() {
            return Err(CodeError::Malformed("trailing bytes"));
        }
        let expires = u64::from(expires_at);
        if expires < now {
            return Err(CodeError::Expired);
        }
        if expires > now.saturating_add(CODE_VALIDITY_SECS + CLOCK_SKEW_SECS) {
            return Err(CodeError::FutureDated);
        }
        Ok(Self {
            kind,
            expires_at,
            nonce,
            identity_key,
            ice_ufrag,
            ice_pwd,
            candidates,
        })
    }
}

/// Bounds-checked reader over the decoded payload.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], CodeError> {
        let (head, tail) = self
            .0
            .split_at_checked(n)
            .ok_or(CodeError::Malformed("truncated"))?;
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, CodeError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodeError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| CodeError::Malformed("truncated"))
    }

    fn candidate(&mut self) -> Result<Candidate, CodeError> {
        let tag = self.u8()?;
        let kind = match tag & 0x0F {
            0 => CandidateKind::Host,
            1 => CandidateKind::ServerReflexive,
            _ => return Err(CodeError::Malformed("candidate type")),
        };
        let ip = match tag >> 4 {
            4 => IpAddr::V4(Ipv4Addr::from(self.array::<4>()?)),
            6 => IpAddr::V6(Ipv6Addr::from(self.array::<16>()?)),
            _ => return Err(CodeError::Malformed("address family")),
        };
        let port = u16::from_be_bytes(self.array()?);
        if port == 0 {
            return Err(CodeError::Malformed("port 0"));
        }
        let unusable = ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
        if unusable {
            return Err(CodeError::Malformed("unusable address"));
        }
        Ok(Candidate {
            kind,
            addr: SocketAddr::new(ip, port),
        })
    }
}
