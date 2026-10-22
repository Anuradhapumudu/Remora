//! Protobuf messages for Phase 3 (protocol.md §3, §5), as Rust structs with
//! `prost` derives (decision D20). Decoding always goes through the `decode_*`
//! functions here, which check sizes before decoding and validate after.

/// How the viewer authenticates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Mode {
    /// Invalid on the wire.
    Unspecified = 0,
    /// One-time password (SPAKE2 + Noise XXpsk0).
    Password = 1,
    /// Pinned trusted device (Noise XX, no password).
    Trusted = 2,
}

/// Viewer → host, first message.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ViewerHello {
    /// Protocol major versions the viewer supports (1..=16 entries).
    #[prost(uint32, repeated, tag = "1")]
    pub versions: Vec<u32>,
    /// Authentication mode.
    #[prost(enumeration = "Mode", tag = "2")]
    pub mode: i32,
    /// Connection nonce (16 bytes).
    #[prost(bytes = "vec", tag = "3")]
    pub nonce: Vec<u8>,
}

/// Host → viewer, reply to [`ViewerHello`].
#[derive(Clone, PartialEq, prost::Message)]
pub struct HostHello {
    /// Chosen protocol major version.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// Host device ID (10 bytes).
    #[prost(bytes = "vec", tag = "2")]
    pub host_device_id: Vec<u8>,
}

/// Reveal of the host's SAS nonce (first Noise transport message).
#[derive(Clone, PartialEq, prost::Message)]
pub struct SasReveal {
    /// `n_r` (32 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub n_r: Vec<u8>,
}

/// Host: the accept prompt is showing.
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct SessionPending {}

/// Host: approved.
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct SessionAccept {
    /// Granted role (1 owner, 2 controller, 3 viewer).
    #[prost(uint32, tag = "1")]
    pub role: u32,
}

/// Host: denied or timed out.
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct SessionReject {
    /// 1 denied by user, 2 prompt timed out.
    #[prost(uint32, tag = "1")]
    pub reason: u32,
}

/// A sender announces its media key. `Debug` never prints the key.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct MediaKeyAnnounce {
    /// Key identifier used in datagram headers.
    #[prost(uint32, tag = "1")]
    pub key_id: u32,
    /// ChaCha20-Poly1305 key (32 bytes).
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
}

impl std::fmt::Debug for MediaKeyAnnounce {
    // The key is a secret (CLAUDE.md: never log secrets); prost's derived
    // Debug would print its bytes, and so would any Envelope holding it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaKeyAnnounce")
            .field("key_id", &self.key_id)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Orderly close.
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct Goodbye {}

/// Host → viewer: the video stream paused or resumed because screen
/// capture was interrupted (display asleep, …) and came back
/// (phase4-criteria §7, protocol.md §5 tag 16).
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct StreamState {
    /// `true`: paused; `false`: resumed.
    #[prost(bool, tag = "1")]
    pub paused: bool,
    /// When paused: 1 display unavailable, 2 access lost, 3 other,
    /// 4 display removed (a receiver treats unknown values as "other").
    /// Must be 0 when resumed.
    #[prost(uint32, tag = "2")]
    pub reason: u32,
    /// With reason 4 (display removed): milliseconds until the host gives
    /// up waiting and ends the session, counted from when this message is
    /// sent; the viewer counts down locally from when it received it. Sent
    /// again only if the deadline changes. 0 with every other reason and
    /// when resumed; at most [`crate::limits::PAUSE_REMAINING_MAX_MS`].
    /// Added 2026-10-22 as a minor addition (protocol.md §8): a viewer
    /// without this field ignores it.
    #[prost(uint32, tag = "3")]
    pub remaining_ms: u32,
}

/// Viewer → host: the viewer's decoder cannot continue (a frame was lost,
/// refused or failed to decode); send a keyframe (protocol.md §5 tag 9).
/// Phase 4 carries no fields; lost frame ids (for LTR recovery) come later.
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct RecoveryRequest {}

/// Mouse button press/release at normalised coordinates.
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct MouseButton {
    /// 1 left, 2 right, 3 middle.
    #[prost(uint32, tag = "1")]
    pub button: u32,
    /// Pressed (true) or released.
    #[prost(bool, tag = "2")]
    pub down: bool,
    /// 0..=1 within the monitor.
    #[prost(float, tag = "3")]
    pub x: f32,
    /// 0..=1 within the monitor.
    #[prost(float, tag = "4")]
    pub y: f32,
}

/// Key press/release by USB HID usage code.
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct Key {
    /// USB HID usage (physical key).
    #[prost(uint32, tag = "1")]
    pub usb_hid_usage: u32,
    /// Pressed (true) or released.
    #[prost(bool, tag = "2")]
    pub down: bool,
}

/// Control messages (reliable stream).
#[derive(Clone, PartialEq, prost::Message)]
pub struct Control {
    /// The message.
    #[prost(oneof = "control::Kind", tags = "2, 3, 4, 5, 6, 9, 14, 16")]
    pub kind: Option<control::Kind>,
}

/// Variants of [`Control`].
pub mod control {
    /// Control message kinds known to this build (protocol.md §5 tags).
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        /// SAS nonce reveal.
        #[prost(message, tag = "2")]
        SasReveal(super::SasReveal),
        /// Prompt showing.
        #[prost(message, tag = "3")]
        Pending(super::SessionPending),
        /// Approved.
        #[prost(message, tag = "4")]
        Accept(super::SessionAccept),
        /// Denied.
        #[prost(message, tag = "5")]
        Reject(super::SessionReject),
        /// Media key announcement.
        #[prost(message, tag = "6")]
        MediaKey(super::MediaKeyAnnounce),
        /// Keyframe request (viewer → host, Active only).
        #[prost(message, tag = "9")]
        Recovery(super::RecoveryRequest),
        /// Orderly close.
        #[prost(message, tag = "14")]
        Bye(super::Goodbye),
        /// Stream paused / resumed (host → viewer, Active only).
        #[prost(message, tag = "16")]
        StreamState(super::StreamState),
    }
}

/// Input messages (reliable stream).
#[derive(Clone, PartialEq, prost::Message)]
pub struct Input {
    /// The message.
    #[prost(oneof = "input::Kind", tags = "1, 2")]
    pub kind: Option<input::Kind>,
}

/// Variants of [`Input`].
pub mod input {
    /// Input kinds known to this build.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        /// Mouse button.
        #[prost(message, tag = "1")]
        Button(super::MouseButton),
        /// Keyboard key.
        #[prost(message, tag = "2")]
        Key(super::Key),
    }
}

/// Everything sent on the encrypted reliable stream.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Envelope {
    /// The message.
    #[prost(oneof = "envelope::Msg", tags = "1, 2")]
    pub msg: Option<envelope::Msg>,
}

/// Variants of [`Envelope`].
pub mod envelope {
    /// Top-level message classes.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Msg {
        /// Control.
        #[prost(message, tag = "1")]
        Control(super::Control),
        /// Input.
        #[prost(message, tag = "2")]
        Input(super::Input),
    }
}

/// Decoding/validation errors (all close the session: fail closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// Input larger than the limit for this message.
    #[error("message of {len} bytes exceeds the {max}-byte limit")]
    TooLarge {
        /// Input length.
        len: usize,
        /// Limit.
        max: usize,
    },
    /// Not valid protobuf.
    #[error("undecodable message")]
    Decode,
    /// Valid protobuf, invalid content.
    #[error("invalid message: {0}")]
    Invalid(&'static str),
}

fn check_len(bytes: &[u8], max: usize) -> Result<(), MessageError> {
    if bytes.len() > max {
        return Err(MessageError::TooLarge {
            len: bytes.len(),
            max,
        });
    }
    Ok(())
}

fn decode<M: prost::Message + Default>(bytes: &[u8], max: usize) -> Result<M, MessageError> {
    check_len(bytes, max)?;
    M::decode(bytes).map_err(|_| MessageError::Decode)
}

fn require(ok: bool, what: &'static str) -> Result<(), MessageError> {
    if ok {
        Ok(())
    } else {
        Err(MessageError::Invalid(what))
    }
}

/// Decodes and validates a [`ViewerHello`] (≤ [`crate::limits::HANDSHAKE_FRAME_MAX`] bytes).
pub fn decode_viewer_hello(bytes: &[u8]) -> Result<ViewerHello, MessageError> {
    use crate::limits::{HANDSHAKE_FRAME_MAX, MAX_VERSIONS};
    let h: ViewerHello = decode(bytes, HANDSHAKE_FRAME_MAX)?;
    require(
        !h.versions.is_empty() && h.versions.len() <= MAX_VERSIONS,
        "version list size",
    )?;
    require(h.versions.iter().all(|&v| v != 0), "version 0")?;
    require(
        matches!(Mode::try_from(h.mode), Ok(Mode::Password | Mode::Trusted)),
        "mode",
    )?;
    require(h.nonce.len() == 16, "nonce length")?;
    Ok(h)
}

/// Decodes and validates a [`HostHello`].
pub fn decode_host_hello(bytes: &[u8]) -> Result<HostHello, MessageError> {
    let h: HostHello = decode(bytes, crate::limits::HANDSHAKE_FRAME_MAX)?;
    require(h.version != 0, "version 0")?;
    require(h.host_device_id.len() == 10, "device id length")?;
    Ok(h)
}

fn unit_interval(v: f32) -> bool {
    v.is_finite() && (0.0..=1.0).contains(&v)
}

/// Decodes and validates an [`Envelope`] (≤ [`crate::limits::ENVELOPE_MAX`] bytes).
/// An envelope with no known message is invalid.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, MessageError> {
    let e: Envelope = decode(bytes, crate::limits::ENVELOPE_MAX)?;
    match &e.msg {
        None => return Err(MessageError::Invalid("empty or unknown envelope")),
        Some(envelope::Msg::Control(c)) => match &c.kind {
            None => return Err(MessageError::Invalid("empty or unknown control message")),
            Some(control::Kind::SasReveal(r)) => require(r.n_r.len() == 32, "SAS nonce length")?,
            Some(control::Kind::Accept(a)) => require((1..=3).contains(&a.role), "role")?,
            Some(control::Kind::Reject(r)) => {
                require((1..=2).contains(&r.reason), "reject reason")?
            }
            Some(control::Kind::MediaKey(k)) => {
                require(k.key.len() == 32, "media key length")?;
                // Datagram headers carry the id as u16 (protocol.md §6).
                require(k.key_id <= u32::from(u16::MAX), "media key id")?;
            }
            Some(
                control::Kind::Pending(_) | control::Kind::Bye(_) | control::Kind::Recovery(_),
            ) => {}
            Some(control::Kind::StreamState(st)) => {
                require(
                    st.paused == (st.reason != 0),
                    "stream state: paused needs a reason, resumed has none",
                )?;
                require(
                    st.paused || st.remaining_ms == 0,
                    "stream state: resumed has no time left",
                )?;
                require(
                    st.remaining_ms <= crate::limits::PAUSE_REMAINING_MAX_MS,
                    "stream state: time left",
                )?;
            }
        },
        Some(envelope::Msg::Input(i)) => match &i.kind {
            None => return Err(MessageError::Invalid("empty or unknown input message")),
            Some(input::Kind::Button(b)) => {
                require((1..=3).contains(&b.button), "mouse button")?;
                require(
                    unit_interval(b.x) && unit_interval(b.y),
                    "pointer coordinates",
                )?;
            }
            Some(input::Kind::Key(k)) => {
                require((1..=0xFFFF).contains(&k.usb_hid_usage), "HID usage")?
            }
        },
    }
    Ok(e)
}
