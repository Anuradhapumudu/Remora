//! Size limits (protocol.md §7). Checked before allocation.

/// Plaintext handshake frame (hellos, SPAKE2 messages).
pub const HANDSHAKE_FRAME_MAX: usize = 4096;
/// Noise frame: Noise's own maximum message size.
pub const NOISE_FRAME_MAX: usize = 65_535;
/// Noise authentication tag.
pub const AEAD_TAG_LEN: usize = 16;
/// Largest protobuf `Envelope` (a Noise frame minus its tag).
pub const ENVELOPE_MAX: usize = NOISE_FRAME_MAX - AEAD_TAG_LEN;
/// Connection-code text, checked before decoding.
pub const CODE_TEXT_MAX: usize = 1024;
/// Candidates per connection code.
pub const MAX_CANDIDATES: usize = 8;
/// Device name in an identity certificate (UTF-8 bytes).
pub const DEVICE_NAME_MAX: usize = 64;
/// Generic cap on repeated protobuf fields.
pub const MAX_REPEATED: usize = 64;
/// Protocol versions a `ViewerHello` may list.
pub const MAX_VERSIONS: usize = 16;
/// Connection-code validity window.
pub const CODE_VALIDITY_SECS: u64 = 300;
/// Clock-skew allowance when judging a code's expiry.
pub const CLOCK_SKEW_SECS: u64 = 30;
/// Clear media-datagram header.
pub const DATAGRAM_HEADER_LEN: usize = 16;
/// Largest datagram we accept (one QUIC DATAGRAM frame on any sane path).
pub const DATAGRAM_MAX: usize = 1500;
