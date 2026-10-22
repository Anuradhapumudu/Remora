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
/// Fragments of one video frame (protocol.md §7).
pub const MAX_FRAGMENTS: usize = 8192;
/// One reassembled video frame (protocol.md §7; dropped, not fatal).
pub const FRAME_MAX: usize = 8 * 1024 * 1024;
/// Video frames being reassembled at once; beyond this the oldest is dropped.
pub const MAX_OPEN_FRAMES: usize = 16;
/// All fragments held for reassembly together (Phase 4 addition: without
/// it, 16 open frames of 8 MiB would allow 128 MiB from a malicious host,
/// most of the viewer's 150 MB budget). Oldest frames are dropped first.
pub const REASSEMBLY_BYTES_MAX: usize = 32 * 1024 * 1024;
/// Largest `StreamState.remaining_ms` (1 hour): the host waits 2 minutes
/// for a removed display (roadmap D-29), so anything near this is a bug
/// or a hostile host; refusing it keeps the viewer's countdown sane.
pub const PAUSE_REMAINING_MAX_MS: u32 = 3_600_000;
/// Plaintext header of a video-fragment body (protocol.md §6).
pub const FRAGMENT_HEADER_LEN: usize = 18;
/// Largest media datagram the host sends (protocol.md §6): with QUIC's
/// own overhead the UDP payload stays under 1200 bytes, the size every
/// QUIC path must carry (quinn-proto 0.11.19 `src/config/transport.rs:646-649`:
/// "a QUIC endpoint can split outgoing data in packets of 1200 bytes"), so
/// no path-MTU discovery is needed.
pub const VIDEO_DATAGRAM_TARGET: usize = 1100;
/// Video data bytes in one fragment: the target minus the clear header,
/// the fragment header and the AEAD tag.
pub const VIDEO_FRAGMENT_DATA: usize =
    VIDEO_DATAGRAM_TARGET - DATAGRAM_HEADER_LEN - FRAGMENT_HEADER_LEN - AEAD_TAG_LEN;
