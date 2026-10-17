//! phase3-criteria A26 / threat model INV7: every parser rejects oversized
//! input BEFORE allocating memory proportional to it. Measured with the
//! counting allocator (architecture.md D19). Written before the implementation.

use remora_proto::code::{CodeError, ConnectionCode};
use remora_proto::datagram::{DatagramError, DatagramHeader};
use remora_proto::frame::{FrameDecoder, FrameError};
use remora_proto::limits::{CODE_TEXT_MAX, DATAGRAM_MAX, ENVELOPE_MAX, HANDSHAKE_FRAME_MAX};
use remora_proto::messages::{MessageError, decode_envelope, decode_viewer_hello};
use remora_testkit::{CountingAlloc, count_allocations};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// "Nothing proportional": a small fixed budget, far below any input size used.
const SMALL: usize = 256;

#[test]
fn oversized_frame_prefix_rejected_before_buffering() {
    let mut d = FrameDecoder::new(HANDSHAKE_FRAME_MAX);
    let (r, stats) = count_allocations(|| d.push(&[0xFF, 0xFF]));
    assert_eq!(
        r,
        Err(FrameError::TooLarge {
            len: 0xFFFF,
            max: HANDSHAKE_FRAME_MAX
        })
    );
    assert!(stats.peak_bytes <= SMALL, "{stats:?}");
    assert_eq!(d.push(&[1, 0]), Err(FrameError::Poisoned), "fail closed");
}

#[test]
fn oversized_prefix_split_across_pushes_is_still_rejected() {
    let mut d = FrameDecoder::new(HANDSHAKE_FRAME_MAX);
    assert_eq!(d.push(&[0x10]), Ok(vec![]));
    assert_eq!(
        d.push(&[0x01]),
        Err(FrameError::TooLarge {
            len: 0x1001,
            max: HANDSHAKE_FRAME_MAX
        })
    );
}

#[test]
fn a_huge_push_never_buffers_more_than_one_frame() {
    // 1 MiB of input: one valid 3-byte frame, then a prefix claiming 0xFFFF.
    let mut input = vec![0, 3, 7, 7, 7, 0xFF, 0xFF];
    input.resize(1 << 20, 0xAB);
    let mut d = FrameDecoder::new(HANDSHAKE_FRAME_MAX);
    let (r, stats) = count_allocations(|| d.push(&input));
    assert_eq!(
        r,
        Err(FrameError::TooLarge {
            len: 0xFFFF,
            max: HANDSHAKE_FRAME_MAX
        })
    );
    assert!(
        stats.peak_bytes <= HANDSHAKE_FRAME_MAX + SMALL,
        "buffered the input: {stats:?}"
    );
}

#[test]
fn huge_connection_code_rejected_before_decoding() {
    let text = "A".repeat(1 << 20);
    let (r, stats) = count_allocations(|| ConnectionCode::parse(&text, 0));
    assert_eq!(r, Err(CodeError::TooLong));
    assert!(stats.peak_bytes <= SMALL, "{stats:?}");
    let just_over = "A".repeat(CODE_TEXT_MAX + 1);
    assert_eq!(
        ConnectionCode::parse(&just_over, 0),
        Err(CodeError::TooLong)
    );
}

#[test]
fn oversized_messages_rejected_before_decoding() {
    let big = vec![0u8; ENVELOPE_MAX + 1];
    let (r, stats) = count_allocations(|| decode_envelope(&big));
    assert_eq!(
        r,
        Err(MessageError::TooLarge {
            len: ENVELOPE_MAX + 1,
            max: ENVELOPE_MAX
        })
    );
    assert!(stats.peak_bytes <= SMALL, "{stats:?}");

    let big_hello = vec![0u8; HANDSHAKE_FRAME_MAX + 1];
    let (r, stats) = count_allocations(|| decode_viewer_hello(&big_hello));
    assert!(matches!(r, Err(MessageError::TooLarge { .. })));
    assert!(stats.peak_bytes <= SMALL, "{stats:?}");
}

#[test]
fn repeated_field_flood_is_bounded_by_the_frame_limit() {
    // A ViewerHello listing 1000 versions (packed varints, ~1 KB on the wire).
    let mut wire = vec![0x0A]; // field 1, length-delimited (packed)
    wire.push(0xE8); // varint 1000
    wire.push(0x07);
    wire.extend(std::iter::repeat_n(1u8, 1000));
    let (r, stats) = count_allocations(|| decode_viewer_hello(&wire));
    assert!(matches!(r, Err(MessageError::Invalid(_))), "{r:?}");
    assert!(
        stats.peak_bytes <= 16 * HANDSHAKE_FRAME_MAX,
        "allocation must stay bounded by the frame limit: {stats:?}"
    );
}

#[test]
fn datagram_header_parsing_allocates_nothing() {
    let mut dgram = vec![1u8, 0, 0, 1];
    dgram.resize(DATAGRAM_MAX, 0);
    let (r, stats) =
        count_allocations(|| DatagramHeader::parse(&dgram).map(|(h, body)| (h, body.len())));
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(stats.total_bytes, 0, "{stats:?}");
    assert_eq!(
        DatagramHeader::parse(&vec![1u8; DATAGRAM_MAX + 1]).err(),
        Some(DatagramError::TooLong)
    );
}

#[test]
fn a_huge_push_completing_a_split_prefix_never_buffers_the_input() {
    // The prefix arrives split (slow path), then 1 MiB in a single push: the
    // rest of the prefix, a 256-byte body, then a prefix claiming 0xFFFF.
    let mut d = FrameDecoder::new(HANDSHAKE_FRAME_MAX);
    assert_eq!(d.push(&[0x01]), Ok(vec![]));
    let mut input = vec![0x00];
    input.extend_from_slice(&[7; 256]);
    input.extend_from_slice(&[0xFF, 0xFF]);
    input.resize(1 << 20, 0xAB);
    let (r, stats) = count_allocations(|| d.push(&input));
    assert_eq!(
        r,
        Err(FrameError::TooLarge {
            len: 0xFFFF,
            max: HANDSHAKE_FRAME_MAX
        })
    );
    assert!(
        stats.peak_bytes <= HANDSHAKE_FRAME_MAX + SMALL,
        "buffered the input: {stats:?}"
    );
}
