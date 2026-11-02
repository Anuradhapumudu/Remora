//! phase4.8-criteria A3 (and A5's shape): an audio datagram's body is
//! untrusted. It is parsed with limits checked before anything is kept:
//! malformed, empty or oversized packets are refused, never decoded.
//! Written before the parser exists.

use remora_proto::audio::{AUDIO_BODY_HEADER_LEN, AudioError, AudioPacket, MAX_OPUS_BYTES};
use remora_proto::datagram::DatagramKind;

fn body(seq: u32, ts: u64, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(data);
    b
}

#[test]
fn a_packet_round_trips() {
    let p = AudioPacket {
        seq: 7,
        capture_ts_us: 1_234_567,
        data: vec![0xAB; 320],
    };
    let wire = p.encode();
    assert_eq!(wire.len(), AUDIO_BODY_HEADER_LEN + 320);
    assert_eq!(AudioPacket::parse(&wire), Ok(p));
}

#[test]
fn a3_short_empty_and_oversized_bodies_are_refused() {
    assert_eq!(AudioPacket::parse(&[]), Err(AudioError::TooShort));
    assert_eq!(
        AudioPacket::parse(&[0; AUDIO_BODY_HEADER_LEN - 1]),
        Err(AudioError::TooShort)
    );
    assert_eq!(AudioPacket::parse(&body(1, 2, &[])), Err(AudioError::Empty));
    assert!(AudioPacket::parse(&body(1, 2, &vec![1; MAX_OPUS_BYTES])).is_ok());
    assert_eq!(
        AudioPacket::parse(&body(1, 2, &vec![1; MAX_OPUS_BYTES + 1])),
        Err(AudioError::TooLong)
    );
}

#[test]
fn a3_a_full_audio_datagram_fits_the_video_datagram_target() {
    use remora_proto::limits::{AEAD_TAG_LEN, DATAGRAM_HEADER_LEN, VIDEO_DATAGRAM_TARGET};
    // Checked when the test compiles: a constant fact about the limits.
    const _: () = assert!(
        DATAGRAM_HEADER_LEN + AUDIO_BODY_HEADER_LEN + MAX_OPUS_BYTES + AEAD_TAG_LEN
            <= VIDEO_DATAGRAM_TARGET
    );
}

#[test]
fn the_audio_kind_is_on_the_wire() {
    use remora_proto::datagram::DatagramHeader;
    let h = DatagramHeader {
        kind: DatagramKind::AudioPacket,
        flags: 0,
        key_id: 1,
        counter: 9,
        stream_id: 0,
        layer_id: 0,
    };
    let enc = h.encode();
    assert_eq!(enc[0], 0x04, "protocol.md: 0x04 audio packet");
    let mut datagram = enc.to_vec();
    datagram.extend_from_slice(&[0; 16]); // a body's worth: at least the AEAD tag
    let (back, _) = DatagramHeader::parse(&datagram).expect("parse");
    assert_eq!(back, h);
}
