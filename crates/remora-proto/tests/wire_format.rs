//! Framing, message validation and datagram header — the behaviour every later
//! attack test relies on. Written before the implementation.

use prost::Message;
use remora_proto::datagram::{DatagramError, DatagramHeader, DatagramKind};
use remora_proto::frame::{FrameDecoder, FrameError, encode_frame};
use remora_proto::limits::HANDSHAKE_FRAME_MAX;
use remora_proto::messages::{
    Control, Envelope, HostHello, Input, Key, MediaKeyAnnounce, MessageError, Mode, MouseButton,
    SasReveal, SessionAccept, SessionReject, ViewerHello, control, decode_envelope,
    decode_host_hello, decode_viewer_hello, envelope, input,
};

// ── framing ──────────────────────────────────────────────────────────────────

#[test]
fn frames_round_trip_at_every_split_point() {
    let mut wire = Vec::new();
    for p in [vec![1u8], vec![2, 3], vec![4; 300]] {
        wire.extend(encode_frame(&p, HANDSHAKE_FRAME_MAX).expect("encode"));
    }
    for split in 0..=wire.len() {
        let mut d = FrameDecoder::new(HANDSHAKE_FRAME_MAX);
        let mut got = d.push(&wire[..split]).expect("first half");
        got.extend(d.push(&wire[split..]).expect("second half"));
        assert_eq!(
            got,
            vec![vec![1u8], vec![2, 3], vec![4; 300]],
            "split at {split}"
        );
    }
}

#[test]
fn empty_and_oversized_frames_are_rejected() {
    assert_eq!(encode_frame(&[], 10), Err(FrameError::Empty));
    assert_eq!(
        encode_frame(&[0; 11], 10),
        Err(FrameError::TooLarge { len: 11, max: 10 })
    );
    assert!(encode_frame(&[0; 10], 10).is_ok());
    let mut d = FrameDecoder::new(10);
    assert_eq!(d.push(&[0, 0]), Err(FrameError::Empty));
    assert_eq!(d.push(&[0, 1, 9]), Err(FrameError::Poisoned));
    let mut d = FrameDecoder::new(10);
    assert_eq!(
        d.push(&[0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .map(|v| v.len()),
        Ok(1),
        "exactly max is fine"
    );
}

// ── messages ─────────────────────────────────────────────────────────────────

fn hello() -> ViewerHello {
    ViewerHello {
        versions: vec![1],
        mode: Mode::Password as i32,
        nonce: vec![9; 16],
    }
}

#[test]
fn valid_hellos_decode() {
    assert_eq!(decode_viewer_hello(&hello().encode_to_vec()), Ok(hello()));
    let hh = HostHello {
        version: 1,
        host_device_id: vec![5; 10],
    };
    assert_eq!(decode_host_hello(&hh.encode_to_vec()), Ok(hh));
}

#[test]
fn invalid_hellos_are_rejected() {
    let bad = |h: ViewerHello| decode_viewer_hello(&h.encode_to_vec());
    assert!(matches!(
        bad(ViewerHello {
            versions: vec![],
            ..hello()
        }),
        Err(MessageError::Invalid(_))
    ));
    assert!(matches!(
        bad(ViewerHello {
            versions: vec![1; 17],
            ..hello()
        }),
        Err(MessageError::Invalid(_))
    ));
    assert!(
        matches!(
            bad(ViewerHello {
                versions: vec![0],
                ..hello()
            }),
            Err(MessageError::Invalid(_))
        ),
        "version 0"
    );
    assert!(matches!(
        bad(ViewerHello {
            nonce: vec![9; 15],
            ..hello()
        }),
        Err(MessageError::Invalid(_))
    ));
    assert!(
        matches!(
            bad(ViewerHello { mode: 0, ..hello() }),
            Err(MessageError::Invalid(_))
        ),
        "unspecified mode"
    );
    assert!(
        matches!(
            bad(ViewerHello {
                mode: 99,
                ..hello()
            }),
            Err(MessageError::Invalid(_))
        ),
        "unknown mode"
    );
    let hh = |id: usize, v: u32| {
        decode_host_hello(
            &HostHello {
                version: v,
                host_device_id: vec![5; id],
            }
            .encode_to_vec(),
        )
    };
    assert!(matches!(hh(9, 1), Err(MessageError::Invalid(_))));
    assert!(matches!(hh(10, 0), Err(MessageError::Invalid(_))));
    assert_eq!(
        decode_viewer_hello(&[0xFF, 0xFF, 0xFF]),
        Err(MessageError::Decode)
    );
}

fn ctl(kind: control::Kind) -> Vec<u8> {
    Envelope {
        msg: Some(envelope::Msg::Control(Control { kind: Some(kind) })),
    }
    .encode_to_vec()
}

fn inp(kind: input::Kind) -> Vec<u8> {
    Envelope {
        msg: Some(envelope::Msg::Input(Input { kind: Some(kind) })),
    }
    .encode_to_vec()
}

#[test]
fn valid_envelopes_decode() {
    for bytes in [
        ctl(control::Kind::SasReveal(SasReveal { n_r: vec![1; 32] })),
        ctl(control::Kind::Accept(SessionAccept { role: 2 })),
        ctl(control::Kind::Reject(SessionReject { reason: 1 })),
        ctl(control::Kind::MediaKey(MediaKeyAnnounce {
            key_id: 7,
            key: vec![3; 32],
        })),
        inp(input::Kind::Button(MouseButton {
            button: 1,
            down: true,
            x: 0.0,
            y: 1.0,
        })),
        inp(input::Kind::Key(Key {
            usb_hid_usage: 4,
            down: true,
        })),
    ] {
        assert!(decode_envelope(&bytes).is_ok(), "{bytes:?}");
    }
}

#[test]
fn invalid_envelopes_are_rejected() {
    let invalid = |b: Vec<u8>| matches!(decode_envelope(&b), Err(MessageError::Invalid(_)));
    assert!(
        invalid(Envelope { msg: None }.encode_to_vec()),
        "empty envelope"
    );
    assert!(
        invalid(vec![0x98, 0x06, 0x01]),
        "only an unknown field (tag 99)"
    );
    assert!(invalid(
        Envelope {
            msg: Some(envelope::Msg::Control(Control { kind: None }))
        }
        .encode_to_vec()
    ));
    assert!(invalid(ctl(control::Kind::SasReveal(SasReveal {
        n_r: vec![1; 31]
    }))));
    assert!(invalid(ctl(control::Kind::MediaKey(MediaKeyAnnounce {
        key_id: 7,
        key: vec![3; 31]
    }))));
    assert!(invalid(ctl(control::Kind::Accept(SessionAccept {
        role: 0
    }))));
    assert!(invalid(ctl(control::Kind::Accept(SessionAccept {
        role: 4
    }))));
    assert!(invalid(ctl(control::Kind::Reject(SessionReject {
        reason: 3
    }))));
    for (x, y) in [
        (f32::NAN, 0.5),
        (0.5, f32::INFINITY),
        (-0.01, 0.5),
        (0.5, 1.01),
    ] {
        assert!(
            invalid(inp(input::Kind::Button(MouseButton {
                button: 1,
                down: true,
                x,
                y
            }))),
            "({x},{y})"
        );
    }
    assert!(invalid(inp(input::Kind::Button(MouseButton {
        button: 4,
        down: true,
        x: 0.5,
        y: 0.5
    }))));
    assert!(invalid(inp(input::Kind::Key(Key {
        usb_hid_usage: 0,
        down: true
    }))));
    assert_eq!(
        decode_envelope(&[0x0A, 0xFF]),
        Err(MessageError::Decode),
        "truncated"
    );
}

// ── datagram header ──────────────────────────────────────────────────────────

fn header() -> DatagramHeader {
    DatagramHeader {
        kind: DatagramKind::VideoFragment,
        flags: 0b101,
        key_id: 0x0102,
        counter: 0x0304_0506_0708_090A,
        stream_id: 0x0B0C,
        layer_id: 0x0D,
    }
}

#[test]
fn datagram_header_layout_and_round_trip() {
    let h = header().encode();
    assert_eq!(
        h,
        [1, 0b101, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0],
        "protocol.md §6 layout"
    );
    let mut d = h.to_vec();
    d.extend_from_slice(&[0xEE; 16]); // body = just the tag
    assert_eq!(DatagramHeader::parse(&d), Ok((header(), &[0xEE; 16][..])));
}

#[test]
fn invalid_datagram_headers_are_rejected() {
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut d = header().encode().to_vec();
        d.extend_from_slice(&[0; 16]);
        f(&mut d);
        DatagramHeader::parse(&d).err()
    };
    assert_eq!(with(&|d| d.truncate(31)), Some(DatagramError::TooShort));
    assert_eq!(with(&|d| d[0] = 0), Some(DatagramError::UnknownKind(0)));
    assert_eq!(with(&|d| d[0] = 4), Some(DatagramError::UnknownKind(4)));
    assert_eq!(with(&|d| d[1] = 0b1000), Some(DatagramError::UnknownFlags));
    assert_eq!(with(&|d| d[15] = 1), Some(DatagramError::Reserved));
    assert_eq!(with(&|_| {}), None);
}
