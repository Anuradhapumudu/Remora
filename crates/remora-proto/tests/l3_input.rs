//! phase4.6-criteria L3: every input field is checked when the envelope is
//! decoded, before anything can reach an injector. Written before the new
//! kinds (`PointerMove`, `Scroll`, `ReleaseAll`) exist.

use prost::Message;
use remora_proto::limits::SCROLL_MAX;
use remora_proto::messages::{
    Envelope, Input, Key, MessageError, MouseButton, PointerMove, ReleaseAll, Scroll,
    decode_envelope, envelope, input,
};

fn wire(kind: input::Kind) -> Vec<u8> {
    Envelope {
        msg: Some(envelope::Msg::Input(Input { kind: Some(kind) })),
    }
    .encode_to_vec()
}

fn accepted(kind: input::Kind) -> bool {
    decode_envelope(&wire(kind)).is_ok()
}

fn refused(kind: input::Kind) -> bool {
    matches!(decode_envelope(&wire(kind)), Err(MessageError::Invalid(_)))
}

const BAD_FLOATS: [f32; 6] = [
    f32::NAN,
    f32::INFINITY,
    f32::NEG_INFINITY,
    -0.001,
    1.001,
    1e30,
];

#[test]
fn pointer_move_inside_the_monitor_is_accepted() {
    for (x, y) in [(0.0, 0.0), (1.0, 1.0), (0.5, 0.25)] {
        assert!(accepted(input::Kind::Move(PointerMove { x, y })), "{x},{y}");
    }
}

#[test]
fn pointer_move_outside_or_not_a_number_is_refused() {
    for v in BAD_FLOATS {
        assert!(
            refused(input::Kind::Move(PointerMove { x: v, y: 0.5 })),
            "x={v}"
        );
        assert!(
            refused(input::Kind::Move(PointerMove { x: 0.5, y: v })),
            "y={v}"
        );
    }
}

#[test]
fn buttons_left_right_middle_back_forward_only() {
    let b = |button| MouseButton {
        button,
        down: true,
        x: 0.5,
        y: 0.5,
    };
    for ok in 1..=5 {
        assert!(accepted(input::Kind::Button(b(ok))), "button {ok}");
    }
    for bad in [0, 6, 255, u32::MAX] {
        assert!(refused(input::Kind::Button(b(bad))), "button {bad}");
    }
}

#[test]
fn scroll_is_finite_and_bounded() {
    let s = |dx, dy| {
        input::Kind::Scroll(Scroll {
            dx,
            dy,
            precise: true,
        })
    };
    assert!(accepted(s(0.0, -3.0)));
    assert!(accepted(s(SCROLL_MAX, -SCROLL_MAX)));
    for v in [
        f32::NAN,
        f32::INFINITY,
        SCROLL_MAX * 1.01,
        -SCROLL_MAX * 1.01,
    ] {
        assert!(refused(s(v, 0.0)), "dx={v}");
        assert!(refused(s(0.0, v)), "dy={v}");
    }
}

#[test]
fn release_all_is_accepted() {
    assert!(accepted(input::Kind::ReleaseAll(ReleaseAll {})));
}

#[test]
fn key_zero_is_refused() {
    assert!(refused(input::Kind::Key(Key {
        usb_hid_usage: 0,
        down: true
    })));
    assert!(accepted(input::Kind::Key(Key {
        usb_hid_usage: 0x04, // A
        down: true
    })));
}
