//! N4 (phase4-criteria §6, INV9): the `Debug` form of every type that
//! holds video content prints sizes, ids and times — never the content.
//! A `{:?}` in a log line or an error must not be a way to log the screen.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use remora_proto::limits::VIDEO_FRAGMENT_DATA;
use remora_proto::video::{Reassembler, ReassemblyEvent, packetize};
use remora_testkit::canary::find_windows;

/// A frame whose every byte is distinctive.
fn frame(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(73).wrapping_add(151))
        .collect()
}

fn assert_clean(what: &str, debug: &str, content: &[u8]) {
    let leaks = find_windows(debug, "frame", content, 16);
    assert!(leaks.is_empty(), "{what} prints content: {leaks:?}");
}

#[test]
fn n4_fragments_print_no_content() {
    let data = frame(3 * VIDEO_FRAGMENT_DATA);
    let frags = packetize(7, 1_000, true, &data, VIDEO_FRAGMENT_DATA).unwrap();
    for f in &frags {
        assert_clean("Fragment", &format!("{f:?}"), &data);
    }
}

#[test]
fn n4_a_reassembler_holding_part_of_a_frame_prints_no_content() {
    let data = frame(3 * VIDEO_FRAGMENT_DATA);
    let frags = packetize(7, 1_000, true, &data, VIDEO_FRAGMENT_DATA).unwrap();
    let mut r = Reassembler::new();
    // Two of three fragments: the frame is open, its bytes held inside.
    for f in &frags[..2] {
        assert!(r.push(f.flags, &f.body).is_empty());
    }
    assert_clean("Reassembler", &format!("{r:?}"), &data);
    // And the completed frame, as an event.
    let ev = r.push(frags[2].flags, &frags[2].body);
    assert!(matches!(ev[0], ReassemblyEvent::Frame(_)));
    assert_clean("ReassemblyEvent", &format!("{ev:?}"), &data);
}
