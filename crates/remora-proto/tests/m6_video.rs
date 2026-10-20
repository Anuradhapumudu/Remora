//! Phase 4 step 3: video fragmentation and reassembly (protocol.md §6–§7),
//! including the M6 attacks (phase4-criteria §5): every limit is enforced
//! BEFORE storing or allocating, measured with the counting allocator
//! (architecture.md D19). Written before the implementation.
//!
//! What would these still pass with if a limit were removed? Each attack
//! test checks both the outcome (rejected / dropped with its reason) AND
//! that nothing proportional to the hostile input was allocated or kept
//! (`bytes_in_flight`, `peak_bytes`), so a check that runs only after
//! storing the data fails.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use remora_proto::datagram::{FLAG_KEYFRAME, FLAG_LAST};
use remora_proto::limits::{
    FRAGMENT_HEADER_LEN, FRAME_MAX, MAX_FRAGMENTS, MAX_OPEN_FRAMES, REASSEMBLY_BYTES_MAX,
};
use remora_proto::video::{
    DropReason, FragmentError, FragmentHeader, PacketizeError, Reassembler, ReassemblyEvent,
    VideoFrame, packetize,
};
use remora_testkit::{CountingAlloc, count_allocations};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// "Nothing proportional": a small fixed budget.
const SMALL: usize = 512;

fn header(frame_id: u32, frag_index: u16, frag_count: u16) -> FragmentHeader {
    FragmentHeader {
        frame_id,
        frag_index,
        frag_count,
        fec_group: 0,
        capture_ts_us: 1_000 + u64::from(frame_id),
    }
}

fn last_flag(h: &FragmentHeader) -> u8 {
    if h.frag_index + 1 == h.frag_count {
        FLAG_LAST
    } else {
        0
    }
}

/// Pushes a fragment with consistent flags (keyframe off).
fn push(r: &mut Reassembler, h: FragmentHeader, data: &[u8]) -> Vec<ReassemblyEvent> {
    r.push(last_flag(&h), &h.encode_with(data))
}

fn frames(ev: &[ReassemblyEvent]) -> Vec<&VideoFrame> {
    ev.iter()
        .filter_map(|e| match e {
            ReassemblyEvent::Frame(f) => Some(f),
            _ => None,
        })
        .collect()
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

// ------------------------------------------------------------ format --

#[test]
fn fragment_body_layout_is_exactly_protocol_section_6() {
    let h = FragmentHeader {
        frame_id: 0x0102_0304,
        frag_index: 0x0506,
        frag_count: 0x0708,
        fec_group: 0,
        capture_ts_us: 0x1112_1314_1516_1718,
    };
    let body = h.encode_with(&[0xAA, 0xBB]);
    assert_eq!(
        body,
        vec![
            1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0xAA,
            0xBB
        ]
    );
    assert_eq!(FRAGMENT_HEADER_LEN, 18);
    let (parsed, data) = FragmentHeader::parse(&body).unwrap();
    assert_eq!(parsed, h);
    assert_eq!(data, &[0xAA, 0xBB]);
}

#[test]
fn malformed_bodies_are_rejected() {
    let ok = header(1, 0, 1).encode_with(&[7]);
    assert_eq!(
        FragmentHeader::parse(&ok[..FRAGMENT_HEADER_LEN]),
        Err(FragmentError::TooShort),
        "no data"
    );
    assert_eq!(
        FragmentHeader::parse(&ok[..5]),
        Err(FragmentError::TooShort)
    );
    assert_eq!(FragmentHeader::parse(&[]), Err(FragmentError::TooShort));
    let bad = |h: FragmentHeader| FragmentHeader::parse(&h.encode_with(&[1])).unwrap_err();
    assert_eq!(bad(header(1, 0, 0)), FragmentError::BadCount(0));
    let over = (MAX_FRAGMENTS + 1) as u16;
    assert_eq!(bad(header(1, 0, over)), FragmentError::BadCount(over));
    assert_eq!(
        bad(header(1, 3, 3)),
        FragmentError::BadIndex { index: 3, count: 3 }
    );
    let mut fec = header(1, 0, 1);
    fec.fec_group = 1;
    assert_eq!(bad(fec), FragmentError::UnsupportedFec);
    // The largest legal count is accepted.
    assert!(FragmentHeader::parse(&header(1, 0, MAX_FRAGMENTS as u16).encode_with(&[1])).is_ok());
}

// --------------------------------------------------------- packetize --

#[test]
fn packetize_round_trips_and_sets_the_flags() {
    let data = pattern(10_000, 3);
    let frags = packetize(7, 42, true, &data, 1_000).unwrap();
    assert_eq!(frags.len(), 10);
    let mut r = Reassembler::new();
    let mut got = Vec::new();
    for (i, f) in frags.iter().enumerate() {
        assert_ne!(
            f.flags & FLAG_KEYFRAME,
            0,
            "every fragment of a keyframe says so"
        );
        assert_eq!(f.flags & FLAG_LAST != 0, i == frags.len() - 1);
        let (h, d) = FragmentHeader::parse(&f.body).unwrap();
        assert_eq!(
            (h.frame_id, h.frag_index, h.frag_count, h.capture_ts_us),
            (7, i as u16, 10, 42)
        );
        assert!(d.len() <= 1_000);
        got.extend(r.push(f.flags, &f.body));
    }
    let fs = frames(&got);
    assert_eq!(fs.len(), 1);
    assert_eq!(fs[0].data, data);
    assert!(fs[0].keyframe);
    assert_eq!(fs[0].capture_ts_us, 42);
    // A P-frame carries no keyframe flag; an uneven split keeps every byte.
    let frags = packetize(8, 43, false, &pattern(2_501, 9), 1_000).unwrap();
    assert_eq!(frags.len(), 3);
    assert!(frags.iter().all(|f| f.flags & FLAG_KEYFRAME == 0));
}

#[test]
fn packetize_refuses_what_a_viewer_would_refuse() {
    assert_eq!(
        packetize(1, 0, true, &[], 1_000),
        Err(PacketizeError::Empty)
    );
    assert_eq!(packetize(1, 0, true, &[1], 0), Err(PacketizeError::NoRoom));
    let too_many = vec![0u8; MAX_FRAGMENTS * 10 + 1];
    assert_eq!(
        packetize(1, 0, true, &too_many, 10),
        Err(PacketizeError::TooLarge(too_many.len()))
    );
    let too_big = vec![0u8; FRAME_MAX + 1];
    assert_eq!(
        packetize(1, 0, true, &too_big, 1_200),
        Err(PacketizeError::TooLarge(FRAME_MAX + 1))
    );
    // Exactly at the limits is fine.
    assert_eq!(
        packetize(1, 0, true, &vec![0u8; MAX_FRAGMENTS], 1)
            .unwrap()
            .len(),
        MAX_FRAGMENTS
    );
}

// -------------------------------------------------------- reassembly --

#[test]
fn fragments_in_any_order_make_one_frame_and_frames_report_gaps() {
    let mut r = Reassembler::new();
    let d = pattern(3_000, 1);
    let mut ev = Vec::new();
    for i in [2u16, 0, 1] {
        let part = &d[usize::from(i) * 1_000..usize::from(i + 1) * 1_000];
        ev.extend(push(&mut r, header(1, i, 3), part));
    }
    let fs = frames(&ev);
    assert_eq!(fs.len(), 1);
    assert_eq!(fs[0].data, d);
    assert!(!fs[0].follows_previous, "the first frame follows nothing");
    let ev = push(&mut r, header(2, 0, 1), &[5]);
    assert!(frames(&ev)[0].follows_previous);
    let ev = push(&mut r, header(4, 0, 1), &[5]);
    assert!(!frames(&ev)[0].follows_previous, "frame 3 is missing");
    assert_eq!(r.open_frames(), 0);
    assert_eq!(r.bytes_in_flight(), 0);
}

#[test]
fn a_newer_complete_frame_abandons_older_incomplete_ones() {
    let mut r = Reassembler::new();
    push(&mut r, header(1, 0, 2), &[1; 100]); // frame 1 waits for its 2nd fragment
    let ev = push(&mut r, header(2, 0, 1), &[2; 10]);
    assert!(ev.contains(&ReassemblyEvent::Dropped {
        frame_id: 1,
        reason: DropReason::Superseded
    }));
    assert_eq!(frames(&ev)[0].frame_id, 2);
    assert_eq!(r.bytes_in_flight(), 0, "frame 1's bytes are released");
    // Its missing fragment arriving now is late, not a frame.
    let ev = push(&mut r, header(1, 1, 2), &[1; 100]);
    assert_eq!(ev, vec![ReassemblyEvent::Late { frame_id: 1 }]);
    // So is anything for a frame already delivered.
    let ev = push(&mut r, header(2, 0, 1), &[2; 10]);
    assert_eq!(ev, vec![ReassemblyEvent::Late { frame_id: 2 }]);
}

#[test]
fn a_duplicate_fragment_is_not_counted_twice() {
    let mut r = Reassembler::new();
    push(&mut r, header(1, 0, 2), &[1; 10]);
    let ev = push(&mut r, header(1, 0, 2), &[9; 10]);
    assert!(
        frames(&ev).is_empty(),
        "a duplicate does not complete the frame"
    );
    assert_eq!(r.bytes_in_flight(), 10);
    let ev = push(&mut r, header(1, 1, 2), &[3; 5]);
    let fs = frames(&ev);
    assert_eq!(
        fs[0].data,
        [vec![1; 10], vec![3; 5]].concat(),
        "first copy kept"
    );
}

// ----------------------------------------------------------- M6 attacks --

#[test]
fn m6_bad_counts_and_indexes_are_rejected_before_allocating() {
    let mut r = Reassembler::new();
    for (h, err) in [
        (header(1, 0, 0), FragmentError::BadCount(0)),
        (
            header(1, 0, (MAX_FRAGMENTS + 1) as u16),
            FragmentError::BadCount((MAX_FRAGMENTS + 1) as u16),
        ),
        (
            header(1, 9, 9),
            FragmentError::BadIndex { index: 9, count: 9 },
        ),
    ] {
        let body = h.encode_with(&[1; 64]);
        let (ev, stats) = count_allocations(|| r.push(0, &body));
        assert_eq!(ev, vec![ReassemblyEvent::Rejected(err)]);
        assert!(stats.peak_bytes <= SMALL, "{err:?}: {stats:?}");
    }
    assert_eq!(r.open_frames(), 0);
    assert_eq!(r.bytes_in_flight(), 0);
}

#[test]
fn m6_a_zero_length_fragment_is_rejected() {
    let mut r = Reassembler::new();
    let body = header(1, 0, 1).encode_with(&[]);
    assert_eq!(
        r.push(FLAG_LAST, &body),
        vec![ReassemblyEvent::Rejected(FragmentError::TooShort)]
    );
}

#[test]
fn m6_a_last_flag_that_disagrees_with_the_index_is_rejected() {
    let mut r = Reassembler::new();
    let body = header(1, 0, 2).encode_with(&[1]);
    assert_eq!(
        r.push(FLAG_LAST, &body),
        vec![ReassemblyEvent::Rejected(FragmentError::BadLastFlag)]
    );
    let body = header(1, 1, 2).encode_with(&[1]);
    assert_eq!(
        r.push(0, &body),
        vec![ReassemblyEvent::Rejected(FragmentError::BadLastFlag)]
    );
}

#[test]
fn m6_fragments_that_disagree_drop_their_frame() {
    // count changes, keyframe flag changes, capture time changes
    for second in [
        (0u8, {
            let mut h = header(1, 1, 3);
            h.frag_count = 3;
            h
        }),
        (FLAG_KEYFRAME, header(1, 1, 2)),
        (0, {
            let mut h = header(1, 1, 2);
            h.capture_ts_us += 1;
            h
        }),
    ] {
        let mut r = Reassembler::new();
        push(&mut r, header(1, 0, 2), &[1; 10]);
        let (flags, h) = second;
        let ev = r.push(flags | last_flag(&h), &h.encode_with(&[2; 10]));
        assert!(
            ev.contains(&ReassemblyEvent::Dropped {
                frame_id: 1,
                reason: DropReason::Inconsistent
            }),
            "{ev:?}"
        );
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.open_frames(), 0);
    }
}

#[test]
fn m6_a_frame_over_8_mib_is_dropped_before_the_overflowing_fragment_is_kept() {
    let mut r = Reassembler::new();
    let chunk = vec![7u8; 1_400];
    let count = (FRAME_MAX / chunk.len() + 2) as u16; // more fragments than fit
    let mut dropped = false;
    let mut peak_in_flight = 0;
    for i in 0..count - 1 {
        let ev = push(&mut r, header(1, i, count), &chunk);
        peak_in_flight = peak_in_flight.max(r.bytes_in_flight());
        if ev.contains(&ReassemblyEvent::Dropped {
            frame_id: 1,
            reason: DropReason::TooLarge,
        }) {
            dropped = true;
            break;
        }
    }
    assert!(
        dropped,
        "the frame must be dropped once it exceeds FRAME_MAX"
    );
    assert!(
        peak_in_flight <= FRAME_MAX,
        "never held more than FRAME_MAX: {peak_in_flight}"
    );
    assert_eq!(r.bytes_in_flight(), 0);
}

#[test]
fn m6_more_than_16_open_frames_evict_the_oldest() {
    let mut r = Reassembler::new();
    for id in 1..=MAX_OPEN_FRAMES as u32 {
        push(&mut r, header(id, 0, 2), &[1; 10]);
    }
    assert_eq!(r.open_frames(), MAX_OPEN_FRAMES);
    let ev = push(&mut r, header(100, 0, 2), &[1; 10]);
    assert!(ev.contains(&ReassemblyEvent::Dropped {
        frame_id: 1,
        reason: DropReason::TooManyOpen
    }));
    assert_eq!(r.open_frames(), MAX_OPEN_FRAMES);
}

#[test]
fn m6_the_total_byte_budget_evicts_the_oldest_and_bounds_memory() {
    // Big frames (each under FRAME_MAX) from a malicious host, never completed.
    let mut r = Reassembler::new();
    let chunk = vec![3u8; 1_400];
    let per_frame = 4 * 1024 * 1024 / chunk.len(); // ~4 MiB per frame
    let frames_sent = 12u32; // 48 MiB offered, over the 32 MiB budget
    let mut over_budget = 0;
    let (_, stats) = count_allocations(|| {
        for id in 1..=frames_sent {
            for i in 0..per_frame as u16 {
                let ev = push(&mut r, header(id, i, per_frame as u16 + 1), &chunk);
                over_budget += ev
                    .iter()
                    .filter(|e| {
                        matches!(
                            e,
                            ReassemblyEvent::Dropped {
                                reason: DropReason::OverBudget,
                                ..
                            }
                        )
                    })
                    .count();
                assert!(r.bytes_in_flight() <= REASSEMBLY_BYTES_MAX);
            }
        }
    });
    assert!(
        over_budget >= 4,
        "{over_budget} frames evicted for the budget"
    );
    // Memory follows the budget, not the 48 MiB offered (some slack for
    // bookkeeping and the allocator's view of growth).
    assert!(
        stats.peak_bytes <= REASSEMBLY_BYTES_MAX + REASSEMBLY_BYTES_MAX / 8,
        "{stats:?}"
    );
}

#[test]
fn m6_a_completed_frame_allocates_only_its_own_size() {
    let mut r = Reassembler::new();
    let chunk = vec![1u8; 1_000];
    for i in 0..9u16 {
        push(&mut r, header(1, i, 10), &chunk);
    }
    let (ev, stats) = count_allocations(|| push(&mut r, header(1, 9, 10), &chunk));
    assert_eq!(frames(&ev)[0].data.len(), 10_000);
    assert!(stats.peak_bytes <= 10_000 + 2_000 + SMALL, "{stats:?}");
}

#[test]
fn video_frame_debug_never_prints_the_payload() {
    let f = VideoFrame {
        frame_id: 1,
        keyframe: true,
        capture_ts_us: 2,
        follows_previous: false,
        data: vec![0xC4; 8],
    };
    let s = format!("{f:?}");
    assert!(
        !s.contains("196") && !s.contains("c4") && !s.contains("C4"),
        "{s}"
    );
    assert!(s.contains("bytes: 8"), "{s}");
}
