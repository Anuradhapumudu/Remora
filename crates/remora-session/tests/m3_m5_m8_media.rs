//! Media datagrams in the session layer (phase4-criteria §5, step 4):
//!
//! * **M3** no media before `Active`: the host seals nothing for a session
//!   in any earlier state; a viewer waiting for approval drops media unread
//!   (the datagram can legitimately overtake `SessionAccept`).
//! * **M5** tampering: every bit flip, truncation and unknown key is
//!   dropped and counted; the session continues and nothing reaches the
//!   decoder.
//! * **M8** key use: counters strictly increase, rotation at the packet
//!   limit and after an hour, the grace window for late packets, one key
//!   per session, announced key ids strictly increasing.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use std::collections::HashMap;

use common::evil::{control_envelope, evil_host_viewer_pending};
use common::*;
use rand_core::OsRng;
use remora_crypto::media::MediaSender;
use remora_crypto::secret::MediaKey;
use remora_proto::datagram::{DatagramHeader, DatagramKind, FLAG_KEYFRAME, FLAG_LAST};
use remora_proto::limits::{DATAGRAM_HEADER_LEN, VIDEO_FRAGMENT_DATA};
use remora_proto::messages::{MediaKeyAnnounce, SessionAccept, control};
use remora_proto::video::{FragmentHeader, VideoFrame};
use remora_session::media::{KEY_GRACE_MS, KEY_LIFETIME_MS};
use remora_session::{
    FailReason, Host, HostAction, MediaStats, SessionId, State, ViewerAction, Violation,
};

/// A frame of `len` bytes that is different for every `seed`.
fn frame(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// The host sends one frame; announcements (frames) reach the viewer at
/// once, and the media datagrams for `c` are returned, in order, unsent.
fn send(host: &mut Host, c: &mut Conn, keyframe: bool, data: &[u8]) -> Vec<Vec<u8>> {
    let acts = host
        .send_video(keyframe, 7_000, data, c.now, &mut OsRng)
        .unwrap();
    let mut media = Vec::new();
    let mut rest = Vec::new();
    for a in acts {
        match a {
            HostAction::Media { id, datagram } if id == c.id => media.push(datagram.into_bytes()),
            HostAction::Media { .. } => {}
            other => rest.push(other),
        }
    }
    c.host_actions(host, rest);
    media
}

/// Delivers datagrams to the viewer; returns the frames it produced.
fn deliver(c: &mut Conn, datagrams: &[Vec<u8>]) -> Vec<VideoFrame> {
    let mut frames = Vec::new();
    for d in datagrams {
        for a in c.viewer.on_datagram(d, c.now) {
            match a {
                ViewerAction::Video(f) => frames.push(f),
                other => panic!("unexpected viewer action {other:?}"),
            }
        }
    }
    frames
}

fn header_of(d: &[u8]) -> DatagramHeader {
    DatagramHeader::parse(d).unwrap().0
}

fn active(host: &mut Host) -> Conn {
    let v = device("viewer");
    to_active(host, &v, ip(1))
}

// ------------------------------------------------------------------ M3 --

#[test]
fn m3_host_seals_nothing_for_a_session_before_active() {
    let h = device("host");
    let v = device("viewer");
    let mut host = host_with(&h, vec![]);
    // A positive control: without an Active session that does get media,
    // "no media for the others" would pass even if sending were broken.
    let control = to_active(&mut host, &v, ip(9));

    let mut seen = Vec::new();
    for keep in 0..6 {
        // Stop the handshake after `keep` viewer frames reached the host.
        let mut c = {
            let mode = password_mode(&host, None);
            let (mut c, first) = start(&mut host, &v, mode, ip(10 + keep as u8), T0);
            c.pump(&mut host, first, Vec::new(), &mut |v2h, i, f| {
                (!v2h || i < keep).then_some(f)
            });
            c
        };
        let state = host.state(c.id).unwrap();
        seen.push(state);
        let acts = host
            .send_video(true, 1, &frame(3 * VIDEO_FRAGMENT_DATA, 1), T0, &mut OsRng)
            .unwrap();
        assert!(
            acts.iter()
                .any(|a| matches!(a, HostAction::Media { id, .. } if *id == control.id)),
            "the Active control session got no media: the check below would be vacuous"
        );
        let leaked: Vec<_> = acts
            .iter()
            .filter(|a| match a {
                HostAction::Media { id, .. } | HostAction::Send { id, .. } => *id == c.id,
                _ => false,
            })
            .collect();
        assert!(leaked.is_empty(), "{state:?}: {leaked:?}");
        // Closed is "before Active" too, for a session that never got there.
        // (Every other session is closed as well: the host holds at most 4
        // handshakes at once.)
        if keep < 5 {
            let acts = host.disconnect(c.id);
            c.host_actions(&mut host, acts);
        } else {
            let acts = host.deny(c.id);
            c.host_actions(&mut host, acts);
            assert_eq!(host.state(c.id), Some(State::Closed));
            let acts = host
                .send_video(true, 2, &frame(10, 2), T0, &mut OsRng)
                .unwrap();
            assert!(
                !acts.iter().any(|a| matches!(a,
                    HostAction::Media { id, .. } | HostAction::Send { id, .. } if *id == c.id)),
                "denied session got media"
            );
        }
    }
    for want in [
        State::Hello,
        State::Spake,
        State::Noise,
        State::PendingApproval,
    ] {
        assert!(seen.contains(&want), "never tested {want:?}: {seen:?}");
    }
}

#[test]
fn m3_viewer_drops_media_that_overtakes_the_accept() {
    let h = device("host");
    let v = device("viewer");
    let mut host = host_with(&h, vec![]);
    let mut c = to_prompt(&mut host, &v, ip(1));
    let (id, sas) = c.log.prompt().unwrap();
    // The host accepts and streams at once; the datagrams arrive first.
    let accept = host.approve(id, sas).unwrap();
    let early = host
        .send_video(
            true,
            1,
            &frame(2 * VIDEO_FRAGMENT_DATA + 5, 3),
            T0,
            &mut OsRng,
        )
        .unwrap();
    let early: Vec<Vec<u8>> = early
        .into_iter()
        .filter_map(|a| match a {
            HostAction::Media { datagram, .. } => Some(datagram.into_bytes()),
            _ => None,
        })
        .collect();
    assert_eq!(early.len(), 3);
    assert_eq!(c.viewer.state(), State::PendingApproval);
    assert!(
        deliver(&mut c, &early).is_empty(),
        "media reached the decoder before Active"
    );
    assert_eq!(
        c.viewer.state(),
        State::PendingApproval,
        "the session must survive the race"
    );
    assert_eq!(c.viewer.media_stats().before_active, 3);
    assert_eq!(c.viewer.media_stats().opened, 0, "not even opened");
    // Then the accept and the keys arrive; the next frame plays.
    c.host_actions(&mut host, accept);
    assert_eq!(c.viewer.state(), State::Active);
    let next = send(&mut host, &mut c, true, &frame(100, 4));
    let frames = deliver(&mut c, &next);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].data, frame(100, 4));
}

#[test]
fn approving_asks_for_a_keyframe_and_announces_two_keys() {
    let h = device("host");
    let v = device("viewer");
    let mut host = host_with(&h, vec![]);
    let c = to_prompt(&mut host, &v, ip(1));
    let (id, sas) = c.log.prompt().unwrap();
    let acts = host.approve(id, sas).unwrap();
    assert!(acts.contains(&HostAction::ForceKeyframe));
    let sends = acts
        .iter()
        .filter(|a| matches!(a, HostAction::Send { .. }))
        .count();
    assert_eq!(sends, 3, "accept, current key, next key");
}

// ------------------------------------------------------------------ M5 --

#[test]
fn m5_every_tampered_datagram_is_dropped_counted_and_the_stream_continues() {
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    let mut c = active(&mut host);
    let good = send(&mut host, &mut c, true, &frame(40, 5));
    assert_eq!(good.len(), 1);
    let good = &good[0];
    let mut forged = 0u64;
    let mut try_one = |c: &mut Conn, d: Vec<u8>, what: &str| {
        let frames = deliver(c, &[d]);
        assert!(frames.is_empty(), "{what}: reached the decoder");
        assert_eq!(c.viewer.state(), State::Active, "{what}: session ended");
        forged += 1;
        assert_eq!(
            c.viewer.media_stats().dropped(),
            forged,
            "{what}: not counted"
        );
    };
    // Bit flips in the header (AAD), the ciphertext and the tag.
    for byte in 0..good.len() {
        for bit in 0..8 {
            let mut d = good.clone();
            d[byte] ^= 1 << bit;
            try_one(&mut c, d, &format!("byte {byte} bit {bit}"));
        }
    }
    // Truncations, down to nothing.
    for len in 0..good.len() {
        try_one(&mut c, good[..len].to_vec(), &format!("truncated to {len}"));
    }
    // A datagram correctly sealed, but under a key that was never announced.
    let mut stranger = MediaSender::new(9, MediaKey::generate(&mut OsRng));
    let body = FragmentHeader {
        frame_id: 1,
        frag_index: 0,
        frag_count: 1,
        fec_group: 0,
        capture_ts_us: 1,
    }
    .encode_with(b"forged frame");
    let d = stranger.seal(header_of(good), &body).unwrap().into_bytes();
    try_one(&mut c, d, "unknown key id");
    let stats = c.viewer.media_stats();
    assert_eq!(stats.frames, 0);
    assert_eq!(stats.opened, 0, "a forgery opened");
    // The stranger, and 15 of the 16 key-id bit flips: the flip to id 1
    // names the announced next key, so that one fails authentication.
    assert_eq!(stats.unknown_key, 1 + 15, "unknown key ids");
    // Forgeries did not burn the genuine packet's counter: it still plays.
    let frames = deliver(&mut c, std::slice::from_ref(good));
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].data, frame(40, 5));
    // And the stream goes on.
    let more = send(&mut host, &mut c, false, &frame(41, 6));
    assert_eq!(deliver(&mut c, &more).len(), 1);
}

#[test]
fn m5_a_replayed_datagram_is_dropped_and_counted() {
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    let mut c = active(&mut host);
    let d = send(&mut host, &mut c, true, &frame(10, 7));
    assert_eq!(deliver(&mut c, &d).len(), 1);
    assert!(deliver(&mut c, &d).is_empty());
    assert_eq!(c.viewer.media_stats().replayed, 1);
    assert_eq!(c.viewer.state(), State::Active);
}

// ------------------------------------------------------------------ M8 --

#[test]
fn m8_counters_strictly_increase_and_never_repeat_over_a_million_packets() {
    // 10^6 as M8 asks. The mutation job (which reruns this once per mutant)
    // sets M8_packets lower, like A04_SAMPLES: any count still shows a
    // repeat or a missed rotation, the full count is CI's normal test run.
    let packets: u64 = std::env::var("M8_packets")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);
    assert!(
        packets >= 20_000,
        "M8_packets={packets}: too few to rotate 20 times"
    );
    let per_key = packets / 20;
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    host.set_key_rotation(per_key);
    let mut c = active(&mut host);
    let mut last: HashMap<u16, u64> = HashMap::new();
    let mut key_order: Vec<u16> = Vec::new();
    let data = [0x5a_u8];
    for _ in 0..packets {
        let ds = send(&mut host, &mut c, false, &data);
        assert_eq!(ds.len(), 1);
        let h = header_of(&ds[0]);
        if key_order.last() != Some(&h.key_id) {
            assert!(
                key_order.last().is_none_or(|&k| h.key_id > k),
                "key id went back: {key_order:?} then {}",
                h.key_id
            );
            key_order.push(h.key_id);
        }
        if let Some(&prev) = last.get(&h.key_id) {
            assert!(
                h.counter > prev,
                "key {} counter {} after {prev}",
                h.key_id,
                h.counter
            );
        }
        last.insert(h.key_id, h.counter);
        let frames = deliver(&mut c, &ds);
        assert_eq!(
            frames.len(),
            1,
            "packet under key {} counter {}",
            h.key_id,
            h.counter
        );
    }
    // Strictly increasing per key, and a key id is never used again after
    // the next one started: so no (key, nonce) pair repeated.
    assert_eq!(
        key_order,
        (0..(packets / per_key) as u16).collect::<Vec<_>>()
    );
    for (&k, &c) in &last {
        assert_eq!(c, per_key - 1, "key {k} ended at counter {c}");
    }
    let stats = c.viewer.media_stats();
    assert_eq!(stats.frames, packets);
    assert_eq!(stats.dropped(), 0);
}

#[test]
fn m8_rotation_keeps_old_keys_for_the_grace_window_only() {
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    host.set_key_rotation(10);
    let mut c = active(&mut host);
    let mut old: Vec<Vec<u8>> = (0..10)
        .map(|i| send(&mut host, &mut c, i == 0, &frame(20, i)).remove(0))
        .collect();
    assert!(old.iter().all(|d| header_of(d).key_id == 0));
    // Hold back two key-0 packets (a reordering network); deliver the rest.
    let late_a = old.remove(4);
    let late_b = old.remove(4);
    deliver(&mut c, &old);
    let new = send(&mut host, &mut c, true, &frame(20, 99));
    assert_eq!(header_of(&new[0]).key_id, 1, "rotated after 10 packets");
    assert_eq!(
        deliver(&mut c, &new).len(),
        1,
        "key 1 was announced in advance"
    );

    // Inside the grace window the old key still opens a late packet (its
    // frame is late for the reassembler, but it authenticated).
    c.now = T0.plus(KEY_GRACE_MS - 1);
    c.viewer.tick(c.now);
    let before = c.viewer.media_stats();
    deliver(&mut c, &[late_a]);
    assert_eq!(c.viewer.media_stats().opened, before.opened + 1);
    // From the end of the window it is gone.
    c.now = T0.plus(KEY_GRACE_MS);
    c.viewer.tick(c.now);
    deliver(&mut c, &[late_b]);
    let after = c.viewer.media_stats();
    assert_eq!(after.opened, before.opened + 1);
    assert_eq!(after.unknown_key, before.unknown_key + 1);
    assert_eq!(after.late_fragments, 1, "frame 4 came after frame 10");
    assert_eq!(c.viewer.state(), State::Active);
    // Only the superseded key went: the current key (1) still plays...
    let now = send(&mut host, &mut c, false, &frame(20, 100));
    assert_eq!(header_of(&now[0]).key_id, 1);
    assert_eq!(deliver(&mut c, &now).len(), 1, "current key retired");
    // ...and so does the announced next key (2), after the next rotation.
    let mut rotated = Vec::new();
    for i in 0..9 {
        rotated.extend(send(&mut host, &mut c, false, &frame(20, 101 + i)));
    }
    assert_eq!(header_of(rotated.last().unwrap()).key_id, 2);
    assert_eq!(deliver(&mut c, &rotated).len(), 9, "next key retired");
}

#[test]
fn m8_a_key_is_replaced_after_an_hour_even_with_few_packets() {
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    let mut c = active(&mut host);
    let first = send(&mut host, &mut c, true, &frame(5, 1));
    assert_eq!(header_of(&first[0]).key_id, 0);
    // protocol.md §6: one hour.
    assert_eq!(KEY_LIFETIME_MS, 60 * 60 * 1000);
    c.now = T0.plus(KEY_LIFETIME_MS - 1);
    let still = send(&mut host, &mut c, false, &frame(5, 2));
    assert_eq!(header_of(&still[0]).key_id, 0);
    c.now = T0.plus(KEY_LIFETIME_MS);
    let next = send(&mut host, &mut c, false, &frame(5, 3));
    assert_eq!(header_of(&next[0]).key_id, 1);
    deliver(&mut c, &first);
    deliver(&mut c, &still);
    assert_eq!(deliver(&mut c, &next).len(), 1);
}

#[test]
fn m8_every_session_has_its_own_key() {
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    let (va, vb) = (device("a"), device("b"));
    let mut a = to_active(&mut host, &va, ip(1));
    let mut b = to_active(&mut host, &vb, ip(2));
    let acts = host
        .send_video(true, 1, &frame(30, 8), T0, &mut OsRng)
        .unwrap();
    let for_session = |id: SessionId| -> Vec<Vec<u8>> {
        acts.iter()
            .filter_map(|x| match x {
                HostAction::Media { id: i, datagram } if *i == id => Some(datagram.to_vec()),
                _ => None,
            })
            .collect()
    };
    let (da, db) = (for_session(a.id), for_session(b.id));
    assert_eq!((da.len(), db.len()), (1, 1));
    // Same key id and counter, different ciphertext: different keys.
    assert_eq!(header_of(&da[0]), header_of(&db[0]));
    assert_ne!(da[0], db[0]);
    // A's datagram does not open on B's session, nor B's on A's.
    assert!(deliver(&mut b, &da).is_empty());
    assert!(deliver(&mut a, &db).is_empty());
    assert_eq!(b.viewer.media_stats().auth_failed, 1);
    assert_eq!(a.viewer.media_stats().auth_failed, 1);
    assert_eq!(deliver(&mut a, &da).len(), 1);
    assert_eq!(deliver(&mut b, &db).len(), 1);
}

/// An evil host past approval announcing keys of its choosing.
fn announce(e: &mut common::evil::EvilHost, key_id: u32) -> Vec<ViewerAction> {
    let f = e
        .est
        .encrypt(&control_envelope(control::Kind::MediaKey(
            MediaKeyAnnounce {
                key_id,
                key: vec![key_id as u8; 32],
            },
        )))
        .unwrap();
    e.viewer.on_frame(&f, T0, &mut OsRng)
}

fn evil_active() -> common::evil::EvilHost {
    let (h, v) = (device("host"), device("viewer"));
    let otp = remora_crypto::secret::Otp::parse("123456").unwrap();
    let mut e = evil_host_viewer_pending(&v, &h, &otp);
    let accept = e
        .est
        .encrypt(&control_envelope(control::Kind::Accept(SessionAccept {
            role: 1,
        })))
        .unwrap();
    e.viewer.on_frame(&accept, T0, &mut OsRng);
    assert_eq!(e.viewer.state(), State::Active);
    e
}

fn violation(acts: &[ViewerAction]) -> Option<FailReason> {
    acts.iter().find_map(|a| match a {
        ViewerAction::Failed { reason, .. } => Some(reason.clone()),
        _ => None,
    })
}

#[test]
fn m8_a_key_id_announced_again_or_lower_ends_the_session() {
    // Reusing a key id would reuse its nonce space with a new key: refused.
    for (first, second) in [(3, 3), (3, 2), (5, 0)] {
        let mut e = evil_active();
        assert!(violation(&announce(&mut e, first)).is_none());
        let acts = announce(&mut e, second);
        assert!(
            matches!(
                violation(&acts),
                Some(FailReason::ProtocolViolation(Violation::MediaKey(_)))
            ),
            "{first} then {second}: {acts:?}"
        );
        assert_eq!(e.viewer.state(), State::Closed);
    }
}

#[test]
fn m8_a_key_id_above_u16_is_malformed() {
    let mut e = evil_active();
    let acts = announce(&mut e, 70_000);
    assert!(
        matches!(
            violation(&acts),
            Some(FailReason::ProtocolViolation(Violation::Malformed(_)))
        ),
        "{acts:?}"
    );
}

#[test]
fn m8_a_host_cannot_make_the_viewer_hold_unbounded_keys() {
    // Keys nobody has used yet cannot be retired: the fifth is refused.
    let mut e = evil_active();
    for id in 0..4 {
        assert!(violation(&announce(&mut e, id)).is_none(), "key {id}");
    }
    assert!(matches!(
        violation(&announce(&mut e, 4)),
        Some(FailReason::ProtocolViolation(Violation::MediaKey(_)))
    ));
}

#[test]
fn media_key_announcements_never_print_the_key() {
    let k = MediaKeyAnnounce {
        key_id: 3,
        key: vec![0xAB; 32],
    };
    let env = remora_proto::messages::Envelope {
        msg: Some(remora_proto::messages::envelope::Msg::Control(
            remora_proto::messages::Control {
                kind: Some(control::Kind::MediaKey(k.clone())),
            },
        )),
    };
    for text in [format!("{k:?}"), format!("{env:?}"), format!("{env:#?}")] {
        assert!(!text.contains("171"), "{text}");
        assert!(!text.to_lowercase().contains("ab, ab"), "{text}");
        assert!(text.contains("redacted"), "{text}");
    }
}

#[test]
fn media_stats_name_every_drop() {
    // The total is the sum of the reasons (a counter left out of
    // `dropped()` would hide drops).
    let s = MediaStats {
        before_active: 1,
        bad_header: 2,
        unknown_key: 4,
        replayed: 8,
        too_old: 16,
        auth_failed: 32,
        ..MediaStats::default()
    };
    assert_eq!(s.dropped(), 63);
}

#[test]
fn fragments_carry_the_frame_and_the_last_flag() {
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    let mut c = active(&mut host);
    let data = frame(2 * VIDEO_FRAGMENT_DATA + 1, 9);
    let ds = send(&mut host, &mut c, true, &data);
    assert_eq!(ds.len(), 3);
    for (i, d) in ds.iter().enumerate() {
        let hd = header_of(d);
        assert_eq!(hd.kind, DatagramKind::VideoFragment);
        assert_eq!(hd.flags & FLAG_KEYFRAME, FLAG_KEYFRAME);
        assert_eq!(hd.flags & FLAG_LAST != 0, i == 2);
        assert!(d.len() <= remora_proto::limits::VIDEO_DATAGRAM_TARGET);
        assert!(d.len() > DATAGRAM_HEADER_LEN);
    }
    let frames = deliver(&mut c, &ds);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].data, data);
    assert!(frames[0].keyframe);
    assert_eq!(frames[0].capture_ts_us, 7_000);
}

#[test]
fn m5_authentic_datagrams_the_decoder_cannot_use_are_counted_not_played() {
    // A malicious but authenticated host: correctly sealed datagrams that
    // are not stream-0 video, or are malformed, or incomplete.
    let mut e = evil_active();
    assert!(violation(&announce(&mut e, 0)).is_none());
    let mut s = MediaSender::new(0, MediaKey::from_bytes([0; 32]));
    let body = |frame_id: u32, idx: u16, count: u16, data: &[u8]| {
        FragmentHeader {
            frame_id,
            frag_index: idx,
            frag_count: count,
            fec_group: 0,
            capture_ts_us: 5,
        }
        .encode_with(data)
    };
    let video = |flags: u8| DatagramHeader {
        kind: DatagramKind::VideoFragment,
        flags,
        key_id: 0,
        counter: 0,
        stream_id: 0,
        layer_id: 0,
    };
    let whole = FLAG_KEYFRAME | FLAG_LAST;
    let mut play = |e: &mut common::evil::EvilHost, h: DatagramHeader, b: Vec<u8>| -> usize {
        let d = s.seal(h, &b).unwrap();
        e.viewer
            .on_datagram(&d, T0)
            .iter()
            .filter(|a| matches!(a, ViewerAction::Video(_)))
            .count()
    };
    // Each of these carries a complete one-fragment frame: only the clear
    // header says it is not for the decoder.
    let not_video = [
        DatagramHeader {
            kind: DatagramKind::FecRepair,
            ..video(whole)
        },
        DatagramHeader {
            kind: DatagramKind::PointerMotion,
            ..video(whole)
        },
        DatagramHeader {
            stream_id: 1,
            ..video(whole)
        },
        DatagramHeader {
            layer_id: 1,
            ..video(whole)
        },
    ];
    for h in not_video {
        assert_eq!(play(&mut e, h, body(1, 0, 1, b"x")), 0, "{h:?}");
    }
    // A malformed fragment body (no data byte).
    assert_eq!(
        play(&mut e, video(whole), body(1, 0, 1, b"")[..18].to_vec()),
        0
    );
    // Frame 1 never completes; frame 2 does and supersedes it; then frame
    // 1's missing half arrives late.
    assert_eq!(play(&mut e, video(FLAG_KEYFRAME), body(1, 0, 2, b"a")), 0);
    assert_eq!(play(&mut e, video(whole), body(2, 0, 1, b"b")), 1);
    assert_eq!(play(&mut e, video(whole), body(1, 1, 2, b"c")), 0);
    let stats = e.viewer.media_stats();
    assert_eq!(
        stats,
        MediaStats {
            opened: 8,
            ignored: 4,
            bad_fragments: 1,
            frames_dropped: 1,
            frames: 1,
            late_fragments: 1,
            ..MediaStats::default()
        }
    );
    assert_eq!(e.viewer.state(), State::Active);
}
