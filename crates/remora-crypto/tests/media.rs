//! phase3-criteria A11 (tampered media dropped, session continues), A12
//! (replay window), A13 (no nonce reuse). The 2³²-packet limit is a unit test
//! in src/media.rs. Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use rand_core::OsRng;
use remora_crypto::media::{
    MAX_LIVE_KEYS, MediaDrop, MediaError, MediaReceiver, MediaSender, REPLAY_WINDOW,
};
use remora_crypto::secret::MediaKey;
use remora_proto::datagram::{DatagramError, DatagramHeader, DatagramKind};

fn header() -> DatagramHeader {
    DatagramHeader {
        kind: DatagramKind::VideoFragment,
        flags: 0b011,
        key_id: 999,    // overwritten by the sender
        counter: 12345, // overwritten by the sender
        stream_id: 2,
        layer_id: 1,
    }
}

fn pair(key_id: u16) -> (MediaSender, MediaReceiver) {
    let key = MediaKey::generate(&mut OsRng);
    let mut r = MediaReceiver::new();
    r.add_key(key_id, key.clone()).unwrap();
    (MediaSender::new(key_id, key), r)
}

#[test]
fn roundtrip_and_sender_owns_key_id_and_counter() {
    let (mut s, mut r) = pair(7);
    for i in 0..5u64 {
        let d = s.seal(header(), format!("frame {i}").as_bytes()).unwrap();
        let (h, body) = r.open(&d).unwrap();
        assert_eq!(h.key_id, 7, "key_id comes from the sender, not the caller");
        assert_eq!(
            h.counter, i,
            "counter comes from the sender, not the caller"
        );
        assert_eq!(h.stream_id, 2);
        assert_eq!(h.layer_id, 1);
        assert_eq!(body, format!("frame {i}").as_bytes());
    }
    assert_eq!(s.packets_sent(), 5);
    assert_eq!(r.dropped(), 0);
}

#[test]
fn layout_is_header_then_ciphertext_then_tag() {
    let (mut s, _) = pair(7);
    let d = s.seal(header(), b"0123456789").unwrap();
    assert_eq!(d.len(), 16 + 10 + 16);
    let (h, _) = DatagramHeader::parse(&d).unwrap();
    assert_eq!(h.counter, 0);
    assert_ne!(&d[16..26], b"0123456789", "body is encrypted");
}

#[test]
fn nonce_is_four_zero_bytes_then_the_counter() {
    // Independent decryption with the chacha20poly1305 crate directly:
    // nonce = 0000 ‖ counter_be, AAD = the 16-byte clear header.
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let key = MediaKey::generate(&mut OsRng);
    let mut s = MediaSender::new(3, key.clone());
    let _ = s.seal(header(), b"skip").unwrap();
    let d = s.seal(header(), b"second").unwrap();
    let cipher = ChaCha20Poly1305::new(key.expose_for_announce().into());
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&1u64.to_be_bytes());
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &d[16..],
                aad: &d[..16],
            },
        )
        .unwrap();
    assert_eq!(pt, b"second");
}

// ---------------------------------------------------------------- A11 ----

#[test]
fn a11_every_bit_flip_is_dropped_and_the_session_continues() {
    let (mut s, mut r) = pair(7);
    let good = s.seal(header(), b"payload bytes").unwrap();
    let mut dropped = 0;
    for byte in 0..good.len() {
        for bit in 0..8 {
            let mut d = good.clone();
            d[byte] ^= 1 << bit;
            assert!(r.open(&d).is_err(), "byte {byte} bit {bit} accepted");
            dropped += 1;
        }
    }
    assert_eq!(r.dropped(), dropped);
    // Forgeries did not burn the real counter: the genuine packet still opens.
    assert_eq!(r.open(&good).unwrap().1, b"payload bytes");
    // And the stream continues.
    let next = s.seal(header(), b"next").unwrap();
    assert_eq!(r.open(&next).unwrap().1, b"next");
}

#[test]
fn a11_header_tamper_is_auth_failure_not_a_parse_error() {
    let (mut s, mut r) = pair(7);
    let good = s.seal(header(), b"x").unwrap();
    for idx in [12, 13, 14] {
        // stream_id, layer_id: still a valid header, but AAD differs
        let mut d = good.clone();
        d[idx] ^= 1;
        assert_eq!(r.open(&d).err(), Some(MediaDrop::Auth), "header byte {idx}");
    }
    let mut d = good.clone();
    d[15] = 1; // reserved byte
    assert_eq!(
        r.open(&d).err(),
        Some(MediaDrop::Header(DatagramError::Reserved))
    );
}

#[test]
fn a11_wrong_or_unknown_key_id_is_dropped() {
    let (mut s, _) = pair(7);
    let d = s.seal(header(), b"x").unwrap();
    let mut r = MediaReceiver::new();
    assert_eq!(r.open(&d).err(), Some(MediaDrop::UnknownKey));
    // A live key under the right id, but a different key.
    r.add_key(7, MediaKey::generate(&mut OsRng)).unwrap();
    assert_eq!(r.open(&d).err(), Some(MediaDrop::Auth));
    assert_eq!(r.dropped(), 2);
}

#[test]
fn a11_truncated_and_oversized_datagrams_are_dropped() {
    let (mut s, mut r) = pair(7);
    let good = s.seal(header(), b"some body").unwrap();
    for cut in [0, 1, 15, 16, 31, good.len() - 1] {
        assert!(r.open(&good[..cut]).is_err(), "cut {cut}");
    }
    assert_eq!(
        r.open(&vec![0; 1501]).err(),
        Some(MediaDrop::Header(DatagramError::TooLong))
    );
    assert_eq!(
        s.seal(header(), &vec![0; 1501]).err(),
        Some(MediaError::BodyTooLarge)
    );
}

// ---------------------------------------------------------------- A12 ----

#[test]
fn a12_duplicate_is_dropped() {
    let (mut s, mut r) = pair(1);
    let d = s.seal(header(), b"x").unwrap();
    assert!(r.open(&d).is_ok());
    assert_eq!(r.open(&d).err(), Some(MediaDrop::Replay));
}

#[test]
fn a12_out_of_order_within_the_window_is_accepted_once() {
    let (mut s, mut r) = pair(1);
    let ds: Vec<_> = (0..100).map(|_| s.seal(header(), b"x").unwrap()).collect();
    for i in (0..100).rev() {
        assert!(r.open(&ds[i]).is_ok(), "packet {i}");
    }
    for d in &ds {
        assert_eq!(r.open(d).err(), Some(MediaDrop::Replay));
    }
}

#[test]
fn a12_window_edges() {
    let (mut s, mut r) = pair(1);
    let ds: Vec<_> = (0..REPLAY_WINDOW + 10)
        .map(|_| s.seal(header(), b"x").unwrap())
        .collect();
    let last = ds.len() - 1;
    assert!(r.open(&ds[last]).is_ok()); // highest = W + 9
    // highest - (W - 1) is the oldest counter still inside the window.
    let oldest_inside = last - (REPLAY_WINDOW as usize - 1);
    assert!(
        r.open(&ds[oldest_inside]).is_ok(),
        "oldest inside the window"
    );
    assert_eq!(
        r.open(&ds[oldest_inside - 1]).err(),
        Some(MediaDrop::TooOld)
    );
    assert_eq!(r.open(&ds[0]).err(), Some(MediaDrop::TooOld));
    assert_eq!(r.open(&ds[oldest_inside]).err(), Some(MediaDrop::Replay));
}

#[test]
fn a12_far_ahead_is_accepted_once_and_slides_the_window() {
    let (mut s, mut r) = pair(1);
    let early: Vec<_> = (0..10).map(|_| s.seal(header(), b"x").unwrap()).collect();
    assert!(r.open(&early[0]).is_ok());
    // Skip 1_000_000 packets (lost), then one arrives.
    for _ in 0..1_000_000 {
        let _ = s.seal(header(), b"").unwrap();
    }
    let far = s.seal(header(), b"far").unwrap();
    assert_eq!(r.open(&far).unwrap().1, b"far");
    assert_eq!(r.open(&far).err(), Some(MediaDrop::Replay));
    // Everything from before is now too old.
    assert_eq!(r.open(&early[5]).err(), Some(MediaDrop::TooOld));
}

#[test]
fn a12_forged_far_ahead_counter_does_not_slide_the_window() {
    // An attacker sends a packet with a huge counter and a bad tag: it must
    // NOT advance the window (which would make every genuine packet "too old").
    let (mut s, mut r) = pair(1);
    let d0 = s.seal(header(), b"zero").unwrap();
    let d1 = s.seal(header(), b"one").unwrap();
    let mut forged = d0.clone();
    forged[4..12].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
    assert_eq!(r.open(&forged).err(), Some(MediaDrop::Auth));
    assert!(r.open(&d1).is_ok());
    assert!(r.open(&d0).is_ok());
}

// ---------------------------------------------------------------- A13 ----

#[test]
fn a13_no_key_counter_pair_ever_repeats() {
    // Property test over pseudo-random sequences of operations (seeded
    // xorshift so a failure is reproducible): seal, rotate to a new key.
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut seen = std::collections::HashSet::new();
    let mut key_id = 0u16;
    let mut s = MediaSender::new(key_id, MediaKey::generate(&mut OsRng));
    for _ in 0..50_000 {
        if next() % 1000 == 0 {
            key_id += 1;
            s = MediaSender::new(key_id, MediaKey::generate(&mut OsRng));
        }
        let d = s.seal(header(), b"p").unwrap();
        let (h, _) = DatagramHeader::parse(&d).unwrap();
        assert!(
            seen.insert((h.key_id, h.counter)),
            "repeated ({}, {})",
            h.key_id,
            h.counter
        );
    }
}

#[test]
fn a13_a_key_id_cannot_be_installed_twice() {
    let mut r = MediaReceiver::new();
    r.add_key(5, MediaKey::generate(&mut OsRng)).unwrap();
    assert_eq!(
        r.add_key(5, MediaKey::generate(&mut OsRng)).err(),
        Some(MediaError::KeyIdReused(5))
    );
    // Not even after it was removed (rotated out).
    r.remove_key(5);
    assert_eq!(
        r.add_key(5, MediaKey::generate(&mut OsRng)).err(),
        Some(MediaError::KeyIdReused(5))
    );
    // Re-announcing the same key bytes under the same id is also refused.
    let k = MediaKey::generate(&mut OsRng);
    r.add_key(6, k.clone()).unwrap();
    assert_eq!(r.add_key(6, k).err(), Some(MediaError::KeyIdReused(6)));
}

#[test]
fn a13_removed_key_no_longer_decrypts() {
    let (mut s, mut r) = pair(4);
    let d = s.seal(header(), b"x").unwrap();
    r.remove_key(4);
    assert_eq!(r.open(&d).err(), Some(MediaDrop::UnknownKey));
}

#[test]
fn live_key_limit() {
    let mut r = MediaReceiver::new();
    for id in 0..MAX_LIVE_KEYS as u16 {
        r.add_key(id, MediaKey::generate(&mut OsRng)).unwrap();
    }
    assert_eq!(
        r.add_key(100, MediaKey::generate(&mut OsRng)).err(),
        Some(MediaError::TooManyKeys)
    );
    r.remove_key(0);
    assert!(r.add_key(100, MediaKey::generate(&mut OsRng)).is_ok());
}

#[test]
fn body_size_boundary() {
    // 1500 (datagram) − 16 (header) − 16 (tag) = 1468 bytes of body.
    let (mut s, mut r) = pair(7);
    let d = s.seal(header(), &vec![1; 1468]).unwrap();
    assert_eq!(d.len(), 1500);
    assert_eq!(r.open(&d).unwrap().1.len(), 1468);
    assert_eq!(
        s.seal(header(), &vec![1; 1469]).err(),
        Some(MediaError::BodyTooLarge)
    );
    assert_eq!(s.packets_sent(), 1, "a refused body does not use a counter");
}

#[test]
fn a12_replay_window_matches_a_reference_model() {
    // Model-based check of the sliding bitmap (mutation-gate finding: the
    // shift was never exercised with bits set). Deliver a pseudo-random mix
    // of in-order, reordered, duplicated, old and far-ahead counters and
    // compare every verdict with a trivially correct model: a set of
    // accepted counters plus the highest one.
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let (mut s, mut r) = pair(1);
    let mut sent: Vec<Vec<u8>> = Vec::new();
    let mut accepted = std::collections::HashSet::new();
    let mut highest: Option<u64> = None;
    for _ in 0..20_000 {
        // Mostly move forward by small, word-crossing and occasionally huge
        // steps; sometimes resend something already sent.
        let pick = next() % 100;
        let c = if pick < 60 || sent.is_empty() {
            let skip = match next() % 10 {
                0 => 63 + next() % 3,          // around a word boundary
                1 => 64 * (1 + next() % 3),    // whole words
                2 if next() % 50 == 0 => 5000, // beyond the window
                _ => next() % 3,
            };
            for _ in 0..skip {
                sent.push(s.seal(header(), b"").unwrap());
            }
            sent.push(s.seal(header(), b"").unwrap());
            (sent.len() - 1) as u64
        } else {
            let back = next() % (REPLAY_WINDOW + 200);
            (sent.len() as u64 - 1).saturating_sub(back)
        };
        let want = match highest {
            Some(h) if c + REPLAY_WINDOW <= h => Err(MediaDrop::TooOld),
            _ if accepted.contains(&c) => Err(MediaDrop::Replay),
            _ => Ok(()),
        };
        let got = r.open(&sent[c as usize]).map(|_| ());
        assert_eq!(got, want, "counter {c}, highest {highest:?}");
        if got.is_ok() {
            accepted.insert(c);
            highest = Some(highest.map_or(c, |h| h.max(c)));
        }
    }
}
