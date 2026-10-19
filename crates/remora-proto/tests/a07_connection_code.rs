//! phase3-criteria A07 (expired / future-dated codes) plus the structural
//! validation every pasted connection code must survive. Written before the
//! implementation (§7b).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use remora_proto::code::{Candidate, CandidateKind, CodeError, CodeKind, ConnectionCode, PREFIX};

const NOW: u64 = 1_800_000_000;

/// Independent bit-by-bit CRC-32 (IEEE) — deliberately a different algorithm
/// from the production table-driven one, so a shared bug can't hide.
fn crc32_bitwise(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn sample(candidates: Vec<Candidate>, expires_at: u32) -> ConnectionCode {
    ConnectionCode {
        kind: CodeKind::Offer,
        expires_at,
        nonce: [0x11; 16],
        identity_key: [0x22; 32],
        ice_ufrag: [1, 2, 3, 4],
        ice_pwd: [0x33; 16],
        candidates,
    }
}

fn v4() -> Candidate {
    Candidate {
        kind: CandidateKind::Host,
        addr: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 20), 47_800)),
    }
}

fn v6() -> Candidate {
    Candidate {
        kind: CandidateKind::ServerReflexive,
        addr: SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7), 50_000)),
    }
}

fn valid() -> ConnectionCode {
    sample(vec![v4(), v6()], (NOW + 300) as u32)
}

/// Builds code text from raw binary (adds CRC), to test fields the encoder
/// would never produce.
fn text_from_raw(mut body: Vec<u8>) -> String {
    let crc = crc32_bitwise(&body);
    body.extend_from_slice(&crc.to_be_bytes());
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(body))
}

/// Raw binary of `valid()` without its CRC, built field by field per protocol.md §2.
fn raw_valid() -> Vec<u8> {
    let mut b = vec![1, 0]; // version, kind = offer
    b.extend_from_slice(&((NOW + 300) as u32).to_be_bytes());
    b.extend_from_slice(&[0x11; 16]);
    b.extend_from_slice(&[0x22; 32]);
    b.extend_from_slice(&[1, 2, 3, 4]);
    b.extend_from_slice(&[0x33; 16]);
    b.push(2); // candidate count
    b.extend_from_slice(&[0x40, 192, 168, 1, 20]); // host, IPv4
    b.extend_from_slice(&47_800u16.to_be_bytes());
    b.push(0x61); // srflx, IPv6
    b.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7).octets());
    b.extend_from_slice(&50_000u16.to_be_bytes());
    b
}

#[test]
fn encoding_matches_the_documented_layout_and_round_trips() {
    let c = valid();
    let text = c.encode();
    assert_eq!(
        text,
        text_from_raw(raw_valid()),
        "layout differs from protocol.md §2"
    );
    assert_eq!(ConnectionCode::parse(&text, NOW), Ok(c));
}

#[test]
fn a07_expired_code_is_rejected() {
    let at = |exp: u64| ConnectionCode::parse(&sample(vec![v4()], exp as u32).encode(), NOW);
    assert_eq!(at(NOW - 1), Err(CodeError::Expired));
    assert_eq!(at(NOW - 3600), Err(CodeError::Expired));
    assert!(
        at(NOW).is_ok(),
        "valid until and including its expiry second"
    );
}

#[test]
fn a07_future_dated_code_is_rejected() {
    let at = |exp: u64| ConnectionCode::parse(&sample(vec![v4()], exp as u32).encode(), NOW);
    assert!(
        at(NOW + 300 + 30).is_ok(),
        "5 min validity + 30 s skew allowance"
    );
    assert_eq!(at(NOW + 300 + 31), Err(CodeError::FutureDated));
    assert_eq!(at(u64::from(u32::MAX)), Err(CodeError::FutureDated));
}

#[test]
fn surrounding_whitespace_is_ignored() {
    let text = valid().encode();
    assert!(ConnectionCode::parse(&format!("  {text}\n"), NOW).is_ok());
}

#[test]
fn wrong_prefix_or_encoding_is_rejected() {
    let text = valid().encode();
    let body = &text[PREFIX.len()..];
    assert_eq!(ConnectionCode::parse(body, NOW), Err(CodeError::BadPrefix));
    assert_eq!(
        ConnectionCode::parse(&format!("remora2:{body}"), NOW),
        Err(CodeError::BadPrefix)
    );
    assert_eq!(
        ConnectionCode::parse(&format!("{text}="), NOW),
        Err(CodeError::BadEncoding),
        "padding not allowed"
    );
    assert_eq!(
        ConnectionCode::parse(&format!("{PREFIX}{}", body.replace('A', "+")), NOW).err(),
        Some(CodeError::BadEncoding)
    );
    assert_eq!(
        ConnectionCode::parse(&format!("{PREFIX}{body}é"), NOW),
        Err(CodeError::BadEncoding)
    );
}

#[test]
fn non_canonical_base64_is_rejected() {
    // 86 decoded bytes (one IPv4 candidate): 86 % 3 = 2, so the last character
    // carries 2 unused bits that must be zero.
    let text = sample(vec![v4()], (NOW + 60) as u32).encode();
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = text.chars().last().expect("non-empty");
    let idx = alphabet.find(last).expect("base64url char");
    let tweaked = alphabet.chars().nth(idx ^ 0b01).expect("in range"); // set an unused bit
    let bad = format!("{}{}", &text[..text.len() - 1], tweaked);
    assert_eq!(
        ConnectionCode::parse(&bad, NOW),
        Err(CodeError::BadEncoding)
    );
}

#[test]
fn every_single_character_typo_is_rejected() {
    let text = valid().encode();
    let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        .chars()
        .collect();
    for pos in PREFIX.len()..text.len() {
        for &c in &alphabet {
            let original = text.as_bytes()[pos] as char;
            if c == original {
                continue;
            }
            let mut typo = text.clone();
            typo.replace_range(pos..=pos, &c.to_string());
            let r = ConnectionCode::parse(&typo, NOW);
            assert!(
                r.is_err(),
                "typo at {pos} ({original}→{c}) was accepted as {r:?}"
            );
        }
    }
}

#[test]
fn structurally_invalid_content_is_rejected() {
    let base = raw_valid();
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = base.clone();
        f(&mut b);
        ConnectionCode::parse(&text_from_raw(b), NOW)
    };
    assert_eq!(with(&|b| b[0] = 2), Err(CodeError::UnsupportedVersion(2)));
    assert!(
        matches!(with(&|b| b[1] = 7), Err(CodeError::Malformed(_))),
        "unknown kind"
    );
    assert!(
        matches!(
            with(&|b| b.push(0)),
            Err(CodeError::Malformed(_) | CodeError::BadLength)
        ),
        "trailing byte"
    );
    let count_at = 2 + 4 + 16 + 32 + 4 + 16;
    assert!(
        matches!(
            with(&|b| b[count_at] = 9),
            Err(CodeError::Malformed(_) | CodeError::BadLength)
        ),
        "> 8 candidates"
    );
    assert!(
        matches!(
            with(&|b| b[count_at] = 3),
            Err(CodeError::Malformed(_) | CodeError::BadLength)
        ),
        "count/length mismatch"
    );
    let first = count_at + 1;
    assert!(
        matches!(with(&|b| b[first] = 0x50), Err(CodeError::Malformed(_))),
        "unknown family nibble"
    );
    assert!(
        matches!(with(&|b| b[first] = 0x42), Err(CodeError::Malformed(_))),
        "unknown candidate type"
    );
    assert!(
        matches!(
            with(&|b| {
                b[first + 5] = 0;
                b[first + 6] = 0
            }),
            Err(CodeError::Malformed(_))
        ),
        "port 0"
    );
    assert!(
        matches!(
            with(&|b| b[first + 1..first + 5].copy_from_slice(&[0, 0, 0, 0])),
            Err(CodeError::Malformed(_))
        ),
        "unspecified address"
    );
    assert!(
        matches!(with(&|b| b[first + 1] = 224), Err(CodeError::Malformed(_))),
        "multicast address"
    );
}

#[test]
fn impossible_lengths_are_rejected() {
    assert_eq!(
        ConnectionCode::parse(PREFIX, NOW),
        Err(CodeError::BadLength)
    );
    assert_eq!(
        ConnectionCode::parse(&text_from_raw(vec![1, 0, 0]), NOW),
        Err(CodeError::BadLength)
    );
}

#[test]
fn damaged_crc_is_corrupted_not_malformed() {
    let mut raw = raw_valid();
    let crc = crc32_bitwise(&raw) ^ 1;
    raw.extend_from_slice(&crc.to_be_bytes());
    let text = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
    assert_eq!(ConnectionCode::parse(&text, NOW), Err(CodeError::Corrupted));
}

// ── boundaries pinned by the mutation-testing gate ──────────────────────────

fn many(n: usize) -> Vec<Candidate> {
    (0..n)
        .map(|i| Candidate {
            kind: CandidateKind::Host,
            addr: SocketAddr::from((
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16 + 1),
                40_000,
            )),
        })
        .collect()
}

#[test]
fn length_bounds_are_exact() {
    // Smallest valid code: no candidates (79 bytes). One byte less is impossible.
    let min = sample(vec![], (NOW + 60) as u32);
    assert_eq!(ConnectionCode::parse(&min.encode(), NOW), Ok(min));
    let mut short = raw_valid();
    short.truncate(2 + 4 + 16 + 32 + 4 + 16); // 74 + 4-byte CRC = 78
    assert_eq!(
        ConnectionCode::parse(&text_from_raw(short), NOW),
        Err(CodeError::BadLength)
    );
    // Largest valid code: 8 IPv6 candidates (231 bytes). One byte more is impossible.
    let max = sample(many(8), (NOW + 60) as u32);
    let text = max.encode();
    assert_eq!(ConnectionCode::parse(&text, NOW), Ok(max));
    let mut raw = URL_SAFE_NO_PAD
        .decode(&text[PREFIX.len()..])
        .expect("valid");
    raw.truncate(raw.len() - 4);
    raw.push(0);
    assert_eq!(
        ConnectionCode::parse(&text_from_raw(raw), NOW),
        Err(CodeError::BadLength)
    );
}

#[test]
fn text_of_exactly_the_limit_is_not_too_long() {
    let text = "A".repeat(remora_proto::limits::CODE_TEXT_MAX);
    assert_eq!(ConnectionCode::parse(&text, NOW), Err(CodeError::BadPrefix));
}

#[test]
fn answer_codes_round_trip() {
    let mut c = valid();
    c.kind = CodeKind::Answer;
    assert_eq!(ConnectionCode::parse(&c.encode(), NOW), Ok(c));
}

#[test]
fn candidate_count_limit_is_exact() {
    let eight = sample(many(8), (NOW + 60) as u32);
    assert!(ConnectionCode::parse(&eight.encode(), NOW).is_ok());
    // Nine candidates with all their bytes present: rejected for the count, not length.
    let mut raw = URL_SAFE_NO_PAD
        .decode(&sample(many(8), (NOW + 60) as u32).encode()[PREFIX.len()..])
        .expect("valid");
    raw.truncate(raw.len() - 4);
    raw[2 + 4 + 16 + 32 + 4 + 16] = 9;
    raw.extend_from_slice(&[0x40, 10, 0, 0, 9, 0x9C, 0x40]);
    let r = ConnectionCode::parse(&text_from_raw(raw), NOW);
    assert!(
        matches!(r, Err(CodeError::Malformed(_) | CodeError::BadLength)),
        "{r:?}"
    );
}
