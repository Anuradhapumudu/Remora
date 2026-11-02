//! phase4.8-criteria A1, A3, A5 in the session layer: audio is sealed per
//! session like video, reaches only Active sessions, arrives intact, and a
//! replayed or malformed audio datagram is not played.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use rand_core::OsRng;
use remora_proto::audio::AudioPacket;
use remora_session::{Host, HostAction, State, ViewerAction};

fn packet(seq: u32) -> AudioPacket {
    AudioPacket {
        seq,
        capture_ts_us: 1_000 + u64::from(seq) * 20_000,
        data: vec![seq as u8; 160],
    }
}

/// The audio datagrams `host` sealed for `c` (other actions applied).
fn send(host: &mut Host, c: &mut Conn, p: &AudioPacket) -> Vec<Vec<u8>> {
    let mut media = Vec::new();
    let mut rest = Vec::new();
    for a in host.send_audio(p, c.now, &mut OsRng) {
        match a {
            HostAction::Media { id, datagram } if id == c.id => media.push(datagram.into_bytes()),
            HostAction::Media { .. } => {}
            other => rest.push(other),
        }
    }
    c.host_actions(host, rest);
    media
}

fn heard(c: &mut Conn, datagrams: &[Vec<u8>]) -> Vec<AudioPacket> {
    let mut out = Vec::new();
    for d in datagrams {
        for a in c.viewer.on_datagram(d, c.now) {
            match a {
                ViewerAction::Audio(p) => out.push(p),
                other => panic!("unexpected viewer action {other:?}"),
            }
        }
    }
    out
}

#[test]
fn audio_is_sealed_and_arrives_intact() {
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    let v = device("viewer");
    let mut c = to_active(&mut host, &v, ip(1));
    let p = packet(3);
    let ds = send(&mut host, &mut c, &p);
    assert_eq!(ds.len(), 1, "one datagram per packet");
    assert_eq!(ds[0][0], 0x04, "audio kind on the wire");
    assert!(
        !ds[0].windows(p.data.len()).any(|w| w == p.data.as_slice()),
        "the Opus bytes are not in the clear"
    );
    assert_eq!(heard(&mut c, &ds), [p]);
    assert_eq!(c.viewer.media_stats().audio_packets, 1);
}

#[test]
fn a1_audio_reaches_only_active_sessions() {
    let h = device("host");
    let mut host = host_multi_viewer(&h);
    let v = device("viewer");
    let control = to_active(&mut host, &v, ip(9));
    // A second viewer stopped at the prompt (PendingApproval).
    let mode = password_mode(&host, None);
    let (pending, first) = start(&mut host, &v, mode, ip(10), T0);
    let mut pending = pending;
    pending.pump(&mut host, first, Vec::new(), &mut |_, _, f| Some(f));
    assert_eq!(
        host.state(pending.id),
        Some(State::PendingApproval),
        "really at the prompt"
    );
    let acts = host.send_audio(&packet(1), T0, &mut OsRng);
    assert!(
        acts.iter()
            .any(|a| matches!(a, HostAction::Media { id, .. } if *id == control.id)),
        "the Active session got audio (positive control)"
    );
    assert!(
        !acts.iter().any(|a| matches!(
            a,
            HostAction::Media { id, .. } | HostAction::Send { id, .. } if *id == pending.id
        )),
        "audio leaked to a session waiting for approval"
    );
}

#[test]
fn a5_a_replayed_audio_datagram_is_not_played_again() {
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    let v = device("viewer");
    let mut c = to_active(&mut host, &v, ip(1));
    let ds = send(&mut host, &mut c, &packet(1));
    assert_eq!(heard(&mut c, &ds).len(), 1);
    assert!(heard(&mut c, &ds).is_empty(), "replay played");
    assert_eq!(c.viewer.media_stats().replayed, 1);
}

#[test]
fn a3_an_empty_audio_body_is_counted_not_played() {
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    let v = device("viewer");
    let mut c = to_active(&mut host, &v, ip(1));
    let empty = AudioPacket {
        seq: 1,
        capture_ts_us: 0,
        data: Vec::new(),
    };
    let ds = send(&mut host, &mut c, &empty);
    assert!(heard(&mut c, &ds).is_empty());
    assert_eq!(c.viewer.media_stats().bad_audio, 1);
}
