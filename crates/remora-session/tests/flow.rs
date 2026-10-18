//! phase3-criteria F1 at the session layer: password and trusted mode reach
//! the prompt with the SAME safety code on both screens; accept → Active,
//! deny → Rejected. Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use remora_crypto::identity::DeviceId;
use remora_session::{AppMessage, CloseCode, HostAction, State, ViewerAction, ViewerMode};

#[test]
fn password_mode_reaches_the_prompt_with_matching_codes() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = to_prompt(&mut host, &v, ip(1));
    let (id, host_sas) = c.log.prompt().expect("prompt");
    assert_eq!(id, c.id);
    assert_eq!(
        c.log.viewer_sas(),
        Some(host_sas),
        "both screens show the same code"
    );
    assert_eq!(
        state_of(&host, &c),
        (Some(State::PendingApproval), State::PendingApproval)
    );
    // The prompt names the viewer by its (untrusted) device name and key.
    assert!(c.log.host.iter().any(|a| matches!(a,
        HostAction::Prompt { viewer_name, viewer_key, .. }
            if viewer_name == "viewer" && *viewer_key == v.key.public())));
    assert_eq!(delivered_count(&c), 0);
}

#[test]
fn accept_makes_both_sides_active_and_input_flows() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_active(&mut host, &v, ip(1));
    assert_eq!(state_of(&host, &c), (Some(State::Active), State::Active));
    assert!(c.log.host.contains(&HostAction::Active { id: c.id }));
    assert!(c.log.viewer.contains(&ViewerAction::Active));
    assert_eq!(host.active_sessions(), vec![c.id]);
    let send = c
        .viewer
        .send_input(input_click())
        .expect("active viewer can send");
    c.feed_viewer_actions(&mut host, vec![send]);
    let got: Vec<_> = c
        .log
        .host
        .iter()
        .filter_map(|a| match a {
            HostAction::Deliver { msg, .. } => Some(msg.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(got, vec![AppMessage::Input(input_click())]);
}

#[test]
fn deny_rejects_both_sides() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_prompt(&mut host, &v, ip(1));
    let acts = host.deny(c.id);
    c.host_actions(&mut host, acts);
    assert_eq!(c.log.host_close(), Some(CloseCode::Rejected));
    assert_eq!(host.state(c.id), Some(State::Closed));
    assert_eq!(c.viewer.state(), State::Closed);
    assert_eq!(
        c.log.viewer_failure(),
        Some(remora_session::FailReason::Rejected)
    );
    assert_eq!(host.limiter().pending(), 0, "slot released");
}

#[test]
fn trusted_mode_reaches_the_prompt_too() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![v.key.public()]);
    let mode = ViewerMode::Trusted {
        pinned: h.key.public(),
    };
    let mut c = connect(&mut host, &v, mode, ip(1), T0);
    assert!(
        c.log.prompt().is_some(),
        "trusted mode still asks the host user (A25-T)"
    );
    assert_eq!(c.log.viewer_sas(), c.log.prompt().map(|p| p.1));
    c.approve(&mut host);
    assert_eq!(state_of(&host, &c), (Some(State::Active), State::Active));
}

#[test]
fn connecting_by_the_right_device_id_works() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mode = password_mode(&host, Some(DeviceId::of(&h.key.public())));
    let c = connect(&mut host, &v, mode, ip(1), T0);
    assert!(c.log.prompt().is_some());
}

#[test]
fn goodbye_from_the_viewer_closes_normally() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let mut c = to_active(&mut host, &v, ip(1));
    let acts = c.viewer.disconnect();
    c.feed_viewer_actions(&mut host, acts);
    assert_eq!(c.viewer.state(), State::Closed);
    assert_eq!(host.state(c.id), Some(State::Closed));
    assert_eq!(c.log.host_close(), Some(CloseCode::Normal));
    assert!(host.active_sessions().is_empty());
}

#[test]
fn hello_carries_version_mode_nonce_and_device_id() {
    use prost::Message;
    use remora_proto::messages::{HostHello, ViewerHello};
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = to_prompt(&mut host, &v, ip(1));
    let vh = ViewerHello::decode(c.v2h[0].as_slice()).unwrap();
    assert_eq!(vh.versions, vec![1]);
    assert_eq!(vh.mode, 1);
    assert_eq!(vh.nonce, vec![3; 16]);
    let hh = HostHello::decode(c.h2v[0].as_slice()).unwrap();
    assert_eq!(hh.version, 1);
    assert_eq!(
        hh.host_device_id,
        DeviceId::of(&h.key.public()).as_bytes().to_vec()
    );
}
