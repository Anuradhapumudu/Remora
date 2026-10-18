//! phase3-criteria A25-T (trusted fast path keeps every check), A16, A19 at
//! the session layer, the close-code table (§2), and A28 for everything the
//! session emits. Written before the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

mod common;

use common::*;
use rand_core::OsRng;
use remora_crypto::identity::DeviceId;
use remora_crypto::noise::HandshakeError;
use remora_crypto::pake::PakeError;
use remora_session::fail::{AuthDetail, Violation};
use remora_session::limiter::Refusal;
use remora_session::{CloseCode, FailReason, HostAction, Refused, State, ViewerMode};

fn trusted(pinned: &Device) -> ViewerMode {
    ViewerMode::Trusted {
        pinned: pinned.key.public(),
    }
}

#[test]
fn close_code_table() {
    use remora_proto::messages::MessageError;
    let table = [
        (
            FailReason::AuthFailed(AuthDetail::Handshake(HandshakeError::Msg1Auth)),
            0x10,
        ),
        (FailReason::AuthFailed(AuthDetail::Pake), 0x10),
        (FailReason::IdentityMismatch, 0x10),
        (FailReason::IdentityChanged, 0x10),
        // A32: a bad PAKE element is locally a protocol violation, on the
        // wire AUTH_FAILED like every other authentication failure.
        (
            FailReason::ProtocolViolation(Violation::PakeElement(PakeError::SmallOrder)),
            0x10,
        ),
        (
            FailReason::ProtocolViolation(Violation::PakeElement(PakeError::NotTorsionFree)),
            0x10,
        ),
        // A frame of the wrong length is framing, not authentication.
        (
            FailReason::ProtocolViolation(Violation::PakeElement(PakeError::WrongLength {
                len: 3,
            })),
            0x11,
        ),
        (
            FailReason::ProtocolViolation(Violation::Malformed(MessageError::Invalid("x"))),
            0x11,
        ),
        (
            FailReason::ProtocolViolation(Violation::Handshake(HandshakeError::CommitmentMismatch)),
            0x11,
        ),
        (FailReason::ProtocolViolation(Violation::BeforeActive), 0x11),
        (FailReason::ProtocolViolation(Violation::WrongRole), 0x11),
        (
            FailReason::ProtocolViolation(Violation::TransportAuth),
            0x11,
        ),
        (
            FailReason::ProtocolViolation(Violation::DatagramBeforeActive),
            0x11,
        ),
        (FailReason::VersionUnsupported, 0x12),
        (FailReason::Rejected, 0x13),
        (FailReason::Timeout, 0x14),
        (FailReason::RateLimited, 0x15),
    ];
    for (reason, code) in table {
        assert_eq!(reason.close_code() as u16, code, "{reason:?}");
    }
}

#[test]
fn a25t_trusted_mode_shows_the_prompt_and_needs_approval() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![v.key.public()]);
    let c = connect(&mut host, &v, trusted(&h), ip(1), T0);
    assert!(
        c.log.prompt().is_some(),
        "owner requirement: trusted devices still get a prompt"
    );
    assert_eq!(host.state(c.id), Some(State::PendingApproval));
    assert!(host.active_sessions().is_empty());
}

#[test]
fn a25t_trusted_mode_counts_against_admission_limits() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![v.key.public()]);
    for k in 0..4u8 {
        let _ = start(&mut host, &v, trusted(&h), ip(k), T0);
    }
    assert_eq!(
        host.accept_connection(ip(9), exporter(1), T0, &mut OsRng),
        Err(Refused(Refusal::TooManyPending))
    );
}

#[test]
fn a25t_host_refuses_an_untrusted_viewer_in_trusted_mode() {
    let (h, v, stranger) = (device("host"), device("viewer"), device("stranger"));
    let mut host = host_with(&h, vec![v.key.public()]);
    let c = connect(&mut host, &stranger, trusted(&h), ip(1), T0);
    assert_eq!(c.log.host_close(), Some(CloseCode::AuthFailed));
    assert_eq!(
        c.log.host_failure(),
        Some(FailReason::AuthFailed(AuthDetail::Handshake(
            HandshakeError::UntrustedKey
        )))
    );
    assert!(c.log.prompt().is_none());
}

#[test]
fn a25t_trusted_mode_with_no_trusted_devices_is_refused() {
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let c = connect(&mut host, &v, trusted(&h), ip(1), T0);
    assert_eq!(c.log.host_close(), Some(CloseCode::AuthFailed));
    assert_eq!(
        c.log.host_failure(),
        Some(FailReason::AuthFailed(AuthDetail::ModeUnavailable))
    );
    assert_eq!(c.h2v.len(), 0, "refused at the hello, nothing sent");
}

#[test]
fn a19_viewer_pinned_to_an_old_host_key_gets_identity_changed() {
    let (h, v, old) = (device("host"), device("viewer"), device("host, old key"));
    let mut host = host_with(&h, vec![v.key.public()]);
    let c = connect(&mut host, &v, trusted(&old), ip(1), T0);
    assert_eq!(c.log.viewer_failure(), Some(FailReason::IdentityChanged));
    assert_eq!(c.viewer.state(), State::Closed);
    assert!(c.log.viewer_sas().is_none(), "never shown a SAS");
    // And it does NOT fall back to the password path: nothing more is sent.
    assert!(
        !c.log
            .viewer
            .iter()
            .skip_while(|a| !matches!(a, remora_session::ViewerAction::Failed { .. }))
            .any(|a| matches!(a, remora_session::ViewerAction::Send(_)))
    );
}

#[test]
fn a16_viewer_asking_for_device_x_aborts_on_device_y() {
    let (h, v, wanted) = (device("host"), device("viewer"), device("the real host"));
    let mut host = host_with(&h, vec![]);
    let mode = password_mode(&host, Some(DeviceId::of(&wanted.key.public())));
    let c = connect(&mut host, &v, mode, ip(1), T0);
    assert_eq!(c.log.viewer_failure(), Some(FailReason::IdentityMismatch));
    assert_eq!(c.log.viewer_close(), Some(CloseCode::AuthFailed));
    assert!(c.log.viewer_sas().is_none(), "aborts before showing a SAS");
    assert!(c.log.prompt().is_none(), "never reaches PendingApproval");
}

#[test]
fn version_unsupported_hello() {
    use prost::Message;
    use remora_proto::messages::{Mode, ViewerHello};
    let h = device("host");
    let mut host = host_with(&h, vec![]);
    let id = host
        .accept_connection(ip(1), exporter(7), T0, &mut OsRng)
        .unwrap();
    let vh = ViewerHello {
        versions: vec![2, 3],
        mode: Mode::Password as i32,
        nonce: vec![3; 16],
    }
    .encode_to_vec();
    let acts = host.on_frame(id, &vh, T0, &mut OsRng);
    assert!(acts.contains(&HostAction::Close {
        id,
        code: CloseCode::VersionUnsupported
    }));
    assert!(acts.iter().any(|a| matches!(
        a,
        HostAction::Failed {
            reason: FailReason::VersionUnsupported,
            ..
        }
    )));
}

#[test]
fn a28_no_secret_appears_in_any_action_or_reason() {
    use remora_testkit::canary::{Canary, find_leaks};
    let (h, v) = (device("host"), device("viewer"));
    let mut host = host_with(&h, vec![]);
    let otp = host.otp().reveal().to_owned();
    let mut c = to_active(&mut host, &v, ip(1));
    let wrong_mode = wrong_password_mode(&host);
    let wrong = connect(&mut host, &v, wrong_mode, ip(2), T0);
    let send = c.viewer.send_input(input_click()).unwrap();
    c.feed_viewer_actions(&mut host, vec![send]);
    let canaries = [
        Canary::new("otp", otp.clone()),
        Canary::new("exporter", vec![7u8; 32]),
    ];
    let text = format!(
        "{:?} {:?} {:?} {:?} {:?}",
        c.log.host, c.log.viewer, wrong.log.host, wrong.log.viewer, host
    );
    // Note: the OTP canary is a 6-digit string, so a random u64 session ID
    // printed in the same text could contain it by chance (≈ 10⁻⁴ per run).
    let leaks = find_leaks(&text, &canaries);
    assert!(leaks.is_empty(), "{leaks:?}");
}
