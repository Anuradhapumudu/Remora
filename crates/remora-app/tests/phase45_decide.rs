//! Phase 4.5 decision module (phase4.5-criteria §4-§6, §10): the GUI's
//! rules without a GUI. Each test names its criteria row; the planted
//! failures are recorded in the commit that adds them.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use remora_app::decide::dialog::{
    ARM_DELAY_MS, Answer, Dialogs, Key, MAX_DIALOGS, OpenError, Trust,
};
use remora_app::decide::host::{HostDesk, HostRequest};
use remora_app::decide::viewer::{
    DECLINED, MISMATCH, Stage, UNVERIFIED, VERIFIED, ViewerDesk, ViewerRequest, WAITING, read_code,
    read_password,
};
use remora_crypto::sas::{Sas, sas};
use remora_session::{CloseCode, Millis, PROMPT_TIMEOUT_MS, SessionId};

fn code(n: u8) -> Sas {
    sas(&[n; 32], &[n.wrapping_add(1); 32], &[n.wrapping_add(2); 32])
}

/// Two different safety codes.
fn two_codes() -> (Sas, Sas) {
    let a = code(1);
    let b = (2..=255).map(code).find(|s| *s != a).unwrap();
    (a, b)
}

const T: Millis = Millis(10_000);

fn at(ms: u64) -> Millis {
    T.plus(ms)
}

fn one_dialog() -> (Dialogs, SessionId, Sas) {
    let mut d = Dialogs::new();
    let (id, s) = (SessionId(7), code(1));
    d.open(id, s, "Bob's Mac", "ABCD-EFGH".into(), Trust::New, T)
        .unwrap();
    (d, id, s)
}

// --------------------------------------------------------------- H2 ------

#[test]
fn h2_accept_is_bound_to_its_own_session_and_code() {
    let (s1, s2) = two_codes();
    let mut d = Dialogs::new();
    d.open(SessionId(1), s1, "A", "A".into(), Trust::New, T)
        .unwrap();
    d.open(SessionId(2), s2, "B", "B".into(), Trust::New, T)
        .unwrap();
    d.press_accept(SessionId(2), at(ARM_DELAY_MS));
    assert_eq!(
        d.release_accept(SessionId(2), at(ARM_DELAY_MS + 50)),
        Some(Answer::Accept {
            id: SessionId(2),
            sas: s2
        })
    );
    // Only B was answered; A is still open and unanswered.
    assert_eq!(d.len(), 1);
    assert_eq!(d.view(at(2000))[0].id, SessionId(1));
}

#[test]
fn h2_accept_on_the_older_dialog_accepts_the_older_session() {
    // The newest dialog is on top; clicking the one under it must answer
    // that one, not "whichever is newest".
    let (s1, s2) = two_codes();
    let mut d = Dialogs::new();
    d.open(SessionId(1), s1, "A", "A".into(), Trust::New, T)
        .unwrap();
    d.open(SessionId(2), s2, "B", "B".into(), Trust::New, T)
        .unwrap();
    d.press_accept(SessionId(1), at(ARM_DELAY_MS));
    assert_eq!(
        d.release_accept(SessionId(1), at(ARM_DELAY_MS + 50)),
        Some(Answer::Accept {
            id: SessionId(1),
            sas: s1
        })
    );
    assert_eq!(d.view(at(2000))[0].id, SessionId(2));
}

#[test]
fn h2_press_on_one_dialog_release_on_another_accepts_nothing() {
    let (s1, s2) = two_codes();
    let mut d = Dialogs::new();
    d.open(SessionId(1), s1, "A", "A".into(), Trust::New, T)
        .unwrap();
    d.open(SessionId(2), s2, "B", "B".into(), Trust::New, T)
        .unwrap();
    d.press_accept(SessionId(1), at(2000));
    assert_eq!(d.release_accept(SessionId(2), at(2100)), None);
    assert_eq!(d.len(), 2);
}

#[test]
fn h2_a_dialog_whose_session_ended_can_never_accept() {
    let (mut d, id, _) = one_dialog();
    d.press_accept(id, at(2000));
    d.close(id, at(2050)); // the viewer left
    assert_eq!(d.release_accept(id, at(2100)), None);
    d.press_accept(id, at(3000));
    assert_eq!(d.release_accept(id, at(3100)), None);
    assert!(d.is_empty());
}

#[test]
fn h2_view_shows_this_dialogs_code_and_escaped_name() {
    let mut d = Dialogs::new();
    let s = code(3);
    d.open(
        SessionId(9),
        s,
        "Eve\u{202E}tpeccA",
        "WXYZ-1234".into(),
        Trust::Pinned,
        T,
    )
    .unwrap();
    let v = &d.view(T)[0];
    assert_eq!(v.sas, remora_app::cli::format_sas(s));
    assert_eq!(v.name, "Eve\\u{202E}tpeccA"); // H6
    assert_eq!(v.device, "WXYZ-1234");
    assert_eq!(v.trust, "known device");
}

// --------------------------------------------------------------- H3 ------

#[test]
fn h3_return_space_escape_deny_and_no_key_accepts() {
    for key in [Key::Return, Key::Space, Key::Escape] {
        let (mut d, id, _) = one_dialog();
        assert_eq!(
            d.key(id, key, at(5000)),
            Some(Answer::Deny { id }),
            "{key:?}"
        );
        assert!(d.is_empty());
    }
    let (mut d, id, _) = one_dialog();
    assert_eq!(d.key(id, Key::Other, at(5000)), None);
    assert_eq!(d.len(), 1);
}

// --------------------------------------------------------------- H4 ------

#[test]
fn h4_click_before_the_delay_does_nothing() {
    let (mut d, id, _) = one_dialog();
    assert!(!d.is_empty());
    d.press_accept(id, at(500));
    assert_eq!(d.release_accept(id, at(550)), None);
    assert!(!d.view(at(500))[0].accept_enabled);
    assert_eq!(d.len(), 1);
}

#[test]
fn h4_press_before_and_release_after_the_delay_does_nothing() {
    let (mut d, id, _) = one_dialog();
    d.press_accept(id, at(900));
    assert_eq!(d.release_accept(id, at(1200)), None);
    assert_eq!(d.len(), 1);
}

#[test]
fn h4_press_and_release_after_the_delay_accepts() {
    let (mut d, id, s) = one_dialog();
    assert!(d.view(at(ARM_DELAY_MS))[0].accept_enabled);
    d.press_accept(id, at(ARM_DELAY_MS));
    assert_eq!(
        d.release_accept(id, at(ARM_DELAY_MS)),
        Some(Answer::Accept { id, sas: s })
    );
}

#[test]
fn h4_a_new_dialog_restarts_the_delay_and_cancels_a_press() {
    let (mut d, id, _) = one_dialog();
    d.press_accept(id, at(1500));
    // A second dialog appears on top before the release.
    d.open(
        SessionId(8),
        code(5),
        "other",
        "X".into(),
        Trust::New,
        at(1600),
    )
    .unwrap();
    assert_eq!(d.release_accept(id, at(1700)), None);
    // Armed again only 1 s after the change.
    d.press_accept(id, at(2500));
    assert_eq!(d.release_accept(id, at(2550)), None);
    assert!(!d.view(at(2599))[0].accept_enabled);
    d.press_accept(id, at(2600));
    assert!(matches!(
        d.release_accept(id, at(2650)),
        Some(Answer::Accept { .. })
    ));
}

#[test]
fn h4_a_closing_dialog_restarts_the_delay() {
    let mut d = Dialogs::new();
    d.open(SessionId(1), code(1), "A", "A".into(), Trust::New, T)
        .unwrap();
    d.open(SessionId(2), code(9), "B", "B".into(), Trust::New, T)
        .unwrap();
    d.close(SessionId(2), at(3000));
    d.press_accept(SessionId(1), at(3500));
    assert_eq!(d.release_accept(SessionId(1), at(3600)), None);
}

#[test]
fn h4_release_without_a_press_does_nothing() {
    let (mut d, id, _) = one_dialog();
    assert_eq!(d.release_accept(id, at(5000)), None);
    d.press_accept(id, at(5000));
    d.cancel_press();
    assert_eq!(d.release_accept(id, at(5100)), None);
}

// --------------------------------------------------------------- H5 ------

#[test]
fn h5_the_dialog_shows_the_sessions_time_left_and_has_no_timer_of_its_own() {
    let (mut d, id, _) = one_dialog();
    assert_eq!(d.view(T)[0].seconds_left, PROMPT_TIMEOUT_MS / 1000);
    assert_eq!(d.view(at(59_001))[0].seconds_left, 1);
    assert_eq!(d.view(at(60_000))[0].seconds_left, 0);
    // Still open at and after 0: only the session layer ends it (A24)...
    assert_eq!(d.view(at(61_000)).len(), 1);
    // ...and when it does, the dialog closes.
    d.close(id, at(61_000));
    assert!(d.view(at(61_000)).is_empty());
}

// --------------------------------------------------------------- R4 ------

#[test]
fn r4_at_most_four_dialogs_never_more() {
    let mut d = Dialogs::new();
    for i in 0..MAX_DIALOGS as u64 {
        d.open(SessionId(i), code(i as u8), "v", "D".into(), Trust::New, T)
            .unwrap();
    }
    assert_eq!(MAX_DIALOGS, 4);
    assert_eq!(
        d.open(SessionId(99), code(99), "fifth", "D".into(), Trust::New, T),
        Err(OpenError::TooMany)
    );
    assert_eq!(d.len(), 4);
    assert_eq!(
        d.open(SessionId(0), code(0), "again", "D".into(), Trust::New, T),
        Err(OpenError::Duplicate)
    );
}

// --------------------------------------------------- I1, I2, H9, H10 -----

#[test]
fn i1_indicator_shown_exactly_while_active() {
    let mut h = HostDesk::new();
    assert!(h.indicator(T).is_none());
    h.dialogs
        .open(SessionId(1), code(1), "Bob", "D".into(), Trust::New, T)
        .unwrap();
    assert!(h.indicator(T).is_none(), "not before Active");
    h.session_active(SessionId(1), "Bob", at(2000));
    let i = h.indicator(at(2000 + 65_000)).expect("shown while active");
    assert_eq!(i.text, "Bob is viewing your screen");
    assert_eq!(i.seconds, 65);
    assert!(h.dialogs.is_empty(), "its dialog is gone");
    h.session_ended(SessionId(2), at(70_000)); // another session: no effect
    assert!(h.indicator(at(70_000)).is_some());
    h.session_ended(SessionId(1), at(70_000));
    assert!(h.indicator(at(70_000)).is_none());
}

#[test]
fn i1_indicator_name_is_escaped() {
    let mut h = HostDesk::new();
    h.session_active(SessionId(1), "x\n\u{202E}y", T);
    assert_eq!(
        h.indicator(T).unwrap().text,
        "x\\u{000A}\\u{202E}y is viewing your screen"
    );
}

#[test]
fn i2_end_session_disconnects_the_active_session() {
    let mut h = HostDesk::new();
    assert_eq!(h.end_session(), None);
    h.session_active(SessionId(4), "Bob", T);
    assert_eq!(h.end_session(), Some(HostRequest::Disconnect(SessionId(4))));
}

#[test]
fn h9_other_dialogs_are_denied_when_a_session_becomes_active() {
    let mut h = HostDesk::new();
    for i in 1..=3 {
        h.dialogs
            .open(SessionId(i), code(i as u8), "v", "D".into(), Trust::New, T)
            .unwrap();
    }
    let reqs = h.session_active(SessionId(2), "v", at(5000));
    assert_eq!(
        reqs,
        vec![
            HostRequest::Answer(Answer::Deny { id: SessionId(1) }),
            HostRequest::Answer(Answer::Deny { id: SessionId(3) }),
        ]
    );
    assert!(h.dialogs.is_empty());
}

#[test]
fn h9_refused_attempts_are_counted() {
    let mut h = HostDesk::new();
    h.refused_busy();
    h.refused_busy();
    assert_eq!(h.refused_busy_count(), 2);
}

#[test]
fn h10_code_hidden_while_active_until_show() {
    let mut h = HostDesk::new();
    assert!(h.secrets_visible(), "no session: shown");
    h.session_active(SessionId(1), "Bob", T);
    assert!(!h.secrets_visible(), "hidden while active");
    h.show_secrets();
    assert!(h.secrets_visible());
    h.hide_secrets();
    assert!(!h.secrets_visible());
    h.show_secrets();
    h.session_ended(SessionId(1), T);
    assert!(h.secrets_visible());
    // A new session starts hidden even if Show was pressed in the last one.
    h.show_secrets();
    h.session_active(SessionId(2), "Bob", T);
    assert!(!h.secrets_visible());
}

// ------------------------------------------------------------- viewer ----

#[test]
fn v1_an_oversized_paste_is_refused_before_parsing() {
    let huge = "x".repeat(remora_proto::limits::CODE_TEXT_MAX + 1);
    let e = read_code(&huge, 0).unwrap_err();
    assert!(e.contains("too long") || e.contains("long"), "{e}");
    assert!(read_code("not a code", 0).is_err());
}

fn a_code(kind: remora_proto::code::CodeKind, now: u32) -> String {
    use remora_proto::code::{Candidate, CandidateKind, ConnectionCode};
    ConnectionCode {
        kind,
        expires_at: now + 300,
        nonce: [7; 16],
        identity_key: *remora_crypto::identity::DeviceKeys::generate(&mut rand_core::OsRng)
            .identity
            .public()
            .as_bytes(),
        ice_ufrag: [1; 4],
        ice_pwd: [2; 16],
        candidates: vec![Candidate {
            kind: CandidateKind::Host,
            addr: "127.0.0.1:4000".parse().unwrap(),
        }],
    }
    .encode()
}

#[test]
fn v1_a_hosts_code_shows_its_device_and_an_answer_code_is_refused() {
    let now: u32 = 1_800_000_000;
    let t = read_code(
        &a_code(remora_proto::code::CodeKind::Offer, now),
        now.into(),
    )
    .unwrap();
    assert_eq!(t.addr, "127.0.0.1:4000".parse().unwrap());
    assert_eq!(t.nonce, [7; 16]);
    assert!(!t.host_device.is_empty());
    let e = read_code(
        &a_code(remora_proto::code::CodeKind::Answer, now),
        now.into(),
    )
    .unwrap_err();
    assert!(e.contains("answer code"), "{e}");
}

#[test]
fn connect_is_possible_only_with_a_valid_code_and_six_digits() {
    let now: u32 = 1_800_000_000;
    let code = a_code(remora_proto::code::CodeKind::Offer, now);
    let can = |c: &str, p: &str| remora_app::decide::viewer::can_connect(c, p, now.into());
    assert!(can(&code, "123456"));
    assert!(can(&code, "123 456"));
    assert!(!can(&code, "12345"));
    assert!(!can(&code, "1234567"));
    assert!(!can(&code, "12345x"));
    assert!(!can("not a code", "123456"));
    assert!(!can(
        &a_code(remora_proto::code::CodeKind::Answer, now),
        "123456"
    ));
}

#[test]
fn v2_password_is_six_digits() {
    assert!(read_password(" 123456 ").is_ok());
    assert!(read_password("123 456").is_ok(), "as the host shows it");
    assert!(read_password("12345").is_err());
    assert!(read_password("abcdef").is_err());
}

#[test]
fn v3_after_the_handshake_code_unverified_and_waiting() {
    let mut v = ViewerDesk::new();
    v.connecting();
    assert_eq!(v.view(T).sas, None);
    v.show_sas(code(1));
    let view = v.view(T);
    assert_eq!(view.stage, Stage::Comparing);
    assert_eq!(view.sas, Some(remora_app::cli::format_sas(code(1))));
    assert_eq!(view.verification, Some(UNVERIFIED));
    assert_eq!(view.waiting, Some(WAITING));
}

#[test]
fn v4_verified_only_by_the_codes_match() {
    let mut v = ViewerDesk::new();
    v.codes_match(); // nothing on screen yet
    assert!(!v.verified());
    v.connecting();
    v.codes_match();
    assert!(!v.verified(), "not before a code is shown");
    v.show_sas(code(1));
    v.active(); // the host accepting does not verify
    assert!(!v.verified());
    assert_eq!(v.view(T).verification, Some(UNVERIFIED));
    v.codes_match();
    assert!(v.verified());
    assert_eq!(v.view(T).verification, Some(VERIFIED));
    // Verified is for this session only.
    v.connecting();
    assert!(!v.verified());
}

#[test]
fn v4_nothing_verifies_after_the_session_ended() {
    let mut v = ViewerDesk::new();
    v.connecting();
    v.show_sas(code(1));
    v.ended(Some(CloseCode::Normal));
    v.codes_match();
    assert!(!v.verified());
}

#[test]
fn v3_active_only_after_the_code_was_shown() {
    let mut v = ViewerDesk::new();
    v.connecting();
    v.active(); // no code on screen yet: not Active
    assert_eq!(v.view(T).stage, Stage::Connecting);
    v.show_sas(code(1));
    v.active();
    assert_eq!(v.view(T).stage, Stage::Active);
    assert_eq!(v.view(T).waiting, None, "the host has answered");
}

#[test]
fn v6_a_silent_host_ends_as_lost_but_never_replaces_a_reason() {
    let mut v = ViewerDesk::new();
    v.connecting();
    v.lost();
    let Stage::Ended(text) = v.view(T).stage else {
        panic!()
    };
    assert!(text.contains("lost"), "{text}");
    v.ended(Some(CloseCode::Rejected));
    let Stage::Ended(again) = v.view(T).stage else {
        panic!()
    };
    assert_eq!(again, text);
    let mut v = ViewerDesk::new();
    v.connecting();
    v.ended(Some(CloseCode::Rejected));
    v.lost();
    assert_eq!(v.view(T).stage, Stage::Ended(DECLINED.into()));
}

#[test]
fn v4_they_dont_match_ends_the_session_and_says_why() {
    let mut v = ViewerDesk::new();
    assert_eq!(v.codes_differ(), None);
    v.connecting();
    v.show_sas(code(1));
    assert_eq!(v.codes_differ(), Some(ViewerRequest::Disconnect));
    assert_eq!(v.view(T).stage, Stage::Ended(MISMATCH.into()));
    // The close that follows does not replace the reason.
    v.ended(Some(CloseCode::Normal));
    assert_eq!(v.view(T).stage, Stage::Ended(MISMATCH.into()));
}

#[test]
fn v5_denied_or_timed_out_says_ask_for_a_new_code() {
    let mut v = ViewerDesk::new();
    v.connecting();
    v.show_sas(code(1));
    v.ended(Some(CloseCode::Rejected));
    assert_eq!(v.view(T).stage, Stage::Ended(DECLINED.into()));
}

#[test]
fn v5_a_rejected_failure_says_ask_for_a_new_code_and_a_first_reason_stays() {
    let mut v = ViewerDesk::new();
    v.connecting();
    v.failed(&remora_session::FailReason::Rejected);
    assert_eq!(v.view(T).stage, Stage::Ended(DECLINED.into()));
    v.ended(Some(CloseCode::Normal));
    assert_eq!(v.view(T).stage, Stage::Ended(DECLINED.into()));
    let mut v = ViewerDesk::new();
    v.connecting();
    v.failed(&remora_session::FailReason::IdentityMismatch);
    let Stage::Ended(text) = v.view(T).stage else {
        panic!()
    };
    assert!(text.contains("not the device in the code"), "{text}");
}

#[test]
fn a_local_error_ends_with_its_reason_but_never_replaces_one() {
    let mut v = ViewerDesk::new();
    v.connecting();
    v.error("no route to host");
    assert_eq!(
        v.view(T).stage,
        Stage::Ended("The connection failed: no route to host".into())
    );
    let mut v = ViewerDesk::new();
    v.connecting();
    v.ended(Some(CloseCode::Rejected));
    v.error("late");
    assert_eq!(v.view(T).stage, Stage::Ended(DECLINED.into()));
}

#[test]
fn v5_busy_host_says_so() {
    let mut v = ViewerDesk::new();
    v.connecting();
    v.ended(Some(CloseCode::HostBusy));
    let Stage::Ended(text) = v.view(T).stage else {
        panic!()
    };
    assert!(text.contains("busy"), "{text}");
}

#[test]
fn v6_display_unavailable_counts_down_locally_then_resumes() {
    let mut v = ViewerDesk::new();
    v.connecting();
    v.show_sas(code(1));
    v.active();
    assert_eq!(v.view(T).display, None);
    v.display_unavailable(120_000, T);
    assert_eq!(
        v.view(T).display.as_deref(),
        Some("Display unavailable \u{2014} 120 s left")
    );
    assert_eq!(
        v.view(at(30_500)).display.as_deref(),
        Some("Display unavailable \u{2014} 90 s left")
    );
    assert_eq!(
        v.view(at(500_000)).display.as_deref(),
        Some("Display unavailable \u{2014} 0 s left")
    );
    // A newer update from the host replaces the local count.
    v.display_unavailable(60_000, at(40_000));
    assert_eq!(
        v.view(at(40_000)).display.as_deref(),
        Some("Display unavailable \u{2014} 60 s left")
    );
    v.resumed();
    assert_eq!(
        v.view(at(41_000)).display.as_deref(),
        Some("The host's display is back.")
    );
}

#[test]
fn v6_disconnect_is_one_click() {
    let mut v = ViewerDesk::new();
    assert_eq!(v.disconnect(), None, "nothing to end on the form");
    v.connecting();
    v.show_sas(code(1));
    v.active();
    assert_eq!(v.disconnect(), Some(ViewerRequest::Disconnect));
    assert!(matches!(v.view(T).stage, Stage::Ended(_)));
}
