//! Linux, needs a desktop session with a saved portal permission, so it is
//! `#[ignore]`d in CI. Run on the laptop:
//!
//!     REMORA_PORTAL_TOKEN=~/.config/Remora/portal-restore-token \
//!       cargo test -p remora-capture --test portal_sessions -- --ignored
//!
//! Two sessions, one after the other, in ONE process: the case that hung
//! on 2026-11-02 (the second session's D-Bus replies were never read
//! because the first session's runtime had been dropped; see the module
//! docs of `sys/linux.rs`).
#![cfg(target_os = "linux")]

use std::sync::mpsc;
use std::time::{Duration, Instant};

use remora_capture::{
    CaptureConfig, CaptureEvent, PortalCapture, PortalOptions, RestoreToken, ScreenCapture,
};

/// The saved permission named by REMORA_PORTAL_TOKEN (read only; the host
/// app keeps it up to date).
fn token() -> Option<RestoreToken> {
    let path = std::env::var_os("REMORA_PORTAL_TOKEN")?;
    RestoreToken::new(&std::fs::read_to_string(path).ok()?)
}

fn one_session(round: u32) {
    let t = Instant::now();
    let mut cap = PortalCapture::open(
        CaptureConfig::default(),
        PortalOptions {
            restore_token: token(),
            control: true,
        },
    )
    .unwrap_or_else(|e| panic!("round {round}: portal: {e}"));
    let opened = t.elapsed();
    assert!(cap.input().is_some(), "round {round}: control was granted");
    let (tx, rx) = mpsc::channel();
    cap.start(Box::new(move |ev| {
        if let CaptureEvent::Frame(f) = ev
            && let Some(img) = f.image
        {
            let _ = tx.send((img.width(), img.height()));
        }
    }))
    .unwrap_or_else(|e| panic!("round {round}: PipeWire: {e}"));
    // GNOME sends a picture at once when a cast starts.
    let size = rx
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| panic!("round {round}: no picture in 10 s"));
    eprintln!("round {round}: portal answered in {opened:?}, picture {size:?}");
    assert!(
        opened < Duration::from_secs(10),
        "round {round}: {opened:?}"
    );
    drop(cap);
}

#[test]
#[ignore = "needs a desktop session and a saved portal permission"]
fn two_portal_sessions_in_one_process() {
    one_session(1);
    one_session(2);
    one_session(3);
}

/// Each input kind leaves this process as a portal call (watch with
/// `dbus-monitor --session interface=org.freedesktop.portal.RemoteDesktop`).
#[test]
#[ignore = "needs a desktop session and a saved portal permission"]
fn every_input_kind_reaches_the_portal() {
    let cap = PortalCapture::open(
        CaptureConfig::default(),
        PortalOptions {
            restore_token: token(),
            control: true,
        },
    )
    .expect("portal");
    let input = cap.input().expect("control granted");
    let (w, h) = input.size();
    input
        .motion(f64::from(w) / 2.0, f64::from(h) / 2.0)
        .expect("motion");
    input.scroll_pixels(0.0, 30.0).expect("smooth scroll");
    input.scroll_steps(1, 0).expect("wheel step");
    std::thread::sleep(Duration::from_millis(500));
    drop(cap);
}
