//! Quitting the app (Cmd+Q) still ends the session with a goodbye.
//!
//! On Cmd+Q, winit 0.30.13 lets AppKit `terminate:` the app:
//! `applicationWillTerminate` closes the windows without a close request
//! (`platform_impl/macos/event_loop.rs:430`) and calls the event loop's
//! `exiting` (`app_state.rs:166-231`); then the process ends. The session
//! thread never got to say goodbye, so the host waited 30 s for the viewer
//! ("connection lost"), still sending sound and, with `--mute-speakers`,
//! keeping its speakers muted (owner, 2026-11-03). Slint 1.18.1 forwards
//! `exiting` to our handler as well (`i-slint-backend-winit` lib.rs:266).
//!
//! So `exiting` asks the session to disconnect and waits, at most
//! [`QUIT_WAIT`], for the session thread to finish: it finishes only
//! after the connection has closed, i.e. after the goodbye went out.

use std::sync::mpsc::Receiver;
use std::time::Duration;

/// Longest wait for the goodbye on quit (on the home network it takes a
/// few milliseconds; a host that is gone must not hold the quit up).
pub(crate) const QUIT_WAIT: Duration = Duration::from_millis(1500);

/// Asks the session to end (`disconnect`) and waits up to `wait` for
/// `done` (the session thread finished). `true` when it finished in time.
pub(crate) fn goodbye(disconnect: impl FnOnce(), done: &Receiver<()>, wait: Duration) -> bool {
    disconnect();
    done.recv_timeout(wait).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    #[test]
    fn quitting_asks_for_the_goodbye_and_waits_for_it() {
        // A session thread that ends only after it was asked to.
        let (ask_tx, ask_rx) = channel::<()>();
        let (done_tx, done_rx) = channel::<()>();
        std::thread::spawn(move || {
            if ask_rx.recv().is_ok() {
                std::thread::sleep(Duration::from_millis(50)); // the goodbye
                let _ = done_tx.send(());
            }
        });
        let ok = goodbye(
            || {
                let _ = ask_tx.send(());
            },
            &done_rx,
            Duration::from_secs(5),
        );
        assert!(ok, "quit without waiting for the goodbye");
    }

    #[test]
    fn a_host_that_is_gone_does_not_hold_the_quit_up() {
        let (_done_tx, done_rx) = channel::<()>();
        let t = std::time::Instant::now();
        assert!(!goodbye(|| {}, &done_rx, Duration::from_millis(100)));
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_session_that_already_ended_quits_at_once() {
        let (done_tx, done_rx) = channel::<()>();
        drop(done_tx); // thread gone: recv fails at once
        let t = std::time::Instant::now();
        let _ = goodbye(|| {}, &done_rx, Duration::from_secs(5));
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "waited for a finished session"
        );
    }
}
