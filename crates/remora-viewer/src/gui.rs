//! `remora-viewer gui`: the viewer's window (phase4.5-criteria §6, §7).
//!
//! One window that goes form → safety code → session → ended:
//!
//! * **V1** the connection code, checked by the existing parser (length
//!   first) as it is typed; the host's device ID shown before connecting;
//! * **V2** the password, masked; parsed into a zeroizing buffer and the
//!   field cleared at **Connect**;
//! * **V3, V4** the safety code, "Unverified", **The codes match** /
//!   **They don't match**;
//! * **V5, V6** the end reason, **Disconnect**, and "Display unavailable -
//!   N s left".
//!
//! The video is our own winit + wgpu window on Slint's event loop (option
//! C′, §2, no `unsafe`): it is created through
//! `invoke_from_active_event_loop`, its events arrive through a
//! `CustomApplicationHandler`, and pictures are drawn on arrival as in the
//! CLI ([`crate::window::VideoWindow`], which also does O1). This module
//! decides nothing itself: [`ViewerDesk`] does.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use remora_app::cli::unix_now;
use remora_app::decide::viewer::{
    Stage, Target, ViewerDesk, ViewerRequest, read_code, read_password,
};
use remora_app::keystore::{self, Role};
use remora_crypto::identity::DeviceId;
use remora_crypto::secret::Otp;
use remora_net::{ViewerClient, ViewerEvent};
use remora_session::{Identity, Millis, PauseReason, ViewerConfig, ViewerMode};
use slint::ComponentHandle;
use winit::event::WindowEvent;
use winit::event_loop::ActiveEventLoop;
use winit::window::WindowId;

use crate::window::VideoWindow;

// The screens: markup only, in remora-ui (architecture D45).
use remora_ui::ViewerWindow;

/// What the viewer GUI needs to connect.
#[derive(Debug, Clone)]
pub(crate) struct Options {
    /// Key file (default: the per-user config directory).
    pub(crate) identity_file: Option<PathBuf>,
    /// Name shown to the host (untrusted text there).
    pub(crate) name: String,
}

/// The viewer GUI: the decision module, the window, and the session.
pub(crate) struct ViewerGui {
    desk: ViewerDesk,
    pub(crate) window: ViewerWindow,
    client: Option<ViewerClient>,
    options: Options,
    started: Instant,
}

thread_local! {
    static GUI: RefCell<Option<Rc<RefCell<ViewerGui>>>> = const { RefCell::new(None) };
    /// The video window, on the UI thread (C′).
    static VIDEO: RefCell<Option<VideoWindow>> = const { RefCell::new(None) };
}

/// Runs `f` on the GUI if it exists and is not in use (a callback that
/// fires while it is in use runs on the next turn of the event loop).
fn on_gui(f: impl FnOnce(&mut ViewerGui) + 'static) {
    GUI.with(|g| {
        let Some(g) = g.borrow().as_ref().map(Rc::clone) else {
            return;
        };
        match g.try_borrow_mut() {
            Ok(mut gui) => f(&mut gui),
            Err(_) => slint::Timer::single_shot(Duration::ZERO, move || on_gui(f)),
        }
    });
}

fn stage_name(s: &Stage) -> &'static str {
    match s {
        Stage::Form => "form",
        Stage::Connecting => "connecting",
        Stage::Comparing => "comparing",
        Stage::Active => "active",
        Stage::Ended(_) => "ended",
    }
}

impl ViewerGui {
    /// The window (not shown yet) with its callbacks wired to [`GUI`].
    pub(crate) fn new(options: Options) -> Result<Rc<RefCell<Self>>, slint::PlatformError> {
        let window = ViewerWindow::new()?;
        window.on_code_edited(|text| on_gui(move |g| g.code_edited(&text)));
        window.on_password_edited(|_| on_gui(|g| g.update_can_connect()));
        window.on_connect(|| on_gui(ViewerGui::connect));
        window.on_codes_match(|| {
            on_gui(|g| {
                g.desk.codes_match();
                g.refresh();
            })
        });
        window.on_codes_differ(|| {
            on_gui(|g| {
                let r = g.desk.codes_differ();
                g.request(r);
            })
        });
        window.on_disconnect(|| {
            on_gui(|g| {
                let r = g.desk.disconnect();
                g.request(r);
            })
        });
        window.on_new_connection(|| {
            on_gui(|g| {
                g.desk = ViewerDesk::new();
                g.window.set_code_text("".into());
                g.window.set_host_device("".into());
                g.window.set_form_error("".into());
                g.update_can_connect();
                g.refresh();
            })
        });
        let gui = Rc::new(RefCell::new(Self {
            desk: ViewerDesk::new(),
            window,
            client: None,
            options,
            started: Instant::now(),
        }));
        GUI.with(|g| *g.borrow_mut() = Some(Rc::clone(&gui)));
        gui.borrow().refresh();
        Ok(gui)
    }

    fn now(&self) -> Millis {
        Millis(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    /// Error prevention (§16): Connect is enabled only for a code the parser
    /// accepts and a 6-digit password.
    fn update_can_connect(&self) {
        let ok = remora_app::decide::viewer::can_connect(
            &self.window.get_code_text(),
            &self.window.get_password_text(),
            unix_now(),
        );
        self.window.set_can_connect(ok);
    }

    /// V1: as the code is typed or pasted, show whose it is (or why not).
    fn code_edited(&mut self, text: &str) {
        self.update_can_connect();
        if text.trim().is_empty() {
            self.window.set_host_device("".into());
            self.window.set_form_error("".into());
            return;
        }
        match read_code(text, unix_now()) {
            Ok(t) => {
                self.window
                    .set_host_device(format!("Host device: {}", t.host_device).into());
                self.window.set_form_error("".into());
            }
            Err(e) => {
                self.window.set_host_device("".into());
                self.window.set_form_error(e.into());
            }
        }
    }

    /// **Connect**: V1 and V2 checks, then the session on its own thread.
    fn connect(&mut self) {
        let code = self.window.get_code_text();
        // V2: the field is cleared at Connect, whatever happens next; our
        // copy is the zeroizing `Otp` (Slint's own copy is §11b's limit).
        let password = self.window.get_password_text();
        self.window.set_password_text("".into());
        self.window.set_can_connect(false);
        let target = match read_code(&code, unix_now()) {
            Ok(t) => t,
            Err(e) => return self.window.set_form_error(e.into()),
        };
        let otp = match read_password(&password) {
            Ok(o) => o,
            Err(e) => return self.window.set_form_error(e.into()),
        };
        drop(password);
        self.window.set_form_error("".into());
        let host = target.host_device.clone();
        VIDEO.with(|v| {
            if let Some(v) = v.borrow_mut().as_mut() {
                v.set_host(host);
            }
        });
        self.desk.connecting();
        let options = self.options.clone();
        let started = std::thread::Builder::new()
            .name("remora-session".into())
            .spawn(move || session(target, otp, options));
        if let Err(e) = started {
            self.desk.error(&e.to_string());
        }
        self.refresh();
    }

    fn request(&mut self, r: Option<ViewerRequest>) {
        if r == Some(ViewerRequest::Disconnect)
            && let Some(c) = &self.client
        {
            c.disconnect();
        }
        self.refresh();
    }

    /// One event from the session thread.
    pub(crate) fn event(&mut self, ev: ViewerEvent) {
        let now = self.now();
        match ev {
            ViewerEvent::ShowSas { sas, .. } => self.desk.show_sas(sas),
            ViewerEvent::Active => self.desk.active(),
            ViewerEvent::StreamPaused(reason) => {
                if let PauseReason::DisplayUnavailable { remaining_ms } = reason {
                    self.desk.display_unavailable(remaining_ms, now);
                }
                VIDEO.with(|v| {
                    if let Some(v) = v.borrow_mut().as_mut() {
                        v.set_pause(Some(crate::Pause::of(reason)));
                    }
                });
            }
            ViewerEvent::StreamResumed => {
                self.desk.resumed();
                VIDEO.with(|v| {
                    if let Some(v) = v.borrow_mut().as_mut() {
                        v.set_pause(None);
                    }
                });
            }
            ViewerEvent::Failed { reason, .. } => self.desk.failed(&reason),
            ViewerEvent::Closed { local, remote } => self.desk.ended(remote.or(local)),
            ViewerEvent::Lost => self.desk.lost(),
            // Pictures reach the window from the decoder, not through here.
            // Played from phase 4.8 step 4 (viewer playback); dropped until then.
            ViewerEvent::Audio(_) => {}
            ViewerEvent::Video(_) => {}
        }
        if matches!(self.desk.view(now).stage, Stage::Ended(_)) {
            self.client = None;
            VIDEO.with(|v| {
                if let Some(v) = v.borrow_mut().as_mut() {
                    v.close();
                }
            });
        }
        self.refresh();
    }

    /// Brings the window in line with the decision module.
    pub(crate) fn refresh(&self) {
        let v = self.desk.view(self.now());
        self.window.set_stage(stage_name(&v.stage).into());
        self.window.set_sas(v.sas.unwrap_or_default().into());
        self.window
            .set_verification(v.verification.unwrap_or_default().into());
        self.window.set_verified(self.desk.verified());
        self.window
            .set_waiting(v.waiting.unwrap_or_default().into());
        self.window
            .set_display(v.display.unwrap_or_default().into());
        if let Stage::Ended(text) = &v.stage {
            self.window.set_ended_text(text.clone().into());
        }
    }
}

/// The session thread: connects, decodes, and reports every event to the
/// UI thread. Pictures go straight to the video window (drawn on arrival).
fn session(target: Target, otp: Otp, options: Options) {
    let report = |ev: ViewerEvent| {
        let _ = slint::invoke_from_event_loop(move || on_gui(move |g| g.event(ev)));
    };
    let fail = |e: anyhow::Error| {
        let text = format!("{e:#}");
        let _ = slint::invoke_from_event_loop(move || {
            on_gui(move |g| {
                g.desk.error(&text);
                g.refresh();
            })
        });
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(e.into()),
    };
    if let Err(e) = rt.block_on(run(target, otp, options, report)) {
        fail(e);
    }
}

async fn run(
    target: Target,
    otp: Otp,
    options: Options,
    report: impl Fn(ViewerEvent),
) -> anyhow::Result<()> {
    let path = match options.identity_file {
        Some(p) => p,
        None => keystore::default_path(Role::Viewer)?,
    };
    let (keys, _) = keystore::load_or_create(&path)?;
    let cert = keys
        .cert(&options.name, unix_now())
        .context("the name is at most 64 bytes")?;
    let config = ViewerConfig {
        identity: Arc::new(Identity {
            noise: keys.noise,
            cert,
        }),
        // Bound to the key in the code: a substituted key fails (A16).
        mode: ViewerMode::Password {
            otp,
            expect: Some(DeviceId::of(&target.host_key)),
        },
    };
    let (client, mut events) = remora_net::connect(target.addr, config, target.nonce).await?;
    let c = client.clone();
    let _ = slint::invoke_from_event_loop(move || {
        VIDEO.with(|v| {
            if let Some(v) = v.borrow_mut().as_mut() {
                v.set_client(Some(c.clone()));
            }
        });
        on_gui(move |g| g.client = Some(c));
    });
    let show: crate::decode::Show = Some(Box::new(|p| {
        let _ = slint::winit_030::invoke_from_active_event_loop(move |el| {
            VIDEO.with(|v| {
                if let Some(v) = v.borrow_mut().as_mut() {
                    v.picture(el, p);
                }
            });
        });
    }));
    let mut decoder =
        crate::decode::Decoder::start(client.clone(), show).context("decoder thread")?;
    let counters = decoder.counters();
    let _ = slint::invoke_from_event_loop(move || {
        VIDEO.with(|v| {
            if let Some(v) = v.borrow_mut().as_mut() {
                v.set_counters(counters);
            }
        });
    });
    while let Some(ev) = events.recv().await {
        match ev {
            ViewerEvent::Video(frame) => decoder.offer(frame),
            ev @ (ViewerEvent::Closed { .. } | ViewerEvent::Lost) => {
                report(ev);
                break;
            }
            ev => report(ev),
        }
    }
    decoder.finish();
    Ok(())
}

/// Routes our video window's events to it; everything else to Slint.
struct Hook;

impl slint::winit_030::CustomApplicationHandler for Hook {
    fn window_event(
        &mut self,
        _el: &ActiveEventLoop,
        id: WindowId,
        _w: Option<&winit::window::Window>,
        slint_window: Option<&slint::Window>,
        event: &WindowEvent,
    ) -> slint::winit_030::EventResult {
        if slint_window.is_some() {
            return slint::winit_030::EventResult::Propagate;
        }
        let closed = VIDEO.with(|v| {
            let mut v = v.borrow_mut();
            match v.as_mut() {
                Some(v) if v.is(id) => Some(v.window_event(event)),
                _ => None,
            }
        });
        match closed {
            // Closing the video window ends the session with a Goodbye.
            Some(true) => {
                on_gui(|g| {
                    let r = g.desk.disconnect();
                    g.request(r);
                });
                slint::winit_030::EventResult::PreventDefault
            }
            Some(false) => slint::winit_030::EventResult::PreventDefault,
            None => slint::winit_030::EventResult::Propagate,
        }
    }
}

/// `remora-viewer gui`.
pub(crate) fn run_gui(options: Options) -> anyhow::Result<u8> {
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .with_winit_custom_application_handler(Hook)
        .select()
        .context("starting the window system")?;
    VIDEO.with(|v| *v.borrow_mut() = Some(VideoWindow::new(false)));
    let gui = ViewerGui::new(options)?;
    gui.borrow().window.show()?;
    drop(gui);
    // The countdown (V6) and the video window's title tick once a second.
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(500),
        || {
            on_gui(|g| g.refresh());
            VIDEO.with(|v| {
                if let Some(v) = v.borrow().as_ref() {
                    v.tick();
                }
            });
        },
    );
    slint::run_event_loop_until_quit()?;
    on_gui(|g| {
        if let Some(c) = g.client.take() {
            c.disconnect();
        }
    });
    Ok(remora_app::cli::exit::OK)
}

#[cfg(test)]
mod tests {
    //! The viewer window driven through Slint's testing backend (phase4.5
    //! V1-V6): buttons found by their accessible label and pressed as
    //! VoiceOver would. No network: session events are fed in directly.
    use i_slint_backend_testing as testing;
    use remora_crypto::identity::DeviceKeys;
    use remora_session::{CloseCode, PauseReason};

    use super::*;

    fn gui() -> Rc<RefCell<ViewerGui>> {
        testing::init_no_event_loop();
        // Never the person's real key file: a throwaway one per test.
        let dir =
            std::env::temp_dir().join(format!("remora-viewer-gui-test-{}", std::process::id()));
        ViewerGui::new(Options {
            identity_file: Some(dir.join(format!("{:?}.key", std::thread::current().id()))),
            name: "test".into(),
        })
        .unwrap()
    }

    fn sas(n: u8) -> remora_crypto::sas::Sas {
        remora_crypto::sas::sas(&[n; 32], &[n; 32], &[n; 32])
    }

    fn show_sas(g: &Rc<RefCell<ViewerGui>>, n: u8) {
        let host = DeviceKeys::generate(&mut rand_core::OsRng)
            .cert("host", 0)
            .unwrap();
        g.borrow_mut()
            .event(ViewerEvent::ShowSas { sas: sas(n), host });
    }

    fn press(w: &ViewerWindow, label: &str) {
        let h = testing::ElementHandle::find_by_accessible_label(w, label)
            .next()
            .unwrap_or_else(|| panic!("no element labelled {label}"));
        h.invoke_accessible_default_action();
    }

    fn code_text(now: u32) -> String {
        use remora_proto::code::{Candidate, CandidateKind, CodeKind, ConnectionCode};
        let key = DeviceKeys::generate(&mut rand_core::OsRng)
            .identity
            .public();
        ConnectionCode {
            kind: CodeKind::Offer,
            expires_at: now + 300,
            nonce: [7; 16],
            identity_key: *key.as_bytes(),
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
    fn v1_the_code_shows_whose_it_is_before_connecting_and_rubbish_says_why() {
        let g = gui();
        let w = g.borrow().window.clone_strong();
        let now = u32::try_from(unix_now()).unwrap();
        g.borrow_mut().code_edited(&code_text(now));
        assert!(
            w.get_host_device().starts_with("Host device: "),
            "{}",
            w.get_host_device()
        );
        assert_eq!(w.get_form_error(), "");
        g.borrow_mut().code_edited(&"x".repeat(5000));
        assert_eq!(w.get_host_device(), "");
        assert!(w.get_form_error().contains("not a valid connection code"));
    }

    #[test]
    fn v2_connect_clears_the_password_field() {
        let g = gui();
        let w = g.borrow().window.clone_strong();
        let now = u32::try_from(unix_now()).unwrap();
        w.set_code_text(code_text(now).into());
        g.borrow_mut().code_edited(&w.get_code_text());
        w.set_password_text("123 456".into());
        g.borrow().update_can_connect();
        assert!(w.get_can_connect());
        press(&w, "Connect");
        assert_eq!(w.get_password_text(), "", "the field is cleared at Connect");
        assert_eq!(w.get_stage(), "connecting");
    }

    #[test]
    fn connect_stays_disabled_until_the_code_and_password_are_valid() {
        let g = gui();
        let w = g.borrow().window.clone_strong();
        let now = u32::try_from(unix_now()).unwrap();
        assert!(!w.get_can_connect(), "empty form");
        w.set_code_text(code_text(now).into());
        g.borrow_mut().code_edited(&w.get_code_text());
        w.set_password_text("12".into());
        g.borrow().update_can_connect();
        assert!(!w.get_can_connect(), "2 digits");
        press(&w, "Connect");
        assert_eq!(w.get_stage(), "form", "a disabled Connect does nothing");
        w.set_password_text("123456".into());
        g.borrow().update_can_connect();
        assert!(w.get_can_connect());
    }

    #[test]
    fn v3_v4_the_code_is_unverified_until_the_person_says_it_matches() {
        let g = gui();
        let w = g.borrow().window.clone_strong();
        g.borrow_mut().desk.connecting();
        show_sas(&g, 1);
        assert_eq!(w.get_stage(), "comparing");
        assert_eq!(w.get_sas(), remora_app::cli::format_sas(sas(1)).as_str());
        assert_eq!(w.get_verification(), remora_app::decide::viewer::UNVERIFIED);
        assert!(!w.get_verified());
        g.borrow_mut().event(ViewerEvent::Active);
        assert!(!w.get_verified(), "the host accepting does not verify");
        press(&w, "The codes match");
        assert!(w.get_verified());
        assert_eq!(w.get_verification(), remora_app::decide::viewer::VERIFIED);
    }

    #[test]
    fn v4_they_dont_match_ends_the_session_and_says_why() {
        let g = gui();
        let w = g.borrow().window.clone_strong();
        g.borrow_mut().desk.connecting();
        show_sas(&g, 2);
        press(&w, "They don't match");
        assert_eq!(w.get_stage(), "ended");
        assert_eq!(w.get_ended_text(), remora_app::decide::viewer::MISMATCH);
    }

    #[test]
    fn v5_declined_says_ask_for_a_new_code() {
        let g = gui();
        let w = g.borrow().window.clone_strong();
        g.borrow_mut().desk.connecting();
        show_sas(&g, 3);
        g.borrow_mut().event(ViewerEvent::Closed {
            local: None,
            remote: Some(CloseCode::Rejected),
        });
        assert_eq!(w.get_stage(), "ended");
        assert_eq!(w.get_ended_text(), remora_app::decide::viewer::DECLINED);
    }

    #[test]
    fn v6_display_unavailable_countdown_and_disconnect() {
        let g = gui();
        let w = g.borrow().window.clone_strong();
        g.borrow_mut().desk.connecting();
        show_sas(&g, 4);
        g.borrow_mut().event(ViewerEvent::Active);
        g.borrow_mut()
            .event(ViewerEvent::StreamPaused(PauseReason::DisplayUnavailable {
                remaining_ms: 120_000,
            }));
        assert!(
            w.get_display().starts_with("Display unavailable"),
            "{}",
            w.get_display()
        );
        g.borrow_mut().event(ViewerEvent::StreamResumed);
        assert_eq!(w.get_display(), "The host's display is back.");
        press(&w, "Disconnect");
        assert_eq!(w.get_stage(), "ended");
    }
}
