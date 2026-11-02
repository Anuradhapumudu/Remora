//! `remora-host gui`: the host's windows (phase4.5-criteria §4, §5).
//!
//! * **Main window**: this computer's device ID, the code and one-time
//!   password with the F-UX3 note for every new pair, the INV12 notice, the
//!   F-UX2 key-file warning, refused "host busy" attempts (H9), and the
//!   code and password hidden while a session is Active (H10).
//! * **One dialog per waiting viewer** (H1-H7): safety code first, device
//!   ID, trust, the name labelled as unchecked, time left; Deny by default.
//! * **Session window** (I1, I2): "<device> is viewing your screen", how
//!   long, **End session**.
//!
//! This module decides nothing. Session events and clicks go to
//! [`remora_app::decide`] ([`HostDesk`]) and the glue does what comes back,
//! through [`HostControl`]: the same `approve(session, sas)` / `deny` /
//! `disconnect` the CLI uses (H11). Accept forwards the pointer's raw press
//! and release so H4 is the decision module's tested rule, not the
//! widget's. Nothing here logs; the password is shown, never logged (H12).

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use remora_app::cli::{PasswordChange, offer_code, unix_now};
use remora_crypto::secret::Otp;
use remora_net::HostServer;

use crate::serve::CODE_TTL;

use remora_app::decide::dialog::{Answer, Key, OpenError, Trust};
use remora_app::decide::host::{HostDesk, HostRequest};
use remora_crypto::identity::IdentityPublic;
use remora_crypto::sas::Sas;
use remora_net::HostEvent;
use remora_session::{Millis, SessionId};
use slint::ComponentHandle;

// The screens: markup only, in remora-ui (architecture D45).
use remora_ui::{DialogWindow, MainWindow, SessionWindow};

/// What the windows ask of the host: the session layer's commands (H11)
/// plus the video stream and the code shown in the main window. The app's
/// implementation drives the real `HostServer`; tests record the calls.
pub(crate) trait HostControl {
    /// Approve exactly this session with exactly this code (A22).
    fn approve(&mut self, id: SessionId, sas: Sas) -> Result<(), String>;
    /// Deny a waiting session.
    fn deny(&mut self, id: SessionId);
    /// End a session (End session, I2).
    fn disconnect(&mut self, id: SessionId);
    /// A session became Active / ended (the stream follows).
    fn session_started(&mut self, id: SessionId);
    /// A session ended.
    fn session_over(&mut self, id: SessionId);
    /// Encode the next frame as a keyframe.
    fn force_keyframe(&mut self);
    /// A fresh code and the current password, with the F-UX3 note when
    /// `explain` (why a new pair appeared).
    fn new_code(&mut self, explain: bool) -> (String, String, String);
    /// The host was told 3 failures replaced the password (INV12).
    fn password_replaced(&mut self);
    /// How long the host still waits for an unavailable display (D-29).
    fn display_wait(&self) -> Option<Duration>;
}

/// Milliseconds since the GUI started (the decision module's clock).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Clock(Instant);

impl Clock {
    pub(crate) fn start() -> Self {
        Self(Instant::now())
    }

    pub(crate) fn now(self) -> Millis {
        Millis(u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// The host GUI: the decision module, the windows and the control.
pub(crate) struct HostGui<C: HostControl> {
    control: C,
    desk: HostDesk,
    trusted: Vec<IdentityPublic>,
    /// The viewers' raw names, for the indicator once Active.
    names: HashMap<SessionId, String>,
    pub(crate) main: MainWindow,
    pub(crate) dialogs: Vec<(SessionId, DialogWindow)>,
    pub(crate) session: SessionWindow,
    refused: Vec<String>,
    /// When the shown code was issued: codes expire (protocol.md §2), so a
    /// fresh one replaces it before it does.
    code_issued: Millis,
    me: Weak<RefCell<Self>>,
}

/// A new code (same password) this long after the last: codes are valid
/// for `CODE_TTL` (5 min).
const CODE_REFRESH_MS: u64 = 270_000;

/// The most refused attempts listed by time and address (the count is
/// shown in full).
const REFUSED_SHOWN: usize = 5;

impl<C: HostControl + 'static> HostGui<C> {
    /// Builds the windows (not shown yet) and wires their callbacks.
    pub(crate) fn new(
        control: C,
        device: String,
        warning: String,
        trusted: Vec<IdentityPublic>,
    ) -> Result<Rc<RefCell<Self>>, slint::PlatformError> {
        let main = MainWindow::new()?;
        let session = SessionWindow::new()?;
        main.set_device(device.into());
        main.set_warning(warning.into());
        let gui = Rc::new_cyclic(|me| {
            RefCell::new(Self {
                control,
                desk: HostDesk::new(),
                trusted,
                names: HashMap::new(),
                main,
                dialogs: Vec::new(),
                session,
                refused: Vec::new(),
                code_issued: Millis(0),
                me: me.clone(),
            })
        });
        {
            let g = gui.borrow();
            let w = g.me.clone();
            g.main
                .on_show_secrets(move || with(&w, move |g, _| g.desk.show_secrets()));
            let w = g.me.clone();
            g.main
                .on_hide_secrets(move || with(&w, move |g, _| g.desk.hide_secrets()));
            let w = g.me.clone();
            g.session.on_end_session(move || {
                with(&w, move |g, _| {
                    if let Some(r) = g.desk.end_session() {
                        g.request(r);
                    }
                })
            });
            // While a session is Active the indicator cannot be closed (I1).
            let w = g.me.clone();
            g.session.window().on_close_requested(move || {
                let active = w
                    .upgrade()
                    .is_some_and(|g| g.borrow().desk.indicator(Millis(0)).is_some());
                if active {
                    slint::CloseRequestResponse::KeepWindowShown
                } else {
                    slint::CloseRequestResponse::HideWindow
                }
            });
        }
        gui.borrow_mut().show_code(false);
        Ok(gui)
    }

    fn show_code(&mut self, explain: bool) {
        self.code_issued = CLOCK.with(TestableClock::now);
        let (code, password, note) = self.control.new_code(explain);
        self.main.set_code(code.into());
        self.main
            .set_password(remora_app::cli::group_password(&password).into());
        self.main.set_note(note.into());
        self.main.set_notice("".into());
    }

    fn request(&mut self, r: HostRequest) {
        match r {
            HostRequest::Answer(Answer::Accept { id, sas }) => {
                if let Err(e) = self.control.approve(id, sas) {
                    self.main
                        .set_notice(format!("Could not accept: {e}").into());
                }
            }
            HostRequest::Answer(Answer::Deny { id }) => self.control.deny(id),
            HostRequest::Disconnect(id) => self.control.disconnect(id),
        }
    }

    fn answer(&mut self, a: Option<Answer>, now: Millis) {
        if let Some(a) = a {
            self.request(HostRequest::Answer(a));
        }
        self.refresh(now);
    }

    /// One event from the session layer.
    pub(crate) fn event(&mut self, ev: HostEvent, now: Millis) {
        match ev {
            HostEvent::Prompt {
                id,
                sas,
                viewer_name,
                viewer_key,
            } => {
                let trust = if self.trusted.contains(&viewer_key) {
                    Trust::Pinned
                } else {
                    Trust::New
                };
                let device = remora_app::cli::short_code_of(&viewer_key).to_string();
                match self
                    .desk
                    .dialogs
                    .open(id, sas, &viewer_name, device, trust, now)
                {
                    Ok(()) => {
                        self.names.insert(id, viewer_name);
                        self.open_dialog(id);
                    }
                    // R4: never a fifth dialog; such a session is denied.
                    Err(OpenError::TooMany) => self.control.deny(id),
                    Err(OpenError::Duplicate) => {}
                }
                // The code and password just used are spent (A06, INV15).
                self.show_code(true);
            }
            HostEvent::PromptClosed { id } => self.desk.dialogs.close(id, now),
            HostEvent::Active { id } => {
                let name = self.names.get(&id).cloned().unwrap_or_default();
                for r in self.desk.session_active(id, &name, now) {
                    self.request(r);
                }
                self.control.session_started(id);
            }
            HostEvent::Failed { .. } => self.show_code(true),
            HostEvent::OtpRotated => {
                self.control.password_replaced();
                self.main
                    .set_notice("3 failed attempts \u{2014} a new password was generated.".into());
            }
            HostEvent::Closed { id, .. } | HostEvent::Lost { id } => {
                self.desk.session_ended(id, now);
                self.names.remove(&id);
                self.control.session_over(id);
            }
            HostEvent::RefusedBusy { peer } => {
                self.desk.refused_busy();
                self.refused.push(format!(
                    "{} from {}",
                    remora_app::cli::utc_time(remora_app::cli::unix_now()),
                    peer.ip()
                ));
                if self.refused.len() > REFUSED_SHOWN {
                    self.refused.remove(0);
                }
            }
            HostEvent::ForceKeyframe => self.control.force_keyframe(),
            HostEvent::OtpUsed { .. } | HostEvent::Deliver { .. } => {}
        }
        self.refresh(now);
    }

    fn open_dialog(&mut self, id: SessionId) {
        let Ok(d) = DialogWindow::new() else {
            // No window, no way to answer: deny rather than leave it waiting.
            self.desk.dialogs.close(id, Millis(0));
            self.control.deny(id);
            return;
        };
        let w = self.me.clone();
        d.on_accept_pressed(move || with(&w, move |g, now| g.desk.dialogs.press_accept(id, now)));
        let w = self.me.clone();
        d.on_accept_released(move || {
            with(&w, move |g, now| {
                let a = g.desk.dialogs.release_accept(id, now);
                g.answer(a, now);
            })
        });
        let w = self.me.clone();
        d.on_accept_cancelled(move || with(&w, move |g, _| g.desk.dialogs.cancel_press()));
        // A deliberate accessibility action (VoiceOver) counts as a click
        // now: the same arming rule applies (Q4).
        let w = self.me.clone();
        d.on_accept_accessible(move || {
            with(&w, move |g, now| {
                g.desk.dialogs.press_accept(id, now);
                let a = g.desk.dialogs.release_accept(id, now);
                g.answer(a, now);
            })
        });
        let w = self.me.clone();
        d.on_deny(move || {
            with(&w, move |g, now| {
                let a = g.desk.dialogs.deny(id, now);
                g.answer(a, now);
            })
        });
        let w = self.me.clone();
        d.on_key_deny(move || {
            with(&w, move |g, now| {
                let a = g.desk.dialogs.key(id, Key::Return, now);
                g.answer(a, now);
            })
        });
        // Closing the dialog's window is a deny, never a silent wait.
        let w = self.me.clone();
        d.window().on_close_requested(move || {
            with(&w, move |g, now| {
                let a = g.desk.dialogs.deny(id, now);
                g.answer(a, now);
            });
            slint::CloseRequestResponse::HideWindow
        });
        self.dialogs.push((id, d));
    }

    /// Brings every window in line with the decision module at `now`:
    /// called after each event and click, and by a timer for the clocks.
    pub(crate) fn refresh(&mut self, now: Millis) {
        if now.0.saturating_sub(self.code_issued.0) >= CODE_REFRESH_MS {
            self.show_code(false);
        }
        let views = self.desk.dialogs.view(now);
        // Close the windows of dialogs that are gone (answered, withdrawn,
        // ended): they can never accept (H2).
        self.dialogs.retain(|(id, d)| {
            let open = views.iter().any(|v| v.id == *id);
            if !open {
                let _ = d.hide();
            }
            open
        });
        for v in &views {
            if let Some((_, d)) = self.dialogs.iter().find(|(id, _)| *id == v.id) {
                d.set_sas(v.sas.clone().into());
                d.set_name(v.name.clone().into());
                d.set_device(v.device.clone().into());
                d.set_trust(v.trust.into());
                d.set_seconds_left(i32::try_from(v.seconds_left).unwrap_or(i32::MAX));
                d.set_accept_enabled(v.accept_enabled);
                if !d.window().is_visible() {
                    let _ = d.show();
                    bring_to_front(d.window());
                }
            }
        }
        let display = self
            .control
            .display_wait()
            .map(remora_app::cli::display_unavailable_text)
            .unwrap_or_default();
        match self.desk.indicator(now) {
            Some(i) => {
                self.session.set_text(i.text.into());
                self.session
                    .set_elapsed(format!("{}:{:02}", i.seconds / 60, i.seconds % 60).into());
                self.session.set_display(display.clone().into());
                if !self.session.window().is_visible() {
                    let _ = self.session.show();
                    if let Some(problem) = on_all_spaces(self.session.window()) {
                        self.main.set_notice(problem.into());
                    }
                }
            }
            None => {
                if self.session.window().is_visible() {
                    let _ = self.session.hide();
                }
            }
        }
        let indicator = self.desk.indicator(now);
        // Visibility of system status: one line saying what is happening now.
        let status = match (&indicator, views.is_empty()) {
            (Some(i), _) => format!(
                "Your screen is being shared: {}.",
                i.text.trim_end_matches(" is viewing your screen")
            ),
            (None, false) => {
                "Someone is asking to see your screen. Answer in the dialog.".to_owned()
            }
            (None, true) => "Waiting for someone to connect.".to_owned(),
        };
        self.main.set_status(status.into());
        self.main.set_session_active(indicator.is_some());
        self.main.set_secrets_visible(self.desk.secrets_visible());
        self.main.set_display(display.into());
        let n = self.desk.refused_busy_count();
        self.main.set_refused(
            if n == 0 {
                String::new()
            } else {
                format!(
                    "Refused while a session was active (host busy, not password attempts): {n}. Latest: {}",
                    self.refused.join(", ")
                )
            }
            .into(),
        );
    }
}

/// Runs `f` on the GUI behind `w` with the current time, if it still
/// exists. If the GUI is busy (a window call made Slint run a callback
/// right away), `f` runs on the next turn of the event loop instead.
fn with<C: HostControl + 'static>(
    w: &Weak<RefCell<HostGui<C>>>,
    f: impl FnOnce(&mut HostGui<C>, Millis) + 'static,
) {
    let Some(g) = w.upgrade() else { return };
    let Ok(mut gui) = g.try_borrow_mut() else {
        let w = w.clone();
        slint::Timer::single_shot(Duration::ZERO, move || with(&w, f));
        return;
    };
    let now = CLOCK.with(TestableClock::now);
    f(&mut gui, now);
}

thread_local! {
    /// The GUI's clock (one per UI thread; tests replace it).
    pub(crate) static CLOCK: TestableClock = TestableClock::default();
}

/// A clock that reads real time, or a fixed time a test sets.
#[derive(Debug, Default)]
pub(crate) struct TestableClock {
    real: std::cell::OnceCell<Clock>,
    fixed: std::cell::Cell<Option<Millis>>,
}

impl TestableClock {
    pub(crate) fn now(&self) -> Millis {
        self.fixed
            .get()
            .unwrap_or_else(|| self.real.get_or_init(Clock::start).now())
    }

    #[cfg(test)]
    pub(crate) fn set(&self, t: Millis) {
        self.fixed.set(Some(t));
    }
}

/// Activates the app and raises the window (H7: the dialog comes to the
/// front over other apps; manual check M2).
fn bring_to_front(w: &slint::Window) {
    use slint::winit_030::WinitWindowAccessor;
    w.with_winit_window(|w| w.focus_window());
}

/// I3 (architecture D46): the session indicator on every Space, also next
/// to a full-screen app. `None` when it took effect or there is no native
/// window (Slint's testing backend); otherwise what the person should know.
fn on_all_spaces(w: &slint::Window) -> Option<String> {
    use remora_input::window::{CAN_JOIN_ALL_SPACES, FULL_SCREEN_AUXILIARY, show_on_all_spaces};
    use slint::winit_030::WinitWindowAccessor;
    use slint::winit_030::winit::raw_window_handle::HasWindowHandle;
    let handle = w.with_winit_window(|w| w.window_handle().ok().map(|h| h.as_raw()))??;
    let want = CAN_JOIN_ALL_SPACES | FULL_SCREEN_AUXILIARY;
    match show_on_all_spaces(handle) {
        Ok(flags) if flags & want == want => None,
        Ok(_) | Err(_) => {
            Some("The session indicator may be hidden behind full-screen apps on this Mac.".into())
        }
    }
}

// ------------------------------------------------------------- the app --

/// The real host behind the windows.
pub(crate) struct Live {
    server: Arc<HostServer>,
    video: crate::serve::Video,
    addr: SocketAddr,
    public: IdentityPublic,
    /// The password last shown, to explain a change (F-UX3).
    shown_password: Otp,
    rotated: bool,
}

impl HostControl for Live {
    fn approve(&mut self, id: SessionId, sas: Sas) -> Result<(), String> {
        // Capture starts first, as in the CLI: a capture that cannot start
        // ends the session with CaptureStopped instead of a blank one.
        self.video.prepare();
        self.server.approve(id, sas).map_err(|e| {
            self.video.idle_check();
            e.to_string()
        })
    }

    fn deny(&mut self, id: SessionId) {
        self.server.deny(id);
    }

    fn disconnect(&mut self, id: SessionId) {
        self.server.disconnect(id);
    }

    fn session_started(&mut self, id: SessionId) {
        self.video.session_active(id);
    }

    fn session_over(&mut self, id: SessionId) {
        self.video.ended(id);
    }

    fn force_keyframe(&mut self) {
        self.video.force_keyframe();
    }

    fn new_code(&mut self, explain: bool) -> (String, String, String) {
        let otp = self.server.otp();
        let note = if explain {
            PasswordChange::between(self.shown_password.reveal(), otp.reveal(), self.rotated)
                .sentence()
                .to_owned()
        } else {
            String::new()
        };
        let nonce = self.server.issue_nonce(CODE_TTL);
        let code = offer_code(
            self.addr,
            &self.public,
            nonce,
            unix_now(),
            CODE_TTL.as_secs(),
        );
        let password = otp.reveal().to_owned();
        self.shown_password = otp;
        self.rotated = false;
        (code.to_string(), password, note)
    }

    fn password_replaced(&mut self) {
        self.rotated = true;
    }

    fn display_wait(&self) -> Option<Duration> {
        self.server.pause_remaining()
    }
}

thread_local! {
    static LIVE: RefCell<Option<Rc<RefCell<HostGui<Live>>>>> = const { RefCell::new(None) };
}

fn on_live(f: impl FnOnce(&mut HostGui<Live>, Millis)) {
    LIVE.with(|l| {
        if let Some(g) = l.borrow().as_ref() {
            let now = CLOCK.with(TestableClock::now);
            f(&mut g.borrow_mut(), now);
        }
    });
}

/// `remora-host gui`: the same host as `serve`, with windows instead of
/// typed commands.
pub(crate) fn run(args: crate::serve::ServeArgs) -> anyhow::Result<()> {
    let setup = crate::serve::setup(&args)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    let (server, mut events) = rt.block_on(HostServer::bind(args.bind, setup.config))?;
    let server = Arc::new(server);
    let live = Live {
        video: crate::serve::Video::new(args.source, args.width, args.timing, Arc::clone(&server)),
        shown_password: server.otp(),
        addr: server.local_addr()?,
        server: Arc::clone(&server),
        public: setup.public,
        rotated: false,
    };
    let device = remora_app::cli::short_code_of(&setup.public).to_string();
    let gui = HostGui::new(live, device, setup.key_warning, setup.trusted)?;
    gui.borrow().main.window().on_close_requested(|| {
        let _ = slint::quit_event_loop();
        slint::CloseRequestResponse::HideWindow
    });
    gui.borrow().main.show()?;
    LIVE.with(|l| *l.borrow_mut() = Some(Rc::clone(&gui)));
    drop(gui);

    // Session events reach the UI thread one by one, in order.
    rt.spawn(async move {
        while let Some(ev) = events.recv().await {
            let sent = slint::invoke_from_event_loop(move || on_live(|g, now| g.event(ev, now)));
            if sent.is_err() {
                break; // the event loop has ended
            }
        }
    });
    // Clocks: the dialogs' time left and arming, the indicator's time.
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(250),
        || on_live(|g, now| g.refresh(now)),
    );
    slint::run_event_loop_until_quit()?;
    timer.stop();
    if let Some(g) = LIVE.with(|l| l.borrow_mut().take()) {
        g.borrow_mut().control.video.stop();
    }
    server.shutdown();
    rt.shutdown_timeout(Duration::from_secs(2));
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The host windows driven like a person would, through Slint's testing
    //! backend (D-4: I1 and I2 as automated tests). A fake control records
    //! what the windows asked the session layer to do.
    use i_slint_backend_testing as testing;
    use slint::platform::{PointerEventButton, WindowEvent};
    use slint::{LogicalPosition, SharedString};

    use super::*;

    #[derive(Default)]
    struct Fake {
        calls: Rc<RefCell<Vec<String>>>,
        codes: u32,
    }

    impl HostControl for Fake {
        fn approve(&mut self, id: SessionId, sas: Sas) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("approve {} {}", id.0, sas.value()));
            Ok(())
        }
        fn deny(&mut self, id: SessionId) {
            self.calls.borrow_mut().push(format!("deny {}", id.0));
        }
        fn disconnect(&mut self, id: SessionId) {
            self.calls.borrow_mut().push(format!("disconnect {}", id.0));
        }
        fn session_started(&mut self, id: SessionId) {
            self.calls.borrow_mut().push(format!("started {}", id.0));
        }
        fn session_over(&mut self, id: SessionId) {
            self.calls.borrow_mut().push(format!("over {}", id.0));
        }
        fn force_keyframe(&mut self) {}
        fn new_code(&mut self, explain: bool) -> (String, String, String) {
            self.codes += 1;
            let note = if explain { "note" } else { "" };
            (
                format!("CODE{}", self.codes),
                format!("{:06}", self.codes),
                note.into(),
            )
        }
        fn password_replaced(&mut self) {}
        fn display_wait(&self) -> Option<Duration> {
            None
        }
    }

    type Gui = Rc<RefCell<HostGui<Fake>>>;

    thread_local! {
        static BACKEND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    fn gui() -> (Gui, Rc<RefCell<Vec<String>>>) {
        // One testing backend per test thread (H3 builds several GUIs).
        if !BACKEND.with(|b| b.replace(true)) {
            testing::init_no_event_loop();
        }
        CLOCK.with(|c| c.set(Millis(1_000)));
        let calls = Rc::new(RefCell::new(Vec::new()));
        let fake = Fake {
            calls: Rc::clone(&calls),
            codes: 0,
        };
        let g = HostGui::new(fake, "HOST-1234".into(), "key warning".into(), vec![]).unwrap();
        (g, calls)
    }

    thread_local! {
        static KEYS: RefCell<HashMap<u8, IdentityPublic>> = RefCell::new(HashMap::new());
    }

    /// The same viewer key for the same `n` within a test.
    fn key(n: u8) -> IdentityPublic {
        KEYS.with(|k| {
            *k.borrow_mut().entry(n).or_insert_with(|| {
                remora_crypto::identity::DeviceKeys::generate(&mut rand_core::OsRng)
                    .identity
                    .public()
            })
        })
    }

    fn sas(n: u8) -> Sas {
        remora_crypto::sas::sas(&[n; 32], &[n; 32], &[n; 32])
    }

    fn at(ms: u64) -> Millis {
        CLOCK.with(|c| c.set(Millis(ms)));
        Millis(ms)
    }

    fn prompt(g: &Gui, id: u64, name: &str, now: Millis) {
        let ev = HostEvent::Prompt {
            id: SessionId(id),
            sas: sas(id as u8),
            viewer_name: name.into(),
            viewer_key: key(id as u8),
        };
        g.borrow_mut().event(ev, now);
    }

    fn dialog(g: &Gui, id: u64) -> DialogWindow {
        let g = g.borrow();
        let (_, d) = g.dialogs.iter().find(|(i, _)| i.0 == id).expect("dialog");
        d.clone_strong()
    }

    /// The middle of the element with accessible label `label` (found the
    /// way VoiceOver finds it; element ids need SLINT_EMIT_DEBUG_INFO).
    fn centre(c: &impl ComponentHandle, label: &str) -> LogicalPosition {
        let h = testing::ElementHandle::find_by_accessible_label(c, label)
            .next()
            .unwrap_or_else(|| panic!("no element labelled {label}"));
        let (p, s) = (h.absolute_position(), h.size());
        LogicalPosition::new(p.x + s.width / 2.0, p.y + s.height / 2.0)
    }

    fn press(d: &DialogWindow, pos: LogicalPosition) {
        d.window()
            .dispatch_event(WindowEvent::PointerMoved { position: pos });
        d.window().dispatch_event(WindowEvent::PointerPressed {
            position: pos,
            button: PointerEventButton::Left,
        });
    }

    fn release(d: &DialogWindow, pos: LogicalPosition) {
        d.window().dispatch_event(WindowEvent::PointerReleased {
            position: pos,
            button: PointerEventButton::Left,
        });
    }

    #[test]
    fn h1_dialog_shows_code_device_trust_and_escaped_name() {
        let (g, _) = gui();
        prompt(&g, 3, "Eve\n\u{202E}tpeccA", at(1_000));
        let d = dialog(&g, 3);
        assert!(d.window().is_visible());
        assert_eq!(d.get_sas(), remora_app::cli::format_sas(sas(3)).as_str());
        assert_eq!(d.get_name(), "Eve\\u{000A}\\u{202E}tpeccA");
        assert_eq!(
            d.get_device(),
            remora_app::cli::short_code_of(&key(3)).to_string().as_str()
        );
        assert_eq!(d.get_trust(), "new device");
        assert_eq!(d.get_seconds_left(), 60);
        // A second viewer: each dialog shows its own session's code and device.
        prompt(&g, 4, "Bob", at(1_500));
        for id in [3u8, 4] {
            let d = dialog(&g, u64::from(id));
            assert_eq!(
                d.get_sas(),
                remora_app::cli::format_sas(sas(id)).as_str(),
                "dialog {id}"
            );
            assert_eq!(
                d.get_device(),
                remora_app::cli::short_code_of(&key(id))
                    .to_string()
                    .as_str()
            );
        }
    }

    #[test]
    fn h4_the_real_accept_button_needs_press_and_release_after_one_second() {
        let (g, calls) = gui();
        prompt(&g, 5, "Bob", at(1_000));
        let d = dialog(&g, 5);
        let pos = centre(&d, "Accept");
        assert!(!d.get_accept_enabled());
        // Press at 0.9 s, release at 1.2 s: nothing.
        at(1_900);
        press(&d, pos);
        at(2_200);
        g.borrow_mut().refresh(Millis(2_200));
        release(&d, pos);
        assert!(calls.borrow().is_empty(), "{:?}", calls.borrow());
        assert!(d.get_accept_enabled());
        // A whole click after the delay accepts exactly this session.
        at(2_300);
        press(&d, pos);
        release(&d, pos);
        assert_eq!(
            *calls.borrow(),
            vec![format!("approve 5 {}", sas(5).value())]
        );
    }

    #[test]
    fn h3_return_space_and_escape_deny() {
        for k in [
            SharedString::from(slint::platform::Key::Return),
            SharedString::from(" "),
            SharedString::from(slint::platform::Key::Escape),
        ] {
            let (g, calls) = gui();
            prompt(&g, 6, "Bob", at(1_000));
            let d = dialog(&g, 6);
            at(9_000);
            d.window()
                .dispatch_event(WindowEvent::KeyPressed { text: k.clone() });
            d.window()
                .dispatch_event(WindowEvent::KeyReleased { text: k.clone() });
            assert_eq!(*calls.borrow(), vec!["deny 6".to_string()], "{k:?}");
            assert!(!d.window().is_visible(), "the dialog closes");
        }
    }

    #[test]
    fn i1_session_window_shown_exactly_while_active_and_code_hidden() {
        let (g, _) = gui();
        let main = g.borrow().main.clone_strong();
        let session = g.borrow().session.clone_strong();
        assert!(!session.window().is_visible());
        assert!(main.get_secrets_visible());
        g.borrow_mut().refresh(at(500));
        assert_eq!(main.get_status(), "Waiting for someone to connect.");
        prompt(&g, 7, "Bob", at(1_000));
        assert!(!session.window().is_visible(), "not before Active");
        assert!(
            main.get_status().starts_with("Someone is asking"),
            "{}",
            main.get_status()
        );
        g.borrow_mut()
            .event(HostEvent::Active { id: SessionId(7) }, at(5_000));
        assert!(session.window().is_visible());
        assert_eq!(session.get_text(), "Bob is viewing your screen");
        assert_eq!(main.get_status(), "Your screen is being shared: Bob.");
        assert!(!main.get_secrets_visible(), "H10: hidden while active");
        assert!(g.borrow().dialogs.is_empty(), "its dialog is gone");
        g.borrow_mut().refresh(at(65_000 + 5_000));
        assert_eq!(session.get_elapsed(), "1:05");
        g.borrow_mut().event(
            HostEvent::Closed {
                id: SessionId(7),
                code: remora_session::CloseCode::Normal,
            },
            at(80_000),
        );
        assert!(!session.window().is_visible());
        assert!(main.get_secrets_visible());
    }

    #[test]
    fn i2_end_session_is_one_click() {
        let (g, calls) = gui();
        prompt(&g, 8, "Bob", at(1_000));
        g.borrow_mut()
            .event(HostEvent::Active { id: SessionId(8) }, at(3_000));
        let session = g.borrow().session.clone_strong();
        let end = testing::ElementHandle::find_by_accessible_label(&session, "End session")
            .next()
            .expect("End session");
        end.invoke_accessible_default_action();
        assert!(
            calls.borrow().contains(&"disconnect 8".to_string()),
            "{:?}",
            calls.borrow()
        );
    }

    #[test]
    fn i1_the_session_window_cannot_be_closed_while_active() {
        let (g, _) = gui();
        prompt(&g, 9, "Bob", at(1_000));
        g.borrow_mut()
            .event(HostEvent::Active { id: SessionId(9) }, at(3_000));
        let session = g.borrow().session.clone_strong();
        session.window().dispatch_event(WindowEvent::CloseRequested);
        assert!(session.window().is_visible());
    }

    #[test]
    fn h9_waiting_dialogs_are_denied_when_one_becomes_active() {
        let (g, calls) = gui();
        prompt(&g, 1, "A", at(1_000));
        prompt(&g, 2, "B", at(1_000));
        g.borrow_mut()
            .event(HostEvent::Active { id: SessionId(1) }, at(4_000));
        assert!(
            calls.borrow().contains(&"deny 2".to_string()),
            "{:?}",
            calls.borrow()
        );
        assert!(g.borrow().dialogs.is_empty());
        g.borrow_mut().event(
            HostEvent::RefusedBusy {
                peer: "127.0.0.1:5000".parse().unwrap(),
            },
            at(5_000),
        );
        assert!(g.borrow().main.get_refused().contains("127.0.0.1"));
    }

    #[test]
    fn closing_a_dialog_window_denies() {
        let (g, calls) = gui();
        prompt(&g, 4, "Bob", at(1_000));
        let d = dialog(&g, 4);
        d.window().dispatch_event(WindowEvent::CloseRequested);
        assert_eq!(*calls.borrow(), vec!["deny 4".to_string()]);
    }

    #[test]
    fn a_new_prompt_shows_a_new_code_with_the_note() {
        let (g, _) = gui();
        let main = g.borrow().main.clone_strong();
        assert_eq!(main.get_code(), "CODE1");
        assert_eq!(main.get_note(), "");
        prompt(&g, 2, "Bob", at(1_000));
        assert_eq!(main.get_code(), "CODE2");
        assert_eq!(main.get_note(), "note");
    }
}
