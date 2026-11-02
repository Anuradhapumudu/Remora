//! `remora-host serve`: Phase 3 command-line host on loopback.
//!
//! Prints (one per line, stable prefixes - the end-to-end tests read them):
//! `device:`, `identity:`, `listening:`, then `code:` and `password:` for
//! the next connection. Each accept prompt shows the viewer's name, device
//! code and the safety code under a short **prompt number** (1, 2, 3, …,
//! never reused in a run); the user answers `accept <n>` or `deny <n>`.
//! While a session is active the host prints `SESSION ACTIVE <n>` (INV11)
//! and `session ended <n>` when it ends. Every run warns on stderr that the
//! key file is unencrypted (F-UX2); a new code/password pair comes with a
//! `note:` line saying why (F-UX3).
//!
//! Remote input is NOT echoed: a keystroke could be someone typing a
//! password. Where this OS has an injector (Linux, phase 4.6) input goes
//! through one guard per Active session (`control.rs`); elsewhere the CLI
//! only says that input is arriving.
//!
//! Phase 4: once a viewer is accepted the host streams `--source` (the
//! screen by default on macOS; architecture D42) and prints `streaming:`,
//! `capture paused/resumed/stopped` and `streaming stopped` lines.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use remora_app::cli::{
    PasswordChange, format_sas, identity_hex, key_file_warning, offer_code, parse_identity,
    short_code_of, unix_now,
};
use remora_app::devices::DeviceList;
use remora_app::keystore::{self, Role};
use remora_app::prompts::{HostCommand, SessionBook, no_such_prompt, parse_host_command};
use remora_crypto::identity::IdentityPublic;
use remora_crypto::sas::Sas;
use remora_crypto::secret::Otp;
use remora_net::{HostEvent, HostServer, IDLE_TIMEOUT};
use remora_session::{HostConfig, Identity, SessionId};

/// The announced nonce is replaced this often, before it expires
/// ([`CODE_TTL`]).
const ANNOUNCE_REFRESH: Duration = Duration::from_secs(240);

/// How long each printed connection code is valid (protocol.md §2: ≤ 5 min).
pub(crate) const CODE_TTL: Duration = Duration::from_secs(300);

/// `remora-host serve` options.
#[derive(clap::Args, Debug)]
pub(crate) struct ServeArgs {
    /// Address to listen on (Phase 3: a specific local address).
    #[arg(long, default_value = "127.0.0.1:0")]
    pub(crate) bind: SocketAddr,
    /// Key file (default: the per-user config directory).
    #[arg(long)]
    identity_file: Option<PathBuf>,
    /// Name shown to viewers (untrusted text, ≤ 64 bytes).
    #[arg(long, default_value = "Remora host")]
    name: String,
    /// A viewer identity key (64 hex digits) allowed to connect without a
    /// password (trusted mode). May be repeated.
    #[arg(long = "trust", value_name = "KEY")]
    trusted: Vec<String>,
    /// What to stream once a viewer is approved: the screen, a numbered
    /// test pattern (no Screen Recording permission needed; tests and
    /// measurements), or nothing (Phase 3: control channel only).
    #[arg(long, value_enum, default_value_t = Source::default())]
    pub(crate) source: Source,
    /// Width of the streamed picture in pixels (the screen is scaled to
    /// it, keeping its aspect ratio; never upscaled).
    #[arg(long, default_value_t = 1920)]
    pub(crate) width: u32,
    /// Print one `timing:` line per sent frame on stderr: shared-clock
    /// times of capture, encoder output and send (latency measurement,
    /// phase4-criteria P1/P2). Times only.
    #[arg(long)]
    pub(crate) timing: bool,
    /// Do not announce this host on the home network (phase4.7: by default
    /// it announces its device code, never its name, while it is ready).
    #[arg(long)]
    pub(crate) no_announce: bool,
}

/// `serve --source`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// The main display.
    Screen,
    /// A test pattern whose frames carry their number (phase4-criteria P7).
    Synthetic,
    /// No video.
    None,
}

impl Default for Source {
    /// The screen where this build can capture it (macOS; Linux through
    /// the desktop portal, phase 4.6); nothing elsewhere yet.
    fn default() -> Self {
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            Source::Screen
        } else {
            Source::None
        }
    }
}

pub(crate) fn run(args: ServeArgs) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    rt.block_on(serve(args))
}

/// What both front ends (CLI and GUI) build a host from.
pub(crate) struct Setup {
    pub(crate) config: HostConfig,
    pub(crate) public: IdentityPublic,
    /// The `--trust` keys (the GUI shows "known device" for them; the CLI
    /// only passes them to the session layer through `config`).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) trusted: Vec<IdentityPublic>,
    /// The F-UX2 warning about the unencrypted key file (shown every run).
    pub(crate) key_warning: String,
    /// Where a new identity was created, if one was.
    pub(crate) created: Option<PathBuf>,
    /// The remembered viewers' file, next to the key file (phase4.7 Q4).
    pub(crate) known_path: PathBuf,
}

/// Checks the options and loads (or creates) this host's keys.
pub(crate) fn setup(args: &ServeArgs) -> anyhow::Result<Setup> {
    check_source(args.source, args.width)?;
    if args.bind.ip().is_unspecified() {
        bail!(
            "Phase 3 listens on a specific address (e.g. 127.0.0.1:0), not {}",
            args.bind
        );
    }
    let trusted = args
        .trusted
        .iter()
        .map(|k| parse_identity(k).with_context(|| format!("--trust {k}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let path = match &args.identity_file {
        Some(p) => p.clone(),
        None => keystore::default_path(Role::Host)?,
    };
    let (keys, created) = keystore::load_or_create(&path)?;
    let cert = keys
        .cert(&args.name, unix_now())
        .context("--name is at most 64 bytes")?;
    let public = keys.identity.public();
    let config = host_config(
        Identity {
            noise: keys.noise,
            cert,
        },
        trusted.clone(),
    );
    Ok(Setup {
        config,
        public,
        trusted,
        key_warning: key_file_warning(&path),
        known_path: path.with_file_name("known-viewers"),
        created: created.then_some(path),
    })
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let Setup {
        mut config,
        public,
        key_warning,
        created,
        trusted: flagged,
        known_path,
    } = setup(&args)?;
    // Remembered viewers (phase4.7 C2): trusted next to any --trust keys.
    let known = DeviceList::load(&known_path)
        .with_context(|| format!("remembered viewers in {}", known_path.display()))?;
    config.trusted = trusted_keys(&flagged, &known);
    // F-UX2: on EVERY run, not only when the file is created.
    eprintln!("{key_warning}");
    if let Some(path) = created {
        println!("note: created a new device identity in {}", path.display());
    }
    let (server, mut events) = HostServer::bind(args.bind, config).await?;
    let server = Arc::new(server);
    let addr = server.local_addr()?;
    println!("device: {}", short_code_of(&public));
    println!("identity: {}", identity_hex(&public));
    println!("listening: {addr}");
    let ui_server = Arc::clone(&server);
    let mut ui = Ui {
        shown_password: server.otp(),
        server,
        addr,
        public,
        book: SessionBook::new(),
        control: crate::control::Control::new(None),
        rotated: false,
        video: Video::new(args.source, args.width, args.timing, Arc::clone(&ui_server)),
        flagged,
        known,
        known_path,
        announcer: None,
    };
    if !args.no_announce {
        match remora_net::discovery::Announcer::new(addr.ip()) {
            Ok(a) => {
                ui.announcer = Some(a);
                println!(
                    "announce: findable on this network by device code {} while ready (not by name; --no-announce turns it off)",
                    short_code_of(&public)
                );
            }
            Err(e) => println!("announce: off ({e})"),
        }
    }
    if !ui.known.is_empty() {
        println!(
            "known: {} remembered viewer(s) may connect without a password - you still approve each one (type 'known')",
            ui.known.len()
        );
    }
    ui.control = crate::control::Control::new(injector(&ui.video));
    if ui.control.can_control() {
        println!("control: an accepted viewer can use this computer's mouse and keyboard");
    } else {
        println!("control: view only (no remote control on this system yet)");
    }
    ui.print_code(false);
    ui.refresh_announcement();

    let mut stdin = stdin_lines();
    // D-29: while the captured display is unavailable, say how long is left.
    // A fresh announced nonce before the last one expires (CODE_TTL).
    let mut announce_every = tokio::time::interval(ANNOUNCE_REFRESH);
    announce_every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut wait_line = tokio::time::interval(remora_app::cli::WAIT_LINE_EVERY);
    wait_line.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = announce_every.tick() => ui.refresh_announcement(),
            _ = wait_line.tick() => {
                if let Some(left) = ui.server.pause_remaining() {
                    println!("{}", remora_app::cli::display_unavailable_text(left));
                }
            }
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                ui.handle_event(ev);
            }
            line = stdin.recv() => {
                let Some(line) = line else { break };
                if !ui.handle_command(&line) {
                    break;
                }
            }
        }
    }
    ui.video.stop();
    ui.server.shutdown();
    Ok(())
}

/// What `known` prints: one line per viewer, its untrusted name escaped
/// (C8, H6).
fn known_lines(known: &DeviceList) -> Vec<String> {
    if known.is_empty() {
        return vec!["known: no remembered viewers".into()];
    }
    known
        .iter()
        .map(|d| {
            format!(
                "known: {} (device {})",
                remora_proto::display_text::display_name(&d.name),
                d.code()
            )
        })
        .collect()
}

/// Keys allowed in trusted mode: the `--trust` flags plus the remembered
/// viewers.
fn trusted_keys(flagged: &[IdentityPublic], known: &DeviceList) -> Vec<IdentityPublic> {
    let mut keys = flagged.to_vec();
    keys.extend(known.iter().map(|d| d.key).filter(|k| !flagged.contains(k)));
    keys
}

/// The session layer's configuration for this app: password mode on, the
/// `--trust` keys, and one viewer at a time (phase4.5-criteria H9, owner
/// 2026-10-25). The GUI uses the same function, so both front ends refuse a
/// second viewer.
pub(crate) fn host_config(identity: Identity, trusted: Vec<IdentityPublic>) -> HostConfig {
    HostConfig {
        identity: Arc::new(identity),
        password_enabled: true,
        trusted,
        one_active_session: true,
    }
}

/// What the host captures when it streams the screen. The cursor is drawn
/// into the video (owner, 2026-11-01: "Remora doesn't capture the mouse
/// cursor"): the design sends it separately so the viewer can draw it
/// without the video's delay (docs/quality.md, roadmap D-48), and until that
/// channel exists a screen without its pointer is not usable.
#[cfg(target_os = "macos")]
pub(crate) fn screen_capture_config(width: u32) -> remora_capture::CaptureConfig {
    remora_capture::CaptureConfig {
        width,
        show_cursor: true,
        ..remora_capture::CaptureConfig::default()
    }
}

/// One session as the person sees it: a prompt number (F-UX1) for the
/// protocol's random 64-bit session ID.
struct Entry {
    id: SessionId,
    /// The safety code on its prompt while it waits for accept/deny
    /// (approval is bound to it, A22); `None` once active.
    pending: Option<Sas>,
    /// Who it is (from the prompt): what `remember` would save.
    viewer: Option<(IdentityPublic, String)>,
}

/// The host CLI's state.
struct Ui {
    server: Arc<HostServer>,
    addr: SocketAddr,
    public: IdentityPublic,
    book: SessionBook<Entry>,
    /// Remote control: one input guard per Active session.
    control: crate::control::Control<Injector>,
    /// The password last printed, to explain a change (F-UX3).
    shown_password: Otp,
    /// The host replaced the password after failed attempts since it was
    /// last printed.
    rotated: bool,
    video: Video,
    /// The `--trust` keys (trusted for this run only, never saved).
    flagged: Vec<IdentityPublic>,
    /// Remembered viewers (phase4.7 C2, C7): changed only by `remember`
    /// and `forget` typed here.
    known: DeviceList,
    known_path: PathBuf,
    /// Home-network announcement (phase4.7 C5): only while ready, i.e. no
    /// session Active; a fresh nonce after every attempt.
    announcer: Option<remora_net::discovery::Announcer>,
}

impl Ui {
    /// Prints a fresh single-use code and the current password. With
    /// `explain`, first a line saying why a new pair appeared (F-UX3).
    fn print_code(&mut self, explain: bool) {
        let otp = self.server.otp();
        if explain {
            let change =
                PasswordChange::between(self.shown_password.reveal(), otp.reveal(), self.rotated);
            println!("{}", change.note());
        }
        let nonce = self.server.issue_nonce(CODE_TTL);
        println!(
            "code: {}",
            offer_code(
                self.addr,
                &self.public,
                nonce,
                unix_now(),
                CODE_TTL.as_secs()
            )
        );
        println!("password: {}", otp.reveal());
        self.shown_password = otp;
        self.rotated = false;
    }

    fn number_of(&self, id: SessionId) -> Option<u64> {
        self.book.find(|e| e.id == id)
    }

    fn waiting(&self) -> Vec<u64> {
        self.book.numbers_where(|e| e.pending.is_some())
    }

    /// Announces a fresh nonce, or nothing while a session is Active (C5).
    fn refresh_announcement(&mut self) {
        let busy = !self.video.active.is_empty();
        let Some(a) = self.announcer.as_mut() else {
            return;
        };
        if busy {
            a.withdraw();
            return;
        }
        let announcement = remora_net::discovery::Announcement {
            id: remora_crypto::identity::DeviceId::of(&self.public),
            nonce: self.server.issue_nonce(CODE_TTL),
            port: self.addr.port(),
        };
        if let Err(e) = a.announce(&announcement) {
            println!("announce: {e}");
        }
    }

    fn handle_event(&mut self, ev: HostEvent) {
        // Every attempt may have used the announced nonce; a session
        // starting or ending changes whether the host is ready (C5).
        let refresh = matches!(
            ev,
            HostEvent::Prompt { .. }
                | HostEvent::Active { .. }
                | HostEvent::Failed { .. }
                | HostEvent::Closed { .. }
                | HostEvent::Lost { .. }
        );
        self.handle_event_inner(ev);
        if refresh {
            self.refresh_announcement();
        }
    }

    fn handle_event_inner(&mut self, ev: HostEvent) {
        let outcome = self.control.on_event(&ev, Instant::now());
        self.control_outcome(outcome);
        match ev {
            HostEvent::Prompt {
                id,
                sas,
                viewer_name,
                viewer_key,
            } => {
                let n = self.book.insert(Entry {
                    id,
                    pending: Some(sas),
                    viewer: Some((viewer_key, viewer_name.clone())),
                });
                println!(
                    "prompt {n}: {viewer_name:?} (device {}) safety code {} - check it matches the viewer's screen, then type 'accept {n}' or 'deny {n}'",
                    short_code_of(&viewer_key),
                    format_sas(sas),
                );
                // The code and password just used are spent (A06, INV15).
                self.print_code(true);
            }
            HostEvent::PromptClosed { id } => {
                if let Some(n) = self.number_of(id)
                    && let Some(e) = self.book.get_mut(n)
                    && e.pending.take().is_some()
                {
                    println!("prompt withdrawn {n}");
                }
            }
            HostEvent::Active { id } => {
                let n = match self.number_of(id) {
                    Some(n) => n,
                    // Every session is prompted, trusted or not (threat
                    // model §4 item 6); kept so a session never goes unnumbered.
                    None => self.book.insert(Entry {
                        id,
                        pending: None,
                        viewer: None,
                    }),
                };
                let mut viewer = None;
                if let Some(e) = self.book.get_mut(n) {
                    e.pending = None;
                    viewer = e.viewer.as_ref().map(|(k, _)| *k);
                }
                println!(
                    "SESSION ACTIVE {n}: a viewer is connected (type 'disconnect {n}' to end it)"
                );
                if viewer.is_some_and(|k| self.known.get(&k).is_none()) {
                    println!(
                        "note: type 'remember {n}' to let this viewer connect without a password next time (you still approve every connection)"
                    );
                }
                self.video.active.insert(id);
            }
            // Applied (or not) by `control` above.
            HostEvent::Deliver { .. } => {}
            HostEvent::Failed { id, reason, .. } => {
                match self.number_of(id) {
                    Some(n) => println!("failed {n}: {reason}"),
                    None => println!("failed: {reason}"),
                }
                self.print_code(true);
            }
            HostEvent::OtpRotated => {
                self.rotated = true;
                println!("note: 3 failed attempts - the password was replaced");
            }
            HostEvent::OtpUsed { .. } => {}
            // H9: refused before the handshake, so not a password attempt;
            // one line per attempt (owner), time and address only.
            HostEvent::RefusedBusy { peer } => println!(
                "refused: {} tried to connect at {} while a session is active (host busy; not a password attempt)",
                peer.ip(),
                remora_app::cli::utc_time(unix_now())
            ),
            // A new viewer, a viewer's request (rate-limited by the
            // session) or capture resumed.
            HostEvent::ForceKeyframe => self.video.force_keyframe(),
            HostEvent::Closed { id, code } => {
                self.video.ended(id);
                if let Some(n) = self.number_of(id) {
                    self.book.remove(n);
                    println!("session ended {n} ({code:?})");
                }
            }
            // Walkthrough 2026-10-21: a dead connection used to be printed
            // as "session ended (Normal)".
            HostEvent::Lost { id } => {
                self.video.ended(id);
                if let Some(n) = self.number_of(id) {
                    self.book.remove(n);
                    println!(
                        "connection lost {n}: no reply from the viewer for {} s - session ended",
                        IDLE_TIMEOUT.as_secs()
                    );
                }
            }
        }
    }

    /// `remember <n>` (phase4.7 C2): only for a session the person here
    /// accepted (its prompt is answered), never automatically.
    fn remember(&mut self, n: u64) {
        let Some(Entry {
            pending: None,
            viewer: Some((key, name)),
            ..
        }) = self.book.get(n)
        else {
            println!(
                "remember {n}: only a viewer you accepted can be remembered (no accepted session {n})"
            );
            return;
        };
        let (key, name) = (*key, name.clone());
        let device = remora_app::devices::Device {
            key,
            name: name
                .chars()
                .take(remora_app::devices::MAX_NAME)
                .collect::<String>(),
            addr: None,
        };
        if let Err(e) = self
            .known
            .remember(device)
            .and_then(|()| self.known.save(&self.known_path))
        {
            println!("remember {n}: {e}");
            return;
        }
        self.server
            .set_trusted(trusted_keys(&self.flagged, &self.known));
        println!(
            "remembered {} (device {}): it can connect without a password; you still approve every connection. 'forget {}' undoes it",
            remora_proto::display_text::display_name(&name),
            short_code_of(&key),
            short_code_of(&key)
        );
    }

    /// `forget <device code>` (C7): takes effect for the next connection.
    fn forget(&mut self, code: &remora_crypto::identity::ShortCode) {
        let Some(key) = self.known.find_code(code).map(|d| d.key) else {
            println!("forget: no remembered viewer has device code {code} (type 'known')");
            return;
        };
        self.known.forget(&key);
        if let Err(e) = self.known.save(&self.known_path) {
            println!("forget: {e}");
        }
        self.server
            .set_trusted(trusted_keys(&self.flagged, &self.known));
        println!("forgot device {code}: it needs the password again (and your approval)");
    }

    /// `known`: the remembered viewers (names escaped, H6/C8).
    fn list_known(&self) {
        for line in known_lines(&self.known) {
            println!("{line}");
        }
    }

    /// Prints what remote control did; ends a session the guard refused.
    fn control_outcome(&mut self, outcome: crate::control::Outcome) {
        use crate::control::Outcome;
        let n = |ui: &Self, id| ui.number_of(id).map_or(String::new(), |n| format!(" {n}"));
        match outcome {
            Outcome::None => {}
            // What was typed is never shown (INV9): it could be a password.
            Outcome::FirstInput(id) => {
                println!(
                    "input{}: the viewer is controlling this computer (input not shown)",
                    n(self, id)
                )
            }
            Outcome::NoInjector(id) => println!(
                "input{}: receiving input events (not applied: no remote control on this system yet)",
                n(self, id)
            ),
            Outcome::ConnectFailed(id, e) => {
                println!(
                    "control{}: remote control unavailable, view only ({e})",
                    n(self, id)
                )
            }
            Outcome::End(id, why) => {
                println!("input refused{}: {why} - ending the session", n(self, id));
                self.server.disconnect(id);
            }
        }
    }

    /// Applies one typed line; `false` to quit. Every mistake gets an
    /// explicit answer (F-UX1).
    fn handle_command(&mut self, line: &str) -> bool {
        let cmd = match parse_host_command(line) {
            Ok(cmd) => cmd,
            Err(e) => {
                println!("{e}");
                return true;
            }
        };
        match cmd {
            HostCommand::Nothing => {}
            HostCommand::Quit => return false,
            HostCommand::Accept(n) => match self.book.get(n) {
                // Approval is bound to the session AND the code on its prompt (A22).
                Some(Entry {
                    id,
                    pending: Some(sas),
                    ..
                }) => {
                    let (id, sas) = (*id, *sas);
                    // Capture starts before the approval, so a capture
                    // that cannot start ends this session with
                    // CaptureStopped instead of an Active session that
                    // never shows anything.
                    self.video.prepare();
                    if let Err(e) = self.server.approve(id, sas) {
                        println!("cannot accept {n}: {e}");
                        self.video.idle_check();
                    }
                    // On success the session's Active (or Closed) event
                    // arrives later through the event channel.
                }
                Some(Entry { pending: None, .. }) => {
                    println!("session {n} is already active - nothing to accept")
                }
                None => println!("{}", no_such_prompt(n, &self.waiting())),
            },
            HostCommand::Deny(n) => match self.book.get_mut(n) {
                Some(e) if e.pending.is_some() => {
                    e.pending = None;
                    self.server.deny(e.id);
                }
                Some(_) => println!("session {n} is already active - use 'disconnect {n}'"),
                None => println!("{}", no_such_prompt(n, &self.waiting())),
            },
            HostCommand::Remember(n) => self.remember(n),
            HostCommand::Forget(code) => self.forget(&code),
            HostCommand::Known => self.list_known(),
            HostCommand::Disconnect(n) => match self.book.get(n) {
                Some(e) => self.server.disconnect(e.id),
                None => println!("no session {n}"),
            },
        }
        true
    }
}

/// Checks `--source` and `--width` before anything starts.
fn check_source(source: Source, width: u32) -> anyhow::Result<()> {
    if source == Source::None {
        return Ok(());
    }
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        bail!(
            "--source {source:?}: no screen capture or encoder on this OS yet (Phase 6.5); use --source none"
        );
    }
    if cfg!(target_os = "linux") && source == Source::Synthetic {
        bail!("--source synthetic is macOS-only for now; use --source screen or none");
    }
    // The barcode strip that numbers each test frame (P7) is 704 pixels wide.
    if source == Source::Synthetic && width < 704 {
        bail!("--source synthetic needs --width 704 or more (got {width})");
    }
    if width < 2 {
        bail!("--width must be at least 2");
    }
    Ok(())
}

/// The video stream (macOS, Linux): started when the person accepts a viewer,
/// stopped when the last session ends, so nothing is captured while
/// nobody is connected.
pub(crate) struct Video {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    source: Source,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    width: u32,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    server: Arc<HostServer>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    timing: bool,
    /// Sessions that are Active.
    pub(crate) active: std::collections::HashSet<SessionId>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    running: Option<crate::stream::Streamer>,
    /// Linux: the input side of the portal session that is showing the
    /// screen, while it runs (the injector is opened from it, D48).
    #[cfg(target_os = "linux")]
    portal_input: Arc<std::sync::Mutex<Option<remora_capture::PortalInput>>>,
}

impl Video {
    pub(crate) fn new(source: Source, width: u32, timing: bool, server: Arc<HostServer>) -> Self {
        // Other systems stream nothing yet (`check_source` refused it).
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let _ = (source, width, timing, server);
        Self {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            source,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            width,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            server,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            timing,
            active: std::collections::HashSet::new(),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            running: None,
            #[cfg(target_os = "linux")]
            portal_input: Arc::default(),
        }
    }

    /// Makes sure the stream runs before a viewer is approved, and tells
    /// the session layer whether capture works.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(crate) fn prepare(&mut self) {
        use remora_session::CaptureStatus;

        if self.running.is_some() || self.source == Source::None {
            return;
        }
        let capture = match self.open_capture() {
            Ok(c) => c,
            Err(e) => {
                println!("cannot stream: {e:#}");
                self.server.capture_changed(CaptureStatus::Stopped);
                return;
            }
        };
        let out: Arc<dyn crate::stream::VideoOut> = Arc::new(Out {
            server: Arc::clone(&self.server),
            timing: self.timing,
        });
        match crate::stream::Streamer::start(capture, out) {
            Ok(s) => {
                println!("streaming: {:?}, H.264", self.source);
                self.running = Some(s);
                self.server.capture_changed(CaptureStatus::Running);
            }
            Err(e) => {
                println!("cannot stream: {e:#}");
                self.server.capture_changed(CaptureStatus::Stopped);
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn prepare(&mut self) {}

    /// The screen (or the macOS test pattern) to stream.
    #[cfg(target_os = "macos")]
    fn open_capture(&mut self) -> anyhow::Result<Box<dyn remora_capture::ScreenCapture>> {
        use remora_capture::MacScreenCapture;
        Ok(match self.source {
            Source::Screen => Box::new(MacScreenCapture::main_display(screen_capture_config(
                self.width,
            ))?),
            // 16:9, as a typical screen.
            _ => Box::new(crate::stream::SyntheticCapture::new(
                self.width,
                self.width * 9 / 16,
                60,
            )),
        })
    }

    /// Linux: one portal session for the screen and remote control (D48).
    /// The first time GNOME asks the person at this computer; the answer
    /// is saved (restore token, 0600) so later sessions start without it.
    #[cfg(target_os = "linux")]
    fn open_capture(&mut self) -> anyhow::Result<Box<dyn remora_capture::ScreenCapture>> {
        use remora_capture::{CaptureConfig, PortalCapture, PortalOptions};
        let mut capture = PortalCapture::open(
            CaptureConfig {
                width: self.width,
                show_cursor: true,
                ..CaptureConfig::default()
            },
            PortalOptions {
                restore_token: load_portal_token(),
                control: true,
            },
        )?;
        save_portal_token(capture.take_new_token());
        if let Ok(mut slot) = self.portal_input.lock() {
            *slot = capture.input();
        }
        Ok(Box::new(capture))
    }

    pub(crate) fn force_keyframe(&self) {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(s) = &self.running {
            s.force_keyframe();
        }
    }

    /// Session `id` is over.
    pub(crate) fn ended(&mut self, id: SessionId) {
        self.active.remove(&id);
        self.idle_check();
    }

    /// Stops the stream when no session is Active.
    pub(crate) fn idle_check(&mut self) {
        if self.active.is_empty() {
            self.stop();
        }
    }

    pub(crate) fn stop(&mut self) {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(s) = self.running.take() {
            s.stop();
            println!("streaming stopped");
        }
        #[cfg(target_os = "linux")]
        if let Ok(mut slot) = self.portal_input.lock() {
            *slot = None;
        }
    }
}

/// Frames and capture state into the host server.
#[cfg(any(target_os = "macos", target_os = "linux"))]
struct Out {
    server: Arc<HostServer>,
    timing: bool,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl crate::stream::VideoOut for Out {
    fn video(&self, keyframe: bool, capture_ts_us: u64, data: &[u8]) {
        let now_us = || remora_app::clock::monotonic_ns().map_or(0, |n| n / 1000);
        let encoded_us = now_us();
        if let Err(e) = self.server.send_video(keyframe, capture_ts_us, data) {
            // Sizes and counts only (INV9).
            eprintln!("video frame of {} bytes not sent: {e}", data.len());
        } else if self.timing {
            // Times and sizes only (INV9).
            eprintln!(
                "timing: capture_us={capture_ts_us} encoded_us={encoded_us} sent_us={} bytes={} keyframe={keyframe}",
                now_us(),
                data.len()
            );
        }
    }

    fn captured(&self, capture_ts_us: u64) {
        if self.timing {
            // Times only (INV9): P3's denominator.
            eprintln!("captured: capture_us={capture_ts_us}");
        }
    }

    fn not_encoded(&self, capture_ts_us: u64, why: crate::stream::NotEncoded) {
        if self.timing {
            eprintln!("not encoded: capture_us={capture_ts_us} ({why:?})");
        }
    }

    fn capture(&self, status: remora_session::CaptureStatus) {
        use remora_session::{CaptureStatus, PauseReason};
        match status {
            CaptureStatus::Running => println!("capture resumed"),
            CaptureStatus::Interrupted(PauseReason::DisplayUnavailable { remaining_ms }) => {
                let left = std::time::Duration::from_millis(u64::from(remaining_ms));
                println!(
                    "capture paused - {} (viewers are told)",
                    remora_app::cli::display_unavailable_text(left)
                );
            }
            CaptureStatus::Interrupted(r) => println!("capture paused ({r:?}) - viewers are told"),
            CaptureStatus::Stopped => println!("capture stopped - active sessions end"),
        }
        self.server.capture_changed(status);
    }
}

/// The OS input injector behind the guard.
type Injector = Box<dyn remora_input::guard::Backend + Send>;

/// How this OS opens its injector for a session; `None` where there is
/// none yet (macOS: Phase 6).
#[cfg(not(target_os = "linux"))]
fn injector(_video: &Video) -> Option<crate::control::Connect<Injector>> {
    None
}

/// Linux: input goes into the portal session that is showing the screen
/// (it exists from `accept`, before the session is Active).
#[cfg(target_os = "linux")]
fn injector(video: &Video) -> Option<crate::control::Connect<Injector>> {
    use remora_input::guard::BackendError;
    let slot = Arc::clone(&video.portal_input);
    Some(Box::new(move || {
        let input = slot
            .lock()
            .ok()
            .and_then(|s| s.clone())
            .ok_or_else(|| BackendError("the screen is not being shared".into()))?;
        Ok(Box::new(remora_input::PortalBackend::new(input)) as Injector)
    }))
}

/// Where the desktop portal's saved permission (restore token) is kept:
/// next to the host's key file, readable by this user only (L8).
#[cfg(target_os = "linux")]
pub(crate) fn portal_token_path() -> anyhow::Result<PathBuf> {
    let key = keystore::default_path(Role::Host)?;
    Ok(key.with_file_name("portal-restore-token"))
}

/// The saved permission, if there is one (L8: never printed).
#[cfg(target_os = "linux")]
pub(crate) fn load_portal_token() -> Option<remora_capture::RestoreToken> {
    let path = portal_token_path().ok()?;
    remora_app::token_file::load(&path).and_then(|t| remora_capture::RestoreToken::new(&t))
}

/// Keeps GNOME's newest token for the next session (owner-only file).
#[cfg(target_os = "linux")]
pub(crate) fn save_portal_token(token: Option<remora_capture::RestoreToken>) {
    let (Some(token), Ok(path)) = (token, portal_token_path()) else {
        return;
    };
    if let Err(e) = remora_app::token_file::save(&path, token.expose()) {
        // The path and the error, never the token (L8).
        eprintln!(
            "could not save the screen-sharing permission in {}: {e}",
            path.display()
        );
    }
}

/// `remora-host forget-permission`: deletes the saved screen-sharing and
/// remote-control permission, so the next session asks at this computer
/// again (phase4.6-criteria Q5).
#[cfg(target_os = "linux")]
pub(crate) fn forget_permission() -> anyhow::Result<()> {
    let path = portal_token_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => println!(
            "deleted {}: the next session asks on this computer again",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("nothing saved at {}", path.display())
        }
        Err(e) => return Err(e).with_context(|| format!("deleting {}", path.display())),
    }
    println!(
        "GNOME may also list Remora under Settings > Privacy > Screen Sharing / Remote Desktop."
    );
    Ok(())
}

/// Lines typed on stdin, read on a plain thread (stdin is blocking).
fn stdin_lines() -> tokio::sync::mpsc::UnboundedReceiver<String> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// `remora-host identity`: print (creating if needed) this host's identity.
pub(crate) fn identity(file: Option<PathBuf>) -> anyhow::Result<()> {
    let path = match file {
        Some(p) => p,
        None => keystore::default_path(Role::Host)?,
    };
    let (keys, _) = keystore::load_or_create(&path)?;
    eprintln!("{}", key_file_warning(&path));
    let public = keys.identity.public();
    println!("identity: {}", identity_hex(&public));
    println!("device: {}", short_code_of(&public));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn the_streamed_screen_shows_the_cursor() {
        let c = screen_capture_config(1920);
        assert!(
            c.show_cursor,
            "until the separate cursor channel (D-48) exists"
        );
        assert_eq!(c.width, 1920);
    }

    #[test]
    fn h9_the_app_serves_one_viewer_at_a_time() {
        let keys = remora_crypto::identity::DeviceKeys::generate(&mut rand_core::OsRng);
        let identity = Identity {
            cert: keys.cert("test", 0).expect("short name"),
            noise: keys.noise,
        };
        assert!(host_config(identity, vec![]).one_active_session);
    }
}

/// phase4.7-criteria C2: only the person at the host changes the list.
#[cfg(test)]
mod c2_tests {
    use std::time::Duration;

    use remora_crypto::identity::IdentityKeypair;

    use super::*;

    async fn ui(dir: &std::path::Path) -> Ui {
        ui_with_events(dir).await.0
    }

    pub(super) async fn ui_with_events_for_c3(
        dir: &std::path::Path,
    ) -> (Ui, tokio::sync::mpsc::UnboundedReceiver<HostEvent>) {
        ui_with_events(dir).await
    }

    async fn ui_with_events(
        dir: &std::path::Path,
    ) -> (Ui, tokio::sync::mpsc::UnboundedReceiver<HostEvent>) {
        let keys = remora_crypto::identity::DeviceKeys::generate(&mut rand_core::OsRng);
        let identity = Identity {
            cert: keys.cert("host", 0).expect("short name"),
            noise: keys.noise,
        };
        let (server, events) = HostServer::bind(
            "127.0.0.1:0".parse().expect("addr"),
            host_config(identity, vec![]),
        )
        .await
        .expect("bind");
        let server = Arc::new(server);
        let ui = Ui {
            shown_password: server.otp(),
            addr: server.local_addr().expect("addr"),
            public: keys.identity.public(),
            book: SessionBook::new(),
            control: crate::control::Control::new(None),
            rotated: false,
            video: Video::new(Source::None, 1920, false, Arc::clone(&server)),
            server,
            flagged: vec![],
            known: DeviceList::new(),
            known_path: dir.join("known-viewers"),
            announcer: None,
        };
        (ui, events)
    }

    fn prompt(id: u64, key: IdentityPublic) -> HostEvent {
        HostEvent::Prompt {
            id: SessionId(id),
            sas: remora_crypto::sas::sas(&[1; 32], &[2; 32], &[3; 32]),
            viewer_name: "viewer".into(),
            viewer_key: key,
        }
    }

    #[tokio::test]
    async fn c2_accepting_never_remembers_only_the_remember_command_does() {
        let dir = std::env::temp_dir().join(format!("remora-c2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut ui = ui(&dir).await;
        let v = IdentityKeypair::generate(&mut rand_core::OsRng).public();
        ui.handle_event(prompt(1, v));
        // Not answered yet: cannot be remembered.
        ui.handle_command("remember 1");
        assert!(ui.known.is_empty(), "a pending prompt was remembered");
        ui.handle_event(HostEvent::Active { id: SessionId(1) });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(ui.known.is_empty(), "accepting alone remembered the viewer");
        assert!(
            !ui.known_path.exists(),
            "a list file appeared without 'remember'"
        );
        ui.handle_command("remember 1");
        assert_eq!(ui.known.get(&v).map(|d| d.name.as_str()), Some("viewer"));
        assert_eq!(
            DeviceList::load(&ui.known_path)
                .expect("saved")
                .get(&v)
                .map(|d| d.key),
            Some(v)
        );
        assert_eq!(trusted_keys(&ui.flagged, &ui.known), vec![v]);
        let code = short_code_of(&v);
        ui.handle_command(&format!("forget {code}"));
        assert!(ui.known.is_empty());
        assert!(DeviceList::load(&ui.known_path).expect("saved").is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// phase4.7-criteria C3 through the real host app: a remembered viewer,
/// connecting for real in trusted mode, is prompted and never Active
/// until the person types `accept`.
#[cfg(test)]
mod c3_tests {
    use std::time::Duration;

    use remora_crypto::identity::DeviceKeys;
    use remora_session::{ViewerConfig, ViewerMode};

    use super::c2_tests::ui_with_events_for_c3 as ui_with_events;
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn c3_a_remembered_viewer_waits_for_accept_in_the_host_app() {
        let dir = std::env::temp_dir().join(format!("remora-c3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (mut ui, mut events) = ui_with_events(&dir).await;
        let viewer = DeviceKeys::generate(&mut rand_core::OsRng);
        let viewer_key = viewer.identity.public();
        ui.known
            .remember(remora_app::devices::Device {
                key: viewer_key,
                name: "viewer".into(),
                addr: None,
            })
            .expect("remember");
        ui.server.set_trusted(trusted_keys(&ui.flagged, &ui.known));
        let config = ViewerConfig {
            identity: Arc::new(Identity {
                cert: viewer.cert("viewer", 0).expect("name"),
                noise: viewer.noise,
            }),
            mode: ViewerMode::Trusted { pinned: ui.public },
        };
        let nonce = ui.server.issue_nonce(CODE_TTL);
        let (_client, _viewer_events) = remora_net::connect(ui.addr, config, nonce)
            .await
            .expect("connect");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let (mut prompted, mut active) = (false, false);
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events.recv()).await {
            prompted |= matches!(ev, HostEvent::Prompt { .. });
            active |= matches!(ev, HostEvent::Active { .. });
            ui.handle_event(ev);
        }
        assert!(prompted, "a remembered viewer is still prompted");
        assert!(!active, "Active without anyone typing accept");
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// phase4.7-criteria C8: a remembered viewer's name is untrusted text.
#[cfg(test)]
mod c8_tests {
    use super::*;

    #[test]
    fn c8_known_viewer_names_are_shown_escaped() {
        let mut known = DeviceList::new();
        let hostile = "Phone\nknown: Admin (device 0000 000 0000-0) \u{202e}x";
        known
            .remember(remora_app::devices::Device {
                key: remora_crypto::identity::IdentityKeypair::generate(&mut rand_core::OsRng)
                    .public(),
                name: hostile.into(),
                addr: None,
            })
            .expect("add");
        let lines = known_lines(&known);
        assert_eq!(lines.len(), 1);
        assert!(
            !lines[0].contains('\n'),
            "a newline in a name made a second line: {lines:?}"
        );
        assert!(!lines[0].contains('\u{202e}'), "bidi override shown raw");
    }
}
