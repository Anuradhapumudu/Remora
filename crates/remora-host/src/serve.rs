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
//! password; Phase 3 has no injector, so the CLI only counts events.
//!
//! Phase 4: once a viewer is accepted the host streams `--source` (the
//! screen by default on macOS; architecture D42) and prints `streaming:`,
//! `capture paused/resumed/stopped` and `streaming stopped` lines.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use remora_app::cli::{
    PasswordChange, format_sas, identity_hex, key_file_warning, offer_code, parse_identity,
    short_code_of, unix_now,
};
use remora_app::keystore::{self, Role};
use remora_app::prompts::{HostCommand, SessionBook, no_such_prompt, parse_host_command};
use remora_crypto::identity::IdentityPublic;
use remora_crypto::sas::Sas;
use remora_crypto::secret::Otp;
use remora_net::{HostEvent, HostServer, IDLE_TIMEOUT};
use remora_session::{HostConfig, Identity, SessionId};

/// How long each printed connection code is valid (protocol.md §2: ≤ 5 min).
const CODE_TTL: Duration = Duration::from_secs(300);

/// `remora-host serve` options.
#[derive(clap::Args, Debug)]
pub(crate) struct ServeArgs {
    /// Address to listen on (Phase 3: a specific local address).
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,
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
    source: Source,
    /// Width of the streamed picture in pixels (the screen is scaled to
    /// it, keeping its aspect ratio; never upscaled).
    #[arg(long, default_value_t = 1920)]
    width: u32,
    /// Print one `timing:` line per sent frame on stderr: shared-clock
    /// times of capture, encoder output and send (latency measurement,
    /// phase4-criteria P1/P2). Times only.
    #[arg(long)]
    timing: bool,
}

/// `serve --source`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// The main display.
    Screen,
    /// A test pattern whose frames carry their number (phase4-criteria P7).
    Synthetic,
    /// No video.
    None,
}

impl Default for Source {
    /// The screen where this build can capture it (macOS); nothing
    /// elsewhere until those backends exist (Phase 6.5).
    fn default() -> Self {
        if cfg!(target_os = "macos") {
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

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
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
    let path = match args.identity_file {
        Some(p) => p,
        None => keystore::default_path(Role::Host)?,
    };
    let (keys, created) = keystore::load_or_create(&path)?;
    // F-UX2: on EVERY run, not only when the file is created.
    eprintln!("{}", key_file_warning(&path));
    if created {
        println!("note: created a new device identity in {}", path.display());
    }
    let cert = keys
        .cert(&args.name, unix_now())
        .context("--name is at most 64 bytes")?;
    let public = keys.identity.public();
    let config = HostConfig {
        identity: Arc::new(Identity {
            noise: keys.noise,
            cert,
        }),
        password_enabled: true,
        trusted,
    };
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
        inputs: HashMap::new(),
        rotated: false,
        video: Video::new(args.source, args.width, args.timing, Arc::clone(&ui_server)),
    };
    ui.print_code(false);

    let mut stdin = stdin_lines();
    // D-29: while the captured display is removed, say how long is left.
    let mut wait_line = tokio::time::interval(remora_app::cli::WAIT_LINE_EVERY);
    wait_line.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = wait_line.tick() => {
                if let Some(left) = ui.server.pause_remaining() {
                    println!("{}", remora_app::cli::display_removed_text(left));
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

/// One session as the person sees it: a prompt number (F-UX1) for the
/// protocol's random 64-bit session ID.
struct Entry {
    id: SessionId,
    /// The safety code on its prompt while it waits for accept/deny
    /// (approval is bound to it, A22); `None` once active.
    pending: Option<Sas>,
}

/// The host CLI's state.
struct Ui {
    server: Arc<HostServer>,
    addr: SocketAddr,
    public: IdentityPublic,
    book: SessionBook<Entry>,
    inputs: HashMap<SessionId, u64>,
    /// The password last printed, to explain a change (F-UX3).
    shown_password: Otp,
    /// The host replaced the password after failed attempts since it was
    /// last printed.
    rotated: bool,
    video: Video,
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

    fn handle_event(&mut self, ev: HostEvent) {
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
                    None => self.book.insert(Entry { id, pending: None }),
                };
                if let Some(e) = self.book.get_mut(n) {
                    e.pending = None;
                }
                println!(
                    "SESSION ACTIVE {n}: a viewer is connected (type 'disconnect {n}' to end it)"
                );
                self.video.active.insert(id);
            }
            HostEvent::Deliver { id, .. } => {
                let count = self.inputs.entry(id).or_default();
                *count += 1;
                if *count == 1 {
                    match self.number_of(id) {
                        Some(n) => println!("input {n}: receiving input events (not shown)"),
                        None => println!("input: receiving input events (not shown)"),
                    }
                }
            }
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
            // A new viewer, a viewer's request (rate-limited by the
            // session) or capture resumed.
            HostEvent::ForceKeyframe => self.video.force_keyframe(),
            HostEvent::Closed { id, code } => {
                self.inputs.remove(&id);
                self.video.ended(id);
                if let Some(n) = self.number_of(id) {
                    self.book.remove(n);
                    println!("session ended {n} ({code:?})");
                }
            }
            // Walkthrough 2026-10-21: a dead connection used to be printed
            // as "session ended (Normal)".
            HostEvent::Lost { id } => {
                self.inputs.remove(&id);
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
    if !cfg!(target_os = "macos") {
        bail!(
            "--source {source:?}: no screen capture or encoder on this OS yet (Phase 6.5); use --source none"
        );
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

/// The video stream (macOS): started when the person accepts a viewer,
/// stopped when the last session ends, so nothing is captured while
/// nobody is connected.
struct Video {
    #[cfg(target_os = "macos")]
    source: Source,
    #[cfg(target_os = "macos")]
    width: u32,
    #[cfg(target_os = "macos")]
    server: Arc<HostServer>,
    #[cfg(target_os = "macos")]
    timing: bool,
    /// Sessions that are Active.
    active: std::collections::HashSet<SessionId>,
    #[cfg(target_os = "macos")]
    running: Option<crate::stream::Streamer>,
}

impl Video {
    fn new(source: Source, width: u32, timing: bool, server: Arc<HostServer>) -> Self {
        // Other systems stream nothing yet (`check_source` refused it).
        #[cfg(not(target_os = "macos"))]
        let _ = (source, width, timing, server);
        Self {
            #[cfg(target_os = "macos")]
            source,
            #[cfg(target_os = "macos")]
            width,
            #[cfg(target_os = "macos")]
            server,
            #[cfg(target_os = "macos")]
            timing,
            active: std::collections::HashSet::new(),
            #[cfg(target_os = "macos")]
            running: None,
        }
    }

    /// Makes sure the stream runs before a viewer is approved, and tells
    /// the session layer whether capture works.
    #[cfg(target_os = "macos")]
    fn prepare(&mut self) {
        use remora_capture::{CaptureConfig, MacScreenCapture, ScreenCapture};
        use remora_session::CaptureStatus;

        if self.running.is_some() || self.source == Source::None {
            return;
        }
        let capture: anyhow::Result<Box<dyn ScreenCapture>> = match self.source {
            Source::Screen => MacScreenCapture::main_display(CaptureConfig {
                width: self.width,
                ..CaptureConfig::default()
            })
            .map(|c| Box::new(c) as Box<dyn ScreenCapture>)
            .map_err(anyhow::Error::from),
            // 16:9, as a typical screen.
            _ => Ok(Box::new(crate::stream::SyntheticCapture::new(
                self.width,
                self.width * 9 / 16,
                60,
            ))),
        };
        let out: Arc<dyn crate::stream::VideoOut> = Arc::new(Out {
            server: Arc::clone(&self.server),
            timing: self.timing,
        });
        match capture.and_then(|c| crate::stream::Streamer::start(c, out)) {
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

    #[cfg(not(target_os = "macos"))]
    fn prepare(&mut self) {}

    fn force_keyframe(&self) {
        #[cfg(target_os = "macos")]
        if let Some(s) = &self.running {
            s.force_keyframe();
        }
    }

    /// Session `id` is over.
    fn ended(&mut self, id: SessionId) {
        self.active.remove(&id);
        self.idle_check();
    }

    /// Stops the stream when no session is Active.
    fn idle_check(&mut self) {
        if self.active.is_empty() {
            self.stop();
        }
    }

    fn stop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(s) = self.running.take() {
            s.stop();
            println!("streaming stopped");
        }
    }
}

/// Frames and capture state into the host server (macOS).
#[cfg(target_os = "macos")]
struct Out {
    server: Arc<HostServer>,
    timing: bool,
}

#[cfg(target_os = "macos")]
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
            CaptureStatus::Interrupted(PauseReason::DisplayRemoved { remaining_ms }) => {
                let left = std::time::Duration::from_millis(u64::from(remaining_ms));
                println!(
                    "capture paused - {} (viewers are told)",
                    remora_app::cli::display_removed_text(left)
                );
            }
            CaptureStatus::Interrupted(r) => println!("capture paused ({r:?}) - viewers are told"),
            CaptureStatus::Stopped => println!("capture stopped - active sessions end"),
        }
        self.server.capture_changed(status);
    }
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
