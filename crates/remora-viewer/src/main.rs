//! Remora viewer: views and controls a remote Remora host.
//!
//! Phase 3: `connect` runs the authenticated handshake against a host's
//! connection code on loopback and shows the safety code. Phase 4: it
//! decodes the video it receives (step 5) and shows it in a window (step
//! 6), or only decodes it with `--no-window` (step 7a).
//!
//! Output lines (stable prefixes; the end-to-end tests read them):
//! `safety code:`, `SESSION ACTIVE`, `rejected by the host`, `identity
//! mismatch: ...`, `this device's identity changed ...`, `failed: ...`,
//! `session ended`, `video:` (decoder counts, at the end). Exit codes:
//! see [`remora_app::cli::exit`].

#![forbid(unsafe_code)]

mod decode;
#[cfg(target_os = "macos")]
mod gui;
#[cfg(target_os = "macos")]
mod input;
#[cfg(target_os = "macos")]
mod keymap;
#[cfg(target_os = "macos")]
mod quit;
mod sound;
#[cfg(target_os = "macos")]
mod window;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use remora_app::cli::{
    Looks, exit, format_sas, identity_hex, join_device_words, key_file_warning, misplaced,
    parse_identity, short_code_of, unix_now,
};
use remora_app::devices::{Device, DeviceList, MAX_NAME};
use remora_app::keystore::{self, Role};
use remora_crypto::identity::{DeviceId, IdentityCert, IdentityPublic, ShortCode};
use remora_crypto::secret::Otp;
use remora_net::{IDLE_TIMEOUT, ViewerEvent, connect};
use remora_proto::code::{CodeKind, ConnectionCode};
use remora_proto::display_text::display_name;
use remora_session::{CloseCode, FailReason, Identity, ViewerConfig, ViewerMode};

#[derive(Parser)]
#[command(version, about = "Remora viewer (pre-alpha)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Phase 3: connect to a host with its connection code (loopback).
    Connect(ConnectArgs),
    /// Phase 4.5: connect with a window: paste the code, type the
    /// password, compare the safety code.
    #[cfg(target_os = "macos")]
    Gui {
        /// Key file (default: the per-user config directory).
        #[arg(long)]
        identity_file: Option<PathBuf>,
        /// Name shown to the host (untrusted text, ≤ 64 bytes).
        #[arg(long, default_value = "Remora viewer")]
        name: String,
    },
    /// List the saved computers (phase4.7).
    Saved {
        /// Key file (default: the per-user config directory); the list is
        /// kept next to it.
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
    /// Forget a saved computer by its device code.
    Forget {
        /// The device code, as `saved` lists it.
        code: String,
        /// Key file (default: the per-user config directory).
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
    /// Print this viewer's identity key and device code (created if needed).
    Identity {
        /// Key file (default: the per-user config directory).
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct ConnectArgs {
    /// The host's connection code (its `code:` line, `remora1:...`).
    /// Leave it out and give `--device` to find the host on this network
    /// instead (phase4.7).
    #[arg(required_unless_present = "device")]
    code: Option<String>,
    /// Key file (default: the per-user config directory).
    #[arg(long)]
    identity_file: Option<PathBuf>,
    /// Name shown to the host (untrusted text, ≤ 64 bytes).
    #[arg(long, default_value = "Remora viewer")]
    name: String,
    /// The host's one-time password (asked on stdin if not given).
    #[arg(long, conflicts_with = "pin")]
    password: Option<String>,
    /// Trusted mode: the host's identity key (its `identity:` line, 64 hex
    /// digits); replaces the password.
    #[arg(long)]
    pin: Option<String>,
    /// The device code of the host you mean to reach (the host's `device:`
    /// line, e.g. --device 8531 422 5411-5, quotes optional); refuse any
    /// other.
    #[arg(long, value_name = "DEVICE CODE")]
    device: Option<String>,
    /// After the host approves, save it: next time `--device <code>`
    /// connects without a password, in trusted mode against the saved key
    /// (the host must remember this viewer too, and still approves).
    #[arg(long)]
    save: bool,
    /// Decode the video but open no window (tests and measurements); the
    /// decoder's counts are printed when the session ends.
    #[arg(long)]
    no_window: bool,
    /// Print one `timing:` line per drawn frame on stderr: shared-clock
    /// times of capture, arrival, decode, GPU draw done and present
    /// (latency measurement, phase4-criteria P1/P2), and once a second a
    /// `media:` line with the media datagram counts (P3). Times and counts
    /// only.
    #[arg(long)]
    timing: bool,
    /// Play no sound from the host (phase4.8). While connected,
    /// Ctrl+Option+M in the window mutes and unmutes instead.
    #[arg(long)]
    no_audio: bool,
}

fn main() -> ExitCode {
    // F-UX6: a device code typed without quotes is rejoined first.
    let cli = Cli::parse_from(join_device_words(remora_app::cli::args_or_gui(
        std::env::args_os(),
        std::env::var_os("REMORA_GUI"),
    )));
    init_logging();
    let result = match cli.command {
        None => {
            println!(
                "{} {} (pre-alpha: try --help)",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            Ok(exit::OK)
        }
        Some(Command::Identity { identity_file }) => identity(identity_file).map(|()| exit::OK),
        Some(Command::Saved { identity_file }) => list_saved(identity_file).map(|()| exit::OK),
        Some(Command::Forget {
            code,
            identity_file,
        }) => forget_saved(&code, identity_file).map(|()| exit::OK),
        Some(Command::Connect(args)) => connect_command(args),
        #[cfg(target_os = "macos")]
        Some(Command::Gui {
            identity_file,
            name,
        }) => gui::run_gui(gui::Options {
            identity_file,
            name,
        }),
    };
    ExitCode::from(exit_code(result))
}

/// The exit code for a command's result, printing the error if any.
fn exit_code(result: anyhow::Result<u8>) -> u8 {
    match result {
        Ok(code) => code,
        Err(e) => {
            println!("failed: {e:#}");
            exit::ERROR
        }
    }
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")
}

/// macOS: the window owns the main thread and the session runs on its
/// own (phase4-criteria R1); the session's output and exit codes are
/// unchanged.
#[cfg(target_os = "macos")]
fn connect_command(args: ConnectArgs) -> anyhow::Result<u8> {
    use window::Event;
    if args.no_window {
        let display = Display {
            show: None,
            on_counters: Box::new(|_| {}),
            on_client: Box::new(|_| {}),
            on_pause: Box::new(|_| {}),
            close: None,
        };
        return runtime().and_then(|rt| rt.block_on(run_connect(args, display)));
    }
    window::run(args.timing, move |proxy, close| {
        let show_proxy = proxy.clone();
        let counters_proxy = proxy.clone();
        let pause_proxy = proxy.clone();
        let client_proxy = proxy.clone();
        let display = Display {
            on_client: Box::new(move |c| {
                let _ = client_proxy.send_event(Event::Client(c));
            }),
            show: Some(Box::new(move |p| {
                let _ = show_proxy.send_event(Event::Picture(p));
            })),
            on_counters: Box::new(move |c| {
                let _ = counters_proxy.send_event(Event::Counters(c));
            }),
            on_pause: Box::new(move |p| {
                let _ = pause_proxy.send_event(Event::Pause(p));
            }),
            close: Some(close),
        };
        let code = exit_code(runtime().and_then(|rt| rt.block_on(run_connect(args, display))));
        let _ = proxy.send_event(Event::Ended(code));
    })
}

/// Other systems: no window or decoder yet (Phase 6.5).
#[cfg(not(target_os = "macos"))]
fn connect_command(args: ConnectArgs) -> anyhow::Result<u8> {
    let _ = (args.no_window, args.timing); // no window here either way
    let display = Display {
        show: decode::Show,
        on_counters: Box::new(|_| {}),
        on_client: Box::new(|_| {}),
        on_pause: Box::new(|_| {}),
        close: None,
    };
    runtime().and_then(|rt| rt.block_on(run_connect(args, display)))
}

/// Where decoded pictures go, and how the window asks to end the session.
struct Display {
    show: decode::Show,
    on_counters: Box<dyn FnOnce(Arc<decode::Counters>) + Send>,
    /// The connection, for the window's mouse and keyboard (step 3).
    on_client: Box<dyn FnOnce(remora_net::ViewerClient) + Send>,
    /// The stream paused (`Some`) or resumed (`None`), for the window.
    on_pause: Box<dyn Fn(Option<Pause>) + Send>,
    close: Option<tokio::sync::oneshot::Receiver<()>>,
}

/// A paused stream as the viewer shows it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pause {
    /// Why, for a person.
    pub(crate) why: &'static str,
    /// Display unavailable (D-29): when the host gives up, on this viewer's
    /// clock (counted from when the message arrived).
    pub(crate) deadline: Option<std::time::Instant>,
}

impl Pause {
    pub(crate) fn of(reason: remora_session::PauseReason) -> Self {
        let deadline = match reason {
            remora_session::PauseReason::DisplayUnavailable { remaining_ms } => Some(
                std::time::Instant::now()
                    + std::time::Duration::from_millis(u64::from(remaining_ms)),
            ),
            _ => None,
        };
        Self {
            why: pause_text(reason),
            deadline,
        }
    }

    /// What to show now: the countdown if the display is unavailable.
    pub(crate) fn text(&self) -> String {
        match self.deadline {
            Some(d) => remora_app::cli::display_unavailable_text(
                d.saturating_duration_since(std::time::Instant::now()),
            ),
            None => format!("Stream paused: {}.", self.why),
        }
    }
}

fn identity(file: Option<PathBuf>) -> anyhow::Result<()> {
    let path = match file {
        Some(p) => p,
        None => keystore::default_path(Role::Viewer)?,
    };
    let (keys, _) = keystore::load_or_create(&path)?;
    // F-UX2: on every run that loads the key file.
    eprintln!("{}", key_file_warning(&path));
    let public = keys.identity.public();
    println!("identity: {}", identity_hex(&public));
    println!("device: {}", short_code_of(&public));
    Ok(())
}

/// How long the viewer looks for a device on the network: an announcing
/// host answers within about 1 s, but one that has just started is silent
/// for its first few seconds while its name is checked (spike S-C1: 7 s).
const FIND_WAIT: std::time::Duration = std::time::Duration::from_secs(8);

/// Where and whom to connect to.
struct Target {
    host_id: DeviceId,
    /// Known only from a connection code (the network gives the ID).
    host_key: Option<IdentityPublic>,
    addr: std::net::SocketAddr,
    nonce: [u8; 16],
}

/// From the connection code, or (no code, `--device` given) by finding the
/// host on this network (phase4.7 step 5). `None` after printing why the
/// device asked for is not the one reached (A16).
fn resolve_target(args: &ConnectArgs) -> anyhow::Result<Option<Target>> {
    let want = match &args.device {
        Some(typed) => Some(
            ShortCode::parse(typed)
                .map_err(|e| anyhow!("--device: {e} - {}", misplaced(Looks::DeviceCode, typed)))?,
        ),
        None => None,
    };
    let Some(text) = &args.code else {
        let Some(want) = want else {
            return Err(anyhow!(
                "give the host's connection code, or --device to find it on this network"
            ));
        };
        println!("looking for device {want} on this network...");
        let found = remora_net::discovery::find(&want, FIND_WAIT).map_err(|e| anyhow!("{e}"))?;
        let Some((addrs, a)) = found else {
            return Err(anyhow!(
                "device {want} was not found on this network. Is its host running, on the same Wi-Fi, and free? A host serving another viewer does not announce itself until that session ends (up to 30 s after a viewer vanishes). Its connection code still works"
            ));
        };
        let ip = addrs
            .first()
            .copied()
            .ok_or_else(|| anyhow!("device {want} announced no address"))?;
        // `find` returns only an announcement whose full ID gives `want`;
        // the handshake then expects that full ID (A16).
        return Ok(Some(Target {
            host_id: a.id,
            host_key: None,
            addr: std::net::SocketAddr::new(ip, a.port),
            nonce: a.nonce,
        }));
    };
    // The code is checked before any network traffic (A07: expiry).
    let code = ConnectionCode::parse(text.trim(), unix_now()).map_err(|e| {
        anyhow!(
            "connection code: {e} - {}",
            misplaced(Looks::ConnectionCode, text)
        )
    })?;
    if code.kind != CodeKind::Offer {
        return Err(anyhow!("this is an answer code, not a host's offer code"));
    }
    let host_key = IdentityPublic::from_bytes(code.identity_key);
    let host_id = DeviceId::of(&host_key);
    let addr = code
        .candidates
        .first()
        .map(|c| c.addr)
        .ok_or_else(|| anyhow!("connection code has no address"))?;
    // A16: the user asked for a specific device; refuse a code for another
    // one before connecting at all.
    if let Some(want) = want
        && !want.matches(&host_id)
    {
        println!(
            "identity mismatch: this code is for device {}, not {} which you asked for - not connecting",
            host_id.short_code(),
            want
        );
        return Ok(None);
    }
    Ok(Some(Target {
        host_id,
        host_key: Some(host_key),
        addr,
        nonce: code.nonce,
    }))
}

async fn run_connect(args: ConnectArgs, display: Display) -> anyhow::Result<u8> {
    let timing = args.timing;
    let Some(target) = resolve_target(&args)? else {
        return Ok(exit::IDENTITY);
    };
    let Target {
        host_id,
        host_key,
        addr,
        nonce,
    } = target;

    let key_path = match &args.identity_file {
        Some(p) => p.clone(),
        None => keystore::default_path(Role::Viewer)?,
    };
    let saved_path = saved_path(&key_path);
    let saved = DeviceList::load(&saved_path)
        .with_context(|| format!("saved computers in {}", saved_path.display()))?;
    let use_saved = args.pin.is_none() && args.password.is_none();
    let saved_choice = if use_saved {
        saved_choice(&saved, host_id, host_key)
    } else {
        SavedChoice::NotSaved
    };
    let mode = match (&args.pin, saved_choice) {
        (None, SavedChoice::Changed { saved_key }) => {
            // C1 / A19: never re-save silently, never fall back to a password.
            println!(
                "this computer's identity changed: you saved {} but device {} now presents another key - not connecting. If it was reinstalled, 'remora-viewer forget' it and connect with its password again",
                short_code_of(&saved_key),
                host_id.short_code()
            );
            return Ok(exit::IDENTITY);
        }
        (None, SavedChoice::Saved { key }) => {
            println!("saved computer: connecting without a password (the host still approves)");
            ViewerMode::Trusted { pinned: key }
        }
        (Some(pin), _) => {
            let pinned = parse_identity(pin)
                .map_err(|e| anyhow!("--pin: {e} - {}", misplaced(Looks::IdentityKey, pin)))?;
            // A19: the pinned device now presents another key. Hard failure,
            // never a silent re-pin and never a fallback to a password.
            // (Found on the network, only the ID is known before the
            // handshake; the handshake then checks the key itself.)
            if host_key.map_or(DeviceId::of(&pinned) != host_id, |k| k != pinned) {
                println!(
                    "this device's identity changed: you trust {} but the code is for {} - not connecting",
                    short_code_of(&pinned),
                    host_id.short_code()
                );
                return Ok(exit::IDENTITY);
            }
            ViewerMode::Trusted { pinned }
        }
        (None, SavedChoice::NotSaved) => {
            let typed = match &args.password {
                Some(p) => p.clone(),
                None => ask_password()?,
            };
            let otp = Otp::parse(typed.trim())
                .map_err(|e| anyhow!("password: {e} - {}", misplaced(Looks::Password, &typed)))?;
            // Bind the session to the key in the code: the host's cert must
            // have this device ID (80 bits), so a substituted key fails.
            ViewerMode::Password {
                otp,
                expect: Some(host_id),
            }
        }
    };

    let trusted_saved = matches!(mode, ViewerMode::Trusted { .. }) && args.pin.is_none();
    let path = key_path;
    let (keys, _) = keystore::load_or_create(&path)?;
    // F-UX2: on every run that loads the key file.
    eprintln!("{}", key_file_warning(&path));
    let cert = keys
        .cert(&args.name, unix_now())
        .context("--name is at most 64 bytes")?;
    let config = ViewerConfig {
        identity: Arc::new(Identity {
            noise: keys.noise,
            cert,
        }),
        mode,
    };
    println!(
        "connecting to {addr} (host device {})",
        host_id.short_code()
    );
    let (client, mut events) = connect(addr, config, nonce).await?;
    let mut decoder =
        decode::Decoder::start(client.clone(), display.show).context("decoder thread")?;
    (display.on_counters)(decoder.counters());
    (display.on_client)(client.clone());
    let mut saved = saved;
    let save = args.save;
    let mut on_active = |host: &IdentityCert| {
        if !save {
            return;
        }
        let device = Device {
            key: *host.identity(),
            name: host.device_name().chars().take(MAX_NAME).collect(),
            addr: Some(addr),
        };
        match saved
            .remember(device)
            .and_then(|()| saved.save(&saved_path))
        {
            Ok(()) => println!(
                "saved {} (device {}): next time 'remora-viewer connect --device \"{}\"' needs no password - if the person at the host also types 'remember' there. The host still approves every connection",
                display_name(host.device_name()),
                short_code_of(host.identity()),
                short_code_of(host.identity())
            ),
            Err(e) => println!("could not save this computer: {e}"),
        }
    };
    let code = session_loop(
        &client,
        &mut events,
        &mut decoder,
        display.close,
        &*display.on_pause,
        Flags {
            timing,
            audio: !args.no_audio,
        },
        &mut on_active,
    )
    .await;
    if code == exit::AUTH && trusted_saved {
        println!(
            "the host does not (or no longer) know this viewer: connect once with its password and ask the person there to type 'remember <n>' - or 'remora-viewer forget' this computer"
        );
    }
    let t = decoder.finish();
    println!(
        "video: {} frames decoded, {} refused, {} waiting for a keyframe, {} failed, {} dropped",
        t.decoded, t.refused, t.waiting, t.failed, t.dropped
    );
    drop(client);
    Ok(code)
}

/// `connect` switches the session loop reads.
#[derive(Debug, Clone, Copy)]
struct Flags {
    /// `--timing`: the once-a-second `media:` line.
    timing: bool,
    /// Not `--no-audio`: play the host's sound once active.
    audio: bool,
}

/// Shows the session's events until it ends; returns the exit code.
async fn session_loop(
    client: &remora_net::ViewerClient,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<ViewerEvent>,
    decoder: &mut decode::Decoder,
    mut close: Option<tokio::sync::oneshot::Receiver<()>>,
    on_pause: &(dyn Fn(Option<Pause>) + Send),
    Flags { timing, audio }: Flags,
    on_active: &mut dyn FnMut(&IdentityCert),
) -> u8 {
    let mut outcome: Option<u8> = None;
    // Phase 4.8: opened when the session becomes active; dropped (its
    // `sound:` counts line printed) when this returns.
    let mut sound: Option<sound::Sound> = None;
    let mut interrupted = false;
    // The host's identity as the handshake verified it (for --save).
    let mut verified: Option<IdentityCert> = None;
    let mut pause: Option<Pause> = None;
    // `--timing`: the media counts once a second, so a measurement can
    // check its own window (P3: 0 authentication failures, 0 frames
    // given up). Counts only, never content (INV9).
    let mut media_line = tokio::time::interval(std::time::Duration::from_secs(1));
    // D-29: while the host waits for its unavailable display, say how long is left.
    let mut wait_line = tokio::time::interval(remora_app::cli::WAIT_LINE_EVERY);
    wait_line.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let ev = tokio::select! {
            _ = wait_line.tick() => {
                if let Some(p) = pause.filter(|p| p.deadline.is_some()) {
                    println!("{}", p.text());
                }
                continue;
            }
            _ = media_line.tick(), if timing => {
                if let Some(m) = client.media_stats().await {
                    eprintln!(
                        "media: opened={} auth_failed={} replayed={} too_old={} unknown_key={} bad_header={} bad_fragments={} late_fragments={} frames={} frames_dropped={}",
                        m.opened, m.auth_failed, m.replayed, m.too_old, m.unknown_key,
                        m.bad_header, m.bad_fragments, m.late_fragments, m.frames, m.frames_dropped
                    );
                }
                continue;
            }
            ev = events.recv() => match ev {
                Some(ev) => ev,
                None => break,
            },
            // Ctrl-C: say goodbye, so the host ends the session at once
            // (and announces itself again) instead of after 30 s of
            // silence (owner's laptop, 2026-11-02). A second Ctrl-C quits
            // at once (tokio now owns the signal, so it would not by itself).
            _ = tokio::signal::ctrl_c() => {
                if interrupted {
                    std::process::exit(130);
                }
                interrupted = true;
                println!("ending the session...");
                client.disconnect();
                continue;
            }
            // The window was closed: end the session the normal way and
            // keep reading until the connection reports how it ended.
            _ = async { if let Some(c) = close.as_mut() { let _ = c.await; } }, if close.is_some() => {
                close = None;
                client.disconnect();
                continue;
            }
        };
        match ev {
            ViewerEvent::ShowSas { sas, host } => {
                verified = Some(host.clone());
                println!(
                    "safety code: {} - compare it with the host's screen (host {:?}, device {})",
                    format_sas(sas),
                    host.device_name(),
                    short_code_of(host.identity())
                );
                // F-UX4: the decision is made on the host, not here.
                println!(
                    "waiting for the person at the host to accept or deny (nothing to type here)"
                );
            }
            ViewerEvent::Active => {
                println!("SESSION ACTIVE");
                if audio && sound.is_none() {
                    sound = Some(sound::Sound::start(timing));
                }
                if let Some(host) = &verified {
                    on_active(host);
                }
            }
            ViewerEvent::StreamPaused(reason) => {
                let p = Pause::of(reason);
                match p.deadline {
                    Some(_) => println!("stream paused - {} The session stays open", p.text()),
                    None => println!("stream paused ({}) - the session stays open", p.why),
                }
                pause = Some(p);
                on_pause(pause);
                wait_line.reset();
            }
            ViewerEvent::StreamResumed => {
                println!("stream resumed");
                pause = None;
                on_pause(None);
            }
            ViewerEvent::Audio(p) => {
                if let Some(s) = &sound {
                    s.offer(p);
                }
            }
            ViewerEvent::Video(frame) => decoder.offer(frame),
            ViewerEvent::Failed { reason, .. } => outcome = Some(report_failure(&reason)),
            ViewerEvent::Closed { local, remote } => {
                return outcome.unwrap_or_else(|| report_close(local, remote));
            }
            ViewerEvent::Lost => {
                return outcome.unwrap_or_else(|| {
                    println!(
                        "failed: connection lost - no reply from the host for {} s (network down, or the host stopped)",
                        IDLE_TIMEOUT.as_secs()
                    );
                    exit::ERROR
                });
            }
        }
    }
    outcome.unwrap_or(exit::ERROR)
}

/// What a saved-computers list says about the host about to be reached
/// (phase4.7-criteria C1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SavedChoice {
    /// Not saved: the password as usual.
    NotSaved,
    /// Saved with this key: trusted mode, pinned to it.
    Saved { key: IdentityPublic },
    /// Saved, but the host now presents another identity: hard failure.
    Changed { saved_key: IdentityPublic },
}

/// C1: a saved computer is reached only in trusted mode against the saved
/// key. Matched by its device code; if the ID (or, from a connection code,
/// the key) it presents is not the saved one, that is an identity change.
fn saved_choice(
    saved: &DeviceList,
    host_id: DeviceId,
    host_key: Option<IdentityPublic>,
) -> SavedChoice {
    let Some(d) = saved.find_code(&host_id.short_code()) else {
        return SavedChoice::NotSaved;
    };
    let same = DeviceId::of(&d.key) == host_id && host_key.is_none_or(|k| k == d.key);
    if same {
        SavedChoice::Saved { key: d.key }
    } else {
        SavedChoice::Changed { saved_key: d.key }
    }
}

/// The saved-computers file, next to the viewer's key file (phase4.7 Q4).
fn saved_path(key_path: &std::path::Path) -> PathBuf {
    key_path.with_file_name("saved-devices")
}

fn key_path(file: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    Ok(match file {
        Some(p) => p,
        None => keystore::default_path(Role::Viewer)?,
    })
}

/// `remora-viewer saved` (names escaped: untrusted text, H6/C8).
fn list_saved(file: Option<PathBuf>) -> anyhow::Result<()> {
    let list = DeviceList::load(&saved_path(&key_path(file)?))?;
    for line in saved_lines(&list) {
        println!("{line}");
    }
    Ok(())
}

/// What `saved` prints: one line per computer, its untrusted name escaped
/// (C8, H6).
fn saved_lines(list: &DeviceList) -> Vec<String> {
    if list.is_empty() {
        return vec!["no saved computers (connect with --save to save one)".into()];
    }
    list.iter()
        .map(|d| {
            let addr = d.addr.map_or_else(|| "-".to_owned(), |a| a.to_string());
            format!(
                "saved: {} (device {}, last at {addr})",
                display_name(&d.name),
                d.code()
            )
        })
        .collect()
}

/// `remora-viewer forget <code>`.
fn forget_saved(code: &str, file: Option<PathBuf>) -> anyhow::Result<()> {
    let code = ShortCode::parse(code).map_err(|e| anyhow!("device code: {e}"))?;
    let path = saved_path(&key_path(file)?);
    let mut list = DeviceList::load(&path)?;
    let Some(key) = list.find_code(&code).map(|d| d.key) else {
        println!("no saved computer has device code {code} (see 'remora-viewer saved')");
        return Ok(());
    };
    list.forget(&key);
    list.save(&path)?;
    println!("forgot device {code}: connecting to it needs its password again");
    Ok(())
}

fn report_failure(reason: &FailReason) -> u8 {
    match reason {
        FailReason::Rejected => {
            println!("rejected by the host (a new attempt needs a fresh code and password)");
            exit::REJECTED
        }
        FailReason::IdentityMismatch => {
            println!("identity mismatch: the host is not the device in the code - not continuing");
            exit::IDENTITY
        }
        FailReason::IdentityChanged => {
            println!("this device's identity changed - not continuing");
            exit::IDENTITY
        }
        FailReason::AuthFailed(_) => {
            println!("failed: {reason}");
            exit::AUTH
        }
        other => {
            println!("failed: {other}");
            exit::ERROR
        }
    }
}

/// What a pause reason means, for a person.
fn pause_text(reason: remora_session::PauseReason) -> &'static str {
    match reason {
        remora_session::PauseReason::DisplayAsleep => "the host's display is asleep",
        remora_session::PauseReason::AccessLost => "the host's system took the screen away",
        remora_session::PauseReason::Other => "the host's screen capture was interrupted",
        remora_session::PauseReason::DisplayUnavailable { .. } => {
            "the host's display is unavailable (lid closed or disconnected)"
        }
    }
}

fn report_close(local: Option<CloseCode>, remote: Option<CloseCode>) -> u8 {
    match remote.or(local) {
        Some(CloseCode::Normal) => {
            println!("session ended");
            exit::OK
        }
        Some(CloseCode::Rejected) => {
            println!("rejected by the host (a new attempt needs a fresh code and password)");
            exit::REJECTED
        }
        Some(CloseCode::CaptureStopped) => {
            println!("failed: the host's screen capture stopped (it needs attention at the host)");
            exit::ERROR
        }
        Some(CloseCode::HostBusy) => {
            println!(
                "the host is busy: someone else is connected to it (try again when their session ends)"
            );
            exit::ERROR
        }
        Some(CloseCode::AuthFailed) => {
            println!("failed: authentication failed (wrong or used password, or not trusted)");
            exit::AUTH
        }
        other => {
            println!("failed: connection closed ({other:?})");
            exit::ERROR
        }
    }
}

fn ask_password() -> anyhow::Result<String> {
    use std::io::Write;
    print!("password: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line)
}

/// Logs to stderr (stdout carries the CLI's own output).
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// phase4.7-criteria C8: a saved computer's name is untrusted text (the
/// host chose it); `saved` must never print it raw.
#[cfg(test)]
mod c8_tests {
    use super::*;

    #[test]
    fn c8_saved_names_are_shown_escaped() {
        let mut list = DeviceList::new();
        let hostile = "Office\nsaved: Bank (device 0000 000 0000-0) \u{202e}evil";
        list.remember(Device {
            key: remora_crypto::identity::IdentityKeypair::generate(&mut rand_core::OsRng).public(),
            name: hostile.into(),
            addr: None,
        })
        .expect("add");
        let lines = saved_lines(&list);
        assert_eq!(lines.len(), 1);
        assert!(
            !lines[0].contains('\n'),
            "a newline in a name made a second line: {lines:?}"
        );
        assert!(!lines[0].contains('\u{202e}'), "bidi override shown raw");
        assert!(lines[0].contains(&display_name(hostile)));
    }
}

/// phase4.7-criteria C1: a saved computer only in trusted mode against
/// the saved key; anything else under its code is an identity change.
#[cfg(test)]
mod c1_tests {
    use rand_core::OsRng;
    use remora_crypto::identity::IdentityKeypair;

    use super::*;

    fn key() -> IdentityPublic {
        IdentityKeypair::generate(&mut OsRng).public()
    }

    #[test]
    fn c1_saved_computers_are_pinned_and_a_changed_identity_is_refused() {
        let (a, b) = (key(), key());
        let mut saved = DeviceList::new();
        saved
            .remember(Device {
                key: a,
                name: "Fedora laptop".into(),
                addr: None,
            })
            .expect("add");
        let id_a = DeviceId::of(&a);
        assert_eq!(
            saved_choice(&DeviceList::new(), id_a, None),
            SavedChoice::NotSaved
        );
        assert_eq!(
            saved_choice(&saved, DeviceId::of(&b), None),
            SavedChoice::NotSaved
        );
        // Found on the network (ID only) or from a code with the same key.
        assert_eq!(
            saved_choice(&saved, id_a, None),
            SavedChoice::Saved { key: a }
        );
        assert_eq!(
            saved_choice(&saved, id_a, Some(a)),
            SavedChoice::Saved { key: a }
        );
        // A code for the same device ID but another key.
        assert_eq!(
            saved_choice(&saved, id_a, Some(b)),
            SavedChoice::Changed { saved_key: a }
        );
        // Another ID with the same short code (the code uses its first 8
        // bytes of 10): announced on the network, not the saved computer.
        let mut bytes = *id_a.as_bytes();
        bytes[9] ^= 1;
        let impostor = DeviceId::from_bytes(bytes);
        assert_eq!(impostor.short_code(), id_a.short_code());
        assert_eq!(
            saved_choice(&saved, impostor, None),
            SavedChoice::Changed { saved_key: a }
        );
    }
}
