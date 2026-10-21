//! Remora viewer: views and controls a remote Remora host.
//!
//! Phase 3: `connect` runs the authenticated handshake against a host's
//! connection code on loopback and shows the safety code. Phase 4: it
//! decodes the video it receives (step 5); the window comes in step 6.
//!
//! Output lines (stable prefixes; the end-to-end tests read them):
//! `safety code:`, `SESSION ACTIVE`, `rejected by the host`, `identity
//! mismatch: ...`, `this device's identity changed ...`, `failed: ...`,
//! `session ended`. Exit codes: see [`remora_app::cli::exit`].

#![forbid(unsafe_code)]

mod decode;
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
use remora_app::keystore::{self, Role};
use remora_crypto::identity::{DeviceId, IdentityPublic, ShortCode};
use remora_crypto::secret::Otp;
use remora_net::{IDLE_TIMEOUT, ViewerEvent, connect};
use remora_proto::code::{CodeKind, ConnectionCode};
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
    code: String,
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
    /// Decode the video but open no window (tests and measurements); the
    /// decoder's counts are printed when the session ends.
    #[arg(long)]
    no_window: bool,
}

fn main() -> ExitCode {
    // F-UX6: a device code typed without quotes is rejoined first.
    let cli = Cli::parse_from(join_device_words(std::env::args_os()));
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
        Some(Command::Connect(args)) => connect_command(args),
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
    window::run(move |proxy, close| {
        let show_proxy = proxy.clone();
        let counters_proxy = proxy.clone();
        let display = Display {
            show: Box::new(move |p| {
                let _ = show_proxy.send_event(Event::Picture(p));
            }),
            on_counters: Box::new(move |c| {
                let _ = counters_proxy.send_event(Event::Counters(c));
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
    let display = Display {
        show: decode::Show,
        on_counters: Box::new(|_| {}),
        close: None,
    };
    runtime().and_then(|rt| rt.block_on(run_connect(args, display)))
}

/// Where decoded pictures go, and how the window asks to end the session.
struct Display {
    show: decode::Show,
    on_counters: Box<dyn FnOnce(Arc<decode::Counters>) + Send>,
    close: Option<tokio::sync::oneshot::Receiver<()>>,
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

async fn run_connect(args: ConnectArgs, display: Display) -> anyhow::Result<u8> {
    let _ = args.no_window; // step 7 GREEN
    // The code is checked before any network traffic (A07: expiry).
    let code = ConnectionCode::parse(args.code.trim(), unix_now()).map_err(|e| {
        anyhow!(
            "connection code: {e} - {}",
            misplaced(Looks::ConnectionCode, &args.code)
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
    if let Some(typed) = &args.device {
        let want = ShortCode::parse(typed)
            .map_err(|e| anyhow!("--device: {e} - {}", misplaced(Looks::DeviceCode, typed)))?;
        if !want.matches(&host_id) {
            println!(
                "identity mismatch: this code is for device {}, not {} which you asked for - not connecting",
                host_id.short_code(),
                want
            );
            return Ok(exit::IDENTITY);
        }
    }

    let mode = match &args.pin {
        Some(pin) => {
            let pinned = parse_identity(pin)
                .map_err(|e| anyhow!("--pin: {e} - {}", misplaced(Looks::IdentityKey, pin)))?;
            // A19: the pinned device now presents another key. Hard failure,
            // never a silent re-pin and never a fallback to a password.
            if pinned != host_key {
                println!(
                    "this device's identity changed: you trust {} but the code is for {} - not connecting",
                    short_code_of(&pinned),
                    host_id.short_code()
                );
                return Ok(exit::IDENTITY);
            }
            ViewerMode::Trusted { pinned }
        }
        None => {
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

    let path = match args.identity_file {
        Some(p) => p,
        None => keystore::default_path(Role::Viewer)?,
    };
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
    let (client, mut events) = connect(addr, config, code.nonce).await?;
    let mut decoder =
        decode::Decoder::start(client.clone(), display.show).context("decoder thread")?;
    (display.on_counters)(decoder.counters());
    let code = session_loop(&client, &mut events, &mut decoder, display.close).await;
    let (decoded, refused, failed, dropped) = decoder.finish();
    println!(
        "video: {decoded} frames decoded, {refused} refused, {failed} failed, {dropped} dropped"
    );
    drop(client);
    Ok(code)
}

/// Shows the session's events until it ends; returns the exit code.
async fn session_loop(
    client: &remora_net::ViewerClient,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<ViewerEvent>,
    decoder: &mut decode::Decoder,
    mut close: Option<tokio::sync::oneshot::Receiver<()>>,
) -> u8 {
    let mut outcome: Option<u8> = None;
    loop {
        let ev = tokio::select! {
            ev = events.recv() => match ev {
                Some(ev) => ev,
                None => break,
            },
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
            ViewerEvent::Active => println!("SESSION ACTIVE"),
            ViewerEvent::StreamPaused(reason) => {
                println!(
                    "stream paused ({}) - the session stays open",
                    pause_text(reason)
                )
            }
            ViewerEvent::StreamResumed => println!("stream resumed"),
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
        remora_session::PauseReason::DisplayUnavailable => {
            "the host's display is asleep, closed or unavailable"
        }
        remora_session::PauseReason::AccessLost => "the host's system took the screen away",
        remora_session::PauseReason::Other => "the host's screen capture was interrupted",
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
