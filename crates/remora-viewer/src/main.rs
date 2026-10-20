//! Remora viewer: views and controls a remote Remora host.
//!
//! Phase 3: `connect` runs the authenticated handshake against a host's
//! connection code on loopback and shows the safety code; no screen yet.
//!
//! Output lines (stable prefixes; the end-to-end tests read them):
//! `safety code:`, `SESSION ACTIVE`, `rejected by the host`, `identity
//! mismatch: ...`, `this device's identity changed ...`, `failed: ...`,
//! `session ended`. Exit codes: see [`remora_app::cli::exit`].

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use remora_app::cli::{
    exit, format_sas, identity_hex, key_file_warning, parse_identity, short_code_of, unix_now,
};
use remora_app::keystore::{self, Role};
use remora_crypto::identity::{DeviceId, IdentityPublic, ShortCode};
use remora_crypto::secret::Otp;
use remora_net::{ViewerEvent, connect};
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
    /// The host's connection code (`remora1:...`).
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
    /// Trusted mode: the host's pinned identity key (64 hex digits).
    #[arg(long)]
    pin: Option<String>,
    /// The device code of the host you mean to reach; refuse any other.
    #[arg(long)]
    device: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
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
        Some(Command::Connect(args)) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("starting the async runtime")
            .and_then(|rt| rt.block_on(run_connect(args))),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            println!("failed: {e:#}");
            ExitCode::from(exit::ERROR)
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

async fn run_connect(args: ConnectArgs) -> anyhow::Result<u8> {
    // The code is checked before any network traffic (A07: expiry).
    let code = ConnectionCode::parse(args.code.trim(), unix_now()).context("connection code")?;
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
    if let Some(want) = &args.device {
        let want = ShortCode::parse(want).context("--device")?;
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
            let pinned = parse_identity(pin).context("--pin")?;
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
            let otp = Otp::parse(typed.trim()).context("password")?;
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
    let mut outcome: Option<u8> = None;
    while let Some(ev) = events.recv().await {
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
            ViewerEvent::Deliver(_) => {}
            ViewerEvent::Failed { reason, .. } => outcome = Some(report_failure(&reason)),
            ViewerEvent::Closed { local, remote } => {
                let code = outcome.unwrap_or_else(|| report_close(local, remote));
                drop(client);
                return Ok(code);
            }
        }
    }
    Ok(outcome.unwrap_or(exit::ERROR))
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
