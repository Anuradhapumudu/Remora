//! Remora host: shares this computer's screen with an approved viewer.
//!
//! Phase 3: `serve` runs an authenticated, approval-gated session over QUIC
//! on loopback (no screen yet); plus the Phase 2 developer tools.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[cfg(target_os = "macos")]
mod bench;
mod serve;
#[cfg(target_os = "macos")]
mod stream;
// Used by the macOS benchmark; pure Rust, so their tests run on every platform.
#[cfg(any(target_os = "macos", test))]
mod stats;
#[cfg(any(target_os = "macos", test))]
mod sysmon;

#[derive(Parser)]
#[command(version, about = "Remora host (pre-alpha)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Phase 3: accept authenticated, host-approved sessions on loopback.
    Serve(serve::ServeArgs),
    /// Print this host's identity key and device code (created if needed).
    Identity {
        /// Key file (default: the per-user config directory).
        #[arg(long)]
        identity_file: Option<std::path::PathBuf>,
    },
    /// Phase 2: capture the screen, hardware-encode to .h264, print measured stats.
    #[cfg(target_os = "macos")]
    BenchCapture(bench::BenchArgs),
    /// List capturable displays and their IDs.
    #[cfg(target_os = "macos")]
    ListDisplays,
    /// Phase 4 T2: print capture events (interrupted / resumed) with times.
    #[cfg(target_os = "macos")]
    WatchCapture {
        /// How long to watch.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
    /// Phase 2: report encoder capabilities (4:4:4, LTR, intra-refresh) as evidence.
    #[cfg(target_os = "macos")]
    ProbeEncoder,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    let result: anyhow::Result<()> = match cli.command {
        None => {
            println!(
                "{} {} (pre-alpha: no remote desktop yet; try --help for developer tools)",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Some(Command::Serve(args)) => serve::run(args),
        Some(Command::Identity { identity_file }) => serve::identity(identity_file),
        #[cfg(target_os = "macos")]
        Some(Command::BenchCapture(args)) => bench::run(args),
        #[cfg(target_os = "macos")]
        Some(Command::ProbeEncoder) => bench::probe(),
        #[cfg(target_os = "macos")]
        Some(Command::ListDisplays) => bench::list_displays(),
        #[cfg(target_os = "macos")]
        Some(Command::WatchCapture { seconds }) => bench::watch_capture(seconds),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Logs to stderr (stdout carries the CLI's own output). `RUST_LOG`
/// controls the level; the default shows warnings, e.g. one
/// `handshake_failed` per failed attempt (never a secret).
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
