//! Remora host: shares this computer's screen with an approved viewer.
//!
//! Pre-alpha: currently only developer tools (`bench-capture`, `probe-encoder`).

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[cfg(target_os = "macos")]
mod bench;
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
    /// Phase 2: capture the screen, hardware-encode to .h264, print measured stats.
    #[cfg(target_os = "macos")]
    BenchCapture(bench::BenchArgs),
    /// List capturable displays and their IDs.
    #[cfg(target_os = "macos")]
    ListDisplays,
    /// Phase 2: report encoder capabilities (4:4:4, LTR, intra-refresh) as evidence.
    #[cfg(target_os = "macos")]
    ProbeEncoder,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: anyhow::Result<()> = match cli.command {
        None => {
            println!(
                "{} {} (pre-alpha: no remote desktop yet; try --help for developer tools)",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        #[cfg(target_os = "macos")]
        Some(Command::BenchCapture(args)) => bench::run(args),
        #[cfg(target_os = "macos")]
        Some(Command::ProbeEncoder) => bench::probe(),
        #[cfg(target_os = "macos")]
        Some(Command::ListDisplays) => bench::list_displays(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
