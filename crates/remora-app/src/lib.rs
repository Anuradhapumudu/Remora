//! Remora application support shared by `remora-host` and `remora-viewer`
//! (GPL-3.0-or-later like the apps). Unlike the library crates it may do
//! file I/O.
//!
//! * [`keystore`] — the device's long-term keys in an owner-only file
//!   (0600 on Unix, refused if anyone else can read it). **Development-stage
//!   measure:** the keys move to the OS keychain before v0.1 (roadmap D-5);
//!   until then both apps print [`cli::key_file_warning`] on every run.
//! * [`cli`] — formatting and parsing shared by the two command-line apps.
//! * [`clock`] — the monotonic clock both apps stamp latency with (P0).
//! * [`prompts`] — short prompt numbers and the commands typed at the host.
//! * [`devices`] — remembered devices: the viewer's saved computers and
//!   the host's known viewers (phase4.7-criteria C6).
//! * [`token_file`] — the desktop portal's saved permission (Linux), in an
//!   owner-only file.
//! * [`decide`] — the GUI's decisions (dialogs, indicator, viewer
//!   verification) without any GUI types (phase4.5-criteria §10).

#![forbid(unsafe_code)]

pub mod cli;
pub mod clock;
pub mod decide;
pub mod devices;
pub mod keystore;
pub mod prompts;
mod sys;
pub mod token_file;
