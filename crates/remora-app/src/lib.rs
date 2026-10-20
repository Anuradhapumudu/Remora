//! Remora application support shared by `remora-host` and `remora-viewer`
//! (GPL-3.0-or-later like the apps). Unlike the library crates it may do
//! file I/O.
//!
//! * [`keystore`] — the device's long-term keys in an owner-only file
//!   (0600 on Unix, refused if anyone else can read it). **Development-stage
//!   measure:** the keys move to the OS keychain before v0.1 (roadmap D-5);
//!   until then both apps print [`cli::key_file_warning`] on every run.
//! * [`cli`] — formatting and parsing shared by the two command-line apps.
//! * [`prompts`] — short prompt numbers and the commands typed at the host.

#![forbid(unsafe_code)]

pub mod cli;
pub mod keystore;
pub mod prompts;
