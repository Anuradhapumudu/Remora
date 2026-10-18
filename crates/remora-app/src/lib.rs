//! Remora application support shared by `remora-host` and `remora-viewer`
//! (GPL-3.0-or-later like the apps). Unlike the library crates it may do
//! file I/O.
//!
//! * [`keystore`] — the device's long-term keys in an owner-only file.
//!   **Development-stage measure:** the keys move to the OS keychain before
//!   v0.1 (roadmap "Known gaps").
//! * [`cli`] — formatting and parsing shared by the two command-line apps. Until then the file is created with
//!   permissions 0600 on Unix and is refused if anyone else can read it.

#![forbid(unsafe_code)]

pub mod cli;
pub mod keystore;
