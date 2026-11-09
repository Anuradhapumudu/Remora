//! The GUI's decisions as plain Rust (phase4.5-criteria §10): who may see
//! the screen (dialogs), what the indicator and windows show, and how the
//! viewer's verification works. No Slint types: the GUI code feeds events
//! and clicks in and does what comes back, so every rule here is tested
//! without a window and is in the mutation-testing gate.

pub mod dialog;
pub mod host;
pub mod name;
pub mod viewer;
