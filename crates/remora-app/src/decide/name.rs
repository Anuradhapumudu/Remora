//! H6: the escaping lives in `remora-proto` (MIT OR Apache-2.0, with the
//! other code that handles untrusted text, and fuzzed there:
//! `fuzz/fuzz_targets/display_name.rs`).

pub use remora_proto::display_text::{display_name, is_escaped, undo_display_name};
