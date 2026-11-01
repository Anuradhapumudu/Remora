//! H6 (phase4.5-criteria §4): any untrusted name → display_name must never
//! panic, must leave no character that could move, hide or reorder text,
//! and must lose nothing (undo gives the name back), so two different names
//! never look the same.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_proto::display_text::{display_name, is_escaped, undo_display_name};

fuzz_target!(|data: &[u8]| {
    let Ok(name) = std::str::from_utf8(data) else { return };
    let shown = display_name(name);
    assert!(!shown.chars().any(is_escaped), "{shown:?}");
    assert_eq!(undo_display_name(&shown).as_deref(), Some(name));
});
