//! Any text → ConnectionCode::parse must return, never panic; a successful
//! parse must re-encode to a code that parses to the same value.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_proto::code::ConnectionCode;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let now = 1_800_000_000;
    if let Ok(code) = ConnectionCode::parse(text, now) {
        assert_eq!(ConnectionCode::parse(&code.encode(), now), Ok(code));
    }
});
