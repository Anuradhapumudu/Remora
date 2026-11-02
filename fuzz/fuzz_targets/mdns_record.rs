//! phase4.7-criteria C4: arbitrary mDNS answers (instance name, TXT
//! entries, port) into the parser. No panic; whatever is accepted is a
//! consistent announcement: its instance name is its own ID's code.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_net::discovery::{instance_name, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Line 1: instance; line 2: port; then key=value lines.
    let mut lines = text.split('\n');
    let instance = lines.next().unwrap_or_default();
    let port = lines.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let props: Vec<(&str, &str)> = lines
        .map(|l| l.split_once('=').unwrap_or((l, "")))
        .collect();
    if let Ok(a) = parse(instance, &props, port) {
        assert_eq!(instance, instance_name(&a.id));
        assert_ne!(a.port, 0);
    }
});
