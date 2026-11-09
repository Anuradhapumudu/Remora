//! phase4.7-criteria C6: arbitrary bytes as a saved-devices / known-viewers
//! file. No panic, and whatever parses stays within the limits and
//! renders back to text that parses to the same list.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_app::devices::{DeviceList, MAX_DEVICES, MAX_NAME};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(list) = DeviceList::parse(text) {
        assert!(list.len() <= MAX_DEVICES);
        assert!(list.iter().all(|d| d.name.len() <= MAX_NAME));
        let again = DeviceList::parse(&list.render()).expect("our own text parses");
        assert_eq!(again, list, "render/parse round trip");
    }
});
