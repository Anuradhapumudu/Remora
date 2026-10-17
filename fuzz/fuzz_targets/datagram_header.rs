//! Arbitrary bytes into the datagram header parser: no panic; a parsed header
//! re-encodes to exactly the bytes it came from.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remora_proto::datagram::DatagramHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok((h, body)) = DatagramHeader::parse(data) {
        assert_eq!(&h.encode()[..], &data[..16]);
        assert_eq!(body.len(), data.len() - 16);
    }
});
