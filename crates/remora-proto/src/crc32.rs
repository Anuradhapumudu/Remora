//! CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) — used ONLY to catch typos
//! in pasted connection codes. It is not a security check.

/// CRC-32 of `data`.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let _ = data;
    todo!("phase 3 step 2: implement after the tests")
}

#[cfg(test)]
mod tests {
    use super::crc32;

    #[test]
    fn standard_check_values() {
        // The CRC-32/ISO-HDLC "check" value from the CRC catalogue.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    }
}
