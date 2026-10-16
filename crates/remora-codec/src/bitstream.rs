//! Pure H.264/HEVC byte-stream helpers (no FFI): AVCC → Annex B conversion and
//! profile inspection. These parse encoder output, so they never panic and
//! reject malformed input with an error.

use crate::CodecError;

/// Annex B start code prepended to every NAL unit in our output.
pub const START_CODE: [u8; 4] = [0, 0, 0, 1];

/// Converts length-prefixed NAL units (AVCC/HVCC, as produced by VideoToolbox)
/// into an Annex B byte stream, appending to `out`.
///
/// `length_size` is the size of each big-endian length prefix (1, 2 or 4).
/// Zero-length NAL units are skipped.
pub fn length_prefixed_to_annexb(
    src: &[u8],
    length_size: usize,
    out: &mut Vec<u8>,
) -> Result<(), CodecError> {
    if !matches!(length_size, 1 | 2 | 4) {
        return Err(CodecError::Bitstream("invalid NAL length size"));
    }
    // A 4-byte prefix becomes a 4-byte start code, so this is usually exact.
    out.reserve(src.len() + if length_size < 4 { src.len() / 2 } else { 0 });
    let mut rest = src;
    while !rest.is_empty() {
        let Some((prefix, tail)) = rest.split_at_checked(length_size) else {
            return Err(CodecError::Bitstream("truncated NAL length prefix"));
        };
        let len = prefix
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        let Some((nal, tail)) = tail.split_at_checked(len) else {
            return Err(CodecError::Bitstream("NAL length exceeds buffer"));
        };
        if !nal.is_empty() {
            out.extend_from_slice(&START_CODE);
            out.extend_from_slice(nal);
        }
        rest = tail;
    }
    Ok(())
}

/// Profile and chroma format read from a sequence parameter set (SPS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileInfo {
    /// H.264 `profile_idc` (66 Baseline, 100 High, 244 High 4:4:4 Predictive, …) or
    /// HEVC `general_profile_idc` (1 Main, 2 Main 10, 4 Range Extensions).
    pub profile_idc: u8,
    /// `chroma_format_idc`: 0 monochrome, 1 = 4:2:0, 2 = 4:2:2, 3 = 4:4:4.
    /// `None` if the SPS was too short to reach the field.
    pub chroma_format_idc: Option<u32>,
}

impl ProfileInfo {
    /// True only if the stream itself declares 4:4:4 chroma.
    pub fn is_444(&self) -> bool {
        self.chroma_format_idc == Some(3)
    }
}

/// Removes emulation-prevention bytes (`00 00 03` → `00 00`) to get the raw payload.
fn unescape_rbsp(nal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal.len());
    let mut zeros = 0;
    for &b in nal {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out
}

/// Minimal MSB-first bit reader with Exp-Golomb support; every read is bounds-checked.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn bit(&mut self) -> Option<u32> {
        let byte = *self.data.get(self.pos / 8)?;
        let v = (byte >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Some(u32::from(v))
    }
    fn bits(&mut self, n: u32) -> Option<u32> {
        (0..n).try_fold(0u32, |acc, _| Some((acc << 1) | self.bit()?))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n)?;
        (self.pos <= self.data.len() * 8).then_some(())
    }
    /// Unsigned Exp-Golomb `ue(v)`; rejects codes longer than 31 bits.
    fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        Some((1u32 << zeros) - 1 + self.bits(zeros)?)
    }
}

/// Reads profile and chroma format from an H.264 SPS NAL unit (starting at the NAL header).
pub fn h264_sps_profile(sps: &[u8]) -> Option<ProfileInfo> {
    if sps.first()? & 0x1f != 7 {
        return None;
    }
    let rbsp = unescape_rbsp(&sps[1..]);
    let mut r = Bits {
        data: &rbsp,
        pos: 0,
    };
    let profile_idc = r.bits(8)? as u8;
    r.skip(16)?; // constraint flags + level_idc
    let chroma_format_idc = (|| {
        r.ue()?; // seq_parameter_set_id
        // Only these "high" profiles carry chroma_format_idc; all others are 4:2:0.
        if matches!(
            profile_idc,
            100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
        ) {
            r.ue()
        } else {
            Some(1)
        }
    })();
    Some(ProfileInfo {
        profile_idc,
        chroma_format_idc,
    })
}

/// Reads profile and chroma format from an HEVC SPS NAL unit (starting at the NAL header).
pub fn hevc_sps_profile(sps: &[u8]) -> Option<ProfileInfo> {
    if (sps.first()? >> 1) & 0x3f != 33 {
        return None;
    }
    let rbsp = unescape_rbsp(sps.get(2..)?);
    let mut r = Bits {
        data: &rbsp,
        pos: 0,
    };
    r.skip(4)?; // sps_video_parameter_set_id
    let max_sub_layers_minus1 = r.bits(3)?;
    r.skip(1)?; // temporal_id_nesting
    // profile_tier_level: general_profile_space(2) tier(1) profile_idc(5)
    r.skip(3)?;
    let profile_idc = r.bits(5)? as u8;
    let chroma_format_idc = (|| {
        r.skip(32 + 48 + 8)?; // compatibility flags, constraint flags, general_level_idc
        let mut profile_present = [false; 8];
        let mut level_present = [false; 8];
        for i in 0..max_sub_layers_minus1 as usize {
            profile_present[i] = r.bit()? == 1;
            level_present[i] = r.bit()? == 1;
        }
        if max_sub_layers_minus1 > 0 {
            r.skip(2 * (8 - max_sub_layers_minus1 as usize))?; // reserved_zero_2bits
        }
        for i in 0..max_sub_layers_minus1 as usize {
            if profile_present[i] {
                r.skip(88)?;
            }
            if level_present[i] {
                r.skip(8)?;
            }
        }
        r.ue()?; // sps_seq_parameter_set_id
        r.ue()
    })();
    Some(ProfileInfo {
        profile_idc,
        chroma_format_idc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_four_byte_prefixes() {
        let src = [0, 0, 0, 2, 0x65, 0xAA, 0, 0, 0, 1, 0x41];
        let mut out = Vec::new();
        length_prefixed_to_annexb(&src, 4, &mut out).unwrap();
        assert_eq!(out, [0, 0, 0, 1, 0x65, 0xAA, 0, 0, 0, 1, 0x41]);
    }

    #[test]
    fn converts_short_prefixes_and_skips_empty_nals() {
        let src = [0, 1, 0x67, 0, 0, 0, 2, 0x68, 0xCE];
        let mut out = Vec::new();
        length_prefixed_to_annexb(&src, 2, &mut out).unwrap();
        assert_eq!(out, [0, 0, 0, 1, 0x67, 0, 0, 0, 1, 0x68, 0xCE]);
    }

    #[test]
    fn rejects_malformed_input_without_panicking() {
        let mut out = Vec::new();
        assert!(length_prefixed_to_annexb(&[0, 0, 0, 9, 1], 4, &mut out).is_err());
        assert!(length_prefixed_to_annexb(&[0, 0], 4, &mut out).is_err());
        assert!(length_prefixed_to_annexb(&[1, 2, 3], 3, &mut out).is_err());
        assert!(length_prefixed_to_annexb(&[0xff; 64], 4, &mut out).is_err());
        assert!(length_prefixed_to_annexb(&[], 4, &mut out).is_ok());
    }

    #[test]
    fn exhaustive_short_inputs_never_panic() {
        // Every 0..=2-byte input with every length size: cheap fuzz-style coverage
        // (the cargo-fuzz target covers longer inputs).
        let mut out = Vec::new();
        for len in 0..=2usize {
            for v in 0..(1u32 << (8 * len)) {
                let bytes = v.to_be_bytes();
                let src = &bytes[4 - len..];
                for ls in [1, 2, 4] {
                    out.clear();
                    let _ = length_prefixed_to_annexb(src, ls, &mut out);
                }
            }
        }
    }

    #[test]
    fn reads_h264_profile_and_chroma() {
        // 0x67 SPS; profile 100 (High), constraints 0, level 40; ue(0)=1, ue(3)=00100 → 0b1001_0000.
        let high444 = [0x67, 100, 0x00, 0x28, 0x90];
        let p = h264_sps_profile(&high444).unwrap();
        assert_eq!(
            p,
            ProfileInfo {
                profile_idc: 100,
                chroma_format_idc: Some(3)
            }
        );
        assert!(p.is_444());
        // ue(1) = 010 after sps_id → 4:2:0: bits 1 010 → 0b1010_0000.
        let high420 = [0x67, 100, 0x00, 0x28, 0xA0];
        assert_eq!(
            h264_sps_profile(&high420).unwrap().chroma_format_idc,
            Some(1)
        );
        // Baseline has no chroma field: always 4:2:0.
        let base = [0x67, 66, 0xC0, 0x1F, 0x80];
        assert_eq!(h264_sps_profile(&base).unwrap().chroma_format_idc, Some(1));
        assert_eq!(h264_sps_profile(&[0x68, 66]), None); // PPS, not SPS
        assert_eq!(
            h264_sps_profile(&[0x67, 100, 0x00, 0x28]).map(|p| p.chroma_format_idc),
            Some(None)
        );
    }

    #[test]
    fn reads_hevc_profile_and_chroma() {
        // header 42 01; vps=0,max_sub_layers_minus1=0,nesting=1 → 0x01; PTL 12 bytes
        // (profile byte 0x04 = RExt, then 10 zero bytes, level 0x5d); ue(0) ue(3) → 0x90.
        let mut sps = vec![0x42, 0x01, 0x01, 0x04];
        sps.extend_from_slice(&[0; 10]);
        sps.extend_from_slice(&[0x5d, 0x90]);
        let p = hevc_sps_profile(&sps).unwrap();
        assert_eq!(
            p,
            ProfileInfo {
                profile_idc: 4,
                chroma_format_idc: Some(3)
            }
        );
        assert_eq!(hevc_sps_profile(&[0x40, 0x01, 0x01, 0x01]), None); // VPS
        assert_eq!(
            hevc_sps_profile(&sps[..6]).map(|p| p.chroma_format_idc),
            Some(None)
        );
    }

    #[test]
    fn removes_emulation_prevention_bytes() {
        assert_eq!(
            unescape_rbsp(&[0, 0, 3, 1, 0, 0, 3, 0, 0, 3]),
            [0, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(unescape_rbsp(&[0, 3, 0, 0, 3]), [0, 3, 0, 0]);
    }

    #[test]
    fn truncated_or_garbage_sps_never_panics() {
        for len in 0..24 {
            let junk = vec![0xffu8; len];
            let mut h = junk.clone();
            if let Some(b) = h.first_mut() {
                *b = 0x67;
            }
            let _ = h264_sps_profile(&h);
            let mut v = junk;
            if v.len() > 1 {
                v[0] = 0x42;
            }
            let _ = hevc_sps_profile(&v);
        }
    }
}
