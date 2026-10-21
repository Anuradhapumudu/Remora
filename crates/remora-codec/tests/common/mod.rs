//! Builds H.264 parameter sets bit by bit (ITU-T H.264 §7.3.2.1.1 and
//! §7.3.2.2), so tests can declare any size or feature they want.
#![allow(dead_code)] // each test file uses part of it

#[cfg(target_os = "macos")]
pub(crate) mod vt;

/// MSB-first bit writer with Exp-Golomb codes.
#[derive(Default)]
pub(crate) struct BitWriter {
    bytes: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    pub(crate) fn u(&mut self, n: u32, v: u64) -> &mut Self {
        for i in (0..n).rev() {
            if self.bits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if (v >> i) & 1 == 1 {
                let last = self.bytes.len() - 1;
                self.bytes[last] |= 0x80 >> (self.bits % 8);
            }
            self.bits += 1;
        }
        self
    }

    pub(crate) fn ue(&mut self, v: u64) -> &mut Self {
        let x = v + 1;
        let len = 64 - x.leading_zeros();
        self.u(len - 1, 0).u(len, x)
    }

    pub(crate) fn se(&mut self, v: i64) -> &mut Self {
        let k = if v > 0 { 2 * v - 1 } else { -2 * v };
        self.ue(k as u64)
    }

    /// `rbsp_trailing_bits`, then emulation prevention, behind `header`.
    pub(crate) fn nal(mut self, header: u8) -> Vec<u8> {
        self.u(1, 1);
        let mut out = vec![header];
        let mut zeros = 0;
        for &b in &self.bytes {
            if zeros >= 2 && b <= 3 {
                out.push(3);
                zeros = 0;
            }
            zeros = if b == 0 { zeros + 1 } else { 0 };
            out.push(b);
        }
        out
    }
}

/// An SPS with every field the parser reads; defaults = 1920 × 1088 coded,
/// cropped to 1080, Baseline, as VideoToolbox's low-latency encoder makes.
#[derive(Clone)]
pub(crate) struct Sps {
    pub(crate) profile_idc: u8,
    pub(crate) level_idc: u8,
    pub(crate) sps_id: u64,
    pub(crate) chroma_format_idc: u64,
    pub(crate) bit_depth_minus8: u64,
    pub(crate) scaling_lists: bool,
    pub(crate) poc_type: u64,
    pub(crate) poc_cycle: Vec<i64>,
    pub(crate) width_mbs: u64,
    pub(crate) height_map_units: u64,
    pub(crate) frame_mbs_only: bool,
    /// left, right, top, bottom (in crop units).
    pub(crate) crop: Option<(u64, u64, u64, u64)>,
}

impl Default for Sps {
    fn default() -> Self {
        Self {
            profile_idc: 66,
            level_idc: 40,
            sps_id: 0,
            chroma_format_idc: 1,
            bit_depth_minus8: 0,
            scaling_lists: false,
            poc_type: 2,
            poc_cycle: Vec::new(),
            width_mbs: 120,
            height_map_units: 68,
            frame_mbs_only: true,
            crop: Some((0, 0, 0, 4)),
        }
    }
}

impl Sps {
    pub(crate) fn sized(width_mbs: u64, height_map_units: u64) -> Self {
        Self {
            width_mbs,
            height_map_units,
            crop: None,
            ..Self::default()
        }
    }

    pub(crate) fn high(mut self) -> Self {
        self.profile_idc = 100;
        self
    }

    pub(crate) fn nal(&self) -> Vec<u8> {
        let mut w = BitWriter::default();
        w.u(8, u64::from(self.profile_idc))
            .u(8, 0)
            .u(8, u64::from(self.level_idc))
            .ue(self.sps_id);
        if matches!(
            self.profile_idc,
            100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128
        ) {
            w.ue(self.chroma_format_idc);
            if self.chroma_format_idc == 3 {
                w.u(1, 0); // separate_colour_plane_flag
            }
            w.ue(self.bit_depth_minus8)
                .ue(self.bit_depth_minus8)
                .u(1, 0);
            w.u(1, u64::from(self.scaling_lists));
            if self.scaling_lists {
                let lists = if self.chroma_format_idc == 3 { 12 } else { 8 };
                for i in 0..lists {
                    w.u(1, 1); // list present
                    let size = if i < 6 { 16 } else { 64 };
                    // Deltas 0 keep nextScale at 8: every entry is coded.
                    for _ in 0..size {
                        w.se(0);
                    }
                }
            }
        }
        w.ue(0); // log2_max_frame_num_minus4
        w.ue(self.poc_type);
        match self.poc_type {
            0 => {
                w.ue(0);
            }
            1 => {
                w.u(1, 0).se(0).se(0).ue(self.poc_cycle.len() as u64);
                for &o in &self.poc_cycle {
                    w.se(o);
                }
            }
            _ => {}
        }
        w.ue(1).u(1, 0); // max_num_ref_frames, gaps
        w.ue(self.width_mbs - 1).ue(self.height_map_units - 1);
        w.u(1, u64::from(self.frame_mbs_only));
        if !self.frame_mbs_only {
            w.u(1, 0);
        }
        w.u(1, 1); // direct_8x8_inference
        match self.crop {
            Some((l, r, t, b)) => {
                w.u(1, 1).ue(l).ue(r).ue(t).ue(b);
            }
            None => {
                w.u(1, 0);
            }
        }
        w.u(1, 0); // no VUI
        w.nal(0x67)
    }
}

/// A PPS naming `sps_id`.
pub(crate) fn pps(pps_id: u64, sps_id: u64) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.ue(pps_id).ue(sps_id).u(1, 0).u(1, 0).ue(0).ue(0).ue(0);
    w.u(1, 0).u(2, 0).se(0).se(0).se(0).u(1, 1).u(1, 0).u(1, 0);
    w.nal(0x68)
}

/// Joins NAL units into an Annex B frame with 4-byte start codes.
pub(crate) fn annexb(nals: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for n in nals {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(n);
    }
    out
}

/// A stand-in IDR slice (header 0x65) and P slice (0x41).
pub(crate) const IDR: &[u8] = &[0x65, 0x88, 0x84, 0x21, 0xA0];
pub(crate) const SLICE: &[u8] = &[0x41, 0x9A, 0x02, 0x04];

/// A keyframe with the default SPS.
pub(crate) fn keyframe(sps: &Sps) -> Vec<u8> {
    annexb(&[&sps.nal(), &pps(0, sps.sps_id), IDR])
}
