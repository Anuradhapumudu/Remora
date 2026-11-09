//! B G R x pictures → YUV 4:2:0 (I420) for software encoders.
//!
//! BT.709, video range: the matrix the viewer's shader assumes
//! (`remora-viewer/src/render.rs`), so colours come out as they went in.
//! Integer arithmetic (8-bit fixed point), chroma = the average of each 2×2
//! block. Rows are split over several threads: at 1080p one thread takes
//! ~8 ms, eight ~1.5 ms on the owner's laptop (spike S-L1b).

/// I420 planes for a `width × height` picture (both even).
#[derive(Clone, PartialEq, Eq)]
pub struct I420 {
    /// Width in pixels (even).
    pub width: usize,
    /// Height in pixels (even).
    pub height: usize,
    /// Luma, `width × height`.
    pub y: Vec<u8>,
    /// Blue-difference chroma, `width/2 × height/2`.
    pub u: Vec<u8>,
    /// Red-difference chroma, `width/2 × height/2`.
    pub v: Vec<u8>,
}

impl std::fmt::Debug for I420 {
    // Never the pixels (INV9).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "I420({}x{})", self.width, self.height)
    }
}

/// BT.709 video-range luma of one pixel.
fn luma(r: i32, g: i32, b: i32) -> u8 {
    // 0.2126, 0.7152, 0.0722 scaled by 219/255 and 256: 47, 157, 16.
    (16 + ((47 * r + 157 * g + 16 * b + 128) >> 8)) as u8
}

/// BT.709 video-range chroma (U, V) of an average colour.
fn chroma(r: i32, g: i32, b: i32) -> (u8, u8) {
    // -0.1146, -0.3854, 0.5 scaled by 224/255 and 256: -25.8, -86.7, 112.4.
    // -86 (not -87) so the row sums to 0 and greys get U = 128 exactly;
    // the spike's -87 tinted every grey (U = 127), caught by the test below.
    let u = 128 + ((-26 * r - 86 * g + 112 * b + 128) >> 8);
    // 0.5, -0.4542, -0.0458 → 112.4, -102.1, -10.3 (sums to 0).
    let v = 128 + ((112 * r - 102 * g - 10 * b + 128) >> 8);
    (u.clamp(0, 255) as u8, v.clamp(0, 255) as u8)
}

/// Converts a B G R x picture of `width × height` pixels whose rows are
/// `stride` bytes apart. Odd sizes lose their last column / row (4:2:0
/// needs even sizes). `None` if `px` is too short for those numbers or the
/// picture is smaller than 2×2.
pub fn bgrx_to_i420(
    px: &[u8],
    stride: usize,
    width: usize,
    height: usize,
    threads: usize,
) -> Option<I420> {
    let (w, h) = (width & !1, height & !1);
    if w < 2 || h < 2 || stride < width.checked_mul(4)? {
        return None;
    }
    if px.len() < stride.checked_mul(height - 1)?.checked_add(width * 4)? {
        return None;
    }
    let mut out = I420 {
        width: w,
        height: h,
        y: vec![0; w * h],
        u: vec![0; w * h / 4],
        v: vec![0; w * h / 4],
    };
    let pairs = h / 2;
    let per = pairs.div_ceil(threads.clamp(1, 64));
    std::thread::scope(|s| {
        let ys = out.y.chunks_mut(w * 2 * per);
        let us = out.u.chunks_mut(w / 2 * per);
        let vs = out.v.chunks_mut(w / 2 * per);
        for (t, ((yc, uc), vc)) in ys.zip(us).zip(vs).enumerate() {
            let first = t * per;
            s.spawn(move || {
                for pr in 0..uc.len() / (w / 2) {
                    let r0 = (first + pr) * 2;
                    for x2 in 0..w / 2 {
                        let (mut rs, mut gs, mut bs) = (0i32, 0i32, 0i32);
                        for dy in 0..2 {
                            for dx in 0..2 {
                                let i = (r0 + dy) * stride + (x2 * 2 + dx) * 4;
                                let (b, g, r) =
                                    (i32::from(px[i]), i32::from(px[i + 1]), i32::from(px[i + 2]));
                                yc[(pr * 2 + dy) * w + x2 * 2 + dx] = luma(r, g, b);
                                rs += r;
                                gs += g;
                                bs += b;
                            }
                        }
                        let (u, v) = chroma(rs / 4, gs / 4, bs / 4);
                        uc[pr * (w / 2) + x2] = u;
                        vc[pr * (w / 2) + x2] = v;
                    }
                }
            });
        }
    });
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: usize, h: usize, bgr: [u8; 3]) -> Vec<u8> {
        (0..w * h)
            .flat_map(|_| [bgr[0], bgr[1], bgr[2], 0])
            .collect()
    }

    /// The exact BT.709 video-range formulas in floating point.
    fn reference(r: f64, g: f64, b: f64) -> (f64, f64, f64) {
        let (kr, kb) = (0.2126, 0.0722);
        let y = kr * r + (1.0 - kr - kb) * g + kb * b;
        let u = (b - y) / (2.0 * (1.0 - kb));
        let v = (r - y) / (2.0 * (1.0 - kr));
        (
            16.0 + 219.0 * y / 255.0,
            128.0 + 224.0 * u / 255.0,
            128.0 + 224.0 * v / 255.0,
        )
    }

    #[test]
    fn colours_match_bt709_video_range_within_one_step() {
        for bgr in [
            [0, 0, 0],
            [255, 255, 255],
            [0, 0, 255],
            [0, 255, 0],
            [255, 0, 0],
            [30, 140, 220],
        ] {
            let p = bgrx_to_i420(&solid(4, 2, bgr), 16, 4, 2, 1).expect("valid");
            let (y, u, v) = reference(f64::from(bgr[2]), f64::from(bgr[1]), f64::from(bgr[0]));
            for (got, want, what) in [(p.y[0], y, "Y"), (p.u[0], u, "U"), (p.v[0], v, "V")] {
                assert!(
                    (f64::from(got) - want).abs() <= 1.0,
                    "{bgr:?} {what}: {got} vs {want:.1}"
                );
            }
        }
        // Greys carry no colour at all: U = V = 128 exactly.
        for g in [0, 1, 77, 128, 200, 254, 255] {
            let p = bgrx_to_i420(&solid(2, 2, [g; 3]), 8, 2, 2, 1).expect("valid");
            assert_eq!((p.u[0], p.v[0]), (128, 128), "grey {g}");
        }
    }

    #[test]
    fn threads_and_padding_do_not_change_the_result() {
        // A gradient 64x36 with 16 bytes of padding per row.
        let (w, h, stride) = (64, 36, 64 * 4 + 16);
        let px: Vec<u8> = (0..h)
            .flat_map(|r| (0..stride).map(move |c| ((r * 7 + c * 3) % 251) as u8))
            .collect();
        let one = bgrx_to_i420(&px, stride, w, h, 1).expect("valid");
        for t in [2, 3, 8, 64, 1000] {
            assert_eq!(
                bgrx_to_i420(&px, stride, w, h, t),
                Some(one.clone()),
                "{t} threads"
            );
        }
    }

    #[test]
    fn short_or_tiny_pictures_are_refused_and_odd_sizes_cropped() {
        assert!(bgrx_to_i420(&[0; 15], 8, 2, 2, 1).is_none(), "short");
        assert!(bgrx_to_i420(&[0; 64], 4, 2, 2, 1).is_none(), "stride < row");
        assert!(bgrx_to_i420(&[0; 64], 8, 1, 2, 1).is_none(), "too narrow");
        let odd = bgrx_to_i420(&solid(3, 3, [0; 3]), 12, 3, 3, 1).expect("cropped");
        assert_eq!(
            (odd.width, odd.height, odd.y.len(), odd.u.len()),
            (2, 2, 4, 1)
        );
        assert_eq!(format!("{odd:?}"), "I420(2x2)", "no pixels in Debug");
    }
}
