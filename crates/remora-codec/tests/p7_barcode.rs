//! P7 (phase4-criteria §4), the parts that run on every OS: the frame
//! number barcode and the NV12 plane checks a renderer relies on.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is how a test fails

use remora_codec::Nv12;
use remora_codec::barcode::{CELL, CELLS, HEIGHT, WIDTH, read_luma, read_rgba, stamp};

const W: usize = 1280;
const H: usize = 720;

fn plane(fill: u8) -> Vec<u8> {
    vec![fill; W * H]
}

/// What the renderer makes of a luma plane: BT.709 video range → full
/// range grey, as RGBA.
fn as_rgba(luma: &[u8], stride: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(W * H * 4);
    for row in luma.chunks(stride).take(H) {
        for &y in &row[..W] {
            let v = ((f32::from(y) - 16.0) * 255.0 / 219.0).clamp(0.0, 255.0) as u8;
            out.extend_from_slice(&[v, v, v, 255]);
        }
    }
    out
}

#[test]
fn p7_the_strip_fits_where_documented() {
    assert_eq!(WIDTH, CELLS * CELL);
    assert_eq!(HEIGHT, CELL);
    assert_eq!(CELLS, 2 + 32 + 8 + 2);
}

#[test]
fn p7_numbers_round_trip_through_luma_and_rgba() {
    for v in [0, 1, 2, 0x8000_0000, 0x1234_5678, u32::MAX - 1, u32::MAX] {
        let mut y = plane(128);
        assert!(stamp(&mut y, W, W, H, v));
        assert_eq!(read_luma(&y, W, W, H), Some(v), "{v:#x} luma");
        assert_eq!(
            read_rgba(&as_rgba(&y, W), W * 4, W, H),
            Some(v),
            "{v:#x} rgba"
        );
    }
}

#[test]
fn p7_the_strip_is_only_where_it_says() {
    // Stamping touches the top-left WIDTH × HEIGHT pixels and nothing else.
    let mut y = plane(77);
    assert!(stamp(&mut y, W, W, H, 0xA5A5_5A5A));
    for (i, &b) in y.iter().enumerate() {
        let (x, r) = (i % W, i / W);
        if x >= WIDTH || r >= HEIGHT {
            assert_eq!(b, 77, "pixel {x},{r} changed");
        } else {
            assert!(b == 16 || b == 235, "pixel {x},{r} = {b}");
        }
    }
    // Guards: white, black at the start; black, white at the end.
    assert_eq!(y[CELL / 2], 235);
    assert_eq!(y[CELL + CELL / 2], 16);
    assert_eq!(y[(CELLS - 2) * CELL + CELL / 2], 16);
    assert_eq!(y[(CELLS - 1) * CELL + CELL / 2], 235);
}

#[test]
fn p7_a_strided_plane_works() {
    let stride = W + 64;
    let mut y = vec![128u8; stride * H];
    assert!(stamp(&mut y, stride, W, H, 4242));
    assert_eq!(read_luma(&y, stride, W, H), Some(4242));
    // The padding at the end of each row is not touched.
    assert!(y.chunks(stride).all(|r| r[W..].iter().all(|&b| b == 128)));
}

#[test]
fn p7_compression_noise_is_tolerated() {
    // Every pixel off by up to ±60 (cells are 16 / 235): still the number.
    let mut y = plane(128);
    stamp(&mut y, W, W, H, 987_654_321);
    let mut x: u32 = 1;
    for p in y.iter_mut() {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let n = (x >> 16) as i32 % 121 - 60;
        *p = (i32::from(*p) + n).clamp(0, 255) as u8;
    }
    assert_eq!(read_luma(&y, W, W, H), Some(987_654_321));
}

#[test]
fn p7_a_wrong_cell_reads_as_no_number_never_another_number() {
    let mut y = plane(128);
    stamp(&mut y, W, W, H, 0x0F0F_1234);
    for cell in 0..CELLS {
        let mut z = y.clone();
        for row in 0..HEIGHT {
            for px in &mut z[row * W + cell * CELL..row * W + (cell + 1) * CELL] {
                *px = if *px == 235 { 16 } else { 235 };
            }
        }
        assert_eq!(read_luma(&z, W, W, H), None, "cell {cell} flipped");
        assert_eq!(
            read_rgba(&as_rgba(&z, W), W * 4, W, H),
            None,
            "cell {cell} rgba"
        );
    }
}

#[test]
fn p7_any_two_wrong_cells_read_as_no_number() {
    // Every pair of the 40 data + check cells (780 pairs), for a few
    // numbers: the documented claim that CRC-8 (0x07) catches all one- and
    // two-cell errors in this strip, checked rather than assumed.
    let flip = |y: &mut [u8], cell: usize| {
        for row in 0..HEIGHT {
            for px in &mut y[row * W + cell * CELL..row * W + (cell + 1) * CELL] {
                *px = if *px == 235 { 16 } else { 235 };
            }
        }
    };
    for v in [0u32, 1, 0xDEAD_BEEF, u32::MAX] {
        let mut y = plane(128);
        stamp(&mut y, W, W, H, v);
        for a in 2..42 {
            for b in a + 1..42 {
                let mut z = y.clone();
                flip(&mut z, a);
                flip(&mut z, b);
                assert_eq!(read_luma(&z, W, W, H), None, "{v:#x}: cells {a} and {b}");
            }
        }
    }
}

#[test]
fn p7_no_strip_reads_as_no_number() {
    assert_eq!(read_luma(&plane(16), W, W, H), None);
    assert_eq!(read_luma(&plane(235), W, W, H), None);
    assert_eq!(read_luma(&plane(128), W, W, H), None);
    assert_eq!(read_rgba(&vec![0u8; W * H * 4], W * 4, W, H), None);
}

#[test]
fn p7_pictures_too_small_or_planes_too_short_are_refused() {
    let mut small = vec![128u8; (WIDTH - 1) * H];
    assert!(!stamp(&mut small, WIDTH - 1, WIDTH - 1, H, 1));
    assert!(small.iter().all(|&b| b == 128));
    let mut short = vec![128u8; WIDTH * (HEIGHT - 1)];
    assert!(!stamp(&mut short, WIDTH, WIDTH, HEIGHT, 1));
    assert_eq!(read_luma(&short, WIDTH, WIDTH, HEIGHT), None);
    // Exactly the strip's size is enough.
    let mut exact = vec![128u8; WIDTH * HEIGHT];
    assert!(stamp(&mut exact, WIDTH, WIDTH, HEIGHT, 7));
    assert_eq!(read_luma(&exact, WIDTH, WIDTH, HEIGHT), Some(7));
    // A stride smaller than the width is refused, never read out of rows.
    assert!(!stamp(&mut exact, WIDTH - 1, WIDTH, HEIGHT, 7));
    assert_eq!(read_rgba(&[0u8; 16], 4, 4, 1), None);
}

// ------------------------------------------------------------- NV12 --

#[test]
fn p7_nv12_planes_are_checked_against_their_sizes() {
    let (w, h) = (6u32, 4u32);
    let y = vec![0u8; 8 * 4];
    let uv = vec![0u8; 8 * 2];
    let f = Nv12::new(w, h, &y, 8, &uv, 8).expect("valid planes");
    assert_eq!((f.width(), f.height()), (6, 4));
    assert_eq!(f.y().1, 8);
    assert_eq!(f.uv().1, 8);
    // The last row needs only the used bytes, not the whole stride.
    assert!(Nv12::new(w, h, &y[..8 * 3 + 6], 8, &uv[..8 + 6], 8).is_some());
    // One byte short in either plane.
    assert!(Nv12::new(w, h, &y[..8 * 3 + 5], 8, &uv, 8).is_none());
    assert!(Nv12::new(w, h, &y, 8, &uv[..8 + 5], 8).is_none());
    // Strides smaller than a row.
    assert!(Nv12::new(w, h, &y, 5, &uv, 8).is_none());
    assert!(Nv12::new(w, h, &y, 8, &uv, 5).is_none());
    // Zero size.
    assert!(Nv12::new(0, h, &y, 8, &uv, 8).is_none());
    assert!(Nv12::new(w, 0, &y, 8, &uv, 8).is_none());
    // Odd sizes round chroma up: 5 × 3 needs 3 chroma pairs × 2 rows.
    let y = vec![0u8; 5 * 3];
    assert!(Nv12::new(5, 3, &y, 5, &[0u8; 6 + 6], 6).is_some());
    assert!(Nv12::new(5, 3, &y, 5, &[0u8; 6 + 5], 6).is_none());
    // Absurd strides do not overflow.
    assert!(Nv12::new(w, h, &y, usize::MAX, &uv, 8).is_none());
}

#[test]
fn p7_nv12_debug_prints_no_pixels() {
    let y = vec![0xABu8; 4 * 2];
    let uv = vec![0xCDu8; 4];
    let f = Nv12::new(4, 2, &y, 4, &uv, 4).unwrap();
    assert_eq!(
        format!("{f:?}"),
        "Nv12 { width: 4, height: 2, y_stride: 4, uv_stride: 4 }"
    );
}
