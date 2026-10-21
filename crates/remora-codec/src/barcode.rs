//! A frame number drawn into the picture, read back after rendering
//! (phase4-criteria P7; quality.md §2 "barcode strip").
//!
//! The strip is one row of [`CELLS`] square cells of [`CELL`] pixels in the
//! top-left corner: two guard cells (white, black), the 32-bit number (most
//! significant bit first), its CRC-8, two guard cells (black, white). A
//! cell is white (luma 235) for 1 and black (luma 16) for 0. Big cells
//! survive video compression; the CRC turns a misread into "no number"
//! rather than a wrong one, so P7 can tell "drawn frame unreadable" from
//! "drawn frame repeated".

/// Pixels per cell side.
pub const CELL: usize = 16;
/// Cells in the strip: 2 guards, 32 data bits, 8 check bits, 2 guards.
pub const CELLS: usize = 44;
/// Strip width in pixels.
pub const WIDTH: usize = CELLS * CELL;
/// Strip height in pixels.
pub const HEIGHT: usize = CELL;

const WHITE: u8 = 235;
const BLACK: u8 = 16;

/// CRC-8, polynomial x⁸ + x² + x + 1 (0x07), over the number's 4 bytes,
/// big-endian. Every one- and two-cell error in the 40 data and check
/// cells is caught (checked exhaustively for four numbers in
/// `tests/p7_barcode.rs`, not assumed).
fn crc8(value: u32) -> u8 {
    let mut crc = 0u8;
    for byte in value.to_be_bytes() {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// The cells, `true` = white.
fn cells(value: u32) -> [bool; CELLS] {
    let mut c = [false; CELLS];
    c[0] = true; // guard: white, black
    let crc = crc8(value);
    for i in 0..32 {
        c[2 + i] = value >> (31 - i) & 1 == 1;
    }
    for i in 0..8 {
        c[34 + i] = crc >> (7 - i) & 1 == 1;
    }
    c[CELLS - 1] = true; // guard: black, white
    c
}

/// The number the cells encode, if the guards and the CRC agree.
fn value_of(c: &[bool; CELLS]) -> Option<u32> {
    if !(c[0] && !c[1] && !c[CELLS - 2] && c[CELLS - 1]) {
        return None;
    }
    let value = (0..32).fold(0u32, |v, i| v << 1 | u32::from(c[2 + i]));
    let crc = (0..8).fold(0u8, |v, i| v << 1 | u8::from(c[34 + i]));
    (crc8(value) == crc).then_some(value)
}

/// Whether a plane of `rows` rows at `stride` bytes per row, each pixel
/// `bpp` bytes, holds the strip; also that the stride covers the width.
fn fits(len: usize, stride: usize, width: usize, height: usize, bpp: usize) -> bool {
    let row = WIDTH * bpp;
    width >= WIDTH
        && height >= HEIGHT
        && stride >= width.saturating_mul(bpp)
        && stride
            .checked_mul(HEIGHT - 1)
            .and_then(|b| b.checked_add(row))
            .is_some_and(|need| len >= need)
}

/// Mean brightness of the 8 × 8 pixels at the centre of each cell, read
/// through `px(offset)`; a cell is white above the midpoint.
fn sample(stride: usize, bpp: usize, threshold: u32, px: impl Fn(usize) -> u32) -> [bool; CELLS] {
    let mut c = [false; CELLS];
    let (from, to) = (CELL / 2 - 4, CELL / 2 + 4);
    for (i, cell) in c.iter_mut().enumerate() {
        let mut sum = 0;
        for row in from..to {
            for col in from..to {
                sum += px(row * stride + (i * CELL + col) * bpp);
            }
        }
        *cell = sum / 64 > threshold;
    }
    c
}

/// Draws `value` into an 8-bit luma plane. Returns `false` (and draws
/// nothing) if the picture is smaller than the strip or the plane is too
/// short for `stride`.
pub fn stamp(luma: &mut [u8], stride: usize, width: usize, height: usize, value: u32) -> bool {
    if !fits(luma.len(), stride, width, height, 1) {
        return false;
    }
    let c = cells(value);
    for row in 0..HEIGHT {
        let line = &mut luma[row * stride..row * stride + WIDTH];
        for (i, cell) in line.as_chunks_mut::<CELL>().0.iter_mut().enumerate() {
            cell.fill(if c[i] { WHITE } else { BLACK });
        }
    }
    true
}

/// Reads the number from an 8-bit luma plane (as stamped).
pub fn read_luma(luma: &[u8], stride: usize, width: usize, height: usize) -> Option<u32> {
    if !fits(luma.len(), stride, width, height, 1) {
        return None;
    }
    // Midpoint of 16 and 235.
    value_of(&sample(stride, 1, 125, |o| u32::from(luma[o])))
}

/// Reads the number from a rendered RGBA (or BGRA) picture, 4 bytes per
/// pixel: what the viewer drew.
pub fn read_rgba(rgba: &[u8], stride: usize, width: usize, height: usize) -> Option<u32> {
    if !fits(rgba.len(), stride, width, height, 4) {
        return None;
    }
    // The three colour channels averaged (the order does not matter);
    // midpoint of 0 and 255.
    let grey =
        |o: usize| (u32::from(rgba[o]) + u32::from(rgba[o + 1]) + u32::from(rgba[o + 2])) / 3;
    value_of(&sample(stride, 4, 127, grey))
}
