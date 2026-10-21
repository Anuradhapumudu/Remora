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

/// Draws `value` into an 8-bit luma plane. Returns `false` (and draws
/// nothing) if the picture is smaller than the strip or the plane is too
/// short for `stride`.
pub fn stamp(luma: &mut [u8], stride: usize, width: usize, height: usize, value: u32) -> bool {
    let _ = (luma, stride, width, height, value);
    false // RED: not yet
}

/// Reads the number from an 8-bit luma plane (as stamped).
pub fn read_luma(luma: &[u8], stride: usize, width: usize, height: usize) -> Option<u32> {
    let _ = (luma, stride, width, height);
    None // RED: not yet
}

/// Reads the number from a rendered RGBA (or BGRA) picture, 4 bytes per
/// pixel: what the viewer drew.
pub fn read_rgba(rgba: &[u8], stride: usize, width: usize, height: usize) -> Option<u32> {
    let _ = (rgba, stride, width, height);
    None // RED: not yet
}
